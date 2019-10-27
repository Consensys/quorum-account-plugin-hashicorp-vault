// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
package manager

import (
	"bytes"
	"crypto/ecdsa"
	crand "crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/cache"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/config"
)

var (
	ErrLocked = accounts.NewAuthNeededError("password or unlock")
)

// walletRefreshCycle is the maximum time between wallet refreshes (if filesystem notifications don't work)
const walletRefreshCycle = 3 * time.Second

// Backend manages acct storage for a Hashicorp Vault, using an acctconfig storage directory on disk.
type Backend struct {
	vaultClientManager *vaultClientManager          // Manages the authenticated clients for a Vault server, providing the means to add and retrieve accts from the Vault
	cache              cache.AccountCache           // In-memory account cache for the acctconfig directory
	changes            chan struct{}                // Channel receiving change notifications from the cache
	unlocked           map[common.Address]*unlocked // Currently unlocked accounts (decrypted private keys)

	wallets     []accounts.Wallet       // Wallet wrappers around the individual accounts
	updateFeed  event.Feed              // Event feed to notify wallet additions/removals
	updateScope event.SubscriptionScope // Subscription scope tracking current live listeners
	initialised bool
	updating    bool // Whether the event notification loop is running

	mu sync.RWMutex
}

type unlocked struct {
	*Key
	abort chan struct{}
}

type AccountCreator interface {
	NewAccount(vaultAccountConfig config.VaultSecretConfig) (accounts.Account, string, error)
	ImportECDSA(priv *ecdsa.PrivateKey, vaultAccountConfig config.VaultSecretConfig) (accounts.Account, string, error)
}

// NewBackend creates a backend for the Hashicorp Vault and acctconfig directory accounts defined in the VaultConfig.
func NewBackend(config config.VaultConfig) (*Backend, error) {
	keydir, _ := filepath.Abs(config.AccountConfigDir)
	b := &Backend{}
	if err := b.init(keydir, config); err != nil {
		return nil, err
	}
	b.initialised = true
	return b, nil
}

func (b *Backend) init(keydir string, vaultConfig config.VaultConfig) error {
	// Lock the mutex since the account cache might call back with events
	b.mu.Lock()
	defer b.mu.Unlock()

	// First thing we do is check the authentication credentials and setup the vault clients.  No point continuing if incorrect vault credentials have been provided.
	clientManager, err := newVaultClientManager(vaultConfig)
	if err != nil {
		return err
	}
	b.vaultClientManager = clientManager

	// Initialize the set of unlocked keys and the account cache
	b.unlocked = make(map[common.Address]*unlocked)
	b.cache, b.changes = cache.NewAccountCache(keydir, b.vaultClientManager.vaultAddr)

	// In order for this finalizer to work, there must be no references
	// to b.
	runtime.SetFinalizer(b, func(m *Backend) {
		m.cache.Close()
	})

	// Create the initial list of wallets from the cache
	accs := b.cache.Accounts()
	b.wallets = make([]accounts.Wallet, len(accs))
	for i := 0; i < len(accs); i++ {
		b.wallets[i] = &wallet{url: accs[i].URL, account: accs[i], backend: b}
	}

	return nil
}

// Wallets implements accounts.Backend, returning all single-key wallets from the
// acctconfig directory.
func (b *Backend) Wallets() []accounts.Wallet {
	// Make sure the list of wallets is in sync with the account cache
	b.refreshWallets()

	b.mu.RLock()
	defer b.mu.RUnlock()

	cpy := make([]accounts.Wallet, len(b.wallets))
	copy(cpy, b.wallets)
	return cpy
}

// Subscribe implements accounts.Backend, creating an async subscription to
// receive notifications on the addition or removal of wallets.
func (b *Backend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// We need the mutex to reliably start/stop the update loop
	b.mu.Lock()
	defer b.mu.Unlock()

	// Subscribe the caller and track the subscriber count
	sub := b.updateScope.Track(b.updateFeed.Subscribe(sink))

	// Subscribers require an active notification loop, start it
	if !b.updating && b.initialised {
		b.updating = true
		go b.updater()
	}
	return sub
}

// SignHash calculates a ECDSA signature for the given hash. The produced
// signature is in the [R || S || V] format where V is 0 or 1.
func (b *Backend) SignHash(a accounts.Account, hash []byte) ([]byte, error) {
	// Look up the key to sign with and abort if it cannot be found
	b.mu.RLock()
	defer b.mu.RUnlock()

	unlockedKey, found := b.unlocked[a.Address]
	if !found {
		return nil, ErrLocked
	}
	// Sign the hash using plain ECDSA operations
	return crypto.Sign(hash, unlockedKey.PrivateKey)
}

// SignTx signs the given transaction with the requested account.
func (b *Backend) SignTx(a accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	// Look up the key to sign with and abort if it cannot be found
	b.mu.RLock()
	defer b.mu.RUnlock()

	unlockedKey, found := b.unlocked[a.Address]
	if !found {
		return nil, ErrLocked
	}

	if tx.IsPrivate() {
		return types.SignTx(tx, types.QuorumPrivateTxSigner{}, unlockedKey.PrivateKey)
	}

	// Depending on the presence of the chain ID, sign with EIP155 or homestead
	if chainID != nil {
		return types.SignTx(tx, types.NewEIP155Signer(chainID), unlockedKey.PrivateKey)
	}
	return types.SignTx(tx, types.HomesteadSigner{}, unlockedKey.PrivateKey)
}

// SignHashWithPassphrase retrieves the key for the given account from the Vault and uses it to sign the hash.
// passphrase is not used.  The produced signature is in the [R || S || V] format where V is 0 or 1.
func (b *Backend) SignHashWithPassphrase(a accounts.Account, passphrase string, hash []byte) (signature []byte, err error) {
	_, key, err := b.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key.PrivateKey)
	return crypto.Sign(hash, key.PrivateKey)
}

// SignTxWithPassphrase retrieves the key for the given account from the Vault and uses it to sign the transaction.
// passphrase is not used.
func (b *Backend) SignTxWithPassphrase(a accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	_, key, err := b.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key.PrivateKey)

	if tx.IsPrivate() {
		return types.SignTx(tx, types.QuorumPrivateTxSigner{}, key.PrivateKey)
	}
	// Depending on the presence of the chain ID, sign with EIP155 or homestead
	if chainID != nil {
		return types.SignTx(tx, types.NewEIP155Signer(chainID), key.PrivateKey)
	}
	return types.SignTx(tx, types.HomesteadSigner{}, key.PrivateKey)
}

// Unlock retrieves the given account from the Vault and stores it in memory indefinitely.  passphrase is not used.
func (b *Backend) Unlock(a accounts.Account, passphrase string) error {
	return b.TimedUnlock(a, passphrase, 0)
}

// Lock removes the private key with the given address from memory.
func (b *Backend) Lock(addr common.Address) error {
	b.mu.Lock()
	if unl, found := b.unlocked[addr]; found {
		b.mu.Unlock()
		b.expire(addr, unl, time.Duration(0)*time.Nanosecond)
	} else {
		b.mu.Unlock()
	}
	return nil
}

// TimedUnlock retrieves the given account from the Vault.  passphrase is not used. The account
// stays unlocked for the duration of timeout. A timeout of 0 unlocks the account
// until the program exits. The account must match a unique key file.
//
// If the account address is already unlocked for a duration, TimedUnlock extends or
// shortens the active unlock timeout. If the address was previously unlocked
// indefinitely the timeout is not altered.
func (b *Backend) TimedUnlock(a accounts.Account, passphrase string, timeout time.Duration) error {
	a, key, err := b.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	u, found := b.unlocked[a.Address]
	if found {
		if u.abort == nil {
			// The address was unlocked indefinitely, so unlocking
			// it with a timeout would be confusing.
			zeroKey(key.PrivateKey)
			return nil
		}
		// Terminate the expire goroutine and replace it below.
		close(u.abort)
	}
	if timeout > 0 {
		u = &unlocked{Key: key, abort: make(chan struct{})}
		go b.expire(a.Address, u, timeout)
	} else {
		u = &unlocked{Key: key}
	}
	b.unlocked[a.Address] = u
	return nil
}

// Find resolves the given account into a unique entry in the cache, returning the complete account (i.e. address and URL)
// and the path to the accounts acctconfig file
func (b *Backend) Find(a accounts.Account) (accounts.Account, string, error) {
	b.cache.MaybeReload()
	b.cache.Lock()
	defer b.cache.Unlock()
	a, err := b.cache.Find(a)
	if err != nil {
		return accounts.Account{}, "", err
	}
	file, err := b.cache.FindConfigFile(a)
	if err != nil {
		return accounts.Account{}, "", err
	}

	return a, file, nil
}

// NewAccount generates a new key and stores it in Vault at the location defined by the VaultSecretConfig.  The necessary
// config is written to the acctconfig directory for use as an account.
func (b *Backend) NewAccount(vaultAccountConfig config.VaultSecretConfig) (accounts.Account, string, error) {
	toValidate := config.AccountConfig{VaultSecret: vaultAccountConfig}
	if err := toValidate.ValidateForAccountCreation(); err != nil {
		return accounts.Account{}, "", err
	}

	_, account, secretUri, configfilepath, err := storeNewKey(b.vaultClientManager, crand.Reader, vaultAccountConfig)
	if err != nil {
		return accounts.Account{}, "", err
	}
	// Add the account to the cache immediately rather
	// than waiting for file system notifications to pick it up.
	b.cache.Add(account, configfilepath)
	b.refreshWallets()
	return account, secretUri, nil
}

// ImportECDSA stores the provided key in Vault at the location defined by the VaultSecretConfig.  The necessary
// config is written to the acctconfig directory for use as an account.
func (b *Backend) ImportECDSA(priv *ecdsa.PrivateKey, vaultAccountConfig config.VaultSecretConfig) (accounts.Account, string, error) {
	key := newKeyFromECDSA(priv)
	if b.cache.HasAddress(key.Address) {
		return accounts.Account{}, "", fmt.Errorf("account already exists")
	}
	return b.importKey(key, vaultAccountConfig)
}

// refreshWallets retrieves the current account list from the cache and does any necessary wallet updates.
func (b *Backend) refreshWallets() {
	// Retrieve the current list of accounts
	b.mu.Lock()
	accs := b.cache.Accounts()

	// Transform the current list of wallets into the new one
	wallets := make([]accounts.Wallet, 0, len(accs))
	events := []accounts.WalletEvent{}

	for _, account := range accs {
		// Drop wallets while they were in front of the next account
		for len(b.wallets) > 0 && b.wallets[0].URL().Cmp(account.URL) < 0 {
			log.Println("[DEBUG] wallet removed by backend", b.wallets[0])
			events = append(events, accounts.WalletEvent{Wallet: b.wallets[0], Kind: accounts.WalletDropped})
			b.wallets = b.wallets[1:]
		}
		// If there are no more wallets or the account is before the next, wrap new wallet
		if len(b.wallets) == 0 || b.wallets[0].URL().Cmp(account.URL) > 0 {
			wallet := &wallet{url: account.URL, account: account, backend: b}
			log.Println("[DEBUG] new wallet wrapped by backend", wallet)
			events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletArrived})
			wallets = append(wallets, wallet)
			continue
		}
		// If the account is the same as the first wallet, keep it
		if b.wallets[0].Accounts()[0] == account {
			wallets = append(wallets, b.wallets[0])
			b.wallets = b.wallets[1:]
			continue
		}
	}
	// Drop any leftover wallets and set the new batch
	for _, wallet := range b.wallets {
		events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletDropped})
	}
	b.wallets = wallets

	b.mu.Unlock()

	// Fire all wallet events and return
	for _, event := range events {
		log.Println("[DEBUG] backend sending event: ", event.Kind, event.Wallet.URL().String())
		b.updateFeed.Send(event)
	}
}

// updater is responsible for maintaining an up-to-date list of wallets from the acctconfig directory, and for firing
// wallet addition/removal events. It listens for account change events from the underlying account cache, and also
// periodically forces a manual refresh (only triggers for systems where the filesystem notifier is not running).
func (b *Backend) updater() {
	for {
		// Wait for an account update or a refresh timeout
		select {
		case <-b.changes:
		case <-time.After(walletRefreshCycle):
		}
		// Run the wallet refresher
		b.refreshWallets()

		// If all our subscribers left, stop the updater
		b.mu.Lock()
		if b.updateScope.Count() == 0 {
			log.Println("[DEBUG] backend updater stopping")
			b.updating = false
			b.mu.Unlock()
			return
		}
		b.mu.Unlock()
	}
}

var (
	incorrectKeyForAddrErr = errors.New("the address of the account provided does not match the address derived from the private key retrieved from the Vault.  Ensure the correct secret names and versions are specified in the node config.")
)

// getDecryptedKey retrieves the key for the provided account from the Vault using the specified authentication credentials.
// The retrieved key is cross-referenced with the account address to make sure that the matching key has been retrieved.
func (b *Backend) getDecryptedKey(a accounts.Account, auth string) (accounts.Account, *Key, error) {
	a, file, err := b.Find(a)
	if err != nil {
		return a, nil, err
	}

	key, err := b.vaultClientManager.GetKey(a.Address, file, auth)
	if err != nil {
		return a, nil, err
	}

	// validate that the retrieved key is correct for the provided account
	if !bytes.Equal(key.Address.Bytes(), a.Address.Bytes()) {
		zeroKey(key.PrivateKey)
		return a, nil, incorrectKeyForAddrErr
	}
	return a, key, err
}

func (b *Backend) expire(addr common.Address, u *unlocked, timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-u.abort:
		// just quit
	case <-t.C:
		b.mu.Lock()
		// only drop if it's still the same key instance that dropLater
		// was launched with. we can check that using pointer equality
		// because the map stores a new pointer every time the key is
		// unlocked.
		if b.unlocked[addr] == u {
			zeroKey(u.PrivateKey)
			delete(b.unlocked, addr)
		}
		b.mu.Unlock()
	}
}

// importKey adds the provided key to the Vault and created the necessary acctconfig file using the VaultSecretConfig.
// The cache is updated after import.  The new account and Vault URI for the created secret are returned.
func (b *Backend) importKey(key *Key, vaultAccountConfig config.VaultSecretConfig) (accounts.Account, string, error) {
	configfilepath := b.vaultClientManager.JoinPath(keyFileName(key.Address))

	acct, secretUri, err := b.vaultClientManager.StoreKey(configfilepath, vaultAccountConfig, key)
	if err != nil {
		zeroKey(key.PrivateKey)
		return accounts.Account{}, "", err
	}
	b.cache.Add(acct, configfilepath)
	b.refreshWallets()
	return acct, secretUri, nil
}

// zeroKey zeroes a private key in memory.
func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

// parseURL converts a user supplied URL into the accounts specific structure.
func parseURL(url string) (accounts.URL, error) {
	parts := strings.Split(url, "://")
	if len(parts) != 2 || parts[0] == "" {
		return accounts.URL{}, errors.New("protocol scheme missing")
	}
	return accounts.URL{
		Scheme: parts[0],
		Path:   parts[1],
	}, nil
}
