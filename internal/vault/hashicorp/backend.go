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

// Package keystore implements encrypted storage of secp256k1 private keys.
//
// Keys are stored as encrypted JSON files according to the Web3 Secret Storage specification.
// See https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition for more information.
package hashicorp

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/cache"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
)

var (
	ErrLocked  = accounts.NewAuthNeededError("password or unlock")
	ErrNoMatch = errors.New("no key for given address or file")
	ErrDecrypt = errors.New("could not decrypt key with given passphrase")
)

// KeyStoreType is the reflect type of a keystore backend.
var KeyStoreType = reflect.TypeOf(&Backend{})

// KeyStoreScheme is the protocol scheme prefixing account and wallet URLs.
const KeyStoreScheme = "keystore"

const (
	WalletScheme = "hashiwlt"
	AcctScheme   = "hashiacct"
)

// Maximum time between wallet refreshes (if filesystem notifications don't work).
const walletRefreshCycle = 3 * time.Second

// Backend manages a key storage directory on disk.
type Backend struct {
	authManager authManager
	storage     keyStore            // Storage backend, might be cleartext or encrypted
	cache       *cache.AccountCache // In-memory account cache over the filesystem storage
	//TODO has been exported for cache tests due to moving cache into a separate pkg.  Probably don't want to keep exported so review the cache tests
	Changes  chan struct{}                // Channel receiving change notifications from the cache
	unlocked map[common.Address]*unlocked // Currently unlocked account (decrypted private keys)

	wallets     []accounts.Wallet       // Wallet wrappers around the individual key files
	updateFeed  event.Feed              // Event feed to notify wallet additions/removals
	updateScope event.SubscriptionScope // Subscription scope tracking current live listeners
	updating    bool                    // Whether the event notification loop is running

	mu sync.RWMutex
}

type unlocked struct {
	*Key
	abort chan struct{}
}

// NewKeyStore creates a keystore for the given directory.
func NewBackend(config VaultConfig) *Backend {
	keydir, _ := filepath.Abs(config.AccountConfigDir)
	ks := &Backend{storage: &keystoreHashicorp{}}
	ks.init(keydir, config)
	return ks
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

func (b *Backend) init(keydir string, config VaultConfig) {
	// Lock the mutex since the account cache might call back with events
	b.mu.Lock()
	defer b.mu.Unlock()

	// Initialize the set of unlocked keys and the account cache
	b.unlocked = make(map[common.Address]*unlocked)
	b.cache, b.Changes = cache.NewAccountCache(keydir, JsonAccountConfigUnmarshaller{})

	// TODO: In order for this finalizer to work, there must be no references
	// to b. addressCache doesn't keep a reference but unlocked keys do,
	// so the finalizer will not trigger until all timed unlocks have expired.
	runtime.SetFinalizer(b, func(m *Backend) {
		m.cache.Close()
	})
	// Create the initial list of wallets from the cache
	accs := b.cache.Accounts()
	b.wallets = make([]accounts.Wallet, len(accs))

	// create the vault client and authenticate
	b.authManager.init(config.Auth)

	// create the wallets and unlock if configured
	addrs := strings.Split(config.Unlock, ",")
	var toUnlock []common.Address

	for _, addr := range addrs {
		if trimmed := strings.TrimSpace(addr); trimmed != "" {
			if common.IsHexAddress(trimmed) {
				toUnlock = append(toUnlock, common.HexToAddress(trimmed))
			} else {
				// TODO use standard log package
				log.Error("Failed to unlock account", "addr", trimmed, "err", "invalid hex-encoded ethereum address")
			}
		}
	}

	for i := 0; i < len(accs); i++ {
		w := &wallet{account: accs[i], backend: b}
		b.wallets[i] = w
		for _, u := range toUnlock {
			if accs[i].Address == u {
				if err := b.Unlock(accs[i], ""); err != nil {
					log.Error("Failed to unlock account", "addr", accs[i].Address.Hex(), "err", err)
				}
			}
		}
	}
}

// Wallets implements accounts.Backend, returning all single-key wallets from the
// keystore directory.
func (b *Backend) Wallets() []accounts.Wallet {
	// Make sure the list of wallets is in sync with the account cache
	b.refreshWallets()

	b.mu.RLock()
	defer b.mu.RUnlock()

	cpy := make([]accounts.Wallet, len(b.wallets))
	copy(cpy, b.wallets)
	return cpy
}

// refreshWallets retrieves the current account list and based on that does any
// necessary wallet refreshes.
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
			events = append(events, accounts.WalletEvent{Wallet: b.wallets[0], Kind: accounts.WalletDropped})
			b.wallets = b.wallets[1:]
		}
		// If there are no more wallets or the account is before the next, wrap new wallet
		if len(b.wallets) == 0 || b.wallets[0].URL().Cmp(account.URL) > 0 {
			wallet := &wallet{account: account, backend: b}

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
		b.updateFeed.Send(event)
	}
}

// Subscribe implements accounts.Backend, creating an async subscription to
// receive notifications on the addition or removal of keystore wallets.
func (b *Backend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// We need the mutex to reliably start/stop the update loop
	b.mu.Lock()
	defer b.mu.Unlock()

	// Subscribe the caller and track the subscriber count
	sub := b.updateScope.Track(b.updateFeed.Subscribe(sink))

	// Subscribers require an active notification loop, start it
	if !b.updating {
		b.updating = true
		go b.updater()
	}
	return sub
}

// updater is responsible for maintaining an up-to-date list of wallets stored in
// the keystore, and for firing wallet addition/removal events. It listens for
// account change events from the underlying account cache, and also periodically
// forces a manual refresh (only triggers for systems where the filesystem notifier
// is not running).
func (b *Backend) updater() {
	for {
		// Wait for an account update or a refresh timeout
		select {
		case <-b.Changes:
		case <-time.After(walletRefreshCycle):
		}
		// Run the wallet refresher
		b.refreshWallets()

		// If all our subscribers left, stop the updater
		b.mu.Lock()
		if b.updateScope.Count() == 0 {
			b.updating = false
			b.mu.Unlock()
			return
		}
		b.mu.Unlock()
	}
}

// HasAddress reports whether a key with the given address is present.
func (b *Backend) HasAddress(addr common.Address) bool {
	return b.cache.HasAddress(addr)
}

// Accounts returns all key files present in the directory.
func (b *Backend) Accounts() []accounts.Account {
	return b.cache.Accounts()
}

// Delete deletes the key matched by account if the passphrase is correct.
// If the account contains no filename, the address must match a unique key.
func (b *Backend) Delete(a accounts.Account, passphrase string) error {
	// Decrypting the key isn't really necessary, but we do
	// it anyway to check the password and zero out the key
	// immediately afterwards.
	a, key, err := b.getDecryptedKey(a, passphrase)
	if key != nil {
		zeroKey(key.PrivateKey)
	}
	if err != nil {
		return err
	}
	// The order is crucial here. The key is dropped from the
	// cache after the file is gone so that a reload happening in
	// between won't insert it into the cache again.
	err = os.Remove(a.URL.Path)
	if err == nil {
		b.cache.Delete(a)
		b.refreshWallets()
	}
	return err
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

	// start quorum specific
	if tx.IsPrivate() {
		log.Info("Private transaction signing with QuorumPrivateTxSigner")
		return types.SignTx(tx, types.QuorumPrivateTxSigner{}, unlockedKey.PrivateKey)
	} // End quorum specific

	// Depending on the presence of the chain ID, sign with EIP155 or homestead
	if chainID != nil {
		return types.SignTx(tx, types.NewEIP155Signer(chainID), unlockedKey.PrivateKey)
	}
	return types.SignTx(tx, types.HomesteadSigner{}, unlockedKey.PrivateKey)
}

// SignHashWithPassphrase signs hash if the private key matching the given address
// can be decrypted with the given passphrase. The produced signature is in the
// [R || S || V] format where V is 0 or 1.
func (b *Backend) SignHashWithPassphrase(a accounts.Account, passphrase string, hash []byte) (signature []byte, err error) {
	_, key, err := b.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key.PrivateKey)
	return crypto.Sign(hash, key.PrivateKey)
}

// SignTxWithPassphrase signs the transaction if the private key matching the
// given address can be decrypted with the given passphrase.
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

// Unlock unlocks the given account indefinitely.
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

// TimedUnlock unlocks the given account with the passphrase. The account
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

// Find resolves the given account into a unique entry in the keystore.
func (b *Backend) Find(a accounts.Account) (accounts.Account, error) {
	b.cache.MaybeReload()
	b.cache.Mu.Lock()
	a, err := b.cache.Find(a)
	b.cache.Mu.Unlock()
	return a, err
}

func (b *Backend) getDecryptedKey(a accounts.Account, auth string) (accounts.Account, *Key, error) {
	a, err := b.Find(a)
	if err != nil {
		return a, nil, err
	}
	key, err := b.storage.GetKey(a.Address, a.URL.Path, auth)
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

// NewAccount generates a new key and stores it into the key directory,
// encrypting it with the passphrase.
func (b *Backend) NewAccount(passphrase string) (accounts.Account, error) {
	_, account, err := storeNewKey(b.storage, crand.Reader, passphrase)
	if err != nil {
		return accounts.Account{}, err
	}
	// Add the account to the cache immediately rather
	// than waiting for file system notifications to pick it up.
	b.cache.Add(account)
	b.refreshWallets()
	return account, nil
}

// Export exports as a JSON key, encrypted with newPassphrase.
func (b *Backend) Export(a accounts.Account, passphrase, newPassphrase string) (keyJSON []byte, err error) {
	_, key, err := b.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	var N, P int
	if store, ok := b.storage.(*keyStorePassphrase); ok {
		N, P = store.scryptN, store.scryptP
	} else {
		N, P = StandardScryptN, StandardScryptP
	}
	return EncryptKey(key, newPassphrase, N, P)
}

// Import stores the given encrypted JSON key into the key directory.
func (b *Backend) Import(keyJSON []byte, passphrase, newPassphrase string) (accounts.Account, error) {
	key, err := DecryptKey(keyJSON, passphrase)
	if key != nil && key.PrivateKey != nil {
		defer zeroKey(key.PrivateKey)
	}
	if err != nil {
		return accounts.Account{}, err
	}
	return b.importKey(key, newPassphrase)
}

// ImportECDSA stores the given key into the key directory, encrypting it with the passphrase.
func (b *Backend) ImportECDSA(priv *ecdsa.PrivateKey, passphrase string) (accounts.Account, error) {
	key := newKeyFromECDSA(priv)
	if b.cache.HasAddress(key.Address) {
		return accounts.Account{}, fmt.Errorf("account already exists")
	}
	return b.importKey(key, passphrase)
}

func (b *Backend) importKey(key *Key, passphrase string) (accounts.Account, error) {
	a := accounts.Account{Address: key.Address, URL: accounts.URL{Scheme: KeyStoreScheme, Path: b.storage.JoinPath(keyFileName(key.Address))}}
	if err := b.storage.StoreKey(a.URL.Path, key, passphrase); err != nil {
		return accounts.Account{}, err
	}
	b.cache.Add(a)
	b.refreshWallets()
	return a, nil
}

// Update changes the passphrase of an existing account.
func (b *Backend) Update(a accounts.Account, passphrase, newPassphrase string) error {
	a, key, err := b.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}
	return b.storage.StoreKey(a.URL.Path, key, newPassphrase)
}

// ImportPreSaleKey decrypts the given Ethereum presale wallet and stores
// a key file in the key directory. The key file is encrypted with the same passphrase.
func (b *Backend) ImportPreSaleKey(keyJSON []byte, passphrase string) (accounts.Account, error) {
	a, _, err := importPreSaleKey(b.storage, keyJSON, passphrase)
	if err != nil {
		return a, err
	}
	b.cache.Add(a)
	b.refreshWallets()
	return a, nil
}

// zeroKey zeroes a private key in memory.
func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
