package vault

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

// vaultWallet implements accounts.Wallet and represents the common functionality shared by all wallets that manage accounts stored in vaults
type vaultWallet struct {
	backend *VaultBackend
	url     accounts.URL
	vault   vaultService
}

// vaultService defines the vendor-specific functionality that vault wallets must implement
type vaultService interface {
	// Status returns a textual status to aid the user in the current state of the
	// wallet. It also returns an error indicating any failure the wallet might have
	// encountered.
	status() (string, error)

	// open initializes access to a wallet.  It establishes a connection to the vault but does not retrieve private keys from the vault by default.
	open() error

	// close releases any resources held by an open wallet instance.
	close() error

	// accounts returns a copy of the list of signing accounts the wallet is currently aware of.
	accounts() []accounts.Account

	// getKey returns the key for the given account.  If the account is locked and allowUnlock is true, the account will be unlocked by retrieving the key from the vault.  zeroFn is the corresponding zero function for the returned key and should be called to clean up once the key has been used.
	getKey(acct accounts.Account, allowUnlock bool) (key *ecdsa.PrivateKey, zeroFn func(), err error)

	// timedUnlock unlocks the given account for the duration of timeout. A timeout of 0 unlocks the account until the program exits.
	//
	// If the account address is already unlocked for a duration, TimedUnlock extends or
	// shortens the active unlock timeout. If the address was previously unlocked
	// indefinitely the timeout is not altered.
	timedUnlock(acct accounts.Account, timeout time.Duration) error

	// lock removes the private key for the given account from memory.
	lock(acct accounts.Account) error

	add(key *ecdsa.PrivateKey, config interface{}) (common.Address, error)
}

// newHashicorpWallet creates a Hashicorp Vault compatible vaultWallet using the provided config.  Wallet events will be applied to updateFeed.
func newHashicorpWallet(config HashicorpWalletConfig, backend *VaultBackend) (*vaultWallet, error) {
	wUrl, err := MakeWalletUrl(config.VaultUrl, config.AuthorizationID)

	if err != nil {
		return nil, err
	}

	w := &vaultWallet{
		url:     wUrl,
		vault:   newHashicorpService(config, false),
		backend: backend,
	}

	return w, nil
}

// URL implements accounts.Wallet, returning the URL of the configured vault.
func (w *vaultWallet) URL() accounts.URL {
	return w.url
}

// Status implements accounts.Wallet, returning a custom status message from the
// underlying vendor-specific vault service implementation.
func (w *vaultWallet) Status() (string, error) {
	return w.vault.status()
}

// Open implements accounts.Wallet, attempting to open a connection to the
// vault.
func (w *vaultWallet) Open(passphrase string) error {
	if err := w.vault.open(); err != nil {
		return err
	}

	w.backend.updateFeed.Send(accounts.WalletEvent{Wallet: w, Kind: accounts.WalletOpened})

	return nil
}

// Close implements accounts.Wallet, closing the connection to the vault.
func (w *vaultWallet) Close() error {
	return w.vault.close()
}

// Accounts implements accounts.Wallet, returning the list of accounts the wallet is
// currently aware of.
func (w *vaultWallet) Accounts() []accounts.Account {
	return w.vault.accounts()
}

// Contains implements accounts.Wallet, returning whether a particular account is
// or is not managed by this wallet. An account with no url only needs to match
// on the address to return true.
func (w *vaultWallet) Contains(account accounts.Account) bool {
	equal := func(a, b accounts.Account) bool {
		return a.Address == b.Address && (a.URL == b.URL || a.URL == accounts.URL{} || b.URL == accounts.URL{})
	}

	accts := w.Accounts()

	for _, a := range accts {
		if equal(a, account) {
			return true
		}
	}
	return false
}

// Derive implements accounts.Wallet, but is a noop for vault wallets since there
// is no notion of hierarchical account derivation for vault-stored accounts.
func (w *vaultWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	return accounts.Account{}, accounts.ErrNotSupported
}

// SelfDerive implements accounts.Wallet, but is a noop for vault wallets since
// there is no notion of hierarchical account derivation for vault-stored accounts.
func (w *vaultWallet) SelfDerive(base accounts.DerivationPath, chain ethereum.ChainStateReader) {}

// SignHash implements accounts.Wallet, attempting to sign the given hash with
// the given account. If the wallet does not manage this particular account, an
// error is returned.
//
// The hash will not be signed if the account is locked.
func (w *vaultWallet) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	return w.signHash(account, hash, false)
}

// SignTx implements accounts.Wallet, attempting to sign the given transaction
// with the given account. If the wallet does not manage this particular account,
// an error is returned.
//
// The transaction will not be signed if the account is locked.
func (w *vaultWallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return w.signTx(account, tx, chainID, false)
}

// SignHashWithPassphrase implements accounts.Wallet, attempting to sign the given hash with
// the given account. If the wallet does not manage this particular account, an
// error is returned.
//
// If the account is locked, the wallet will unlock it but only for the duration
// of the signing.  The passphrase arg is not used.
func (w *vaultWallet) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	return w.signHash(account, hash, true)
}

// SignTxWithPassphrase implements accounts.Wallet, attempting to sign the given transaction
// with the given account. If the wallet does not manage this particular account,
// an error is returned.
//
// If the account is locked, the wallet will unlock it but only for the duration
// of the signing.  The passphrase arg is not used.
func (w *vaultWallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return w.signTx(account, tx, chainID, true)
}

func (w *vaultWallet) signHash(account accounts.Account, hash []byte, allowUnlock bool) ([]byte, error) {
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}

	key, zero, err := w.vault.getKey(account, allowUnlock)
	defer zero()

	if err != nil {
		return nil, err
	}

	// validate that the retrieved key is correct for the provided account
	address := crypto.PubkeyToAddress(key.PublicKey)
	if !bytes.Equal(address.Bytes(), account.Address.Bytes()) {
		zero()
		return nil, incorrectKeyForAddrErr
	}

	return crypto.Sign(hash, key)
}

func (w *vaultWallet) signTx(account accounts.Account, tx *types.Transaction, chainID *big.Int, allowUnlock bool) (*types.Transaction, error) {
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}

	key, zero, err := w.vault.getKey(account, allowUnlock)
	defer zero()

	if err != nil {
		return nil, err
	}

	// validate that the retrieved key is correct for the provided account
	address := crypto.PubkeyToAddress(key.PublicKey)
	if !bytes.Equal(address.Bytes(), account.Address.Bytes()) {
		zero()
		return nil, incorrectKeyForAddrErr
	}

	// start quorum specific
	if tx.IsPrivate() {
		log.Info("Private transaction signing with QuorumPrivateTxSigner")
		return types.SignTx(tx, types.QuorumPrivateTxSigner{}, key)
	} // End quorum specific

	// Depending on the presence of the chain ID, sign with EIP155 or homestead
	if chainID != nil {
		return types.SignTx(tx, types.NewEIP155Signer(chainID), key)
	}
	return types.SignTx(tx, types.HomesteadSigner{}, key)
}

// TimedUnlock unlocks the given account for the duration of timeout. A timeout of 0 unlocks the account until the program exits.
//
// If the account address is already unlocked for a duration, TimedUnlock extends or
// shortens the active unlock timeout. If the address was previously unlocked
// indefinitely the timeout is not altered.
//
// If the wallet does not manage this particular account, an error is returned.
func (w *vaultWallet) TimedUnlock(account accounts.Account, timeout time.Duration) error {
	if !w.Contains(account) {
		return accounts.ErrUnknownAccount
	}

	return w.vault.timedUnlock(account, timeout)
}

// Lock locks the given account thereby removing the corresponding private key from memory. If the
// wallet does not manage this particular account, an error is returned.
func (w *vaultWallet) Lock(account accounts.Account) error {
	if !w.Contains(account) {
		return accounts.ErrUnknownAccount
	}

	return w.vault.lock(account)
}

func (w *vaultWallet) NewAccount(config interface{}) (common.Address, error) {
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return common.Address{}, err
	}
	// zero the key as new accounts should be locked by default
	defer zeroKey(key)

	return w.vault.add(key, config)
}

func (w *vaultWallet) Import(key *ecdsa.PrivateKey, config interface{}) (common.Address, error) {
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return common.Address{}, err
	}
	// zero the key as new accounts should be locked by default
	defer zeroKey(key)

	return w.vault.add(key, config)
}

//// Store writes the provided private key to the vault as two parts: the hex representation of the key and the 20-byte hex address derived from the key.  The address is returned along with the url identifiers of all secrets written to the vault.
////
//// If an error is encountered during Store, the urls of any secrets already written to the vault will be included in the error.
//func (w *vaultWallet) Store(key *ecdsa.PrivateKey) (common.Address, []string, error) {
//	addr, storedUrls, err := w.vault.store(key)
//
//	if err != nil {
//		return common.Address{}, nil, err
//	}
//
//	return addr, storedUrls, nil
//}

// accountsByURL implements the sort interface to enable the sorting of a slice of accounts alphanumerically by their urls
type accountsByURL []accounts.Account

func (s accountsByURL) Len() int           { return len(s) }
func (s accountsByURL) Less(i, j int) bool { return s[i].URL.Cmp(s[j].URL) < 0 }
func (s accountsByURL) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// zeroKey zeroes a private key in memory
func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
