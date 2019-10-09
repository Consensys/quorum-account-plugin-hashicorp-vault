package hashicorp

import (
	"bytes"
	"errors"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/cache"
	"github.com/hashicorp/vault/api"
	"math/big"
	"runtime"
	"strings"
	"sync"
)

const (
	WalletScheme = "hashiwlt"
	AcctScheme   = "hashiacct"
)

// wallet implements accounts.Wallet and represents the common functionality shared by all wallets that manage accounts stored in vaults
type wallet struct {
	backend *Backend
	url     accounts.URL

	config        HashicorpWalletConfig
	mutex         sync.RWMutex
	client        *api.Client
	disableCache  bool
	failedOpenErr error

	cache    *cache.AccountCache
	changes  chan struct{}                // Channel receiving change notifications from the cache; TODO may not need
	unlocked map[common.Address]*unlocked // Currently unlocked account (decrypted private keys)
}

type unlocked struct {
	// TODO consider not using keystore type, same as with keystore.ErrLocked
	*keystore.Key
	abort chan struct{}
}

// newHashicorpWallet creates a Hashicorp Vault compatible wallet using the provided config.  Wallet events will be applied to updateFeed.
func NewHashicorpWallet(config HashicorpWalletConfig, backend *Backend, disableCache bool) (*wallet, error) {
	wUrl, err := vault.MakeWalletUrl(WalletScheme, config.AuthorizationID, config.VaultUrl)
	if err != nil {
		return nil, err
	}

	// Add the list of accounts to be unlocked; they will be unlocked once the wallet is opened
	// TODO require insecure unlock config option to be true
	addrs := strings.Split(config.Unlock, ",")
	var toUnlock []common.Address

	for _, addr := range addrs {
		if trimmed := strings.TrimSpace(addr); trimmed != "" {
			if common.IsHexAddress(trimmed) {
				toUnlock = append(toUnlock, common.HexToAddress(trimmed))
			} else {
				// TODO use standard log package
				log.Debug("Failed to unlock account", "addr", trimmed, "err", "invalid hex-encoded ethereum address")
			}
		}
	}

	w := &wallet{
		url:     wUrl,
		backend: backend,
		config:  config,
		//toUnlock:     toUnlock,
		unlocked:     make(map[common.Address]*unlocked),
		disableCache: disableCache,
	}

	//// first thing we do is try to setup and authenticate the Vault client - no point continuing if the Vault config is incorrect
	//if err := h.setupClient(); err != nil {
	//	return nil
	//}

	w.cache, w.changes = cache.NewAccountCache(w.config.AccountConfigDir, w, toUnlock, JsonAccountConfigUnmarshaller{})

	// TODO: In order for this finalizer to work, there must be no references
	// to ks. addressCache doesn't keep a reference but unlocked keys do,
	// so the finalizer will not trigger until all timed unlocks have expired.
	runtime.SetFinalizer(w, func(m *wallet) {
		m.cache.Close()
	})

	w.reloadCache()

	return w, nil
}

func (w *wallet) isClosed() bool {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	return w.client == nil
}

func (w *wallet) reloadCache() {
	if !w.disableCache {
		w.cache.MaybeReload()
	}
}

// URL implements accounts.Wallet, returning the URL of the configured vault.
func (w *wallet) URL() accounts.URL {
	return w.url
}

// Status implements accounts.Wallet, returning a custom status message from the
// underlying vendor-specific vault service implementation.
func (w *wallet) Status() (string, error) {
	if w.isClosed() {
		return closed, w.failedOpenErr
	}
	w.reloadCache()
	return w.status()
}

// Open implements accounts.Wallet, attempting to open a connection to the
// vault.
func (w *wallet) Open(passphrase string) error {
	if !w.isClosed() {
		return accounts.ErrWalletAlreadyOpen
	}

	if err := w.setupClient(); err != nil {
		return err
	}

	w.backend.updateFeed.Send(accounts.WalletEvent{Wallet: w, Kind: accounts.WalletOpened})

	return nil
}

// Close implements accounts.Wallet, closing the connection to the vault.
func (w *wallet) Close() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.client.ClearToken()
	w.client = nil

	return nil
}

// Accounts implements accounts.Wallet, returning the list of accounts the wallet is
// currently aware of.
func (w *wallet) Accounts() []accounts.Account {
	if w.cache == nil {
		return []accounts.Account{}
	}

	return w.cache.Accounts()
}

// Contains implements accounts.Wallet, returning whether a particular account is
// or is not managed by this wallet. An account with no url only needs to match
// on the address to return true.
func (w *wallet) Contains(account accounts.Account) bool {
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
func (w *wallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	return accounts.Account{}, accounts.ErrNotSupported
}

// SelfDerive implements accounts.Wallet, but is a noop for vault wallets since
// there is no notion of hierarchical account derivation for vault-stored accounts.
func (w *wallet) SelfDerive(base accounts.DerivationPath, chain ethereum.ChainStateReader) {}

// SignHash implements accounts.Wallet, attempting to sign the given hash with
// the given account. If the wallet does not manage this particular account, an
// error is returned.
//
// The hash will not be signed if the account is locked.
func (w *wallet) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	return w.signHash(account, hash, false)
}

// SignTx implements accounts.Wallet, attempting to sign the given transaction
// with the given account. If the wallet does not manage this particular account,
// an error is returned.
//
// The transaction will not be signed if the account is locked.
func (w *wallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return w.signTx(account, tx, chainID, false)
}

// SignHashWithPassphrase implements accounts.Wallet, attempting to sign the given hash with
// the given account. If the wallet does not manage this particular account, an
// error is returned.
//
// If the account is locked, the wallet will unlock it but only for the duration
// of the signing.  The passphrase arg is not used.
func (w *wallet) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	return w.signHash(account, hash, true)
}

// SignTxWithPassphrase implements accounts.Wallet, attempting to sign the given transaction
// with the given account. If the wallet does not manage this particular account,
// an error is returned.
//
// If the account is locked, the wallet will unlock it but only for the duration
// of the signing.  The passphrase arg is not used.
func (w *wallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return w.signTx(account, tx, chainID, true)
}

var (
	incorrectKeyForAddrErr = errors.New("the address of the account provided does not match the address derived from the private key retrieved from the Vault.  Ensure the correct secret names and versions are specified in the node config.")
)

func (w *wallet) signHash(account accounts.Account, hash []byte, allowUnlock bool) ([]byte, error) {
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}

	key, zero, err := w.getKey(account, allowUnlock)
	defer doIfNotNil(zero)

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

func (w *wallet) signTx(account accounts.Account, tx *types.Transaction, chainID *big.Int, allowUnlock bool) (*types.Transaction, error) {
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}

	key, zero, err := w.getKey(account, allowUnlock)
	defer doIfNotNil(zero)

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

func doIfNotNil(f func()) {
	if f == nil {
		return
	}
	f()
}
