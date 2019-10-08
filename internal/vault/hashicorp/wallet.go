package hashicorp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/cache"
	"github.com/hashicorp/vault/api"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

const (
	WalletScheme = "hashiwlt"
	AcctScheme   = "hashiacct"
)

// wallet implements accounts.Wallet and represents the common functionality shared by all wallets that manage accounts stored in vaults
type wallet struct {
	backend *Backend
	url     accounts.URL

	config HashicorpWalletConfig
	mutex  sync.RWMutex
	client *api.Client
	//toUnlock      []common.Address
	disableCache  bool
	failedOpenErr error

	cache    *cache.AccountCache
	changes  chan struct{}                // Channel receiving change notifications from the cache; TODO may not need
	unlocked map[common.Address]*unlocked // Currently unlocked account (decrypted private keys)
}

type unlocked struct {
	*keystore.Key
	abort chan struct{}
}

// newHashicorpWallet creates a Hashicorp Vault compatible wallet using the provided config.  Wallet events will be applied to updateFeed.
func newHashicorpWallet(config HashicorpWalletConfig, backend *Backend, disableCache bool) (*wallet, error) {
	wUrl, err := MakeWalletUrl(config.VaultUrl, config.AuthorizationID)
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

// Status for a hashicorpService
const (
	closed                     = "Closed"
	hashicorpHealthcheckFailed = "Hashicorp Vault healthcheck failed"
	hashicorpUninitialized     = "Hashicorp Vault uninitialized"
	hashicorpSealed            = "Hashicorp Vault sealed"
)

var (
	hashicorpSealedErr        = errors.New(hashicorpSealed)
	hashicorpUninitializedErr = errors.New(hashicorpUninitialized)
)

type hashicorpHealthcheckErr struct {
	err error
}

func (e hashicorpHealthcheckErr) Error() string {
	return fmt.Sprintf("%v: %v", hashicorpHealthcheckFailed, e.err)
}

// Status implements accounts.Wallet, returning a custom status message from the
// underlying vendor-specific vault service implementation.
func (w *wallet) Status() (string, error) {
	if w.isClosed() {
		return closed, w.failedOpenErr
	}

	w.reloadCache()

	w.mutex.RLock()
	defer w.mutex.RUnlock()

	client := w.client

	health, err := client.Sys().Health()

	switch {
	case err != nil:
		return w.cacheStatus(), hashicorpHealthcheckErr{err: err}
	case !health.Initialized:
		return w.cacheStatus(), hashicorpUninitializedErr
	case health.Sealed:
		return w.cacheStatus(), hashicorpSealedErr
	}

	return w.cacheStatus(), nil
}

// withAcctStatuses appends the locked/unlocked status of the accounts managed by the service to the provided walletStatus.
// Expects RLock to be held.
func (w *wallet) cacheStatus() string {
	// no accounts so just return
	if w.cache == nil || len(w.cache.All) == 0 {
		return ""
	}

	var (
		unlocked, locked             []string
		unlockedStatus, lockedStatus string
	)

	// TODO this does not account for the case where there are multiple accounts/secret configs for the same address.  If vault url is used as the account url then this doesn't become as much of an issue but the user will be hit with an ambiguous acct error when they attempt to sign even though the status may be unlocked

	for uAddr := range w.unlocked {
		unlocked = append(unlocked, hexutil.Encode(uAddr[:]))
	}

	if len(unlocked) > 0 {
		unlockedStatus = fmt.Sprintf("Unlocked: %v", strings.Join(unlocked, ", "))
	}

	for addr, _ := range w.cache.ByAddr {
		if _, ok := w.unlocked[addr]; !ok {
			locked = append(locked, hexutil.Encode(addr[:]))
		}
	}

	if len(locked) > 0 {
		lockedStatus = fmt.Sprintf("Locked: %v", strings.Join(locked, ", "))
	}

	if unlockedStatus != "" && lockedStatus != "" {
		return fmt.Sprintf("%v; %v", unlockedStatus, lockedStatus)
	} else if unlockedStatus != "" {
		return unlockedStatus
	} else {
		return lockedStatus
	}
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

// Environment variable name for Hashicorp Vault authentication credential
const (
	DefaultRoleIDEnv   = "QRM_HASHIVLT_ROLE_ID"
	DefaultSecretIDEnv = "QRM_HASHIVLT_SECRET_ID"
	DefaultTokenEnv    = "QRM_HASHIVLT_TOKEN"
)

type noHashicorpEnvSetErr struct {
	roleIdEnv, secretIdEnv, tokenEnv string
}

func (e noHashicorpEnvSetErr) Error() string {
	return fmt.Sprintf("environment variables are necessary to authenticate with Hashicorp Vault: set %v and %v if using Approle authentication, else set %v", e.roleIdEnv, e.secretIdEnv, e.tokenEnv)
}

type invalidApproleAuthErr struct {
	roleIdEnv, secretIdEnv string
}

func (e invalidApproleAuthErr) Error() string {
	return fmt.Sprintf("both %v and %v environment variables must be set if using Approle authentication", e.roleIdEnv, e.secretIdEnv)
}

func (w *wallet) setupClient() error {
	conf := api.DefaultConfig()
	conf.Address = w.config.VaultUrl

	tlsConfig := &api.TLSConfig{
		CACert:     w.config.CaCert,
		ClientCert: w.config.ClientCert,
		ClientKey:  w.config.ClientKey,
	}

	if err := conf.ConfigureTLS(tlsConfig); err != nil {
		return fmt.Errorf("error creating Hashicorp client: %v", err)
	}

	c, err := api.NewClient(conf)

	if err != nil {
		return fmt.Errorf("error creating Hashicorp client: %v", err)
	}

	roleIDEnv := applyPrefix(w.config.AuthorizationID, DefaultRoleIDEnv)
	secretIDEnv := applyPrefix(w.config.AuthorizationID, DefaultSecretIDEnv)
	tokenEnv := applyPrefix(w.config.AuthorizationID, DefaultTokenEnv)

	roleID := os.Getenv(roleIDEnv)
	secretID := os.Getenv(secretIDEnv)
	token := os.Getenv(tokenEnv)

	if roleID == "" && secretID == "" && token == "" {
		return noHashicorpEnvSetErr{roleIdEnv: roleIDEnv, secretIdEnv: secretIDEnv, tokenEnv: tokenEnv}
	}

	if roleID == "" && secretID != "" || roleID != "" && secretID == "" {
		return invalidApproleAuthErr{roleIdEnv: roleIDEnv, secretIdEnv: secretIDEnv}
	}

	if usingApproleAuth(roleID, secretID) {
		//authenticate the client using approle
		body := map[string]interface{}{"role_id": roleID, "secret_id": secretID}

		approle := w.config.ApprolePath

		if approle == "" {
			approle = "approle"
		}

		resp, err := c.Logical().Write(fmt.Sprintf("auth/%s/login", approle), body)

		if err != nil {
			switch e := err.(type) {
			case *api.ResponseError:
				ee := errors.New(strings.Join(e.Errors, ","))

				w.failedOpenErr = ee
				return ee
			default:
				w.failedOpenErr = e
				return e
			}
		}

		t, err := resp.TokenID()

		c.SetToken(t)
	} else {
		c.SetToken(token)
	}

	w.mutex.Lock()
	w.client = c
	w.mutex.Unlock()

	return nil
}

func usingApproleAuth(roleID, secretID string) bool {
	return roleID != "" && secretID != ""
}

func applyPrefix(pre, val string) string {
	if pre == "" {
		return val
	}

	return fmt.Sprintf("%v_%v", pre, val)
}

// Close implements accounts.Wallet, closing the connection to the vault.
func (w *wallet) Close() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.client = nil

	for _, k := range w.unlocked {
		vault.ZeroKey(k.PrivateKey)
	}
	w.unlocked = nil
	w.changes = nil

	if w.cache != nil {
		w.cache.Close()
		w.cache = nil
	}

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

func (w *wallet) signTx(account accounts.Account, tx *types.Transaction, chainID *big.Int, allowUnlock bool) (*types.Transaction, error) {
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}

	key, zero, err := w.getKey(account, allowUnlock)
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

// getKey returns the key for the given account.  If the account is locked and allowUnlock is true, the account will be unlocked by retrieving the key from the vault.  zeroFn is the corresponding zero function for the returned key and should be called to clean up once the key has been used.  Calls updateCache before attempting to get the key.
//
// The returned key will first be validated to make sure that it is the correct key for the given address.  If not an error will be returned.
func (w *wallet) getKey(acct accounts.Account, allowUnlock bool) (*ecdsa.PrivateKey, func(), error) {
	if w.isClosed() {
		return nil, func() {}, accounts.ErrWalletClosed
	}

	w.reloadCache()

	w.cache.Mu.Lock()
	a, err := w.cache.Find(acct)
	w.cache.Mu.Unlock()

	if err != nil {
		return nil, func() {}, err
	}

	if u, ok := w.unlocked[a.Address]; ok {
		return u.PrivateKey, func() {}, nil
	}

	if !allowUnlock {
		return nil, func() {}, keystore.ErrLocked
	}

	key, err := w.getKeyUsingFileConfig(a.Address, a.URL.Path)

	if err != nil {
		return nil, func() {}, err
	}

	zeroFn := func() {
		b := key.D.Bits()
		for i := range b {
			b[i] = 0
		}
		key = nil
	}

	return key, zeroFn, err
}

func (w *wallet) getKeyUsingFileConfig(addr common.Address, path string) (*ecdsa.PrivateKey, error) {
	// TODO parity with cache getAddress
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config HashicorpAccountConfig

	if err := json.Unmarshal(fileBytes, &config); err != nil {
		return nil, err
	}

	if config == (HashicorpAccountConfig{}) {
		return nil, fmt.Errorf("unable to read vault account config from file %v", path)
	}

	return w.getKeyFromVault(config)
}

// getKeyFromVault retrieves the private key component of the provided secret from the Vault. Expects RLock to be held.
func (w *wallet) getKeyFromVault(c HashicorpAccountConfig) (*ecdsa.PrivateKey, error) {
	hexKey, err := w.getSecretFromVault(c.SecretPath, c.SecretVersion, c.SecretEnginePath)

	if err != nil {
		return nil, err
	}

	key, err := crypto.HexToECDSA(hexKey)

	if err != nil {
		return nil, fmt.Errorf("unable to parse data from Hashicorp Vault to *ecdsa.PrivateKey: %v", err)
	}

	return key, nil
}

// getSecretFromVault retrieves a particular version of the secret 'name' from the provided secret engine. Expects RLock to be held.
func (w *wallet) getSecretFromVault(name string, version int64, engine string) (string, error) {
	path := fmt.Sprintf("%s/data/%s", engine, name)

	versionData := make(map[string][]string)
	versionData["version"] = []string{strconv.FormatInt(version, 10)}

	resp, err := w.client.Logical().ReadWithData(path, versionData)

	if err != nil {
		return "", fmt.Errorf("unable to get secret from Hashicorp Vault: %v", err)
	}

	if resp == nil {
		return "", fmt.Errorf("no data for secret in Hashicorp Vault")
	}

	respData, ok := resp.Data["data"].(map[string]interface{})

	if !ok {
		return "", errors.New("Hashicorp Vault response does not contain data")
	}

	if len(respData) != 1 {
		return "", errors.New("only one key/value pair is allowed in each Hashicorp Vault secret")
	}

	// get secret regardless of key in map
	var s interface{}
	for _, d := range respData {
		s = d
	}

	secret, ok := s.(string)

	if !ok {
		return "", errors.New("Hashicorp Vault response data is not in string format")
	}

	return secret, nil
}

// TimedUnlock unlocks the given account for the duration of timeout. A timeout of 0 unlocks the account until the program exits.
//
// If the account address is already unlocked for a duration, TimedUnlock extends or
// shortens the active unlock timeout. If the address was previously unlocked
// indefinitely the timeout is not altered.
//
// If the wallet does not manage this particular account, an error is returned.
func (w *wallet) TimedUnlock(account accounts.Account, timeout time.Duration) error {
	if !w.Contains(account) {
		return accounts.ErrUnknownAccount
	}

	if w.isClosed() {
		return accounts.ErrWalletClosed
	}

	key, _, err := w.getKey(account, true)

	if err != nil {
		return err
	}

	k := &keystore.Key{
		Address:    account.Address,
		PrivateKey: key,
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()
	u, found := w.unlocked[account.Address]
	if found {
		if u.abort == nil {
			// The address was unlocked indefinitely, so unlocking
			// it with a timeout would be confusing.
			return nil
		}
		// Terminate the expire goroutine and replace it below.
		close(u.abort)
	}
	if timeout > 0 {
		u = &unlocked{Key: k, abort: make(chan struct{})}
		go w.expire(account.Address, u, timeout)
	} else {
		u = &unlocked{Key: k}
	}
	w.unlocked[account.Address] = u
	return nil
}

func (w *wallet) expire(addr common.Address, u *unlocked, timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-u.abort:
		// just quit
	case <-t.C:
		w.mutex.Lock()
		// only drop if it's still the same key instance that dropLater
		// was launched with. we can check that using pointer equality
		// because the map stores a new pointer every time the key is
		// unlocked.
		if w.unlocked[addr] == u {
			vault.ZeroKey(u.PrivateKey)
			delete(w.unlocked, addr)
		}
		w.mutex.Unlock()
	}
}

// Lock locks the given account thereby removing the corresponding private key from memory. If the
// wallet does not manage this particular account, an error is returned.
func (w *wallet) Lock(account accounts.Account) error {
	if !w.Contains(account) {
		return accounts.ErrUnknownAccount
	}

	if w.isClosed() {
		return accounts.ErrWalletClosed
	}

	w.mutex.Lock()
	if unl, found := w.unlocked[account.Address]; found {
		w.mutex.Unlock()
		w.expire(account.Address, unl, time.Duration(0)*time.Nanosecond)
	} else {
		w.mutex.Unlock()
	}
	return nil
}

func (w *wallet) NewAccount(config interface{}) (common.Address, error) {
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return common.Address{}, err
	}
	// zero the key as new accounts should be locked by default
	defer vault.ZeroKey(key)

	return w.add(key, config)
}

func (w *wallet) Import(key *ecdsa.PrivateKey, config interface{}) (common.Address, error) {
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return common.Address{}, err
	}
	// zero the key as new accounts should be locked by default
	defer vault.ZeroKey(key)

	return w.add(key, config)
}

func (w *wallet) add(key *ecdsa.PrivateKey, config interface{}) (common.Address, error) {
	if w.cache.HasAddress(crypto.PubkeyToAddress(key.PublicKey)) {
		return common.Address{}, fmt.Errorf("account already exists")
	}

	c, ok := config.(HashicorpAccountConfig)

	if !ok {
		return common.Address{}, errors.New("config is not of type HashicorpAccountConfig")
	}

	if err := c.ValidateForAccountCreation(); err != nil {
		return common.Address{}, err
	}

	acct, _, err := writeToHashicorpVaultAndFile(w, key, c)

	if err != nil {
		return common.Address{}, err
	}

	// Add the account to the cache immediately rather
	// than waiting for file system notifications to pick it up.
	w.cache.Add(acct)

	return acct.Address, nil
}

//// Store writes the provided private key to the vault as two parts: the hex representation of the key and the 20-byte hex address derived from the key.  The address is returned along with the url identifiers of all secrets written to the vault.
////
//// If an error is encountered during Store, the urls of any secrets already written to the vault will be included in the error.
//func (w *wallet) Store(key *ecdsa.PrivateKey) (common.Address, []string, error) {
//	addr, storedUrls, err := w.vault.store(key)
//
//	if err != nil {
//		return common.Address{}, nil, err
//	}
//
//	return addr, storedUrls, nil
//}

// CreateAccountInHashicorpVault generates a secp256k1 key and corresponding Geth address and stores both in the Vault defined in the provided config.  The key and address are stored in hex string format.
//
// The generated key and address will be saved to only the first HashicorpSecretConfig provided in config.  Any other secret configs are ignored.
//
// The 20-byte hex representation of the Geth address is returned along with the urls of all secrets written to the Vault.  If an error is encountered during the write, the urls of any secrets already written to the vault will be included in the error.
func CreateHashicorpVaultAccount(walletConfig HashicorpWalletConfig, acctConfig HashicorpAccountConfig) (accounts.Account, string, error) {
	w, err := newHashicorpWallet(walletConfig, &Backend{}, true)
	if err != nil {
		return accounts.Account{}, "", err
	}

	if err := w.Open(""); err != nil {
		return accounts.Account{}, "", err
	}
	defer w.Close()

	if _, err := w.Status(); err != nil {
		return accounts.Account{}, "", err
	}

	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return accounts.Account{}, "", err
	}
	defer vault.ZeroKey(key)

	return writeToHashicorpVaultAndFile(w, key, acctConfig)
}

func ImportAsHashicorpVaultAccount(key *ecdsa.PrivateKey, walletConfig HashicorpWalletConfig, acctConfig HashicorpAccountConfig) (accounts.Account, string, error) {
	defer vault.ZeroKey(key)

	w, err := newHashicorpWallet(walletConfig, &Backend{}, true)
	if err != nil {
		return accounts.Account{}, "", err
	}

	if err := w.Open(""); err != nil {
		return accounts.Account{}, "", err
	}
	defer w.Close()

	if _, err := w.Status(); err != nil {
		return accounts.Account{}, "", err
	}

	return writeToHashicorpVaultAndFile(w, key, acctConfig)
}

// TODO makes sense to have these as functions instead of methods?
// TODO create file first then clean up afterwards if vault write fails
func writeToHashicorpVaultAndFile(w *wallet, key *ecdsa.PrivateKey, acctConfig HashicorpAccountConfig) (accounts.Account, string, error) {
	updatedConfig, err := writeToHashicorpVault(w, key, acctConfig)

	if err != nil {
		return accounts.Account{}, "", err
	}

	path, err := writeToFile(w.config.AccountConfigDir, updatedConfig)

	if err != nil {
		return accounts.Account{}, "", err
	}

	acct := accounts.Account{Address: common.HexToAddress(updatedConfig.Address), URL: accounts.URL{Scheme: keystore.KeyStoreScheme, Path: path}}

	return acct, updatedConfig.secretUrl, nil
}

func writeToHashicorpVault(w *wallet, key *ecdsa.PrivateKey, config HashicorpAccountConfig) (HashicorpAccountConfig, error) {
	address := crypto.PubkeyToAddress(key.PublicKey)
	addrHex := hex.EncodeToString(address[:])

	keyBytes := crypto.FromECDSA(key)
	keyHex := hex.EncodeToString(keyBytes)

	secretBaseUrlPath, secretVersion, err := w.writeSecret(config, addrHex, keyHex)

	if err != nil {
		return HashicorpAccountConfig{}, err
	}

	secretUrlPath := fmt.Sprintf("%v/v1/%v?version=%v", w.client.Address(), secretBaseUrlPath, secretVersion)

	config.SecretVersion = secretVersion
	config.Address = addrHex
	config.secretUrl = secretUrlPath

	return config, nil
}

func writeToFile(dir string, toWrite HashicorpAccountConfig) (string, error) {
	filename := joinPath(
		dir,
		keyFileName(common.HexToAddress(toWrite.Address)),
	)

	configBytes, err := json.Marshal(toWrite)

	if err != nil {
		return "", err
	}

	if err := writeKeyFile(filename, configBytes); err != nil {
		return "", err
	}

	return filename, nil
}

func joinPath(dir, filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(dir, filename)
}

// keyFileName implements the naming convention for keyfiles:
// UTC--<created_at UTC ISO8601>-<address hex>
func keyFileName(keyAddr common.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}

func writeKeyFile(file string, content []byte) error {
	name, err := writeTemporaryKeyFile(file, content)
	if err != nil {
		return err
	}
	return os.Rename(name, file)
}

func writeTemporaryKeyFile(file string, content []byte) (string, error) {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return "", err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := ioutil.TempFile(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

// writeSecret stores value in the configured Vault at the location defined by name and secretEngine.
// The secret path and version are returned.
func (w *wallet) writeSecret(config HashicorpAccountConfig, name, value string) (string, int64, error) {
	urlPath := fmt.Sprintf("%s/data/%s", config.SecretEnginePath, config.SecretPath)

	data := make(map[string]interface{})
	data["data"] = map[string]interface{}{
		name: value,
	}

	if !config.SkipCas {
		data["options"] = map[string]interface{}{
			"cas": config.CasValue,
		}
	}

	resp, err := w.getClient().Logical().Write(urlPath, data)

	if err != nil {
		return "", -1, fmt.Errorf("error writing secret to vault: %v", err)
	}

	v, ok := resp.Data["version"]

	if !ok {
		v = json.Number("-1")
	}

	vJson, ok := v.(json.Number)

	version, err := vJson.Int64()

	if err != nil {
		return "", -1, fmt.Errorf("unable to convert version in Vault response to int64: version number is %v", vJson.String())
	}

	return urlPath, version, nil
}

// getClient returns the client property of the hashicorpService by taking an RLock.
//
// Care should be taken not to call this within an existing Lock otherwise this a deadlock will occur.
//
// This should not be used if storing the returned client in a variable for later
// use as the fact it is a pointer means that a full Lock should be held for the
// entirety of the usage of the client.
func (w *wallet) getClient() *api.Client {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	return w.client
}
