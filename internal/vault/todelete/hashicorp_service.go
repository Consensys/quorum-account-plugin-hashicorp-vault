package todelete

//
//import (
//	"crypto/ecdsa"
//	"crypto/rand"
//	"encoding/hex"
//	"encoding/json"
//	"errors"
//	"fmt"
//	"github.com/ethereum/go-ethereum/common/hexutil"
//	"github.com/ethereum/go-ethereum/log"
//	"io/ioutil"
//	"os"
//	"path/filepath"
//	"runtime"
//	"strconv"
//	"strings"
//	"sync"
//	"time"
//
//	"github.com/ethereum/go-ethereum/accounts"
//	"github.com/ethereum/go-ethereum/accounts/keystore"
//	"github.com/ethereum/go-ethereum/common"
//	"github.com/ethereum/go-ethereum/crypto"
//	"github.com/hashicorp/vault/api"
//)
//
//const (
//	WalletScheme = "hashiwlt"
//	AcctScheme   = "hashiacct"
//)
//
//// hashicorpService implements vault.vaultService and represents the Hashicorp Vault-specific functionality used by hashicorp wallets
//type hashicorpService struct {
//
//}
//
//// newHashicorpService creates a hashicorpService using the provided config
//func newHashicorpService(config HashicorpWalletConfig, disableCache bool) *hashicorpService {
//	// Add the list of accounts to be unlocked; they will be unlocked once the wallet is opened
//	// TODO require insecure unlock config option to be true
//	addrs := strings.Split(config.Unlock, ",")
//	var toUnlock []common.Address
//
//	for _, addr := range addrs {
//		if trimmed := strings.TrimSpace(addr); trimmed != "" {
//			if common.IsHexAddress(trimmed) {
//				toUnlock = append(toUnlock, common.HexToAddress(trimmed))
//			} else {
//				log.Debug("Failed to unlock account", "addr", trimmed, "err", "invalid hex-encoded ethereum address")
//			}
//		}
//	}
//
//	h := &hashicorpService{
//		config:       config,
//		toUnlock:     toUnlock,
//		unlocked:     make(map[common.Address]*unlocked),
//		disableCache: disableCache,
//	}
//
//	//// first thing we do is try to setup and authenticate the Vault client - no point continuing if the Vault config is incorrect
//	//if err := h.setupClient(); err != nil {
//	//	return nil
//	//}
//
//	h.cache, h.changes = newAccountCache(h.config.AccountConfigDir, h)
//
//	// TODO: In order for this finalizer to work, there must be no references
//	// to ks. addressCache doesn't keep a reference but unlocked keys do,
//	// so the finalizer will not trigger until all timed unlocks have expired.
//	runtime.SetFinalizer(h, func(m *hashicorpService) {
//		m.cache.close()
//	})
//
//	h.reloadCache()
//
//	return h
//}
//
//func (h *hashicorpService) isClosed() bool {
//	h.mutex.RLock()
//	defer h.mutex.RUnlock()
//
//	return h.client == nil
//}
//
//func (h *hashicorpService) reloadCache() {
//	if !h.disableCache {
//		h.cache.maybeReload()
//	}
//}
//
//// Status for a hashicorpService
//const (
//	closed                     = "Closed"
//	hashicorpHealthcheckFailed = "Hashicorp Vault healthcheck failed"
//	hashicorpUninitialized     = "Hashicorp Vault uninitialized"
//	hashicorpSealed            = "Hashicorp Vault sealed"
//)
//
//var (
//	hashicorpSealedErr        = errors.New(hashicorpSealed)
//	hashicorpUninitializedErr = errors.New(hashicorpUninitialized)
//)
//
//type hashicorpHealthcheckErr struct {
//	err error
//}
//
//func (e hashicorpHealthcheckErr) Error() string {
//	return fmt.Sprintf("%v: %v", hashicorpHealthcheckFailed, e.err)
//}
//
//// status implements vault.vaultService and returns the status of the Vault API client and the unlocked status of any accounts managed by the service.  Calls updateCache before getting the statuses.
//func (h *hashicorpService) status() (string, error) {
//	if h.isClosed() {
//		return closed, h.failedOpenErr
//	}
//
//	h.reloadCache()
//
//	h.mutex.RLock()
//	defer h.mutex.RUnlock()
//
//	client := h.client
//
//	health, err := client.Sys().Health()
//
//	switch {
//	case err != nil:
//		return h.cacheStatus(), hashicorpHealthcheckErr{err: err}
//	case !health.Initialized:
//		return h.cacheStatus(), hashicorpUninitializedErr
//	case health.Sealed:
//		return h.cacheStatus(), hashicorpSealedErr
//	}
//
//	return h.cacheStatus(), nil
//}
//
//// withAcctStatuses appends the locked/unlocked status of the accounts managed by the service to the provided walletStatus.
//// Expects RLock to be held.
//func (h *hashicorpService) cacheStatus() string {
//	// no accounts so just return
//	if h.cache == nil || len(h.cache.all) == 0 {
//		return ""
//	}
//
//	var (
//		unlocked, locked             []string
//		unlockedStatus, lockedStatus string
//	)
//
//	// TODO this does not account for the case where there are multiple accounts/secret configs for the same address.  If vault url is used as the account url then this doesn't become as much of an issue but the user will be hit with an ambiguous acct error when they attempt to sign even though the status may be unlocked
//
//	for uAddr := range h.unlocked {
//		unlocked = append(unlocked, hexutil.Encode(uAddr[:]))
//	}
//
//	if len(unlocked) > 0 {
//		unlockedStatus = fmt.Sprintf("Unlocked: %v", strings.Join(unlocked, ", "))
//	}
//
//	for addr, _ := range h.cache.byAddr {
//		if _, ok := h.unlocked[addr]; !ok {
//			locked = append(locked, hexutil.Encode(addr[:]))
//		}
//	}
//
//	if len(locked) > 0 {
//		lockedStatus = fmt.Sprintf("Locked: %v", strings.Join(locked, ", "))
//	}
//
//	if unlockedStatus != "" && lockedStatus != "" {
//		return fmt.Sprintf("%v; %v", unlockedStatus, lockedStatus)
//	} else if unlockedStatus != "" {
//		return unlockedStatus
//	} else {
//		return lockedStatus
//	}
//}
//
//// open implements vault.vaultService creating a Vault API client from the config properties of the hashicorpService.  Once open, the client attempt to retrieve account addresses for all configured secrets from the vault.  If the service has been configured to unlock all accounts by default then account private keys will also be attempted to be retrieved.  Any unsuccessful address/key retrievals can be retried later by calling updateCache.
////
//// If Approle authentication credentials are set as environment variables, the client will attempt to authenticate with the Vault server using those credentials.  If the approle credentials are not present the Vault will attempt to use a token credential.
////
//// An error is returned if the service is already open.
//func (h *hashicorpService) open() error {
//	if !h.isClosed() {
//		return accounts.ErrWalletAlreadyOpen
//	}
//
//	if err := h.setupClient(); err != nil {
//		return err
//	}
//
//	return nil
//}
//
//// Environment variable name for Hashicorp Vault authentication credential
//const (
//	DefaultRoleIDEnv   = "QRM_HASHIVLT_ROLE_ID"
//	DefaultSecretIDEnv = "QRM_HASHIVLT_SECRET_ID"
//	DefaultTokenEnv    = "QRM_HASHIVLT_TOKEN"
//)
//
//type noHashicorpEnvSetErr struct {
//	roleIdEnv, secretIdEnv, tokenEnv string
//}
//
//func (e noHashicorpEnvSetErr) Error() string {
//	return fmt.Sprintf("environment variables are necessary to authenticate with Hashicorp Vault: set %v and %v if using Approle authentication, else set %v", e.roleIdEnv, e.secretIdEnv, e.tokenEnv)
//}
//
//type invalidApproleAuthErr struct {
//	roleIdEnv, secretIdEnv string
//}
//
//func (e invalidApproleAuthErr) Error() string {
//	return fmt.Sprintf("both %v and %v environment variables must be set if using Approle authentication", e.roleIdEnv, e.secretIdEnv)
//}
//
//func (h *hashicorpService) setupClient() error {
//	conf := api.DefaultConfig()
//	conf.Address = h.config.VaultUrl
//
//	tlsConfig := &api.TLSConfig{
//		CACert:     h.config.CaCert,
//		ClientCert: h.config.ClientCert,
//		ClientKey:  h.config.ClientKey,
//	}
//
//	if err := conf.ConfigureTLS(tlsConfig); err != nil {
//		return fmt.Errorf("error creating Hashicorp client: %v", err)
//	}
//
//	c, err := api.NewClient(conf)
//
//	if err != nil {
//		return fmt.Errorf("error creating Hashicorp client: %v", err)
//	}
//
//	roleIDEnv := applyPrefix(h.config.AuthorizationID, DefaultRoleIDEnv)
//	secretIDEnv := applyPrefix(h.config.AuthorizationID, DefaultSecretIDEnv)
//	tokenEnv := applyPrefix(h.config.AuthorizationID, DefaultTokenEnv)
//
//	roleID := os.Getenv(roleIDEnv)
//	secretID := os.Getenv(secretIDEnv)
//	token := os.Getenv(tokenEnv)
//
//	if roleID == "" && secretID == "" && token == "" {
//		return noHashicorpEnvSetErr{roleIdEnv: roleIDEnv, secretIdEnv: secretIDEnv, tokenEnv: tokenEnv}
//	}
//
//	if roleID == "" && secretID != "" || roleID != "" && secretID == "" {
//		return invalidApproleAuthErr{roleIdEnv: roleIDEnv, secretIdEnv: secretIDEnv}
//	}
//
//	if usingApproleAuth(roleID, secretID) {
//		//authenticate the client using approle
//		body := map[string]interface{}{"role_id": roleID, "secret_id": secretID}
//
//		approle := h.config.ApprolePath
//
//		if approle == "" {
//			approle = "approle"
//		}
//
//		resp, err := c.Logical().Write(fmt.Sprintf("auth/%s/login", approle), body)
//
//		if err != nil {
//			switch e := err.(type) {
//			case *api.ResponseError:
//				ee := errors.New(strings.Join(e.Errors, ","))
//
//				h.failedOpenErr = ee
//				return ee
//			default:
//				h.failedOpenErr = e
//				return e
//			}
//		}
//
//		t, err := resp.TokenID()
//
//		c.SetToken(t)
//	} else {
//		c.SetToken(token)
//	}
//
//	h.mutex.Lock()
//	h.client = c
//	h.mutex.Unlock()
//
//	return nil
//}
//
//func applyPrefix(pre, val string) string {
//	if pre == "" {
//		return val
//	}
//
//	return fmt.Sprintf("%v_%v", pre, val)
//}
//
//type unlocked struct {
//	*keystore.Key
//	abort chan struct{}
//}
//
//// getKeyFromVault retrieves the private key component of the provided secret from the Vault. Expects RLock to be held.
//func (h *hashicorpService) getKeyFromVault(c HashicorpAccountConfig) (*ecdsa.PrivateKey, error) {
//	hexKey, err := h.getSecretFromVault(c.SecretPath, c.SecretVersion, c.SecretEnginePath)
//
//	if err != nil {
//		return nil, err
//	}
//
//	key, err := crypto.HexToECDSA(hexKey)
//
//	if err != nil {
//		return nil, fmt.Errorf("unable to parse data from Hashicorp Vault to *ecdsa.PrivateKey: %v", err)
//	}
//
//	return key, nil
//}
//
//// getSecretFromVault retrieves a particular version of the secret 'name' from the provided secret engine. Expects RLock to be held.
//func (h *hashicorpService) getSecretFromVault(name string, version int64, engine string) (string, error) {
//	path := fmt.Sprintf("%s/data/%s", engine, name)
//
//	versionData := make(map[string][]string)
//	versionData["version"] = []string{strconv.FormatInt(version, 10)}
//
//	resp, err := h.client.Logical().ReadWithData(path, versionData)
//
//	if err != nil {
//		return "", fmt.Errorf("unable to get secret from Hashicorp Vault: %v", err)
//	}
//
//	if resp == nil {
//		return "", fmt.Errorf("no data for secret in Hashicorp Vault")
//	}
//
//	respData, ok := resp.Data["data"].(map[string]interface{})
//
//	if !ok {
//		return "", errors.New("Hashicorp Vault response does not contain data")
//	}
//
//	if len(respData) != 1 {
//		return "", errors.New("only one key/value pair is allowed in each Hashicorp Vault secret")
//	}
//
//	// get secret regardless of key in map
//	var s interface{}
//	for _, d := range respData {
//		s = d
//	}
//
//	secret, ok := s.(string)
//
//	if !ok {
//		return "", errors.New("Hashicorp Vault response data is not in string format")
//	}
//
//	return secret, nil
//}
//
//func usingApproleAuth(roleID, secretID string) bool {
//	return roleID != "" && secretID != ""
//}
//
//// close removes the client from the service preventing it from being able to retrieve data from the Vault.
//func (h *hashicorpService) close() error {
//	h.mutex.Lock()
//	defer h.mutex.Unlock()
//
//	h.client = nil
//
//	for _, k := range h.unlocked {
//		zeroKey(k.PrivateKey)
//	}
//	h.unlocked = nil
//	h.changes = nil
//
//	if h.cache != nil {
//		h.cache.close()
//		h.cache = nil
//	}
//
//	return nil
//}
//
//// accounts returns a copy of the list of signing accounts the wallet is currently aware of.  Calls updateCache before getting the accounts.
//func (h *hashicorpService) accounts() []accounts.Account {
//	if h.cache == nil {
//		return []accounts.Account{}
//	}
//
//	return h.cache.accounts()
//}
//
//var (
//	incorrectKeyForAddrErr = errors.New("the address of the account provided does not match the address derived from the private key retrieved from the Vault.  Ensure the correct secret names and versions are specified in the node config.")
//)
//
//// getKey returns the key for the given account.  If the account is locked and allowUnlock is true, the account will be unlocked by retrieving the key from the vault.  zeroFn is the corresponding zero function for the returned key and should be called to clean up once the key has been used.  Calls updateCache before attempting to get the key.
////
//// The returned key will first be validated to make sure that it is the correct key for the given address.  If not an error will be returned.
//func (h *hashicorpService) getKey(acct accounts.Account, allowUnlock bool) (*ecdsa.PrivateKey, func(), error) {
//	if h.isClosed() {
//		return nil, func() {}, accounts.ErrWalletClosed
//	}
//
//	h.reloadCache()
//
//	h.cache.mu.Lock()
//	a, err := h.cache.find(acct)
//	h.cache.mu.Unlock()
//
//	if err != nil {
//		return nil, func() {}, err
//	}
//
//	if u, ok := h.unlocked[a.Address]; ok {
//		return u.PrivateKey, func() {}, nil
//	}
//
//	if !allowUnlock {
//		return nil, func() {}, keystore.ErrLocked
//	}
//
//	key, err := h.getKeyUsingFileConfig(a.Address, a.URL.Path)
//
//	if err != nil {
//		return nil, func() {}, err
//	}
//
//	zeroFn := func() {
//		b := key.D.Bits()
//		for i := range b {
//			b[i] = 0
//		}
//		key = nil
//	}
//
//	return key, zeroFn, err
//}
//
//func (h *hashicorpService) getKeyUsingFileConfig(addr common.Address, path string) (*ecdsa.PrivateKey, error) {
//	// TODO parity with cache getAddress
//	fileBytes, err := ioutil.ReadFile(path)
//	if err != nil {
//		return nil, err
//	}
//
//	var config HashicorpAccountConfig
//
//	if err := json.Unmarshal(fileBytes, &config); err != nil {
//		return nil, err
//	}
//
//	if config == (HashicorpAccountConfig{}) {
//		return nil, fmt.Errorf("unable to read vault account config from file %v", path)
//	}
//
//	return h.getKeyFromVault(config)
//}
//
//// timedUnlock implements vault.vaultService unlocking the given account for the specified duration. A timeout of 0 unlocks the account until the program exits.
////
//// If the account address is already unlocked for a duration, TimedUnlock extends or
//// shortens the active unlock timeout. If the account address is already unlocked indefinitely no timed unlock is applied.
////
//// Calls updateCache before attempting the unlock.
//func (h *hashicorpService) timedUnlock(acct accounts.Account, duration time.Duration) error {
//	if h.isClosed() {
//		return accounts.ErrWalletClosed
//	}
//
//	key, _, err := h.getKey(acct, true)
//
//	if err != nil {
//		return err
//	}
//
//	k := &keystore.Key{
//		Address:    acct.Address,
//		PrivateKey: key,
//	}
//
//	h.mutex.Lock()
//	defer h.mutex.Unlock()
//	u, found := h.unlocked[acct.Address]
//	if found {
//		if u.abort == nil {
//			// The address was unlocked indefinitely, so unlocking
//			// it with a timeout would be confusing.
//			return nil
//		}
//		// Terminate the expire goroutine and replace it below.
//		close(u.abort)
//	}
//	if duration > 0 {
//		u = &unlocked{Key: k, abort: make(chan struct{})}
//		go h.expire(acct.Address, u, duration)
//	} else {
//		u = &unlocked{Key: k}
//	}
//	h.unlocked[acct.Address] = u
//	return nil
//}
//
//func (h *hashicorpService) expire(addr common.Address, u *unlocked, timeout time.Duration) {
//	t := time.NewTimer(timeout)
//	defer t.Stop()
//	select {
//	case <-u.abort:
//		// just quit
//	case <-t.C:
//		h.mutex.Lock()
//		// only drop if it's still the same key instance that dropLater
//		// was launched with. we can check that using pointer equality
//		// because the map stores a new pointer every time the key is
//		// unlocked.
//		if h.unlocked[addr] == u {
//			zeroKey(u.PrivateKey)
//			delete(h.unlocked, addr)
//		}
//		h.mutex.Unlock()
//	}
//}
//
//// lock implements vault.vaultService and cancels any existing timed unlocks for the provided account and zeroes the corresponding private key if it is present.
//// Calls updateCache before attempting the lock.
//func (h *hashicorpService) lock(acct accounts.Account) error {
//	if h.isClosed() {
//		return accounts.ErrWalletClosed
//	}
//
//	h.mutex.Lock()
//	if unl, found := h.unlocked[acct.Address]; found {
//		h.mutex.Unlock()
//		h.expire(acct.Address, unl, time.Duration(0)*time.Nanosecond)
//	} else {
//		h.mutex.Unlock()
//	}
//	return nil
//}
//
//func (h *hashicorpService) add(key *ecdsa.PrivateKey, config interface{}) (common.Address, error) {
//	if h.cache.hasAddress(crypto.PubkeyToAddress(key.PublicKey)) {
//		return common.Address{}, fmt.Errorf("account already exists")
//	}
//
//	c, ok := config.(HashicorpAccountConfig)
//
//	if !ok {
//		return common.Address{}, errors.New("config is not of type HashicorpAccountConfig")
//	}
//
//	if err := c.ValidateForAccountCreation(); err != nil {
//		return common.Address{}, err
//	}
//
//	acct, _, err := writeToHashicorpVaultAndFile(h, key, c)
//
//	if err != nil {
//		return common.Address{}, err
//	}
//
//	// Add the account to the cache immediately rather
//	// than waiting for file system notifications to pick it up.
//	h.cache.add(acct)
//
//	return acct.Address, nil
//}
//
//// CreateAccountInHashicorpVault generates a secp256k1 key and corresponding Geth address and stores both in the Vault defined in the provided config.  The key and address are stored in hex string format.
////
//// The generated key and address will be saved to only the first HashicorpSecretConfig provided in config.  Any other secret configs are ignored.
////
//// The 20-byte hex representation of the Geth address is returned along with the urls of all secrets written to the Vault.  If an error is encountered during the write, the urls of any secrets already written to the vault will be included in the error.
//func CreateHashicorpVaultAccount(walletConfig HashicorpWalletConfig, acctConfig HashicorpAccountConfig) (accounts.Account, string, error) {
//	hs := newHashicorpService(walletConfig, true)
//
//	if err := hs.open(); err != nil {
//		return accounts.Account{}, "", err
//	}
//	defer hs.close()
//
//	if _, err := hs.status(); err != nil {
//		return accounts.Account{}, "", err
//	}
//
//	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
//	if err != nil {
//		return accounts.Account{}, "", err
//	}
//	defer zeroKey(key)
//
//	return writeToHashicorpVaultAndFile(hs, key, acctConfig)
//}
//
//func ImportAsHashicorpVaultAccount(key *ecdsa.PrivateKey, walletConfig HashicorpWalletConfig, acctConfig HashicorpAccountConfig) (accounts.Account, string, error) {
//	defer zeroKey(key)
//
//	hs := newHashicorpService(walletConfig, true)
//
//	if err := hs.open(); err != nil {
//		return accounts.Account{}, "", err
//	}
//	defer hs.close()
//
//	if _, err := hs.status(); err != nil {
//		return accounts.Account{}, "", err
//	}
//
//	return writeToHashicorpVaultAndFile(hs, key, acctConfig)
//}
//
//// TODO makes sense to have these as functions instead of methods?
//// TODO create file first then clean up afterwards if vault write fails
//func writeToHashicorpVaultAndFile(hs *hashicorpService, key *ecdsa.PrivateKey, acctConfig HashicorpAccountConfig) (accounts.Account, string, error) {
//	updatedConfig, err := writeToHashicorpVault(hs, key, acctConfig)
//
//	if err != nil {
//		return accounts.Account{}, "", err
//	}
//
//	path, err := writeToFile(hs.config.AccountConfigDir, updatedConfig)
//
//	if err != nil {
//		return accounts.Account{}, "", err
//	}
//
//	acct := accounts.Account{Address: common.HexToAddress(updatedConfig.Address), URL: accounts.URL{Scheme: keystore.KeyStoreScheme, Path: path}}
//
//	return acct, updatedConfig.secretUrl, nil
//}
//
//func writeToHashicorpVault(h *hashicorpService, key *ecdsa.PrivateKey, config HashicorpAccountConfig) (HashicorpAccountConfig, error) {
//	address := crypto.PubkeyToAddress(key.PublicKey)
//	addrHex := hex.EncodeToString(address[:])
//
//	keyBytes := crypto.FromECDSA(key)
//	keyHex := hex.EncodeToString(keyBytes)
//
//	secretBaseUrlPath, secretVersion, err := h.writeSecret(config, addrHex, keyHex)
//
//	if err != nil {
//		return HashicorpAccountConfig{}, err
//	}
//
//	secretUrlPath := fmt.Sprintf("%v/v1/%v?version=%v", h.client.Address(), secretBaseUrlPath, secretVersion)
//
//	config.SecretVersion = secretVersion
//	config.Address = addrHex
//	config.secretUrl = secretUrlPath
//
//	return config, nil
//}
//
//func writeToFile(dir string, toWrite HashicorpAccountConfig) (string, error) {
//	filename := joinPath(
//		dir,
//		keyFileName(common.HexToAddress(toWrite.Address)),
//	)
//
//	configBytes, err := json.Marshal(toWrite)
//
//	if err != nil {
//		return "", err
//	}
//
//	if err := writeKeyFile(filename, configBytes); err != nil {
//		return "", err
//	}
//
//	return filename, nil
//}
//
//func joinPath(dir, filename string) string {
//	if filepath.IsAbs(filename) {
//		return filename
//	}
//	return filepath.Join(dir, filename)
//}
//
//// keyFileName implements the naming convention for keyfiles:
//// UTC--<created_at UTC ISO8601>-<address hex>
//func keyFileName(keyAddr common.Address) string {
//	ts := time.Now().UTC()
//	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
//}
//
//func toISO8601(t time.Time) string {
//	var tz string
//	name, offset := t.Zone()
//	if name == "UTC" {
//		tz = "Z"
//	} else {
//		tz = fmt.Sprintf("%03d00", offset/3600)
//	}
//	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
//}
//
//func writeKeyFile(file string, content []byte) error {
//	name, err := writeTemporaryKeyFile(file, content)
//	if err != nil {
//		return err
//	}
//	return os.Rename(name, file)
//}
//
//func writeTemporaryKeyFile(file string, content []byte) (string, error) {
//	// Create the keystore directory with appropriate permissions
//	// in case it is not present yet.
//	const dirPerm = 0700
//	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
//		return "", err
//	}
//	// Atomic write: create a temporary hidden file first
//	// then move it into place. TempFile assigns mode 0600.
//	f, err := ioutil.TempFile(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
//	if err != nil {
//		return "", err
//	}
//	if _, err := f.Write(content); err != nil {
//		f.Close()
//		os.Remove(f.Name())
//		return "", err
//	}
//	f.Close()
//	return f.Name(), nil
//}
//
//// writeSecret stores value in the configured Vault at the location defined by name and secretEngine.
//// The secret path and version are returned.
//func (h *hashicorpService) writeSecret(config HashicorpAccountConfig, name, value string) (string, int64, error) {
//	urlPath := fmt.Sprintf("%s/data/%s", config.SecretEnginePath, config.SecretPath)
//
//	data := make(map[string]interface{})
//	data["data"] = map[string]interface{}{
//		name: value,
//	}
//
//	if !config.SkipCas {
//		data["options"] = map[string]interface{}{
//			"cas": config.CasValue,
//		}
//	}
//
//	resp, err := h.getClient().Logical().Write(urlPath, data)
//
//	if err != nil {
//		return "", -1, fmt.Errorf("error writing secret to vault: %v", err)
//	}
//
//	v, ok := resp.Data["version"]
//
//	if !ok {
//		v = json.Number("-1")
//	}
//
//	vJson, ok := v.(json.Number)
//
//	version, err := vJson.Int64()
//
//	if err != nil {
//		return "", -1, fmt.Errorf("unable to convert version in Vault response to int64: version number is %v", vJson.String())
//	}
//
//	return urlPath, version, nil
//}
//
//// getClient returns the client property of the hashicorpService by taking an RLock.
////
//// Care should be taken not to call this within an existing Lock otherwise this a deadlock will occur.
////
//// This should not be used if storing the returned client in a variable for later
//// use as the fact it is a pointer means that a full Lock should be held for the
//// entirety of the usage of the client.
//func (h *hashicorpService) getClient() *api.Client {
//	h.mutex.RLock()
//	defer h.mutex.RUnlock()
//
//	return h.client
//}
