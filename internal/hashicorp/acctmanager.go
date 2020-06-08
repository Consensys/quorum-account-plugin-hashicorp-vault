package hashicorp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/hashicorp/vault/api"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/types"
	"golang.org/x/crypto/sha3"
)

func NewAccountManager(config config.VaultClient) (AccountManager, error) {
	client, err := newVaultClient(config)
	if err != nil {
		return nil, err
	}

	a := &accountManager{
		client:       client,
		kvEngineName: config.KVEngineName,
		unlocked:     make(map[string]*lockableKey),
	}

	for _, toUnlock := range config.Unlock {
		addr, err := types.NewAddressFromHexString(toUnlock)
		if err != nil {
			log.Printf("[INFO] unable to unlock %v, err = %v", toUnlock, err)
		}
		if err := a.TimedUnlock(addr, 0); err != nil {
			log.Printf("[INFO] unable to unlock %v, err = %v", toUnlock, err)
		}
	}

	return a, nil
}

type AccountManager interface {
	Status() (string, error)
	Accounts() ([]types.Account, error)
	Contains(acctAddr types.Address) (bool, error)
	Sign(acctAddr types.Address, toSign []byte) ([]byte, error)
	UnlockAndSign(acctAddr types.Address, toSign []byte) ([]byte, error)
	TimedUnlock(acctAddr types.Address, duration time.Duration) error
	Lock(acctAddr types.Address)
	NewAccount(conf config.NewAccount) (types.Account, error)
	ImportPrivateKey(privateKeyECDSA *secp256k1.PrivateKey, conf config.NewAccount) (types.Account, error)
}

type accountManager struct {
	client       *vaultClient
	kvEngineName string
	unlocked     map[string]*lockableKey
	mu           sync.Mutex
}

type lockableKey struct {
	key    *secp256k1.PrivateKey
	cancel chan struct{}
}

func privateKeyToAddress(key *secp256k1.PrivateKey) (types.Address, error) {
	pubBytes := key.PubKey().SerializeUncompressed()

	d := sha3.NewLegacyKeccak256()
	_, err := d.Write(pubBytes[1:])
	if err != nil {
		return types.Address{}, err
	}
	pubHash := d.Sum(nil)

	return types.NewAddress(pubHash[12:])
}

type Account struct {
	Address []byte
	Url     string
}

type Transaction struct{}

func (a *accountManager) Status() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	unlockedCount := len(a.unlocked)

	status := fmt.Sprintf("%v unlocked account(s)", unlockedCount)
	if unlockedCount != 0 {
		var unlockedAddrs []string
		for addr, _ := range a.unlocked {
			unlockedAddrs = append(unlockedAddrs, fmt.Sprintf("0x%v", addr))
		}
		status = fmt.Sprintf("%v: %v", status, unlockedAddrs)
	}

	return status, nil
}

func (a *accountManager) Accounts() ([]types.Account, error) {
	var (
		w     = a.client.accts
		accts = make([]types.Account, 0, len(w))
		acct  types.Account
	)
	for url, conf := range w {
		addr, err := types.NewAddressFromHexString(conf.Contents.Address)
		if err != nil {
			return []types.Account{}, err
		}
		acct = types.Account{
			Address: addr,
			URL:     url,
		}
		accts = append(accts, acct)
	}
	return accts, nil
}

func (a *accountManager) Contains(acctAddr types.Address) (bool, error) {
	return a.client.hasAccount(acctAddr), nil
}

func (a *accountManager) Sign(acctAddr types.Address, toSign []byte) ([]byte, error) {
	if !a.client.hasAccount(acctAddr) {
		return nil, errors.New("unknown account")
	}
	a.mu.Lock()
	lockable, ok := a.unlocked[acctAddr.ToHexString()]
	a.mu.Unlock()
	if !ok {
		return nil, errors.New("account locked")
	}
	return a.sign(toSign, lockable.key), nil
}

func (a *accountManager) UnlockAndSign(acctAddr types.Address, toSign []byte) ([]byte, error) {
	if !a.client.hasAccount(acctAddr) {
		return nil, errors.New("unknown account")
	}
	a.mu.Lock()
	lockable, unlocked := a.unlocked[acctAddr.ToHexString()]
	a.mu.Unlock()
	if !unlocked {
		if err := a.TimedUnlock(acctAddr, 0); err != nil {
			return nil, err
		}
		defer a.Lock(acctAddr)
		lockable, _ = a.unlocked[acctAddr.ToHexString()]
	}
	return a.sign(toSign, lockable.key), nil
}

func (a *accountManager) TimedUnlock(acctAddr types.Address, duration time.Duration) error {
	acctFile := a.client.getAccount(acctAddr)

	if acctFile == (config.AccountFile{}) {
		return errors.New("unknown account")
	}

	conf := acctFile.Contents.VaultAccount

	// get from Vault
	vaultLocation := fmt.Sprintf("%v/data/%v", a.kvEngineName, conf.SecretName)

	reqData := make(map[string][]string)
	reqData["version"] = []string{strconv.FormatInt(conf.SecretVersion, 10)}

	resp, err := a.client.Logical().ReadWithData(vaultLocation, reqData)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("empty response from Vault")
	}

	respData, ok := resp.Data["data"].(map[string]interface{})
	if !ok {
		return errors.New("no secret information returned from Vault")
	}
	if len(respData) != 1 {
		return errors.New("only one key/value pair is allowed in each Hashicorp Vault secret")
	}

	// get value regardless of key in map
	privKey, ok := respData[acctFile.Contents.Address]
	if !ok {
		return fmt.Errorf("response does not contain data for account address %v", acctFile.Contents.Address)
	}

	bytKey, err := hex.DecodeString(privKey.(string))
	if err != nil {
		return err
	}
	key := secp256k1.PrivKeyFromBytes(bytKey)

	lockableKey := &lockableKey{
		key: key,
	}

	if duration > 0 {
		go a.lockAfter(acctFile.Contents.Address, lockableKey, duration)
	}

	a.mu.Lock()
	addr := strings.TrimPrefix(acctFile.Contents.Address, "0x")
	a.unlocked[addr] = lockableKey
	a.mu.Unlock()

	return nil
}

func (a *accountManager) lockAfter(addr string, key *lockableKey, duration time.Duration) {
	t := time.NewTimer(duration)
	defer t.Stop()

	select {
	case <-key.cancel:
		// cancel the scheduled lock
	case <-t.C:
		if a.unlocked[addr] == key {
			a.mu.Lock()
			zeroKey(key)
			delete(a.unlocked, addr)
			a.mu.Unlock()
		}
	}
}

func (a *accountManager) Lock(acctAddr types.Address) {
	addrHex := acctAddr.ToHexString()
	a.mu.Lock()
	lockable, ok := a.unlocked[addrHex]
	a.mu.Unlock()

	if ok {
		a.lockAfter(addrHex, lockable, 0)
	}
}

func (a *accountManager) NewAccount(conf config.NewAccount) (types.Account, error) {
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return types.Account{}, err
	}
	return a.writeToVaultAndFile(key, conf)
}

func (a *accountManager) ImportPrivateKey(key *secp256k1.PrivateKey, conf config.NewAccount) (types.Account, error) {
	return a.writeToVaultAndFile(key, conf)
}

func (a *accountManager) writeToVaultAndFile(key *secp256k1.PrivateKey, conf config.NewAccount) (types.Account, error) {
	addr, err := privateKeyToAddress(key)
	if err != nil {
		return types.Account{}, err
	}

	log.Println("[DEBUG] Writing new account data to Vault...")
	addrHex := addr.ToHexString()
	keyHex := hex.EncodeToString(key.Serialize())

	resp, err := a.writeToVault(addrHex, keyHex, conf)
	if err != nil {
		return types.Account{}, fmt.Errorf("unable to write secret to Vault: %v", err)
	}
	log.Println("[INFO] New account data written to Vault")

	log.Println("[DEBUG] Writing new account data to file in account config directory...")
	secretVersion, err := a.getVersionFromResponse(resp)
	if err != nil {
		return types.Account{}, fmt.Errorf("unable to write new account config file: %v", err)
	}

	fileData, err := a.writeToFile(addrHex, secretVersion, conf)
	if err != nil {
		return types.Account{}, fmt.Errorf("unable to write new account config file, err: %v", err)
	}
	log.Printf("[INFO] New account data written to %v", fileData.Path)

	// prepare return value
	accountURL, err := fileData.Contents.AccountURL(a.client.Address(), a.kvEngineName)
	if err != nil {
		return types.Account{}, err
	}

	// update the internal list of accts
	a.client.accts[accountURL] = fileData

	return types.Account{
		Address: addr,
		URL:     accountURL,
	}, nil
}

func (a *accountManager) writeToVault(addrHex string, keyHex string, conf config.NewAccount) (*api.Secret, error) {
	data := make(map[string]interface{})
	data["data"] = map[string]interface{}{
		addrHex: keyHex,
	}

	if !conf.OverwriteProtection.InsecureDisable {
		data["options"] = map[string]interface{}{
			"cas": conf.OverwriteProtection.CurrentVersion,
		}
	}
	vaultLocation := fmt.Sprintf("%v/data/%v", a.kvEngineName, conf.SecretName)

	return a.client.Logical().Write(vaultLocation, data)
}

func (a *accountManager) getVersionFromResponse(resp *api.Secret) (int64, error) {
	v, ok := resp.Data["version"]
	if !ok {
		return 0, errors.New("no version information returned from Vault")
	}
	vJson, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("invalid version information returned from Vault")
	}
	secretVersion, err := vJson.Int64()
	if err != nil {
		return 0, fmt.Errorf("invalid version information returned from Vault, %v", err)
	}
	return secretVersion, nil
}

// writeToFile writes to a temporary hidden file first then renames once complete so that the write appears atomic.  This will be useful if implementing a watcher on the directory
func (a *accountManager) writeToFile(addrHex string, secretVersion int64, conf config.NewAccount) (config.AccountFile, error) {
	now := time.Now().UTC()
	nowISO8601 := now.Format("2006-01-02T15-04-05.000000000Z")
	filename := fmt.Sprintf("UTC--%v--%v", nowISO8601, addrHex)

	fullpath, err := a.client.accountDirectory.Parse(filename)
	if err != nil {
		return config.AccountFile{}, err
	}

	fileData := conf.AccountFile(fullpath.String(), addrHex, secretVersion)

	contents, err := json.Marshal(fileData.Contents)
	if err != nil {
		return config.AccountFile{}, err
	}

	f, err := ioutil.TempFile(filepath.Dir(fullpath.Host+"/"+fullpath.Path), fmt.Sprintf(".%v*.tmp", filepath.Base(fullpath.String())))
	if err != nil {
		return config.AccountFile{}, err
	}
	if _, err := f.Write(contents); err != nil {
		f.Close()
		os.Remove(f.Name())
		return config.AccountFile{}, err
	}
	f.Close()

	if err := os.Rename(f.Name(), fullpath.Host+"/"+fullpath.Path); err != nil {
		return config.AccountFile{}, err
	}
	return fileData, nil
}

func (a *accountManager) sign(toSign []byte, key *secp256k1.PrivateKey) []byte {
	signature := ecdsa.SignCompact(key, toSign, false)
	// SignCompact returns v value at start of sig, geth expects it at the end
	reordedSig := make([]byte, 0, len(signature))
	reordedSig = append(reordedSig, signature[1:]...)
	reordedSig = append(reordedSig, signature[0])
	return reordedSig
}

func zeroKey(lockableKey *lockableKey) {
	lockableKey.key.Zero()
}
