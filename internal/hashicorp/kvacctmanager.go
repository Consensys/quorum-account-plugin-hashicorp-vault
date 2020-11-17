package hashicorp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ConsenSys/quorum-account-plugin-hashicorp-vault/internal/config"
	util "github.com/ConsenSys/quorum-go-utils/account"
	"github.com/ConsenSys/quorum/crypto/secp256k1"
	"github.com/hashicorp/vault/api"
)

func newKVAccountManager(config config.VaultClient) (*kvAccountManager, error) {
	client, err := newVaultClient(config)
	if err != nil {
		return nil, err
	}

	a := &kvAccountManager{
		client:       client,
		kvEngineName: config.KVEngineName,
		unlocked:     make(map[string]*lockableKey),
	}

	for _, toUnlock := range config.Unlock {
		addr, err := util.NewAddressFromHexString(toUnlock)
		if err != nil {
			log.Printf("[INFO] unable to unlock %v, err = %v", toUnlock, err)
		}
		if err := a.TimedUnlock(addr, 0); err != nil {
			log.Printf("[INFO] unable to unlock %v, err = %v", toUnlock, err)
		}
	}

	return a, nil
}

type kvAccountManager struct {
	client       *vaultClient
	kvEngineName string
	unlocked     map[string]*lockableKey
	mu           sync.Mutex
}

type lockableKey struct {
	key    *ecdsa.PrivateKey
	cancel chan struct{}
}

func (k *lockableKey) zero() {
	zeroKey(k.key)
}

func (a *kvAccountManager) Status() (string, error) {
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

func (a *kvAccountManager) Accounts() ([]util.Account, error) {
	return a.client.getAccounts()
}

func (a *kvAccountManager) Contains(acctAddr util.Address) bool {
	return a.client.hasAccount(acctAddr)
}

func (a *kvAccountManager) Sign(acctAddr util.Address, toSign []byte) ([]byte, error) {
	if _, err := a.client.getAccountFile(acctAddr); err != nil {
		return nil, err
	}
	a.mu.Lock()
	lockable, ok := a.unlocked[acctAddr.ToHexString()]
	a.mu.Unlock()
	if !ok {
		return nil, errors.New("account locked")
	}
	return sign(toSign, lockable.key)
}

func (a *kvAccountManager) UnlockAndSign(acctAddr util.Address, toSign []byte) ([]byte, error) {
	if _, err := a.client.getAccountFile(acctAddr); err != nil {
		return nil, err
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
	return sign(toSign, lockable.key)
}

func (a *kvAccountManager) TimedUnlock(acctAddr util.Address, duration time.Duration) error {
	acctFile, err := a.client.getAccountFile(acctAddr)
	if err != nil {
		return err
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

	privKey, ok := respData[acctFile.Contents.Address]
	if !ok {
		return fmt.Errorf("response does not contain data for account address %v", acctFile.Contents.Address)
	}

	key, err := util.NewKeyFromHexString(privKey.(string))
	if err != nil {
		return err
	}

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

func (a *kvAccountManager) lockAfter(addr string, key *lockableKey, duration time.Duration) {
	t := time.NewTimer(duration)
	defer t.Stop()

	select {
	case <-key.cancel:
		// cancel the scheduled lock
	case <-t.C:
		if a.unlocked[addr] == key {
			a.mu.Lock()
			key.zero()
			delete(a.unlocked, addr)
			a.mu.Unlock()
		}
	}
}

func (a *kvAccountManager) Lock(acctAddr util.Address) {
	addrHex := acctAddr.ToHexString()
	a.mu.Lock()
	lockable, ok := a.unlocked[addrHex]
	a.mu.Unlock()

	if ok {
		a.lockAfter(addrHex, lockable, 0)
	}
}

func (a *kvAccountManager) NewAccount(conf config.NewAccount) (util.Account, error) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return util.Account{}, err
	}
	defer zeroKey(key)

	return a.writeToVaultAndFile(key, conf)
}

func (a *kvAccountManager) ImportPrivateKey(key *ecdsa.PrivateKey, conf config.NewAccount) (util.Account, error) {
	defer zeroKey(key)
	return a.writeToVaultAndFile(key, conf)
}

func (a *kvAccountManager) writeToVaultAndFile(key *ecdsa.PrivateKey, conf config.NewAccount) (util.Account, error) {
	addr, err := util.PrivateKeyToAddress(key)
	if err != nil {
		return util.Account{}, err
	}

	if a.Contains(addr) {
		return util.Account{}, errors.New("account already exists")
	}

	log.Println("[DEBUG] Writing new account data to Vault")
	addrHex := addr.ToHexString()
	keyHex, err := util.PrivateKeyToHexString(key)
	if err != nil {
		return util.Account{}, err
	}

	resp, err := a.writeToVault(addrHex, keyHex, conf)
	if err != nil {
		return util.Account{}, fmt.Errorf("unable to write secret to Vault: %v", err)
	}
	log.Println("[INFO] New account data written to Vault")

	log.Println("[DEBUG] Getting new secret version number from response")
	secretVersion, err := a.getVersionFromResponse(resp)
	if err != nil {
		return util.Account{}, fmt.Errorf("unable to write new account config file: %v", err)
	}
	log.Printf("[DEBUG] New secret version number = %v", secretVersion)

	log.Println("[DEBUG] Writing new account data to file in account config directory")
	fileData, err := a.writeToFile(addrHex, secretVersion, conf)
	if err != nil {
		return util.Account{}, fmt.Errorf("unable to write new account config file, err: %v", err)
	}
	log.Printf("[INFO] New account data written to %v", fileData.Path)

	// prepare return value
	accountURL, err := fileData.Contents.AccountURL(a.client.Address(), a.kvEngineName, "data")
	if err != nil {
		return util.Account{}, err
	}

	// update the internal list of accts
	a.client.accts[accountURL] = fileData

	return util.Account{
		Address: addr,
		URL:     accountURL,
	}, nil
}

func (a *kvAccountManager) writeToVault(addrHex string, keyHex string, conf config.NewAccount) (*api.Secret, error) {
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

func (a *kvAccountManager) getVersionFromResponse(resp *api.Secret) (int64, error) {
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
func (a *kvAccountManager) writeToFile(addrHex string, secretVersion int64, conf config.NewAccount) (config.AccountFile, error) {
	now := time.Now().UTC()
	nowISO8601 := now.Format("2006-01-02T15-04-05.000000000Z")
	filename := fmt.Sprintf("UTC--%v--%v", nowISO8601, addrHex)

	fileURL, err := a.client.accountDirectory.Parse(filename)
	if err != nil {
		return config.AccountFile{}, err
	}
	filePath := fileURL.Path
	log.Printf("[DEBUG] writing to file %v", filePath)

	fileData := conf.AccountFile(fileURL.String(), addrHex, secretVersion)

	if err := writeAccountFile(filePath, fileData); err != nil {
		return config.AccountFile{}, err
	}

	return fileData, nil
}

func sign(toSign []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	keyByt, err := util.PrivateKeyToBytes(key)
	if err != nil {
		return nil, err
	}
	defer zero(keyByt)

	return secp256k1.Sign(toSign, keyByt)
}

func zeroKey(key *ecdsa.PrivateKey) {
	b := key.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

func zero(byt []byte) {
	for i := range byt {
		byt[i] = 0
	}
}
