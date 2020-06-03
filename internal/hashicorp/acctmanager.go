package hashicorp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/hashicorp/vault/api"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
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
		if err := a.TimedUnlock(common.HexToAddress(toUnlock), 0); err != nil {
			log.Printf("[INFO] unable to unlock %v, err = %v", toUnlock, err)
		}
	}

	return a, nil
}

type AccountManager interface {
	Status() (string, error)
	Accounts() ([]accounts.Account, error)
	Contains(acctAddr common.Address) (bool, error)
	SignHash(acctAddr common.Address, hash []byte) ([]byte, error)
	UnlockAndSignHash(acctAddr common.Address, hash []byte) ([]byte, error)
	SignTx(acctAddr common.Address, tx *types.Transaction, chainID *big.Int) ([]byte, error)
	UnlockAndSignTx(acctAddr common.Address, tx *types.Transaction, chainID *big.Int) ([]byte, error)
	TimedUnlock(acctAddr common.Address, duration time.Duration) error
	Lock(acctAddr common.Address)
	NewAccount(conf config.NewAccount) (accounts.Account, error)
	ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (accounts.Account, error)
}

type accountManager struct {
	client       *vaultClient
	kvEngineName string
	unlocked     map[string]*lockableKey
	mu           sync.Mutex
}

type lockableKey struct {
	key    *ecdsa.PrivateKey
	cancel chan struct{}
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

func (a *accountManager) Accounts() ([]accounts.Account, error) {
	var (
		w     = a.client.accts
		accts = make([]accounts.Account, 0, len(w))
		acct  accounts.Account
	)
	for url, conf := range w {
		acct = accounts.Account{
			Address: common.HexToAddress(conf.Contents.Address),
			URL:     url,
		}
		accts = append(accts, acct)
	}
	return accts, nil
}

func (a *accountManager) Contains(acctAddr common.Address) (bool, error) {
	return a.client.hasAccount(acctAddr), nil
}

func (a *accountManager) SignHash(acctAddr common.Address, hash []byte) ([]byte, error) {
	if !a.client.hasAccount(acctAddr) {
		return nil, errors.New("unknown account")
	}
	a.mu.Lock()
	lockable, ok := a.unlocked[common.Bytes2Hex(acctAddr.Bytes())]
	a.mu.Unlock()
	if !ok {
		return nil, errors.New("account locked")
	}
	return crypto.Sign(hash, lockable.key)
}

func (a *accountManager) UnlockAndSignHash(acctAddr common.Address, hash []byte) ([]byte, error) {
	if !a.client.hasAccount(acctAddr) {
		return nil, errors.New("unknown account")
	}
	a.mu.Lock()
	lockable, unlocked := a.unlocked[common.Bytes2Hex(acctAddr.Bytes())]
	a.mu.Unlock()
	if !unlocked {
		if err := a.TimedUnlock(acctAddr, 0); err != nil {
			return nil, err
		}
		defer a.Lock(acctAddr)
		lockable, _ = a.unlocked[common.Bytes2Hex(acctAddr.Bytes())]
	}
	return crypto.Sign(hash, lockable.key)
}

func (a *accountManager) SignTx(acctAddr common.Address, tx *types.Transaction, chainID *big.Int) ([]byte, error) {
	if !a.client.hasAccount(acctAddr) {
		return nil, errors.New("unknown account")
	}
	a.mu.Lock()
	lockable, ok := a.unlocked[common.Bytes2Hex(acctAddr.Bytes())]
	a.mu.Unlock()
	if !ok {
		return nil, errors.New("account locked")
	}
	signedTx, err := a.signTx(tx, lockable.key, chainID)
	if err != nil {
		return nil, err
	}
	return rlp.EncodeToBytes(signedTx)
}

func (a *accountManager) UnlockAndSignTx(acctAddr common.Address, tx *types.Transaction, chainID *big.Int) ([]byte, error) {
	if !a.client.hasAccount(acctAddr) {
		return nil, errors.New("unknown account")
	}
	a.mu.Lock()
	lockable, unlocked := a.unlocked[common.Bytes2Hex(acctAddr.Bytes())]
	a.mu.Unlock()
	if !unlocked {
		if err := a.TimedUnlock(acctAddr, 0); err != nil {
			return nil, err
		}
		defer a.Lock(acctAddr)
		lockable, _ = a.unlocked[common.Bytes2Hex(acctAddr.Bytes())]
	}
	signedTx, err := a.signTx(tx, lockable.key, chainID)
	if err != nil {
		return nil, err
	}
	return rlp.EncodeToBytes(signedTx)
}

func (a *accountManager) signTx(tx *types.Transaction, key *ecdsa.PrivateKey, chainID *big.Int) (*types.Transaction, error) {
	if tx.IsPrivate() {
		return types.SignTx(tx, types.QuorumPrivateTxSigner{}, key)
	}
	if chainID == nil {
		return types.SignTx(tx, types.HomesteadSigner{}, key)
	}
	return types.SignTx(tx, types.NewEIP155Signer(chainID), key)
}

func (a *accountManager) TimedUnlock(acctAddr common.Address, duration time.Duration) error {
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

	ecdsaKey, err := crypto.HexToECDSA(privKey.(string))
	if err != nil {
		return err
	}

	lockableKey := &lockableKey{
		key: ecdsaKey,
	}

	if duration > 0 {
		go a.lockAfter(acctFile.Contents.Address, lockableKey, duration)
	}

	a.mu.Lock()
	a.unlocked[acctFile.Contents.Address] = lockableKey
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

func (a *accountManager) Lock(acctAddr common.Address) {
	addrHex := common.Bytes2Hex(acctAddr.Bytes())
	a.mu.Lock()
	lockable, ok := a.unlocked[addrHex]
	a.mu.Unlock()

	if ok {
		a.lockAfter(addrHex, lockable, 0)
	}
}

func (a *accountManager) NewAccount(conf config.NewAccount) (accounts.Account, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return accounts.Account{}, err
	}

	return a.writeToVaultAndFile(privateKeyECDSA, conf)
}

func (a *accountManager) ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (accounts.Account, error) {
	return a.writeToVaultAndFile(privateKeyECDSA, conf)
}

func (a *accountManager) writeToVaultAndFile(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (accounts.Account, error) {
	accountAddress := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey)

	log.Println("[DEBUG] Writing new account data to Vault...")
	addrHex := common.Bytes2Hex(accountAddress.Bytes())
	keyHex := common.Bytes2Hex(crypto.FromECDSA(privateKeyECDSA))

	resp, err := a.writeToVault(addrHex, keyHex, conf)
	if err != nil {
		return accounts.Account{}, fmt.Errorf("unable to write secret to Vault: %v", err)
	}
	log.Println("[INFO] New account data written to Vault")

	log.Println("[DEBUG] Writing new account data to file in account config directory...")
	secretVersion, err := a.getVersionFromResponse(resp)
	if err != nil {
		return accounts.Account{}, fmt.Errorf("unable to write new account config file: %v", err)
	}

	fileData, err := a.writeToFile(addrHex, secretVersion, conf)
	if err != nil {
		return accounts.Account{}, fmt.Errorf("unable to write new account config file, err: %v", err)
	}
	log.Printf("[INFO] New account data written to %v", fileData.Path)

	// prepare return value
	accountURL, err := fileData.Contents.AccountURL(a.client.Address(), a.kvEngineName)
	if err != nil {
		return accounts.Account{}, err
	}

	// update the internal list of accts
	a.client.accts[accountURL] = fileData

	return accounts.Account{
		Address: accountAddress,
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

func zeroKey(lockableKey *lockableKey) {
	b := lockableKey.key.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
