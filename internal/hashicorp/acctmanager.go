package hashicorp

import (
	"bytes"
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
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/config"
)

func NewAccountManager(config config.VaultClient) (*AccountManager, error) {
	client, err := newVaultClient(config)
	if err != nil {
		return nil, err
	}

	a := &AccountManager{client: client, unlocked: make(map[string]*lockableKey)}

	for _, toUnlock := range config.Unlock {
		acct := accounts.Account{Address: common.HexToAddress(toUnlock)}
		if err := a.TimedUnlock(acct, 0); err != nil {
			log.Printf("[INFO] unable to unlock %v, err = %v", toUnlock, err)
		}
	}

	return a, nil
}

type AccountManager struct {
	client   *vaultClient
	unlocked map[string]*lockableKey
	mu       sync.Mutex
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

func (a *AccountManager) Status(wallet accounts.URL) (string, error) {
	if !a.client.hasWallet(wallet) {
		return "", errors.New("unknown wallet")
	}
	addr := a.client.getAccountAddress(wallet)
	_, isUnlocked := a.unlocked[addr]
	if isUnlocked {
		return "unlocked", nil
	}
	return "locked", nil

}

func (a *AccountManager) Account(wallet accounts.URL) (accounts.Account, error) {
	if !a.client.hasWallet(wallet) {
		return accounts.Account{}, errors.New("unknown wallet")
	}
	hexAddr := a.client.getAccountAddress(wallet)
	byteAddr := common.HexToAddress(hexAddr)

	return accounts.Account{Address: byteAddr, URL: wallet}, nil
}

func (a *AccountManager) Contains(account accounts.Account) (bool, error) {
	if !a.client.hasWallet(account.URL) {
		return false, errors.New("unknown wallet")
	}
	acctFile := a.client.wallets[account.URL]
	if bytes.Compare(common.Hex2Bytes(acctFile.Contents.Address), account.Address.Bytes()) != 0 {
		return false, nil
	}
	return true, nil
}

func (a *AccountManager) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	if !a.client.hasWallet(account.URL) {
		return nil, errors.New("unknown wallet")
	}
	a.mu.Lock()
	lockable, ok := a.unlocked[common.Bytes2Hex(account.Address.Bytes())]
	a.mu.Unlock()
	if !ok {
		return nil, errors.New("account locked")
	}
	return crypto.Sign(hash, lockable.key)
}

func (a *AccountManager) UnlockAndSignHash(account accounts.Account, hash []byte) ([]byte, error) {
	a.mu.Lock()
	_, unlocked := a.unlocked[common.Bytes2Hex(account.Address.Bytes())]
	a.mu.Unlock()
	if !unlocked {
		if err := a.TimedUnlock(account, 0); err != nil {
			return nil, err
		}
		defer a.Lock(account)
	}

	return a.SignHash(account, hash)
}

func (a *AccountManager) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) ([]byte, error) {
	if !a.client.hasWallet(account.URL) {
		return nil, errors.New("unknown wallet")
	}
	a.mu.Lock()
	lockable, ok := a.unlocked[common.Bytes2Hex(account.Address.Bytes())]
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

func (a *AccountManager) UnlockAndSignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) ([]byte, error) {
	a.mu.Lock()
	_, unlocked := a.unlocked[common.Bytes2Hex(account.Address.Bytes())]
	a.mu.Unlock()
	if !unlocked {
		if err := a.TimedUnlock(account, 0); err != nil {
			return nil, err
		}
		defer a.Lock(account)
	}

	return a.SignTx(account, tx, chainID)
}

func (a *AccountManager) signTx(tx *types.Transaction, key *ecdsa.PrivateKey, chainID *big.Int) (*types.Transaction, error) {
	if tx.IsPrivate() {
		return types.SignTx(tx, types.QuorumPrivateTxSigner{}, key)
	}
	if chainID == nil {
		return types.SignTx(tx, types.HomesteadSigner{}, key)
	}
	return types.SignTx(tx, types.NewEIP155Signer(chainID), key)
}

func (a *AccountManager) TimedUnlock(account accounts.Account, duration time.Duration) error {
	var acctFile config.AccountFile

	if account.URL != (accounts.URL{}) {
		if a.client.hasWallet(account.URL) {
			file := a.client.wallets[account.URL]
			if file.Contents.Address != common.Bytes2Hex(account.Address.Bytes()) {
				return fmt.Errorf("inconsistent account data provided: request contained URL %v and account address %v, but this URL refers to account config file containing account address %v", account.URL.String(), common.Bytes2Hex(account.Address.Bytes()), file.Contents.Address)
			}
			acctFile = file
		}
	} else {
		for _, file := range a.client.wallets {
			if file.Contents.Address == common.Bytes2Hex(account.Address.Bytes()) {
				acctFile = file
			}
		}
	}

	if acctFile == (config.AccountFile{}) {
		return errors.New("unknown wallet")
	}

	conf := acctFile.Contents.VaultAccount

	// get from Vault
	vaultLocation := fmt.Sprintf("%v/data/%v", conf.SecretEnginePath, conf.SecretPath)

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

func (a *AccountManager) lockAfter(addr string, key *lockableKey, duration time.Duration) {
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

func (a *AccountManager) Lock(account accounts.Account) {
	addrHex := common.Bytes2Hex(account.Address.Bytes())
	a.mu.Lock()
	lockable, ok := a.unlocked[addrHex]
	a.mu.Unlock()

	if ok {
		a.lockAfter(addrHex, lockable, 0)
	}
}

func (a *AccountManager) NewAccount(conf config.NewAccount) (accounts.Account, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return accounts.Account{}, err
	}

	return a.writeToVaultAndFile(privateKeyECDSA, conf)
}

func (a *AccountManager) ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (accounts.Account, error) {
	return a.writeToVaultAndFile(privateKeyECDSA, conf)
}

func (a *AccountManager) WalletURLs() []accounts.URL {
	urls := make([]accounts.URL, 0, len(a.client.wallets))
	for u, _ := range a.client.wallets {
		urls = append(urls, u)
	}
	return urls
}

func (a *AccountManager) writeToVaultAndFile(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (accounts.Account, error) {
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
	accountURL, err := fileData.Contents.AccountURL(a.client.Address())
	if err != nil {
		return accounts.Account{}, err
	}

	return accounts.Account{
		Address: accountAddress,
		URL:     accountURL,
	}, nil
}

func (a *AccountManager) writeToVault(addrHex string, keyHex string, conf config.NewAccount) (*api.Secret, error) {
	data := make(map[string]interface{})
	data["data"] = map[string]interface{}{
		addrHex: keyHex,
	}

	if !conf.InsecureSkipCAS {
		data["options"] = map[string]interface{}{
			"cas": conf.CASValue,
		}
	}
	vaultLocation := fmt.Sprintf("%v/data/%v", conf.SecretEnginePath, conf.SecretPath)

	return a.client.Logical().Write(vaultLocation, data)
}

func (a *AccountManager) getVersionFromResponse(resp *api.Secret) (int64, error) {
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
func (a *AccountManager) writeToFile(addrHex string, secretVersion int64, conf config.NewAccount) (config.AccountFile, error) {
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
