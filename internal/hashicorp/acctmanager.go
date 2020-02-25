package hashicorp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/config"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func NewAccountManager(config config.VaultClient) (*AccountManager, error) {
	client, err := newVaultClient(config)
	if err != nil {
		return nil, err
	}

	return &AccountManager{client: client}, nil
}

type AccountManager struct {
	client   *vaultClient
	unlocked map[string]*lockableKey
}

type lockableKey struct {
	key  string
	lock chan struct{}
}

type Account struct {
	Address []byte
	Url     string
}

type Transaction struct{}

func (a AccountManager) Status(wallet accounts.URL) (string, error) {
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

func (a AccountManager) Account(wallet accounts.URL) (accounts.Account, error) {
	if !a.client.hasWallet(wallet) {
		return accounts.Account{}, errors.New("unknown wallet")
	}
	hexAddr := a.client.getAccountAddress(wallet)
	byteAddr := common.HexToAddress(hexAddr)

	return accounts.Account{Address: byteAddr, URL: wallet}, nil
}

func (a AccountManager) Contains(wallet accounts.URL, account accounts.Account) (bool, error) {
	if account.URL != (accounts.URL{}) && wallet != account.URL {
		return false, fmt.Errorf("wallet %v cannot contain account with URL %v", wallet.String(), account.URL.String())
	}
	if !a.client.hasWallet(wallet) {
		return false, errors.New("unknown wallet")
	}
	acctFile := a.client.wallets[wallet]
	if bytes.Compare(common.Hex2Bytes(acctFile.Contents.Address), account.Address.Bytes()) != 0 {
		return false, nil
	}
	return true, nil
}

func (a AccountManager) SignHash(wallet accounts.URL, account accounts.Account, hash []byte) ([]byte, error) {
	panic("implement me")
}

func (a AccountManager) SignTx(wallet accounts.URL, account accounts.Account, rlpTx []byte, chainId *big.Int) ([]byte, error) {
	panic("implement me")
}

func (a AccountManager) UnlockAndSignHash(wallet accounts.URL, account accounts.Account, hash []byte) ([]byte, error) {
	panic("implement me")
}

func (a AccountManager) UnlockAndSignTx(wallet accounts.URL, account accounts.Account, rlpTx []byte, chainId *big.Int) ([]byte, error) {
	panic("implement me")
}

func (a AccountManager) GetEventStream(*proto.GetEventStreamRequest, proto.AccountManager_GetEventStreamServer) error {
	panic("implement me")
}

func (a AccountManager) TimedUnlock(account accounts.Account, duration time.Duration) error {
	panic("implement me")
}

func (a AccountManager) Lock(account accounts.Account) error {
	panic("implement me")
}

func (a AccountManager) NewAccount(conf config.NewAccount) (accounts.Account, error) {
	if conf.Vault.String() != a.client.Address() {
		return accounts.Account{}, errors.New("incorrect vault url provided")
	}
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return accounts.Account{}, err
	}
	accountAddress := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey)

	// write to vault
	log.Println("[DEBUG] Writing new account data to Vault...")
	addrHex := common.Bytes2Hex(accountAddress.Bytes())
	keyHex := common.Bytes2Hex(crypto.FromECDSA(privateKeyECDSA))

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

	resp, err := a.client.Logical().Write(vaultLocation, data)
	if err != nil {
		return accounts.Account{}, fmt.Errorf("unable to write secret to Vault: %v", err)
	}
	log.Println("[INFO] New account data written to Vault")

	log.Println("[DEBUG] Writing new account data to file in account config directory...")
	v, ok := resp.Data["version"]
	if !ok {
		return accounts.Account{}, errors.New("unable to write new account config file, no version information returned from Vault")
	}
	vJson, ok := v.(json.Number)
	if !ok {
		return accounts.Account{}, errors.New("unable to write new account config file, invalid version information returned from Vault")
	}
	secretVersion, err := vJson.Int64()
	if err != nil {
		return accounts.Account{}, fmt.Errorf("unable to write new account config file, invalid version information returned from Vault")
	}

	// write to file (write to temporary hidden file first then rename once complete so that write appears atomic - useful when implementing a watcher on the directory
	now := time.Now().UTC()
	nowISO8601 := now.Format("2006-01-02T15-04-05.000000000Z")
	filename := fmt.Sprintf("UTC--%v--%v", nowISO8601, common.Bytes2Hex(accountAddress.Bytes()))

	fullpath, err := a.client.accountDirectory.Parse(filename)
	if err != nil {
		return accounts.Account{}, err
	}

	fileData := conf.AccountFile(fullpath.String(), addrHex, secretVersion)

	contents, err := json.Marshal(fileData.Contents)
	if err != nil {
		return accounts.Account{}, err
	}

	f, err := ioutil.TempFile(filepath.Dir(fullpath.Host+"/"+fullpath.Path), fmt.Sprintf(".%v*.tmp", filepath.Base(fullpath.String())))
	if err != nil {
		return accounts.Account{}, err
	}
	if _, err := f.Write(contents); err != nil {
		f.Close()
		os.Remove(f.Name())
		return accounts.Account{}, err
	}
	f.Close()

	if err := os.Rename(f.Name(), fullpath.Host+"/"+fullpath.Path); err != nil {
		return accounts.Account{}, fmt.Errorf("unable to write new account config file, err: %v", err)
	}

	log.Println("[INFO] New account data written to account config directory")

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

func (a AccountManager) ImportAccount(publicKeyHex string, privateKeyHex string, conf config.NewAccount) (accounts.Account, error) {
	panic("implement me")
}
