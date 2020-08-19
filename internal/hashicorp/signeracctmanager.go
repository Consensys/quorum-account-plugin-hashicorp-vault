package hashicorp

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/account"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"log"
	"time"
)

var unsupportedErr = errors.New("not supported when using quorum-signer secret engine")

func NewSignerAccountManager(config config.VaultClient) (*signerAccountManager, error) {
	client, err := newVaultClient(config)
	if err != nil {
		return nil, err
	}

	a := &signerAccountManager{
		client:           client,
		signerEngineName: config.QuorumSignerEngineName,
	}

	return a, nil
}

type signerAccountManager struct {
	client           *vaultClient
	signerEngineName string
}

func (a *signerAccountManager) Status() (string, error) {
	return "ok", nil
}

func (a *signerAccountManager) Accounts() ([]account.Account, error) {
	return a.client.getAccounts()
}

func (a *signerAccountManager) Contains(acctAddr account.Address) bool {
	return a.client.hasAccount(acctAddr)
}

func (a *signerAccountManager) Sign(acctAddr account.Address, toSign []byte) ([]byte, error) {
	panic("implement me")
}

func (a *signerAccountManager) UnlockAndSign(_ account.Address, _ []byte) ([]byte, error) {
	log.Print("[DEBUG] unsupported account manager operation: UnlockAndSign")
	return nil, unsupportedErr
}

func (a *signerAccountManager) TimedUnlock(_ account.Address, _ time.Duration) error {
	log.Print("[DEBUG] unsupported account manager operation: TimedUnlock")
	return unsupportedErr
}

func (a *signerAccountManager) Lock(_ account.Address) {
	log.Print("[DEBUG] unsupported account manager operation: UnlockAndSign")
}

func (a *signerAccountManager) NewAccount(conf config.NewAccount) (account.Account, error) {
	log.Print("[DEBUG] Sending request to Vault to create new account")

	return a.createInVaultAndWriteToFile(conf, nil)
}

func (a *signerAccountManager) ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (account.Account, error) {
	defer zeroKey(privateKeyECDSA)
	log.Print("[DEBUG] Sending request to Vault to import existing account")

	hexKey, err := account.PrivateKeyToHexString(privateKeyECDSA)
	if err != nil {
		return account.Account{}, err
	}

	reqData := map[string]interface{}{
		"import": hexKey,
	}

	return a.createInVaultAndWriteToFile(conf, reqData)
}

func (a *signerAccountManager) createInVaultAndWriteToFile(conf config.NewAccount, reqData map[string]interface{}) (account.Account, error) {
	apiPath := fmt.Sprintf("%v/accounts/%v", a.signerEngineName, conf.SecretName)
	resp, err := a.client.Logical().Write(apiPath, reqData)
	if err != nil {
		return account.Account{}, fmt.Errorf("unable to create new account in Vault, err: %v", err)
	}
	respAddr, ok := resp.Data["addr"]
	if !ok {
		return account.Account{}, errors.New("no addr")
	}
	addrHex, ok := respAddr.(string)
	if !ok {
		return account.Account{}, errors.New("invalid address returned from Vault, err: not string")
	}
	addr, err := account.NewAddressFromHexString(addrHex)
	if err != nil {
		return account.Account{}, fmt.Errorf("invalid address returned from vault, err: %v", err)
	}
	log.Print("[INFO] New account created in Vault")

	// write to file
	log.Print("[DEBUG] Writing new account data to file in account config directory")

	fileData, err := a.writeToFile(addrHex, conf)
	if err != nil {
		return account.Account{}, fmt.Errorf("unable to write new account config file, err: %v", err)
	}
	log.Printf("[INFO] New account data written to %v", fileData.Path)

	// prepare return value
	accountURL, err := fileData.Contents.AccountURL(a.client.Address(), a.signerEngineName, "accounts")
	if err != nil {
		return account.Account{}, err
	}

	// update the internal list of accts
	a.client.accts[accountURL] = fileData

	return account.Account{
		Address: addr,
		URL:     accountURL,
	}, nil
}

func (a *signerAccountManager) writeToFile(addrHex string, conf config.NewAccount) (config.AccountFile, error) {
	now := time.Now().UTC()
	nowISO8601 := now.Format("2006-01-02T15-04-05.000000000Z")
	filename := fmt.Sprintf("UTC--%v--%v", nowISO8601, addrHex)

	fileURL, err := a.client.accountDirectory.Parse(filename)
	if err != nil {
		return config.AccountFile{}, err
	}
	filePath := fileURL.Path
	log.Printf("[DEBUG] writing to file %v", filePath)

	var secretVersion int64 = 0 // versioning not supported so use 0 as this corresponds to latest in the Vault API

	fileData := conf.AccountFile(fileURL.String(), addrHex, secretVersion)

	if err := writeAccountFile(filePath, fileData); err != nil {
		return config.AccountFile{}, err
	}

	return fileData, nil
}
