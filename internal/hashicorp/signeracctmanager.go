package hashicorp

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	util "github.com/consensys/quorum-go-utils/account"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
)

func newSignerAccountManager(config config.VaultClient) (*signerAccountManager, error) {
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

func (a *signerAccountManager) Accounts() ([]util.Account, error) {
	return a.client.getAccounts()
}

func (a *signerAccountManager) Contains(acctAddr util.Address) bool {
	return a.client.hasAccount(acctAddr)
}

func (a *signerAccountManager) Sign(acctAddr util.Address, toSign []byte) ([]byte, error) {
	acctFile, err := a.client.getAccountFile(acctAddr)
	if err != nil {
		return nil, err
	}

	conf := acctFile.Contents.VaultAccount

	vaultLocation := fmt.Sprintf("%v/sign/%v", a.signerEngineName, conf.SecretName)

	reqData := make(map[string][]string)
	toSignHex := hex.EncodeToString(toSign)
	reqData["sign"] = []string{toSignHex}

	resp, err := a.client.Logical().ReadWithData(vaultLocation, reqData)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("empty response from Vault")
	}

	sigHex, ok := resp.Data["sig"].(string)
	if !ok {
		return nil, errors.New("no/invalid signature returned from Vault")
	}

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (a *signerAccountManager) UnlockAndSign(acctAddr util.Address, toSign []byte) ([]byte, error) {
	return a.Sign(acctAddr, toSign)
}

func (a *signerAccountManager) TimedUnlock(_ util.Address, _ time.Duration) error {
	log.Print("[DEBUG] unsupported account manager operation: TimedUnlock")
	return errors.New("unlocking accounts is not necessary when using quorum-signer secret engine")
}

func (a *signerAccountManager) Lock(_ util.Address) {
	log.Print("[DEBUG] unsupported account manager operation: UnlockAndSign")
}

func (a *signerAccountManager) NewAccount(conf config.NewAccount) (util.Account, error) {
	log.Print("[DEBUG] Sending request to Vault to create new account")

	return a.createInVaultAndWriteToFile(conf, nil)
}

func (a *signerAccountManager) ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (util.Account, error) {
	defer zeroKey(privateKeyECDSA)

	addr, err := util.PrivateKeyToAddress(privateKeyECDSA)
	if err != nil {
		return util.Account{}, err
	}

	if a.Contains(addr) {
		return util.Account{}, errors.New("account already exists")
	}

	log.Print("[DEBUG] Sending request to Vault to import existing account")

	hexKey, err := util.PrivateKeyToHexString(privateKeyECDSA)
	if err != nil {
		return util.Account{}, err
	}

	reqData := map[string]interface{}{
		"import": hexKey,
	}

	return a.createInVaultAndWriteToFile(conf, reqData)
}

func (a *signerAccountManager) createInVaultAndWriteToFile(conf config.NewAccount, reqData map[string]interface{}) (util.Account, error) {
	apiPath := fmt.Sprintf("%v/accounts/%v", a.signerEngineName, conf.SecretName)
	resp, err := a.client.Logical().Write(apiPath, reqData)
	if err != nil {
		return util.Account{}, fmt.Errorf("unable to create new account in Vault, err: %v", err)
	}
	respAddr, ok := resp.Data["addr"]
	if !ok {
		return util.Account{}, errors.New("no addr")
	}
	addrHex, ok := respAddr.(string)
	if !ok {
		return util.Account{}, errors.New("invalid address returned from Vault, err: not string")
	}
	addr, err := util.NewAddressFromHexString(addrHex)
	if err != nil {
		return util.Account{}, fmt.Errorf("invalid address returned from vault, err: %v", err)
	}
	log.Print("[INFO] New account created in Vault")

	// write to file
	log.Print("[DEBUG] Writing new account data to file in account config directory")

	fileData, err := a.writeToFile(addrHex, conf)
	if err != nil {
		return util.Account{}, fmt.Errorf("unable to write new account config file, err: %v", err)
	}
	log.Printf("[INFO] New account data written to %v", fileData.Path)

	// prepare return value
	accountURL, err := fileData.Contents.AccountURL(a.client.Address(), a.signerEngineName, "accounts")
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
