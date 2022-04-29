package hashicorp

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	util "github.com/ConsenSys/quorum-go-utils/account"
	"github.com/consensys/quorum-account-plugin-hashicorp-vault/internal/config"
)

func newSignerAccountManager(conf config.VaultClient) (*signerAccountManager, error) {
	client, err := newVaultClient(conf)
	if err != nil {
		return nil, err
	}

	a := &signerAccountManager{
		client:           client,
		signerEngineName: conf.SecretEngineName(),
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

	return hex.DecodeString(sigHex)
}

func (a *signerAccountManager) UnlockAndSign(acctAddr util.Address, toSign []byte) ([]byte, error) {
	return a.Sign(acctAddr, toSign)
}

func (a *signerAccountManager) TimedUnlock(_ util.Address, _ time.Duration) error {
	log.Print("[DEBUG] unsupported account manager operation: TimedUnlock")
	return nil
}

func (a *signerAccountManager) Lock(_ util.Address) {
	log.Print("[DEBUG] unsupported account manager operation: Lock")
}

func (a *signerAccountManager) NewAccount(conf config.NewAccount) (util.Account, error) {
	log.Print("[DEBUG] Sending request to Vault to create new account")

	return a.createInVaultAndWriteToFile(conf, nil)
}

func (a *signerAccountManager) ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (util.Account, error) {
	defer util.ZeroKey(privateKeyECDSA)

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

	fileData, err := writeToFile(addrHex, 0, conf, a.client.accountDirectory) // versioning not supported so use 0 as this corresponds to latest in the Vault API
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
