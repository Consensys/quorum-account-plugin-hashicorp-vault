package hashicorp

import (
	"crypto/ecdsa"
	"errors"
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
	panic("implement me")
}

func (a *signerAccountManager) ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (account.Account, error) {
	panic("implement me")
}
