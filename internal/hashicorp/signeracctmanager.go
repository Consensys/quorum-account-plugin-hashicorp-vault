package hashicorp

import (
	"crypto/ecdsa"
	"errors"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/account"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"time"
)

func NewSignerAccountManager(config config.VaultClient) (*signerAccountManager, error) {
	return nil, errors.New("implement me")
}

type signerAccountManager struct {
}

func (s *signerAccountManager) Status() (string, error) {
	panic("implement me")
}

func (s *signerAccountManager) Accounts() ([]account.Account, error) {
	panic("implement me")
}

func (s *signerAccountManager) Contains(acctAddr account.Address) bool {
	panic("implement me")
}

func (s *signerAccountManager) Sign(acctAddr account.Address, toSign []byte) ([]byte, error) {
	panic("implement me")
}

func (s *signerAccountManager) UnlockAndSign(acctAddr account.Address, toSign []byte) ([]byte, error) {
	panic("implement me")
}

func (s *signerAccountManager) TimedUnlock(acctAddr account.Address, duration time.Duration) error {
	panic("implement me")
}

func (s *signerAccountManager) Lock(acctAddr account.Address) {
	panic("implement me")
}

func (s *signerAccountManager) NewAccount(conf config.NewAccount) (account.Account, error) {
	panic("implement me")
}

func (s *signerAccountManager) ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (account.Account, error) {
	panic("implement me")
}
