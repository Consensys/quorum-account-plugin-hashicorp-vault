package hashicorp

import (
	"crypto/ecdsa"
	"time"

	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/account"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
)

type AccountManager interface {
	Status() (string, error)
	Accounts() ([]account.Account, error)
	Contains(acctAddr account.Address) bool
	Sign(acctAddr account.Address, toSign []byte) ([]byte, error)
	UnlockAndSign(acctAddr account.Address, toSign []byte) ([]byte, error)
	TimedUnlock(acctAddr account.Address, duration time.Duration) error
	Lock(acctAddr account.Address)
	NewAccount(conf config.NewAccount) (account.Account, error)
	ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (account.Account, error)
}
