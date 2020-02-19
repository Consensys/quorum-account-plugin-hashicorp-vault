package hashicorp

import (
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/config"
	"math/big"
	"time"
)

func NewAccountManager(config config.VaultClients) (*AccountManager, error) {
	clients := make([]*vaultClient, len(config))

	for i, conf := range config {
		client, err := newVaultClient(conf)
		if err != nil {
			return nil, err
		}
		clients[i] = client
	}

	return &AccountManager{clients: clients}, nil
}

type AccountManager struct {
	clients []*vaultClient
}

type Account struct {
	Address []byte
	Url     string
}

type Transaction struct{}

func (a AccountManager) Status(walletUrl string) (string, error) {
	panic("implement me")
}

func (a AccountManager) Accounts(walletUrl string) []Account {
	panic("implement me")
}

func (a AccountManager) Contains(walletUrl string, account Account) (bool, error) {
	panic("implement me")
}

func (a AccountManager) SignHash(walletUrl string, account Account, hash []byte) ([]byte, error) {
	panic("implement me")
}

func (a AccountManager) SignTx(walletUrl string, account Account, rlpTx []byte, chainId *big.Int) ([]byte, error) {
	panic("implement me")
}

func (a AccountManager) UnlockAndSignHash(walletUrl string, account Account, hash []byte) ([]byte, error) {
	panic("implement me")
}

func (a AccountManager) UnlockAndSignTx(walletUrl string, account Account, rlpTx []byte, chainId *big.Int) ([]byte, error) {
	panic("implement me")
}

func (a AccountManager) GetEventStream(*proto.GetEventStreamRequest, proto.AccountManager_GetEventStreamServer) error {
	panic("implement me")
}

func (a AccountManager) TimedUnlock(account Account, duration time.Duration) error {
	panic("implement me")
}

func (a AccountManager) Lock(account Account) error {
	panic("implement me")
}

func (a AccountManager) NewAccount(conf config.NewAccount) (Account, error) {
	panic("implement me")
}

func (a AccountManager) ImportAccount(publicKeyHex string, privateKeyHex string, conf config.NewAccount) (Account, error) {
	panic("implement me")
}
