package hashicorp

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
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
	clients  []*vaultClient
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
	for _, client := range a.clients {
		if client.hasWallet(wallet) {
			addr := client.getAccountAddress(wallet)
			_, isUnlocked := a.unlocked[addr]
			if isUnlocked {
				return "unlocked", nil
			}
			return "locked", nil
		}
	}
	return "", errors.New("unknown wallet")
}

func (a AccountManager) Account(wallet accounts.URL) (accounts.Account, error) {
	for _, client := range a.clients {
		if client.hasWallet(wallet) {
			hexAddr := client.getAccountAddress(wallet)
			byteAddr := common.HexToAddress(hexAddr)

			return accounts.Account{Address: byteAddr, URL: wallet}, nil
		}
	}
	return accounts.Account{}, errors.New("unknown wallet")
}

func (a AccountManager) Contains(wallet accounts.URL, account accounts.Account) (bool, error) {
	if account.URL != (accounts.URL{}) && wallet != account.URL {
		return false, fmt.Errorf("wallet %v cannot contain account with URL %v", wallet.String(), account.URL.String())
	}
	for _, client := range a.clients {
		if client.hasWallet(wallet) {
			acctFile := client.wallets[wallet]
			if bytes.Compare(common.Hex2Bytes(acctFile.Contents.Address), account.Address.Bytes()) != 0 {
				return false, nil
			}
			return true, nil
		}
	}
	return false, errors.New("unknown wallet")
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
	panic("implement me")
}

func (a AccountManager) ImportAccount(publicKeyHex string, privateKeyHex string, conf config.NewAccount) (accounts.Account, error) {
	panic("implement me")
}
