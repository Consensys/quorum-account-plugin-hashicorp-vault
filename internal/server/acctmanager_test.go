package server

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
	"github.com/stretchr/testify/require"
)

func TestHashicorpPlugin_NewAccount_ToBeStreamedAsEvent(t *testing.T) {
	a := stubAccountManager{
		newAccountUrl: accounts.URL{
			Scheme: "http",
			Path:   "myacct",
		},
	}
	p := HashicorpPlugin{
		toStream:    make(chan string),
		acctManager: a,
	}

	b, err := json.Marshal(config.NewAccount{
		SecretEnginePath: "eng",
		SecretPath:       "sec",
		InsecureSkipCAS:  true,
	})
	require.NoError(t, err)
	_, err = p.NewAccount(context.Background(), &proto.NewAccountRequest{NewAccountConfig: b})
	require.NoError(t, err)

	select {
	case url := <-p.toStream:
		require.Equal(t, "http://myacct", url)
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "new account url not added to channel")
	}
}

func TestHashicorpPlugin_ImportRawKey_ToBeStreamedAsEvent(t *testing.T) {
	a := stubAccountManager{
		newAccountUrl: accounts.URL{
			Scheme: "http",
			Path:   "myacct",
		},
	}
	p := HashicorpPlugin{
		toStream:    make(chan string),
		acctManager: a,
	}

	b, err := json.Marshal(config.NewAccount{
		SecretEnginePath: "eng",
		SecretPath:       "sec",
		InsecureSkipCAS:  true,
	})
	require.NoError(t, err)
	req := &proto.ImportRawKeyRequest{
		NewAccountConfig: b,
		RawKey:           "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28",
	}
	_, err = p.ImportRawKey(context.Background(), req)
	require.NoError(t, err)

	select {
	case url := <-p.toStream:
		require.Equal(t, "http://myacct", url)
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "new account url not added to channel")
	}
}

type stubAccountManager struct {
	newAccountUrl accounts.URL
}

func (m stubAccountManager) Status(wallet accounts.URL) (string, error) {
	panic("implement me")
}

func (m stubAccountManager) Account(wallet accounts.URL) (accounts.Account, error) {
	panic("implement me")
}

func (m stubAccountManager) Contains(account accounts.Account) (bool, error) {
	panic("implement me")
}

func (m stubAccountManager) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	panic("implement me")
}

func (m stubAccountManager) UnlockAndSignHash(account accounts.Account, hash []byte) ([]byte, error) {
	panic("implement me")
}

func (m stubAccountManager) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) ([]byte, error) {
	panic("implement me")
}

func (m stubAccountManager) UnlockAndSignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) ([]byte, error) {
	panic("implement me")
}

func (m stubAccountManager) TimedUnlock(account accounts.Account, duration time.Duration) error {
	panic("implement me")
}

func (m stubAccountManager) Lock(account accounts.Account) {
	panic("implement me")
}

func (m stubAccountManager) NewAccount(conf config.NewAccount) (accounts.Account, error) {
	return accounts.Account{URL: m.newAccountUrl}, nil
}

func (m stubAccountManager) ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (accounts.Account, error) {
	return accounts.Account{URL: m.newAccountUrl}, nil
}

func (m stubAccountManager) WalletURLs() []accounts.URL {
	panic("implement me")
}
