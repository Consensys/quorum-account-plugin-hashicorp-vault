package hashicorp

import (
	"context"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/config"
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

func (a AccountManager) Status(context.Context, *proto.StatusRequest) (*proto.StatusResponse, error) {
	panic("implement me")
}

func (a AccountManager) Open(context.Context, *proto.OpenRequest) (*proto.OpenResponse, error) {
	panic("implement me")
}

func (a AccountManager) Close(context.Context, *proto.CloseRequest) (*proto.CloseResponse, error) {
	panic("implement me")
}

func (a AccountManager) Accounts(context.Context, *proto.AccountsRequest) (*proto.AccountsResponse, error) {
	panic("implement me")
}

func (a AccountManager) Contains(context.Context, *proto.ContainsRequest) (*proto.ContainsResponse, error) {
	panic("implement me")
}

func (a AccountManager) SignHash(context.Context, *proto.SignHashRequest) (*proto.SignHashResponse, error) {
	panic("implement me")
}

func (a AccountManager) SignTx(context.Context, *proto.SignTxRequest) (*proto.SignTxResponse, error) {
	panic("implement me")
}

func (a AccountManager) SignHashWithPassphrase(context.Context, *proto.SignHashWithPassphraseRequest) (*proto.SignHashResponse, error) {
	panic("implement me")
}

func (a AccountManager) SignTxWithPassphrase(context.Context, *proto.SignTxWithPassphraseRequest) (*proto.SignTxResponse, error) {
	panic("implement me")
}

func (a AccountManager) GetEventStream(*proto.GetEventStreamRequest, proto.AccountManager_GetEventStreamServer) error {
	panic("implement me")
}

func (a AccountManager) TimedUnlock(context.Context, *proto.TimedUnlockRequest) (*proto.TimedUnlockResponse, error) {
	panic("implement me")
}

func (a AccountManager) Lock(context.Context, *proto.LockRequest) (*proto.LockResponse, error) {
	panic("implement me")
}

func (a AccountManager) NewAccount(context.Context, *proto.NewAccountRequest) (*proto.NewAccountResponse, error) {
	panic("implement me")
}

func (a AccountManager) ImportRawKey(context.Context, *proto.ImportRawKeyRequest) (*proto.ImportRawKeyResponse, error) {
	panic("implement me")
}
