package server

import (
	"context"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
)

func (p HashicorpPlugin) Status(context.Context, *proto.StatusRequest) (*proto.StatusResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) Open(context.Context, *proto.OpenRequest) (*proto.OpenResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) Close(context.Context, *proto.CloseRequest) (*proto.CloseResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) Accounts(context.Context, *proto.AccountsRequest) (*proto.AccountsResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) Contains(context.Context, *proto.ContainsRequest) (*proto.ContainsResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) SignHash(context.Context, *proto.SignHashRequest) (*proto.SignHashResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) SignTx(context.Context, *proto.SignTxRequest) (*proto.SignTxResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) SignHashWithPassphrase(context.Context, *proto.SignHashWithPassphraseRequest) (*proto.SignHashResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) SignTxWithPassphrase(context.Context, *proto.SignTxWithPassphraseRequest) (*proto.SignTxResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) GetEventStream(*proto.GetEventStreamRequest, proto.AccountManager_GetEventStreamServer) error {
	panic("implement me")
}

func (p HashicorpPlugin) TimedUnlock(context.Context, *proto.TimedUnlockRequest) (*proto.TimedUnlockResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) Lock(context.Context, *proto.LockRequest) (*proto.LockResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) NewAccount(context.Context, *proto.NewAccountRequest) (*proto.NewAccountResponse, error) {
	panic("implement me")
}

func (p HashicorpPlugin) ImportRawKey(context.Context, *proto.ImportRawKeyRequest) (*proto.ImportRawKeyResponse, error) {
	panic("implement me")
}
