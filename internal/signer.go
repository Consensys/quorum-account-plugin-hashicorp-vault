package internal

import (
	"context"
	"quorum-plugin-hashicorp-account-store/proto"
)

type signer struct{}

func (s *signer) Status(context.Context, *proto.StatusRequest) (*proto.StatusResponse, error) {
	panic("implement me")
}

func (s *signer) Open(context.Context, *proto.OpenRequest) (*proto.OpenResponse, error) {
	panic("implement me")
}

func (s *signer) Close(context.Context, *proto.CloseRequest) (*proto.CloseResponse, error) {
	panic("implement me")
}

func (s *signer) Accounts(context.Context, *proto.AccountsRequest) (*proto.AccountsResponse, error) {
	panic("implement me")
}

func (s *signer) Contains(context.Context, *proto.ContainsRequest) (*proto.ContainsResponse, error) {
	panic("implement me")
}

func (s *signer) SignHash(context.Context, *proto.SignHashRequest) (*proto.SignHashResponse, error) {
	panic("implement me")
}

func (s *signer) SignTx(context.Context, *proto.SignTxRequest) (*proto.SignTxResponse, error) {
	panic("implement me")
}

func (s *signer) SignHashWithPassphrase(context.Context, *proto.SignHashWithPassphraseRequest) (*proto.SignHashResponse, error) {
	panic("implement me")
}

func (s *signer) SignTxWithPassphrase(context.Context, *proto.SignTxWithPassphraseRequest) (*proto.SignTxResponse, error) {
	panic("implement me")
}
