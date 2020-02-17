package server

import (
	"context"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (p HashicorpPlugin) isInitialized() bool {
	return p.acctManager != nil
}

func (p HashicorpPlugin) Status(ctx context.Context, req *proto.StatusRequest) (*proto.StatusResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.Status(ctx, req)
}

func (p HashicorpPlugin) Open(ctx context.Context, req *proto.OpenRequest) (*proto.OpenResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.Open(ctx, req)
}

func (p HashicorpPlugin) Close(ctx context.Context, req *proto.CloseRequest) (*proto.CloseResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.Close(ctx, req)
}

func (p HashicorpPlugin) Accounts(ctx context.Context, req *proto.AccountsRequest) (*proto.AccountsResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.Accounts(ctx, req)
}

func (p HashicorpPlugin) Contains(ctx context.Context, req *proto.ContainsRequest) (*proto.ContainsResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.Contains(ctx, req)
}

func (p HashicorpPlugin) SignHash(ctx context.Context, req *proto.SignHashRequest) (*proto.SignHashResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.SignHash(ctx, req)
}

func (p HashicorpPlugin) SignTx(ctx context.Context, req *proto.SignTxRequest) (*proto.SignTxResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.SignTx(ctx, req)
}

func (p HashicorpPlugin) SignHashWithPassphrase(ctx context.Context, req *proto.SignHashWithPassphraseRequest) (*proto.SignHashResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.SignHashWithPassphrase(ctx, req)
}

func (p HashicorpPlugin) SignTxWithPassphrase(ctx context.Context, req *proto.SignTxWithPassphraseRequest) (*proto.SignTxResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.SignTxWithPassphrase(ctx, req)
}

func (p HashicorpPlugin) GetEventStream(req *proto.GetEventStreamRequest, stream proto.AccountManager_GetEventStreamServer) error {
	if !p.isInitialized() {
		return status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.GetEventStream(req, stream)
}

func (p HashicorpPlugin) TimedUnlock(ctx context.Context, req *proto.TimedUnlockRequest) (*proto.TimedUnlockResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.TimedUnlock(ctx, req)
}

func (p HashicorpPlugin) Lock(ctx context.Context, req *proto.LockRequest) (*proto.LockResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.Lock(ctx, req)
}

func (p HashicorpPlugin) NewAccount(ctx context.Context, req *proto.NewAccountRequest) (*proto.NewAccountResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.NewAccount(ctx, req)
}

func (p HashicorpPlugin) ImportRawKey(ctx context.Context, req *proto.ImportRawKeyRequest) (*proto.ImportRawKeyResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	return p.acctManager.ImportRawKey(ctx, req)
}
