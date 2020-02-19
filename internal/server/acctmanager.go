package server

import (
	"context"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/protoconv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"math/big"
	"net/url"
	"time"
)

func (p HashicorpPlugin) isInitialized() bool {
	return p.acctManager != nil
}

func (p HashicorpPlugin) Status(_ context.Context, req *proto.StatusRequest) (*proto.StatusResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	if _, err := url.Parse(req.WalletUrl); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s, err := p.acctManager.Status(req.WalletUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.StatusResponse{Status: s}, nil
}

// Open is a no-op for Vault-stored accounts
func (p HashicorpPlugin) Open(_ context.Context, _ *proto.OpenRequest) (*proto.OpenResponse, error) {
	return &proto.OpenResponse{}, status.Error(codes.Unimplemented, "open not supported")
}

// Close is a no-op for Vault-stored accounts
func (p HashicorpPlugin) Close(_ context.Context, _ *proto.CloseRequest) (*proto.CloseResponse, error) {
	return &proto.CloseResponse{}, status.Error(codes.Unimplemented, "close not supported")
}

func (p HashicorpPlugin) Accounts(ctx context.Context, req *proto.AccountsRequest) (*proto.AccountsResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	if _, err := url.Parse(req.WalletUrl); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	accts := p.acctManager.Accounts(req.WalletUrl)

	return &proto.AccountsResponse{Accounts: protoconv.AcctsToProto(accts)}, nil
}

func (p HashicorpPlugin) Contains(_ context.Context, req *proto.ContainsRequest) (*proto.ContainsResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	if _, err := url.Parse(req.WalletUrl); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	isContained, err := p.acctManager.Contains(req.WalletUrl, protoconv.AcctFromProto(req.Account))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.ContainsResponse{IsContained: isContained}, nil
}

func (p HashicorpPlugin) SignHash(_ context.Context, req *proto.SignHashRequest) (*proto.SignHashResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	result, err := p.acctManager.SignHash(req.WalletUrl, protoconv.AcctFromProto(req.Account), req.Hash)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.SignHashResponse{Result: result}, nil
}

func (p HashicorpPlugin) SignTx(_ context.Context, req *proto.SignTxRequest) (*proto.SignTxResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}

	chainID := new(big.Int)
	if len(req.ChainID) == 0 {
		chainID = nil
	} else {
		chainID.SetBytes(req.ChainID)
	}

	result, err := p.acctManager.SignTx(req.WalletUrl, protoconv.AcctFromProto(req.Account), req.RlpTx, chainID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.SignTxResponse{RlpTx: result}, nil
}

func (p HashicorpPlugin) SignHashWithPassphrase(_ context.Context, req *proto.SignHashWithPassphraseRequest) (*proto.SignHashResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	result, err := p.acctManager.UnlockAndSignHash(req.WalletUrl, protoconv.AcctFromProto(req.Account), req.Hash)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.SignHashResponse{Result: result}, nil
}

func (p HashicorpPlugin) SignTxWithPassphrase(_ context.Context, req *proto.SignTxWithPassphraseRequest) (*proto.SignTxResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}

	chainID := new(big.Int)
	if len(req.ChainID) == 0 {
		chainID = nil
	} else {
		chainID.SetBytes(req.ChainID)
	}

	result, err := p.acctManager.UnlockAndSignTx(req.WalletUrl, protoconv.AcctFromProto(req.Account), req.RlpTx, chainID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.SignTxResponse{RlpTx: result}, nil
}

// TODO(cjh) read about the GRPCBroker arg to the GRPCServer method as a potential alternative to this
func (p HashicorpPlugin) GetEventStream(_ *proto.GetEventStreamRequest, stream proto.AccountManager_GetEventStreamServer) error {
	if !p.isInitialized() {
		return status.Error(codes.Unavailable, "not configured")
	}

	//wallets := p.acctManager.Wallets()
	//
	//// now that we have the initial set of wallets, subscribe to the acct manager backend to be notified when changes occur
	//eventSubscription := p.acctManager.Subscribe(am.events)
	//defer func() {
	//	eventSubscription.Unsubscribe()
	//	eventSubscription = nil
	//}()
	//
	//// stream the currently held wallets to the caller
	//for _, w := range wallets {
	//	pluginEvent := &proto.GetEventStreamResponse{
	//		WalletEvent: proto.GetEventStreamResponse_WALLET_ARRIVED,
	//		WalletUrl:   w.URL().String(),
	//	}
	//
	//	if err := stream.Send(pluginEvent); err != nil {
	//		log.Println("[ERROR] error sending event: ", pluginEvent, "err: ", err)
	//		return err
	//	}
	//	log.Println("[DEBUG] sent event: ", pluginEvent)
	//}
	//
	//// listen for wallet events and stream to the caller until termination
	//for {
	//	e := <-am.events
	//	pluginEvent := asProtoWalletEvent(e)
	//	log.Println("[DEBUG] read event: ", pluginEvent)
	//	if err := stream.Send(pluginEvent); err != nil {
	//		log.Println("[ERROR] error sending event: ", pluginEvent, "err: ", err)
	//		return err
	//	}
	//	log.Println("[DEBUG] sent event: ", pluginEvent)
	//}
	return status.Error(codes.Unimplemented, "implement me")
}

func (p HashicorpPlugin) TimedUnlock(_ context.Context, req *proto.TimedUnlockRequest) (*proto.TimedUnlockResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}

	err := p.acctManager.TimedUnlock(protoconv.AcctFromProto(req.Account), time.Duration(req.Duration))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.TimedUnlockResponse{}, nil
}

func (p HashicorpPlugin) Lock(_ context.Context, req *proto.LockRequest) (*proto.LockResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	err := p.acctManager.Lock(protoconv.AcctFromProto(req.Account))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.LockResponse{}, nil
}

func (p HashicorpPlugin) NewAccount(_ context.Context, req *proto.NewAccountRequest) (*proto.NewAccountResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	//return p.acctManager.NewAccount(ctx, req)
	return nil, status.Error(codes.Unimplemented, "implement me")
}

func (p HashicorpPlugin) ImportRawKey(_ context.Context, req *proto.ImportRawKeyRequest) (*proto.ImportRawKeyResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	//return p.acctManager.ImportRawKey(ctx, req)
	return nil, status.Error(codes.Unimplemented, "implement me")
}
