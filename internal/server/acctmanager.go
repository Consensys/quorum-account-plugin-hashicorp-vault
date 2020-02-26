package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/config"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/protoconv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"math/big"
	"time"
)

func (p *HashicorpPlugin) isInitialized() bool {
	return p.acctManager != nil
}

func (p *HashicorpPlugin) Status(_ context.Context, req *proto.StatusRequest) (*proto.StatusResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	jsonUrl := fmt.Sprintf("\"%v\"", req.WalletUrl)
	wallet := new(accounts.URL)
	if err := json.Unmarshal([]byte(jsonUrl), wallet); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s, err := p.acctManager.Status(*wallet)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.StatusResponse{Status: s}, nil
}

// Open is a no-op for Vault-stored accounts
func (p *HashicorpPlugin) Open(_ context.Context, _ *proto.OpenRequest) (*proto.OpenResponse, error) {
	return &proto.OpenResponse{}, status.Error(codes.Unimplemented, "open not supported")
}

// Close is a no-op for Vault-stored accounts
func (p *HashicorpPlugin) Close(_ context.Context, _ *proto.CloseRequest) (*proto.CloseResponse, error) {
	return &proto.CloseResponse{}, status.Error(codes.Unimplemented, "close not supported")
}

func (p *HashicorpPlugin) Accounts(ctx context.Context, req *proto.AccountsRequest) (*proto.AccountsResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	jsonUrl := fmt.Sprintf("\"%v\"", req.WalletUrl)
	wallet := new(accounts.URL)
	if err := json.Unmarshal([]byte(jsonUrl), wallet); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	acct, err := p.acctManager.Account(*wallet)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	protoAcct := protoconv.AcctToProto(acct)

	return &proto.AccountsResponse{Accounts: []*proto.Account{protoAcct}}, nil
}

func (p *HashicorpPlugin) Contains(_ context.Context, req *proto.ContainsRequest) (*proto.ContainsResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	jsonUrl := fmt.Sprintf("\"%v\"", req.WalletUrl)
	wallet := new(accounts.URL)
	if err := json.Unmarshal([]byte(jsonUrl), wallet); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	acct, err := protoconv.ProtoToAcct(req.Account)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	isContained, err := p.acctManager.Contains(*wallet, acct)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.ContainsResponse{IsContained: isContained}, nil
}

func (p *HashicorpPlugin) SignHash(_ context.Context, req *proto.SignHashRequest) (*proto.SignHashResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	acct, err := protoconv.ProtoToAcct(req.Account)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	jsonUrl := fmt.Sprintf("\"%v\"", req.WalletUrl)
	wallet := new(accounts.URL)
	if err := json.Unmarshal([]byte(jsonUrl), wallet); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	result, err := p.acctManager.SignHash(*wallet, acct, req.Hash)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.SignHashResponse{Result: result}, nil
}

func (p *HashicorpPlugin) SignTx(_ context.Context, req *proto.SignTxRequest) (*proto.SignTxResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	acct, err := protoconv.ProtoToAcct(req.Account)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	jsonUrl := fmt.Sprintf("\"%v\"", req.WalletUrl)
	wallet := new(accounts.URL)
	if err := json.Unmarshal([]byte(jsonUrl), wallet); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	chainID := new(big.Int)
	if len(req.ChainID) == 0 {
		chainID = nil
	} else {
		chainID.SetBytes(req.ChainID)
	}

	result, err := p.acctManager.SignTx(*wallet, acct, req.RlpTx, chainID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.SignTxResponse{RlpTx: result}, nil
}

func (p *HashicorpPlugin) SignHashWithPassphrase(_ context.Context, req *proto.SignHashWithPassphraseRequest) (*proto.SignHashResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	acct, err := protoconv.ProtoToAcct(req.Account)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	jsonUrl := fmt.Sprintf("\"%v\"", req.WalletUrl)
	wallet := new(accounts.URL)
	if err := json.Unmarshal([]byte(jsonUrl), wallet); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	result, err := p.acctManager.UnlockAndSignHash(*wallet, acct, req.Hash)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.SignHashResponse{Result: result}, nil
}

func (p *HashicorpPlugin) SignTxWithPassphrase(_ context.Context, req *proto.SignTxWithPassphraseRequest) (*proto.SignTxResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	acct, err := protoconv.ProtoToAcct(req.Account)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	jsonUrl := fmt.Sprintf("\"%v\"", req.WalletUrl)
	wallet := new(accounts.URL)
	if err := json.Unmarshal([]byte(jsonUrl), wallet); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	chainID := new(big.Int)
	if len(req.ChainID) == 0 {
		chainID = nil
	} else {
		chainID.SetBytes(req.ChainID)
	}

	result, err := p.acctManager.UnlockAndSignTx(*wallet, acct, req.RlpTx, chainID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.SignTxResponse{RlpTx: result}, nil
}

// TODO(cjh) read about the GRPCBroker arg to the GRPCServer method as a potential alternative to this
func (p *HashicorpPlugin) GetEventStream(_ *proto.GetEventStreamRequest, stream proto.AccountManager_GetEventStreamServer) error {
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

func (p *HashicorpPlugin) TimedUnlock(_ context.Context, req *proto.TimedUnlockRequest) (*proto.TimedUnlockResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	acct, err := protoconv.ProtoToAcct(req.Account)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.acctManager.TimedUnlock(acct, time.Duration(req.Duration)); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.TimedUnlockResponse{}, nil
}

func (p *HashicorpPlugin) Lock(_ context.Context, req *proto.LockRequest) (*proto.LockResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	acct, err := protoconv.ProtoToAcct(req.Account)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	p.acctManager.Lock(acct)
	return &proto.LockResponse{}, nil
}

func (p *HashicorpPlugin) NewAccount(_ context.Context, req *proto.NewAccountRequest) (*proto.NewAccountResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	conf := new(config.NewAccount)
	if err := json.Unmarshal(req.NewAccountConfig, conf); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := conf.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	acct, err := p.acctManager.NewAccount(*conf)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return &proto.NewAccountResponse{
		Account: protoconv.AcctToProto(acct),
		KeyUri:  "", // TODO(cjh) get rid of this field from protobuf def if we're just showing vault secret url
	}, nil
}

func (p *HashicorpPlugin) ImportRawKey(_ context.Context, req *proto.ImportRawKeyRequest) (*proto.ImportRawKeyResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	conf := new(config.NewAccount)
	if err := json.Unmarshal(req.NewAccountConfig, conf); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := conf.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	privateKey, err := crypto.HexToECDSA(req.RawKey)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	acct, err := p.acctManager.ImportPrivateKey(privateKey, *conf)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return &proto.ImportRawKeyResponse{
		Account: protoconv.AcctToProto(acct),
		KeyUri:  "", // TODO(cjh) get rid of this field from protobuf def if we're just showing vault secret url
	}, nil
}
