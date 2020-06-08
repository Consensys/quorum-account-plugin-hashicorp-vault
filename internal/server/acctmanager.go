package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/protoconv"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/types"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (p *HashicorpPlugin) isInitialized() bool {
	return p.acctManager != nil
}

func (p *HashicorpPlugin) Status(_ context.Context, _ *proto.StatusRequest) (*proto.StatusResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	s, err := p.acctManager.Status()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.StatusResponse{Status: s}, nil
}

// Open is a no-op for Vault-stored accounts
func (p *HashicorpPlugin) Open(_ context.Context, _ *proto.OpenRequest) (*proto.OpenResponse, error) {
	return &proto.OpenResponse{}, nil
}

// Close is a no-op for Vault-stored accounts
func (p *HashicorpPlugin) Close(_ context.Context, _ *proto.CloseRequest) (*proto.CloseResponse, error) {
	return &proto.CloseResponse{}, nil
}

func (p *HashicorpPlugin) Accounts(_ context.Context, _ *proto.AccountsRequest) (*proto.AccountsResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	accts, err := p.acctManager.Accounts()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	protoAccts := make([]*proto.Account, 0, len(accts))
	for _, a := range accts {
		protoAccts = append(protoAccts, protoconv.AcctToProto(a))
	}

	return &proto.AccountsResponse{Accounts: protoAccts}, nil
}

func (p *HashicorpPlugin) Contains(_ context.Context, req *proto.ContainsRequest) (*proto.ContainsResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	addr, err := types.NewAddress(req.Address)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	isContained, err := p.acctManager.Contains(addr)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.ContainsResponse{IsContained: isContained}, nil
}

func (p *HashicorpPlugin) Sign(_ context.Context, req *proto.SignRequest) (*proto.SignResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	addr, err := types.NewAddress(req.Address)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	result, err := p.acctManager.Sign(addr, req.ToSign)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.SignResponse{Sig: result}, nil
}

func (p *HashicorpPlugin) UnlockAndSign(_ context.Context, req *proto.UnlockAndSignRequest) (*proto.SignResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	addr, err := types.NewAddress(req.Address)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	result, err := p.acctManager.UnlockAndSign(addr, req.ToSign)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.SignResponse{Sig: result}, nil
}

func (p *HashicorpPlugin) TimedUnlock(_ context.Context, req *proto.TimedUnlockRequest) (*proto.TimedUnlockResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	addr, err := types.NewAddress(req.Address)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.acctManager.TimedUnlock(addr, time.Duration(req.Duration)); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &proto.TimedUnlockResponse{}, nil
}

func (p *HashicorpPlugin) Lock(_ context.Context, req *proto.LockRequest) (*proto.LockResponse, error) {
	if !p.isInitialized() {
		return nil, status.Error(codes.Unavailable, "not configured")
	}
	addr, err := types.NewAddress(req.Address)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	p.acctManager.Lock(addr)
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
	}, nil
}
