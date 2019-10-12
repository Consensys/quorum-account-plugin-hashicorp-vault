package internal

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/hashicorp"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/goquorum/quorum-plugin-definitions/signer/go/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type WalletFinder interface {
	Wallet(url string) (accounts.Wallet, error)
}

type signer struct {
	WalletFinder
}

func (s *signer) init(config hashicorp.HashicorpAccountStoreConfig) error {
	b := hashicorp.NewManager(config.Vaults)
	s.WalletFinder = b
	return nil
}

func (s *signer) Status(_ context.Context, req *proto.StatusRequest) (*proto.StatusResponse, error) {
	w, err := s.Wallet(req.WalletUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	wltStatus, err := w.Status()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.StatusResponse{Status: wltStatus}, nil
}

func (s *signer) Open(_ context.Context, req *proto.OpenRequest) (*proto.OpenResponse, error) {
	w, err := s.Wallet(req.WalletUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if err := w.Open(req.Passphrase); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.OpenResponse{}, nil
}

func (s *signer) Close(_ context.Context, req *proto.CloseRequest) (*proto.CloseResponse, error) {
	w, err := s.Wallet(req.WalletUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if err := w.Close(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.CloseResponse{}, nil
}

func (s *signer) Accounts(_ context.Context, req *proto.AccountsRequest) (*proto.AccountsResponse, error) {
	w, err := s.Wallet(req.WalletUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	accts := w.Accounts()

	protoAccts := make([]*proto.Account, len(accts))
	for i, a := range accts {
		protoAccts[i] = asProtoAccount(a)
	}

	return &proto.AccountsResponse{Accounts: protoAccts}, nil
}

func (s *signer) Contains(_ context.Context, req *proto.ContainsRequest) (*proto.ContainsResponse, error) {
	w, err := s.Wallet(req.WalletUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	a, err := asAccount(req.Account)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.ContainsResponse{IsContained: w.Contains(a)}, nil
}

func (s *signer) SignHash(_ context.Context, req *proto.SignHashRequest) (*proto.SignHashResponse, error) {
	w, err := s.Wallet(req.WalletUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	a, err := asAccount(req.Account)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	result, err := w.SignHash(a, req.Hash)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.SignHashResponse{Result: result}, nil
}

func (s *signer) SignTx(_ context.Context, req *proto.SignTxRequest) (*proto.SignTxResponse, error) {
	w, err := s.Wallet(req.WalletUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	a, err := asAccount(req.Account)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	tx := new(types.Transaction)
	if err := rlp.DecodeBytes(req.RlpTx, tx); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	chainID := &big.Int{}
	chainID.SetBytes(req.ChainID)

	result, err := w.SignTx(a, tx, chainID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	rlpTx, err := rlp.EncodeToBytes(result)
	if err != nil {
		return nil, err
	}

	return &proto.SignTxResponse{RlpTx: rlpTx}, nil
}

func (s *signer) SignHashWithPassphrase(_ context.Context, req *proto.SignHashWithPassphraseRequest) (*proto.SignHashResponse, error) {
	w, err := s.Wallet(req.WalletUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	a, err := asAccount(req.Account)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	result, err := w.SignHashWithPassphrase(a, req.Passphrase, req.Hash)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.SignHashResponse{Result: result}, nil
}

func (s *signer) SignTxWithPassphrase(_ context.Context, req *proto.SignTxWithPassphraseRequest) (*proto.SignTxResponse, error) {
	w, err := s.Wallet(req.WalletUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	a, err := asAccount(req.Account)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	tx := new(types.Transaction)
	if err := rlp.DecodeBytes(req.RlpTx, tx); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	chainID := &big.Int{}
	chainID.SetBytes(req.ChainID)

	result, err := w.SignTxWithPassphrase(a, req.Passphrase, tx, chainID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	rlpTx, err := rlp.EncodeToBytes(result)
	if err != nil {
		return nil, err
	}

	return &proto.SignTxResponse{RlpTx: rlpTx}, nil
}

func (s *signer) Subscribe(*proto.SubscribeRequest, proto.Signer_SubscribeServer) error {
	// TODO
	return nil
}

// TODO duplicated from quorum plugin/accounts/gateway.go
func asAccount(pAcct *proto.Account) (accounts.Account, error) {
	addr := strings.TrimSpace(common.Bytes2Hex(pAcct.Address))

	if !common.IsHexAddress(addr) {
		return accounts.Account{}, fmt.Errorf("invalid hex address: %v", addr)
	}

	url, err := vault.ToUrl(pAcct.Url)
	if err != nil {
		return accounts.Account{}, err
	}

	acct := accounts.Account{
		Address: common.HexToAddress(addr),
		URL:     url,
	}

	return acct, nil
}

func asProtoAccount(acct accounts.Account) *proto.Account {
	return &proto.Account{
		Address: acct.Address.Bytes(),
		Url:     acct.URL.String(),
	}
}

// TODO end duplication
