package internal

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/hashicorp"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/goquorum/quorum-plugin-definitions/signer/go/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type WalletFinderLockerBackend interface {
	accounts.Backend
	Wallet(url string) (accounts.Wallet, error)
	TimedUnlock(acct accounts.Account, passphrase string, timeout time.Duration) error
	Lock(acct accounts.Account) error
}

type signer struct {
	WalletFinderLockerBackend
	events            chan accounts.WalletEvent
	eventSubscription event.Subscription
}

func (s *signer) init(config hashicorp.HashicorpAccountStoreConfig) error {
	log.Println("[PLUGIN SIGNER] init")
	manager, err := hashicorp.NewManager(config.Vaults)
	if err != nil {
		return err
	}
	s.WalletFinderLockerBackend = manager
	s.events = make(chan accounts.WalletEvent, 4*len(config.Vaults))
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

// TODO CancelSubscribe method which calls unsubscribe and stops this loop
// TODO Rename e.g. RegisterListener
func (s *signer) Subscribe(req *proto.SubscribeRequest, stream proto.Signer_SubscribeServer) error {
	defer func() {
		s.eventSubscription.Unsubscribe()
		s.eventSubscription = nil
	}()

	log.Println("[SIGNER] received subscription request from geth")

	wallets := s.Wallets()

	// now that we have the initial set of wallets, subscribe to the acct manager backend to be notified when changes occur
	s.eventSubscription = s.WalletFinderLockerBackend.Subscribe(s.events)

	// stream the currently held wallets to the caller
	for _, w := range wallets {
		pluginEvent := &proto.SubscribeResponse{
			WalletEvent: proto.SubscribeResponse_WALLET_ARRIVED,
			WalletUrl:   w.URL().String(),
		}

		if err := stream.Send(pluginEvent); err != nil {
			log.Println("[SIGNER] error sending event: ", pluginEvent, "err: ", err)
			return err
		}
		log.Println("[SIGNER] sent event: ", pluginEvent)
	}

	// listen for wallet events and stream to the caller until termination
	for {
		e := <-s.events
		log.Println("[SIGNER] read event: ", e)

		if err := stream.Send(asProtoWalletEvent(e)); err != nil {
			log.Println("[SIGNER] error sending event: ", e, "err: ", err)
			return err
		}
		log.Println("[SIGNER] sent event: ", e)
	}
}

func (s *signer) TimedUnlock(_ context.Context, req *proto.TimedUnlockRequest) (*proto.TimedUnlockResponse, error) {
	a, err := asAccount(req.Account)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	err = s.WalletFinderLockerBackend.TimedUnlock(a, req.Password, time.Duration(req.Duration))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.TimedUnlockResponse{}, nil
}

func (s *signer) Lock(_ context.Context, req *proto.LockRequest) (*proto.LockResponse, error) {
	a, err := asAccount(req.Account)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	err = s.WalletFinderLockerBackend.Lock(a)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.LockResponse{}, nil
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

func asProtoWalletEvent(event accounts.WalletEvent) *proto.SubscribeResponse {
	var t proto.SubscribeResponse_WalletEvent

	switch event.Kind {
	case accounts.WalletArrived:
		t = proto.SubscribeResponse_WALLET_ARRIVED
	case accounts.WalletOpened:
		t = proto.SubscribeResponse_WALLET_OPENED
	case accounts.WalletDropped:
		t = proto.SubscribeResponse_WALLET_DROPPED
	}

	return &proto.SubscribeResponse{
		WalletEvent: t,
		WalletUrl:   event.Wallet.URL().String(),
	}
}
