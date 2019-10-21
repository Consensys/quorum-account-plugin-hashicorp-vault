package internal

import (
	"context"
	"errors"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/mock/gomock"
	"github.com/goquorum/quorum-plugin-definitions/signer/go/mock_proto"
	"github.com/goquorum/quorum-plugin-definitions/signer/go/proto"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/plugintest"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/plugintest/mock_accounts"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/plugintest/mock_hashicorp"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/plugintest/mock_internal"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/hashicorp"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
	"time"
)

var (
	wltUrl = accounts.URL{
		Scheme: hashicorp.WalletScheme,
		Path:   "FOO@localhost:8200",
	}

	acct1 = accounts.Account{
		Address: common.HexToAddress("0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"),
		URL:     accounts.URL{Scheme: hashicorp.AcctScheme, Path: "path/to/file1.json"},
	}
	protoAcct1 = &proto.Account{
		Address: acct1.Address.Bytes(),
		Url:     acct1.URL.String(),
	}
	hexkey1 = "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"
	key1, _ = crypto.HexToECDSA(hexkey1)

	acct2 = accounts.Account{
		Address: common.HexToAddress("0x2332f90a329c2c55ba120b1449d36a144d1f9fe4"),
		URL:     accounts.URL{Scheme: hashicorp.AcctScheme, Path: "path/to/file2.json"},
	}
	protoAcct2 = &proto.Account{
		Address: acct2.Address.Bytes(),
		Url:     acct2.URL.String(),
	}
)

func TestSigner_Status(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	mockBackend.
		EXPECT().
		Wallet(wltUrl.String()).
		Return(mockWallet, nil)

	status := "some status"
	mockWallet.
		EXPECT().
		Status().
		Return(status, nil)

	req := &proto.StatusRequest{WalletUrl: wltUrl.String()}
	got, err := s.Status(context.Background(), req)

	want := &proto.StatusResponse{Status: status}

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestSigner_Open(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	mockBackend.
		EXPECT().
		Wallet(wltUrl.String()).
		Return(mockWallet, nil)

	pwd := "pwd"
	mockWallet.
		EXPECT().
		Open(pwd).
		Return(nil)

	req := &proto.OpenRequest{
		WalletUrl:  wltUrl.String(),
		Passphrase: "pwd",
	}
	got, err := s.Open(context.Background(), req)

	want := &proto.OpenResponse{}

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestSigner_Close(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	mockBackend.
		EXPECT().
		Wallet(wltUrl.String()).
		Return(mockWallet, nil)

	mockWallet.
		EXPECT().
		Close().
		Return(nil)

	req := &proto.CloseRequest{WalletUrl: wltUrl.String()}
	got, err := s.Close(context.Background(), req)

	want := &proto.CloseResponse{}

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestSigner_Accounts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	mockBackend.
		EXPECT().
		Wallet(wltUrl.String()).
		Return(mockWallet, nil)

	accts := []accounts.Account{acct1, acct2}
	mockWallet.
		EXPECT().
		Accounts().
		Return(accts)

	req := &proto.AccountsRequest{WalletUrl: wltUrl.String()}
	got, err := s.Accounts(context.Background(), req)

	want := &proto.AccountsResponse{
		Accounts: []*proto.Account{protoAcct1, protoAcct2},
	}

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestSigner_Contains(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	mockBackend.
		EXPECT().
		Wallet(wltUrl.String()).
		Return(mockWallet, nil)

	mockWallet.
		EXPECT().
		Contains(acct1).
		Return(true)

	req := &proto.ContainsRequest{
		WalletUrl: wltUrl.String(),
		Account:   protoAcct1,
	}
	got, err := s.Contains(context.Background(), req)

	want := &proto.ContainsResponse{IsContained: true}

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestSigner_SignHash(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	mockBackend.
		EXPECT().
		Wallet(wltUrl.String()).
		Return(mockWallet, nil)

	toSign := []byte("to sign")
	signed := []byte("signed")
	mockWallet.
		EXPECT().
		SignHash(acct1, toSign).
		Return(signed, nil)

	req := &proto.SignHashRequest{
		WalletUrl: wltUrl.String(),
		Account:   protoAcct1,
		Hash:      toSign,
	}
	got, err := s.SignHash(context.Background(), req)

	want := &proto.SignHashResponse{Result: signed}

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestSigner_SignTx(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	mockBackend.
		EXPECT().
		Wallet(wltUrl.String()).
		Return(mockWallet, nil)

	var (
		// transaction properties
		nonce        uint64 = 1
		to                  = acct2.Address
		amount              = big.NewInt(1)
		gasLimit     uint64 = 0
		gasPrice            = big.NewInt(1)
		toSignTxData        = []byte("this tx is to be signed")
		signedTxData        = []byte("this tx has been signed")

		// SignTx args
		toSign  = types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, toSignTxData)
		signed  = types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, signedTxData)
		chainID = big.NewInt(20)
	)

	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	// When decoding rlp bytes to a tx, the size field is populated (see types/transaction.go: *Transaction.DecodeRLP).  We must populate that field in order to assert that Wallet.SignTxWithPassphrase is called with the expected args.
	toSign.Size()

	mockWallet.
		EXPECT().
		SignTx(acct1, toSign, chainID).
		Return(signed, nil)

	req := &proto.SignTxRequest{
		WalletUrl: wltUrl.String(),
		Account:   protoAcct1,
		RlpTx:     rlpToSign,
		ChainID:   chainID.Bytes(),
	}
	got, err := s.SignTx(context.Background(), req)
	require.NoError(t, err)

	rlpSigned, err := rlp.EncodeToBytes(signed)
	require.NoError(t, err)

	want := &proto.SignTxResponse{
		RlpTx: rlpSigned,
	}

	require.Equal(t, want, got)
}

func TestSigner_SignHashWithPassphrase(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	mockBackend.
		EXPECT().
		Wallet(wltUrl.String()).
		Return(mockWallet, nil)

	pwd := "pwd"
	toSign := []byte("to sign")
	signed := []byte("signed")
	mockWallet.
		EXPECT().
		SignHashWithPassphrase(acct1, pwd, toSign).
		Return(signed, nil)

	req := &proto.SignHashWithPassphraseRequest{
		WalletUrl:  wltUrl.String(),
		Account:    protoAcct1,
		Hash:       toSign,
		Passphrase: pwd,
	}
	got, err := s.SignHashWithPassphrase(context.Background(), req)

	want := &proto.SignHashResponse{Result: signed}

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestSigner_SignTxWithPassphrase(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	mockBackend.
		EXPECT().
		Wallet(wltUrl.String()).
		Return(mockWallet, nil)

	var (
		// transaction properties
		nonce        uint64 = 1
		to                  = acct2.Address
		amount              = big.NewInt(1)
		gasLimit     uint64 = 0
		gasPrice            = big.NewInt(1)
		toSignTxData        = []byte("this tx is to be signed")
		signedTxData        = []byte("this tx has been signed")

		// SignTx args
		toSign  = types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, toSignTxData)
		signed  = types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, signedTxData)
		chainID = big.NewInt(20)

		pwd = "pwd"
	)
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	// When decoding rlp bytes to a tx, the size field is populated (see types/transaction.go: *Transaction.DecodeRLP).  We must populate that field in order to assert that Wallet.SignTxWithPassphrase is called with the expected args.
	toSign.Size()

	mockWallet.
		EXPECT().
		SignTxWithPassphrase(acct1, pwd, toSign, chainID).
		Return(signed, nil)

	req := &proto.SignTxWithPassphraseRequest{
		WalletUrl:  wltUrl.String(),
		Account:    protoAcct1,
		RlpTx:      rlpToSign,
		ChainID:    chainID.Bytes(),
		Passphrase: pwd,
	}
	got, err := s.SignTxWithPassphrase(context.Background(), req)
	require.NoError(t, err)

	rlpSigned, err := rlp.EncodeToBytes(signed)
	require.NoError(t, err)

	want := &proto.SignTxResponse{
		RlpTx: rlpSigned,
	}

	require.Equal(t, want, got)
}

func TestSigner_GetEventStream(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
		events:                    make(chan accounts.WalletEvent, 2),
	}

	mockBackend.
		EXPECT().
		Wallets().
		Return([]accounts.Wallet{mockWallet})

	mockBackend.
		EXPECT().
		Subscribe(gomock.Any()).
		Return(plugintest.StubSubscription{})

	mockWallet.
		EXPECT().
		URL().
		Return(acct1.URL).
		Times(3)

	// add two events to the signer's event channel
	s.events <- accounts.WalletEvent{
		Wallet: mockWallet,
		Kind:   accounts.WalletOpened,
	}
	s.events <- accounts.WalletEvent{
		Wallet: mockWallet,
		Kind:   accounts.WalletDropped,
	}

	// gRPC protobuf versions of the events to be sent over the stream to the caller
	var (
		wantArrivedEvent = &proto.GetEventStreamResponse{
			WalletEvent: proto.GetEventStreamResponse_WALLET_ARRIVED,
			WalletUrl:   acct1.URL.String(),
		}

		wantOpenedEvent = &proto.GetEventStreamResponse{
			WalletEvent: proto.GetEventStreamResponse_WALLET_OPENED,
			WalletUrl:   acct1.URL.String(),
		}

		wantDroppedEvent = &proto.GetEventStreamResponse{
			WalletEvent: proto.GetEventStreamResponse_WALLET_DROPPED,
			WalletUrl:   acct1.URL.String(),
		}
	)

	req := &proto.GetEventStreamRequest{}
	mockStream := mock_proto.NewMockSigner_GetEventStreamServer(ctrl)

	// assert that the events are correctly parsed into protobuf compatible event types
	gomock.InOrder(
		mockStream.
			EXPECT().
			Send(wantArrivedEvent).
			Return(nil),
		mockStream.
			EXPECT().
			Send(wantOpenedEvent).
			Return(nil),
		mockStream.
			EXPECT().
			Send(wantDroppedEvent).
			Return(errors.New("return an error to close the event listening loop")),
	)

	err := s.GetEventStream(req, mockStream)
	require.EqualError(t, err, "return an error to close the event listening loop")
}

func TestSigner_TimedUnlock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	var (
		pwd      = "password"
		duration = time.Second
	)

	mockBackend.
		EXPECT().
		TimedUnlock(acct1, pwd, duration).
		Return(nil)

	req := &proto.TimedUnlockRequest{
		Account:  protoAcct1,
		Password: pwd,
		Duration: duration.Nanoseconds(),
	}
	got, err := s.TimedUnlock(context.Background(), req)
	want := &proto.TimedUnlockResponse{}

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestSigner_Lock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	mockBackend.
		EXPECT().
		Lock(acct1).
		Return(nil)

	req := &proto.LockRequest{
		Account: protoAcct1,
	}
	got, err := s.Lock(context.Background(), req)
	want := &proto.LockResponse{}

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestSigner_NewAccount(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockAccountCreator := mock_hashicorp.NewMockAccountCreator(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	const (
		vaultAddress     = "http://somevault:1"
		authID           = "FOO"
		secretEnginePath = "kv"
		secretPath       = "myacct"
		insecureSkipCas  = true
		casValue         = 1
	)

	newAccountProto := &proto.NewVaultAccount{
		VaultAddress:     vaultAddress,
		AuthID:           authID,
		SecretEnginePath: secretEnginePath,
		SecretPath:       secretPath,
		InsecureSkipCas:  insecureSkipCas,
		CasValue:         casValue,
	}

	mockBackend.
		EXPECT().
		GetAccountCreator(newAccountProto.VaultAddress).
		Return(mockAccountCreator, nil)

	wantConfig := hashicorp.VaultAccountConfig{
		PathParams: hashicorp.PathParams{
			SecretEnginePath: secretEnginePath,
			SecretPath:       secretPath,
		},
		AuthID:          authID,
		InsecureSkipCas: insecureSkipCas,
		CasValue:        casValue,
	}

	mockSecretUri := "some/secret/uri"
	mockAccountCreator.
		EXPECT().
		NewAccount(wantConfig).
		Return(acct1, mockSecretUri, nil)

	req := &proto.NewAccountRequest{
		NewVaultAccount: newAccountProto,
	}
	got, err := s.NewAccount(context.Background(), req)
	want := &proto.NewAccountResponse{
		Account:   protoAcct1,
		SecretUri: mockSecretUri,
	}

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestSigner_ImportRawKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_internal.NewMockWalletFinderLockerBackend(ctrl)
	mockAccountCreator := mock_hashicorp.NewMockAccountCreator(ctrl)

	s := &signer{
		WalletFinderLockerBackend: mockBackend,
	}

	const (
		vaultAddress     = "http://somevault:1"
		authID           = "FOO"
		secretEnginePath = "kv"
		secretPath       = "myacct"
		insecureSkipCas  = true
		casValue         = 1
	)

	newAccountProto := &proto.NewVaultAccount{
		VaultAddress:     vaultAddress,
		AuthID:           authID,
		SecretEnginePath: secretEnginePath,
		SecretPath:       secretPath,
		InsecureSkipCas:  insecureSkipCas,
		CasValue:         casValue,
	}

	mockBackend.
		EXPECT().
		GetAccountCreator(newAccountProto.VaultAddress).
		Return(mockAccountCreator, nil)

	wantConfig := hashicorp.VaultAccountConfig{
		PathParams: hashicorp.PathParams{
			SecretEnginePath: secretEnginePath,
			SecretPath:       secretPath,
		},
		AuthID:          authID,
		InsecureSkipCas: insecureSkipCas,
		CasValue:        casValue,
	}

	mockSecretUri := "some/secret/uri"
	mockAccountCreator.
		EXPECT().
		ImportECDSA(key1, wantConfig).
		Return(acct1, mockSecretUri, nil)

	req := &proto.ImportRawKeyRequest{
		RawKey:          hexkey1,
		NewVaultAccount: newAccountProto,
	}
	got, err := s.ImportRawKey(context.Background(), req)
	want := &proto.ImportRawKeyResponse{
		Account:   protoAcct1,
		SecretUri: mockSecretUri,
	}

	require.NoError(t, err)
	require.Equal(t, want, got)
}
