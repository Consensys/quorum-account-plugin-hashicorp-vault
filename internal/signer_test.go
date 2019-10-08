package internal

import (
	"context"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/mock/gomock"
	"github.com/goquorum/quorum-plugin-definitions/signer/go/proto"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/testmocks/mock_accounts"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/testmocks/mock_vault"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/hashicorp"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
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

	mockBackend := mock_vault.NewMockPluginBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinder: mockBackend,
	}

	mockBackend.
		EXPECT().
		FindWalletByUrl(wltUrl.String()).
		Return(mockWallet, nil)

	status := "some status"
	mockWallet.
		EXPECT().
		Status().
		Return(status, nil)

	req := &proto.StatusRequest{WalletUrl: wltUrl.String()}
	got, err := s.Status(context.Background(), req)

	want := &proto.StatusResponse{Status: status}

	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSigner_Open(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_vault.NewMockPluginBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinder: mockBackend,
	}

	mockBackend.
		EXPECT().
		FindWalletByUrl(wltUrl.String()).
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

	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSigner_Close(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_vault.NewMockPluginBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinder: mockBackend,
	}

	mockBackend.
		EXPECT().
		FindWalletByUrl(wltUrl.String()).
		Return(mockWallet, nil)

	mockWallet.
		EXPECT().
		Close().
		Return(nil)

	req := &proto.CloseRequest{WalletUrl: wltUrl.String()}
	got, err := s.Close(context.Background(), req)

	want := &proto.CloseResponse{}

	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSigner_Accounts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_vault.NewMockPluginBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinder: mockBackend,
	}

	mockBackend.
		EXPECT().
		FindWalletByUrl(wltUrl.String()).
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

	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSigner_Contains(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_vault.NewMockPluginBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinder: mockBackend,
	}

	mockBackend.
		EXPECT().
		FindWalletByUrl(wltUrl.String()).
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

	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSigner_SignHash(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_vault.NewMockPluginBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinder: mockBackend,
	}

	mockBackend.
		EXPECT().
		FindWalletByUrl(wltUrl.String()).
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

	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSigner_SignTx(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_vault.NewMockPluginBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinder: mockBackend,
	}

	mockBackend.
		EXPECT().
		FindWalletByUrl(wltUrl.String()).
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
	toSign.SetPrivate()
	toSign.Size() // This field is populated when the signer decodes the transaction so we mimic that here

	rlpToSign, err := rlp.EncodeToBytes(toSign)
	if err != nil {
		t.Fatal(err)
	}

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

	rlpSigned, err := rlp.EncodeToBytes(signed)
	if err != nil {
		t.Fatal(err)
	}
	want := &proto.SignTxResponse{
		RlpTx: rlpSigned,
	}

	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSigner_SignHashWithPassphrase(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_vault.NewMockPluginBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinder: mockBackend,
	}

	mockBackend.
		EXPECT().
		FindWalletByUrl(wltUrl.String()).
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

	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSigner_SignTxWithPassphrase(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBackend := mock_vault.NewMockPluginBackend(ctrl)
	mockWallet := mock_accounts.NewMockWallet(ctrl)

	s := &signer{
		WalletFinder: mockBackend,
	}

	mockBackend.
		EXPECT().
		FindWalletByUrl(wltUrl.String()).
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
	toSign.SetPrivate()
	toSign.Size() // This field is populated when the signer decodes the transaction so we mimic that here

	rlpToSign, err := rlp.EncodeToBytes(toSign)
	if err != nil {
		t.Fatal(err)
	}

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

	rlpSigned, err := rlp.EncodeToBytes(signed)
	if err != nil {
		t.Fatal(err)
	}
	want := &proto.SignTxResponse{
		RlpTx: rlpSigned,
	}

	assert.NoError(t, err)
	assert.Equal(t, want, got)
}
