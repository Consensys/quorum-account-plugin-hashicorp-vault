package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto_common"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/config"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/test/builders"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/test/env"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/test/util"
	"github.com/stretchr/testify/require"
)

func setupPluginAndVaultAndFiles(t *testing.T, ctx *util.ITContext, args ...map[string]string) {
	err := ctx.StartPlugin(t)
	require.NoError(t, err)

	acctConf := `{
	"address": "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
	"vaultAccount": {
		"SecretEnginePath": "engine",
		"SecretPath": "myAcct",
		"SecretVersion": 2
	},
	"id": "afb297d8-1995-4212-974a-e861d7e31e19",
	"version": 1
}`
	ctx.CreateAccountConfigDirectory(t)
	err = ctx.WriteToAccountConfigDirectory(t, []byte(acctConf))
	require.NoError(t, err)

	var vaultBuilder builders.VaultBuilder
	vaultBuilder.
		WithLoginHandler("myapprole").
		WithHandler(t, builders.HandlerData{
			SecretEnginePath: "engine",
			SecretPath:       "myAcct",
			SecretVersion:    2,
			AcctAddrResponse: "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
			PrivKeyResponse:  "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28",
		}).
		WithAccountCreationHandler(t, builders.HandlerData{
			SecretEnginePath: "engine",
			SecretPath:       "newAcct",
		}).
		WithCaCert(builders.CA_CERT).
		WithServerCert(builders.SERVER_CERT).
		WithServerKey(builders.SERVER_KEY)
	ctx.StartTLSVaultServer(t, vaultBuilder)

	vaultClientBuilder := &builders.VaultClientBuilder{}
	vaultClientBuilder.
		WithVaultUrl(ctx.Vault.URL).
		WithAccountDirectory("file://" + ctx.AccountConfigDirectory).
		WithRoleIdUrl("env://" + env.MY_ROLE_ID).
		WithSecretIdUrl("env://" + env.MY_SECRET_ID).
		WithApprolePath("myapprole").
		WithCaCertUrl("file://" + builders.CA_CERT).
		WithClientCertUrl("file://" + builders.CLIENT_CERT).
		WithClientKeyUrl("file://" + builders.CLIENT_KEY)

	if args != nil {
		if unlock, ok := args[0]["unlock"]; ok {
			vaultClientBuilder.WithUnlock(strings.Split(unlock, ","))
		}
	}
	conf := vaultClientBuilder.Build(t)

	rawConf, err := json.Marshal(&conf)
	require.NoError(t, err)

	_, err = ctx.AccountManager.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: rawConf,
	})
	require.NoError(t, err)
}

func TestPlugin_Init_InvalidPluginConfig(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	err := ctx.StartPlugin(t)
	require.NoError(t, err)

	noVaultUrlConf := `{
	"accountDirectory": "/path/to/dir",
	"authentication": {
		"token": "env://TOKEN"
	}
}`

	_, err = ctx.AccountManager.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: []byte(noVaultUrlConf),
	})

	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = vault must be a valid HTTP/HTTPS url")
}

func TestPlugin_Status_AccountLockedByDefault(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// status
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)

	require.Equal(t, "locked", resp.Status)
}

func TestPlugin_Status_UnknownWallet(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// accounts
	wltUrl := ctx.Vault.URL + "/v1/unknown/data/wallet"

	_, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown wallet")
}

func TestPlugin_Accounts(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// accounts
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	resp, err := ctx.AccountManager.Accounts(context.Background(), &proto.AccountsRequest{WalletUrl: wltUrl})
	require.NoError(t, err)

	want := proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	require.Len(t, resp.Accounts, 1)
	require.Equal(t, want, *resp.Accounts[0])
}

func TestPlugin_Accounts_UnknownWallet(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// accounts
	wltUrl := ctx.Vault.URL + "/v1/unknown/data/wallet"

	_, err := ctx.AccountManager.Accounts(context.Background(), &proto.AccountsRequest{WalletUrl: wltUrl})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown wallet")
}

func TestPlugin_Contains_IsContained(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// contains
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	toFind := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	resp, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{WalletUrl: wltUrl, Account: toFind})
	require.NoError(t, err)
	require.True(t, resp.IsContained)

	// contains - url not required
	toFind = &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     "",
	}

	resp, err = ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{WalletUrl: wltUrl, Account: toFind})
	require.NoError(t, err)
	require.True(t, resp.IsContained)
}

func TestPlugin_Contains_IsNotContained(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// contains
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	toFind := &proto.Account{
		Address: common.Hex2Bytes("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"),
		Url:     wltUrl,
	}

	resp, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{WalletUrl: wltUrl, Account: toFind})
	require.NoError(t, err)
	require.False(t, resp.IsContained)
}

func TestPlugin_Contains_Errors(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// contains - wallet not found
	wltUrl := "http://nottherighturl/doesnt/exist"

	toFind := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	_, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{WalletUrl: wltUrl, Account: toFind})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown wallet")

	// contains - diff acct and wallet url
	toFind = &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     "http://different/to/the/wallet/url",
	}

	_, err = ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{WalletUrl: wltUrl, Account: toFind})
	require.EqualError(t, err, "rpc error: code = Internal desc = wallet http://nottherighturl/doesnt/exist cannot contain account with URL http://different/to/the/wallet/url")
}

func TestPlugin_SignHash(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  acct,
		Duration: 0,
	})
	require.NoError(t, err)

	toSign := crypto.Keccak256([]byte("to sign"))

	resp, err := ctx.AccountManager.SignHash(context.Background(), &proto.SignHashRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		Hash:      toSign,
	})
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	want, _ := crypto.Sign(toSign, prv)

	require.Equal(t, want, resp.Result)
}

func TestPlugin_SignHash_Locked(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	toSign := crypto.Keccak256([]byte("to sign"))

	_, err := ctx.AccountManager.SignHash(context.Background(), &proto.SignHashRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		Hash:      toSign,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = account locked")
}

func TestPlugin_SignHash_UnknownAccount(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "unknownAccount", 1)

	acct := &proto.Account{
		Address: common.Hex2Bytes("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"),
		Url:     wltUrl,
	}

	toSign := crypto.Keccak256([]byte("to sign"))

	_, err := ctx.AccountManager.SignHash(context.Background(), &proto.SignHashRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		Hash:      toSign,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown wallet")
}

func TestPlugin_SignHashWithPassphrase_Locked(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", statusResp.Status)

	toSign := crypto.Keccak256([]byte("to sign"))

	resp, err := ctx.AccountManager.SignHashWithPassphrase(context.Background(), &proto.SignHashWithPassphraseRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		Hash:      toSign,
	})
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	want, _ := crypto.Sign(toSign, prv)
	require.Equal(t, want, resp.Result)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", statusResp.Status)
}

func TestPlugin_SignHashWithPassphrase_AlreadyUnlocked(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  acct,
		Duration: 0,
	})

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", statusResp.Status)

	toSign := crypto.Keccak256([]byte("to sign"))

	resp, err := ctx.AccountManager.SignHashWithPassphrase(context.Background(), &proto.SignHashWithPassphraseRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		Hash:      toSign,
	})
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	want, _ := crypto.Sign(toSign, prv)
	require.Equal(t, want, resp.Result)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", statusResp.Status)
}

func TestPlugin_SignHashWithPassphrase_UnknownAccount(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "unknownAccount", 1)

	acct := &proto.Account{
		Address: common.Hex2Bytes("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"),
		Url:     wltUrl,
	}

	toSign := crypto.Keccak256([]byte("to sign"))

	_, err := ctx.AccountManager.SignHashWithPassphrase(context.Background(), &proto.SignHashWithPassphraseRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		Hash:      toSign,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown wallet")
}

func TestPlugin_SignTx_Private(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  acct,
		Duration: 0,
	})
	require.NoError(t, err)

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	toSign.SetPrivate()
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	resp, err := ctx.AccountManager.SignTx(context.Background(), &proto.SignTxRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   big.NewInt(42).Bytes(),
	})
	require.NoError(t, err)

	got := new(types.Transaction)
	err = rlp.DecodeBytes(resp.RlpTx, got)
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	signer := types.QuorumPrivateTxSigner{}
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], prv)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.
	// When the caller decodes it back to a tx, the size field of the tx is populated (see
	// types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that
	// we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	require.Equal(t, want, got)
}

func TestPlugin_SignTx_Homestead(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  acct,
		Duration: 0,
	})
	require.NoError(t, err)

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	resp, err := ctx.AccountManager.SignTx(context.Background(), &proto.SignTxRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   nil,
	})
	require.NoError(t, err)

	got := new(types.Transaction)
	err = rlp.DecodeBytes(resp.RlpTx, got)
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	signer := types.HomesteadSigner{}
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], prv)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.
	// When the caller decodes it back to a tx, the size field of the tx is populated (see
	// types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that
	// we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	require.Equal(t, want, got)
}

func TestPlugin_SignTx_EIP155(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  acct,
		Duration: 0,
	})
	require.NoError(t, err)

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	resp, err := ctx.AccountManager.SignTx(context.Background(), &proto.SignTxRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   big.NewInt(42).Bytes(),
	})
	require.NoError(t, err)

	got := new(types.Transaction)
	err = rlp.DecodeBytes(resp.RlpTx, got)
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	signer := types.NewEIP155Signer(big.NewInt(42))
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], prv)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.
	// When the caller decodes it back to a tx, the size field of the tx is populated (see
	// types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that
	// we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	require.Equal(t, want, got)
}

func TestPlugin_SignTx_Locked(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	_, err = ctx.AccountManager.SignTx(context.Background(), &proto.SignTxRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   big.NewInt(42).Bytes(),
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = account locked")
}

func TestPlugin_SignTx_UnknownAccount(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "unknownAccount", 1)

	acct := &proto.Account{
		Address: common.Hex2Bytes("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"),
		Url:     wltUrl,
	}

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	_, err = ctx.AccountManager.SignTx(context.Background(), &proto.SignTxRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   big.NewInt(42).Bytes(),
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown wallet")
}

func TestPlugin_SignTxWithPassphrase_Private_Locked(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", statusResp.Status)

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	toSign.SetPrivate()
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	resp, err := ctx.AccountManager.SignTxWithPassphrase(context.Background(), &proto.SignTxWithPassphraseRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   big.NewInt(42).Bytes(),
	})
	require.NoError(t, err)

	got := new(types.Transaction)
	err = rlp.DecodeBytes(resp.RlpTx, got)
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	signer := types.QuorumPrivateTxSigner{}
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], prv)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.
	// When the caller decodes it back to a tx, the size field of the tx is populated (see
	// types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that
	// we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	require.Equal(t, want, got)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", statusResp.Status)
}

func TestPlugin_SignTxWithPassphrase_Private_AlreadyUnlocked(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  acct,
		Duration: 0,
	})

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", statusResp.Status)

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	toSign.SetPrivate()
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	resp, err := ctx.AccountManager.SignTxWithPassphrase(context.Background(), &proto.SignTxWithPassphraseRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   big.NewInt(42).Bytes(),
	})
	require.NoError(t, err)

	got := new(types.Transaction)
	err = rlp.DecodeBytes(resp.RlpTx, got)
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	signer := types.QuorumPrivateTxSigner{}
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], prv)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.
	// When the caller decodes it back to a tx, the size field of the tx is populated (see
	// types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that
	// we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	require.Equal(t, want, got)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", statusResp.Status)
}

func TestPlugin_SignTxWithPassphrase_Homestead_Locked(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", statusResp.Status)

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	resp, err := ctx.AccountManager.SignTxWithPassphrase(context.Background(), &proto.SignTxWithPassphraseRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   nil,
	})
	require.NoError(t, err)

	got := new(types.Transaction)
	err = rlp.DecodeBytes(resp.RlpTx, got)
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	signer := types.HomesteadSigner{}
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], prv)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.
	// When the caller decodes it back to a tx, the size field of the tx is populated (see
	// types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that
	// we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	require.Equal(t, want, got)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", statusResp.Status)
}

func TestPlugin_SignTxWithPassphrase_Homestead_AlreadyUnlocked(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  acct,
		Duration: 0,
	})

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", statusResp.Status)

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	resp, err := ctx.AccountManager.SignTxWithPassphrase(context.Background(), &proto.SignTxWithPassphraseRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   nil,
	})
	require.NoError(t, err)

	got := new(types.Transaction)
	err = rlp.DecodeBytes(resp.RlpTx, got)
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	signer := types.HomesteadSigner{}
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], prv)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.
	// When the caller decodes it back to a tx, the size field of the tx is populated (see
	// types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that
	// we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	require.Equal(t, want, got)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", statusResp.Status)
}

func TestPlugin_SignTxWithPassphrase_EIP155_Locked(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", statusResp.Status)

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	resp, err := ctx.AccountManager.SignTxWithPassphrase(context.Background(), &proto.SignTxWithPassphraseRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   big.NewInt(42).Bytes(),
	})
	require.NoError(t, err)

	got := new(types.Transaction)
	err = rlp.DecodeBytes(resp.RlpTx, got)
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	signer := types.NewEIP155Signer(big.NewInt(42))
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], prv)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.
	// When the caller decodes it back to a tx, the size field of the tx is populated (see
	// types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that
	// we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	require.Equal(t, want, got)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", statusResp.Status)
}

func TestPlugin_SignTxWithPassphrase_EIP155_AlreadyUnlocked(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	acct := &proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  acct,
		Duration: 0,
	})

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", statusResp.Status)

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	resp, err := ctx.AccountManager.SignTxWithPassphrase(context.Background(), &proto.SignTxWithPassphraseRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   big.NewInt(42).Bytes(),
	})
	require.NoError(t, err)

	got := new(types.Transaction)
	err = rlp.DecodeBytes(resp.RlpTx, got)
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	signer := types.NewEIP155Signer(big.NewInt(42))
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], prv)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.
	// When the caller decodes it back to a tx, the size field of the tx is populated (see
	// types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that
	// we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	require.Equal(t, want, got)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", statusResp.Status)
}

func TestPlugin_SignTxWithPassphrase_UnknownAccount(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "unknownAccount", 1)

	acct := &proto.Account{
		Address: common.Hex2Bytes("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"),
		Url:     wltUrl,
	}

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})
	rlpToSign, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	_, err = ctx.AccountManager.SignTxWithPassphrase(context.Background(), &proto.SignTxWithPassphraseRequest{
		WalletUrl: wltUrl,
		Account:   acct,
		RlpTx:     rlpToSign,
		ChainID:   big.NewInt(42).Bytes(),
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown wallet")
}

func TestPlugin_Unlock(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
		Duration: 0,
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", resp.Status)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", resp.Status)
}

func TestPlugin_Unlock_OptionalWalletUrlInRequest(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"), Url: wltUrl},
		Duration: 0,
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", resp.Status)
}

func TestPlugin_Unlock_InvalidOptionalWalletUrlInRequest(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"), Url: "http://this/is/the/wrong/url/for/this/address"},
		Duration: 0,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown wallet")
}

func TestPlugin_Unlock_InconsistentAddressAndWalletUrl(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// the account config directory contains a file that resolves to this wlturl.  The address contained in that file is dc99ddec13457de6c0f6bb8e6cf3955c86f55526.  If we provide this url but a different address we should expect the request to fail.
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"), Url: wltUrl},
		Duration: 0,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "rpc error: code = Internal desc = inconsistent account data provided")
}

func TestPlugin_TimedUnlock(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
		Duration: (1 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", resp.Status)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", resp.Status)
}

func TestPlugin_TimedUnlock_Cancel(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
		Duration: (1 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
		Duration: 0,
	})
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", resp.Status)
}

func TestPlugin_TimedUnlock_Extend(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
		Duration: (1 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
		Duration: (2 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", resp.Status)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", resp.Status)
}

func TestPlugin_TimedUnlock_Shorten(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
		Duration: (2 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
		Duration: (1 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", resp.Status)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", resp.Status)
}

func TestPlugin_UnlockAtStartup(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx, map[string]string{"unlock": "0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526,UnknownAcctShouldNotCauseError"})

	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", resp.Status)
}

func TestPlugin_Lock(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// lock
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
		Duration: 0,
	})
	require.NoError(t, err)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", resp.Status)

	_, err = ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Account: &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", resp.Status)
}

func TestPlugin_Lock_MultipleTimes(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// lock
	_, err := ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Account: &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
	})
	require.NoError(t, err)

	_, err = ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Account: &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
	})
	require.NoError(t, err)
}

func TestPlugin_Lock_CancelsTimedUnlock(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// lock
	wltUrl := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account:  &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
		Duration: time.Second.Nanoseconds(),
	})
	require.NoError(t, err)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "unlocked", resp.Status)

	_, err = ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Account: &proto.Account{Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")},
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)
	require.Equal(t, "locked", resp.Status)

	// sleep for more than the original timed unlock duration to make sure no unexpected behaviour occurs
	time.Sleep(2 * time.Second)
}

func TestPlugin_Lock_UnknownAccount(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// lock
	_, err := ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Account: &proto.Account{Address: common.Hex2Bytes("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")},
	})
	require.NoError(t, err)
}

func TestPlugin_NewAccount(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// new account
	newAcctConfTemplate := `{
	"vault": "%v",
	"secretEnginePath": "engine",
	"secretPath": "newAcct",
	"casValue": %v
}`
	newAcctConf := fmt.Sprintf(newAcctConfTemplate, ctx.Vault.URL, builders.CAS_VALUE)

	files, _ := ioutil.ReadDir(ctx.AccountConfigDirectory)
	require.Len(t, files, 1)

	resp, err := ctx.AccountManager.NewAccount(context.Background(), &proto.NewAccountRequest{NewAccountConfig: []byte(newAcctConf)})
	require.NoError(t, err)

	wantUrl := fmt.Sprintf(ctx.Vault.URL+"/v1/engine/data/newAcct?version=%v", builders.CAS_VALUE+1)

	require.NotNil(t, resp)
	require.Equal(t, wantUrl, resp.Account.Url)
	require.Len(t, resp.Account.Address, 20)

	files, _ = ioutil.ReadDir(ctx.AccountConfigDirectory)
	require.Len(t, files, 2)

	var newFile os.FileInfo

	for _, f := range files {
		if strings.Contains(f.Name(), "UTC") { // this is the new account
			newFile = f
		}
	}

	// check file has been renamed from tmp and contents is correct
	require.False(t, strings.HasPrefix(newFile.Name(), "."))
	require.False(t, strings.HasSuffix(newFile.Name(), ".tmp"))

	raw, err := ioutil.ReadFile(ctx.AccountConfigDirectory + "/" + newFile.Name())
	require.NoError(t, err)
	gotContents := new(config.AccountFileJSON)
	require.NoError(t, json.Unmarshal(raw, gotContents))

	require.NotEmpty(t, gotContents.Address)
	require.Equal(t, "engine", gotContents.VaultAccount.SecretEnginePath)
	require.Equal(t, "newAcct", gotContents.VaultAccount.SecretPath)
	require.Equal(t, int64(6), gotContents.VaultAccount.SecretVersion)
}

func TestPlugin_NewAccount_IncorrectCASValue(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// new account
	newAcctConfTemplate := `{
	"vault": "%v",
	"secretEnginePath": "engine",
	"secretPath": "newAcct",
	"casValue": %v
}`
	newAcctConf := fmt.Sprintf(newAcctConfTemplate, ctx.Vault.URL, builders.CAS_VALUE+10)

	_, err := ctx.AccountManager.NewAccount(context.Background(), &proto.NewAccountRequest{NewAccountConfig: []byte(newAcctConf)})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to write secret to Vault")
	require.Contains(t, err.Error(), "invalid CAS value") // response from mock Vault server
}

func TestPlugin_ImportRawKey(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// new account
	newAcctConfTemplate := `{
	"vault": "%v",
	"secretEnginePath": "engine",
	"secretPath": "newAcct",
	"casValue": %v
}`
	newAcctConf := fmt.Sprintf(newAcctConfTemplate, ctx.Vault.URL, builders.CAS_VALUE)

	files, _ := ioutil.ReadDir(ctx.AccountConfigDirectory)
	require.Len(t, files, 1)

	resp, err := ctx.AccountManager.ImportRawKey(context.Background(),
		&proto.ImportRawKeyRequest{
			RawKey:           "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec",
			NewAccountConfig: []byte(newAcctConf),
		},
	)
	require.NoError(t, err)

	wantUrl := fmt.Sprintf(ctx.Vault.URL+"/v1/engine/data/newAcct?version=%v", builders.CAS_VALUE+1)

	require.NotNil(t, resp)
	require.Equal(t, wantUrl, resp.Account.Url)
	require.Len(t, resp.Account.Address, 20)

	files, _ = ioutil.ReadDir(ctx.AccountConfigDirectory)
	require.Len(t, files, 2)

	var newFile os.FileInfo

	for _, f := range files {
		if strings.Contains(f.Name(), "UTC") { // this is the new account
			newFile = f
		}
	}

	// check file has been renamed from tmp and contents is correct
	require.False(t, strings.HasPrefix(newFile.Name(), "."))
	require.False(t, strings.HasSuffix(newFile.Name(), ".tmp"))

	raw, err := ioutil.ReadFile(ctx.AccountConfigDirectory + "/" + newFile.Name())
	require.NoError(t, err)
	gotContents := new(config.AccountFileJSON)
	require.NoError(t, json.Unmarshal(raw, gotContents))

	require.Equal(t, "4d6d744b6da435b5bbdde2526dc20e9a41cb72e5", gotContents.Address)
	require.Equal(t, "engine", gotContents.VaultAccount.SecretEnginePath)
	require.Equal(t, "newAcct", gotContents.VaultAccount.SecretPath)
	require.Equal(t, int64(6), gotContents.VaultAccount.SecretVersion)
}

func TestPlugin_ImportRawKey_IncorrectCASValue(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// new account
	newAcctConfTemplate := `{
	"vault": "%v",
	"secretEnginePath": "engine",
	"secretPath": "newAcct",
	"casValue": %v
}`
	newAcctConf := fmt.Sprintf(newAcctConfTemplate, ctx.Vault.URL, builders.CAS_VALUE+10)

	_, err := ctx.AccountManager.ImportRawKey(context.Background(),
		&proto.ImportRawKeyRequest{
			RawKey:           "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec",
			NewAccountConfig: []byte(newAcctConf),
		},
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to write secret to Vault")
	require.Contains(t, err.Error(), "invalid CAS value") // response from mock Vault server
}

func TestPlugin_GetEventStream_SendsWalletDetails(t *testing.T) {
	ctx := new(util.ITContext)
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	stream, err := ctx.AccountManager.GetEventStream(context.Background(), &proto.GetEventStreamRequest{})
	require.NoError(t, err)

	respChan := make(chan *proto.GetEventStreamResponse)
	errChan := make(chan error)

	// we start a separate goroutine to receive events from the stream.  stream.Recv() blocks until there are msgs to retrieve.
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				errChan <- err
			} else {
				respChan <- resp
			}
		}
	}()

	// one config file should have been added to the account config directory as part of the test setup
	select {
	case resp := <-respChan:
		wantUrl := fmt.Sprintf("%v/v1/engine/data/myAcct?version=2", ctx.Vault.URL)
		require.Equal(t, wantUrl, resp.WalletUrl)
		require.Equal(t, proto.GetEventStreamResponse_WALLET_ARRIVED, resp.WalletEvent)
	case err := <-errChan:
		require.NoError(t, err)
	}
}
