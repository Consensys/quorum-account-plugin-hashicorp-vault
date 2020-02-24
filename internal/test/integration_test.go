package test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto_common"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/test/builders"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/test/env"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/test/util"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlugin_Init_InvalidPluginConfig(t *testing.T) {
	ctx := util.ITContext{}
	defer ctx.Cleanup()

	acctman, err := ctx.StartPlugin(t)
	require.NoError(t, err)

	noVaultUrlConf := `[
		{
			"accountDirectory": "/path/to/dir",
			"authentication": {
				"token": "env://TOKEN"
			}
		}
	]`

	_, err = acctman.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: []byte(noVaultUrlConf),
	})

	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = invalid config: array index 0: vault must be a valid HTTP/HTTPS url")
}

func TestPlugin_Status_AccountLockedByDefault(t *testing.T) {
	ctx := util.ITContext{}
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	acctman, err := ctx.StartPlugin(t)
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
			PubKeyResponse:   "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
			PrivKeyResponse:  "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28",
		}).
		WithCaCert(builders.CA_CERT).
		WithServerCert(builders.SERVER_CERT).
		WithServerKey(builders.SERVER_KEY)
	ctx.StartTLSVaultServer(t, vaultBuilder)

	var vaultClientsBuilder builders.VaultClientsBuilder
	var vaultClientBuilder builders.VaultClientBuilder

	conf := vaultClientsBuilder.
		WithVaultClient(
			vaultClientBuilder.
				WithVaultUrl(ctx.Vault.URL).
				WithAccountDirectory("file://" + ctx.AccountConfigDirectory).
				WithRoleIdUrl("env://" + env.MY_ROLE_ID).
				WithSecretIdUrl("env://" + env.MY_SECRET_ID).
				WithApprolePath("myapprole").
				WithCaCertUrl("file://" + builders.CA_CERT).
				WithClientCertUrl("file://" + builders.CLIENT_CERT).
				WithClientKeyUrl("file://" + builders.CLIENT_KEY).
				Build(t)).
		Build()

	rawConf, err := json.Marshal(conf)
	require.NoError(t, err)

	_, err = acctman.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: rawConf,
	})
	require.NoError(t, err)

	// status
	wltUrl := fmt.Sprintf("%v/v1/%v/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	resp, err := acctman.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.NoError(t, err)

	require.Equal(t, "locked", resp.Status)
}

func TestPlugin_Status_UnknownWallet(t *testing.T) {
	ctx := util.ITContext{}
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	acctman, err := ctx.StartPlugin(t)
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
			PubKeyResponse:   "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
			PrivKeyResponse:  "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28",
		}).
		WithCaCert(builders.CA_CERT).
		WithServerCert(builders.SERVER_CERT).
		WithServerKey(builders.SERVER_KEY)
	ctx.StartTLSVaultServer(t, vaultBuilder)

	var vaultClientsBuilder builders.VaultClientsBuilder
	var vaultClientBuilder builders.VaultClientBuilder

	conf := vaultClientsBuilder.
		WithVaultClient(
			vaultClientBuilder.
				WithVaultUrl(ctx.Vault.URL).
				WithAccountDirectory("file://" + ctx.AccountConfigDirectory).
				WithRoleIdUrl("env://" + env.MY_ROLE_ID).
				WithSecretIdUrl("env://" + env.MY_SECRET_ID).
				WithApprolePath("myapprole").
				WithCaCertUrl("file://" + builders.CA_CERT).
				WithClientCertUrl("file://" + builders.CLIENT_CERT).
				WithClientKeyUrl("file://" + builders.CLIENT_KEY).
				Build(t)).
		Build()

	rawConf, err := json.Marshal(conf)
	require.NoError(t, err)

	_, err = acctman.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: rawConf,
	})
	require.NoError(t, err)

	// accounts
	wltUrl := ctx.Vault.URL + "/v1/unknown/wallet"

	_, err = acctman.Status(context.Background(), &proto.StatusRequest{WalletUrl: wltUrl})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown wallet")
}

func TestPlugin_Accounts(t *testing.T) {
	ctx := util.ITContext{}
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	acctman, err := ctx.StartPlugin(t)
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
			PubKeyResponse:   "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
			PrivKeyResponse:  "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28",
		}).
		WithCaCert(builders.CA_CERT).
		WithServerCert(builders.SERVER_CERT).
		WithServerKey(builders.SERVER_KEY)
	ctx.StartTLSVaultServer(t, vaultBuilder)

	var vaultClientsBuilder builders.VaultClientsBuilder
	var vaultClientBuilder builders.VaultClientBuilder

	conf := vaultClientsBuilder.
		WithVaultClient(
			vaultClientBuilder.
				WithVaultUrl(ctx.Vault.URL).
				WithAccountDirectory("file://" + ctx.AccountConfigDirectory).
				WithRoleIdUrl("env://" + env.MY_ROLE_ID).
				WithSecretIdUrl("env://" + env.MY_SECRET_ID).
				WithApprolePath("myapprole").
				WithCaCertUrl("file://" + builders.CA_CERT).
				WithClientCertUrl("file://" + builders.CLIENT_CERT).
				WithClientKeyUrl("file://" + builders.CLIENT_KEY).
				Build(t)).
		Build()

	rawConf, err := json.Marshal(conf)
	require.NoError(t, err)

	_, err = acctman.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: rawConf,
	})
	require.NoError(t, err)

	// accounts
	wltUrl := fmt.Sprintf("%v/v1/%v/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2)

	resp, err := acctman.Accounts(context.Background(), &proto.AccountsRequest{WalletUrl: wltUrl})
	require.NoError(t, err)

	want := proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     wltUrl,
	}

	require.Len(t, resp.Accounts, 1)
	require.Equal(t, want, *resp.Accounts[0])
}

func TestPlugin_Accounts_UnknownWallet(t *testing.T) {
	ctx := util.ITContext{}
	defer ctx.Cleanup()

	env.SetRoleID()
	env.SetSecretID()
	defer env.UnsetAll()

	acctman, err := ctx.StartPlugin(t)
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
			PubKeyResponse:   "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
			PrivKeyResponse:  "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28",
		}).
		WithCaCert(builders.CA_CERT).
		WithServerCert(builders.SERVER_CERT).
		WithServerKey(builders.SERVER_KEY)
	ctx.StartTLSVaultServer(t, vaultBuilder)

	var vaultClientsBuilder builders.VaultClientsBuilder
	var vaultClientBuilder builders.VaultClientBuilder

	conf := vaultClientsBuilder.
		WithVaultClient(
			vaultClientBuilder.
				WithVaultUrl(ctx.Vault.URL).
				WithAccountDirectory("file://" + ctx.AccountConfigDirectory).
				WithRoleIdUrl("env://" + env.MY_ROLE_ID).
				WithSecretIdUrl("env://" + env.MY_SECRET_ID).
				WithApprolePath("myapprole").
				WithCaCertUrl("file://" + builders.CA_CERT).
				WithClientCertUrl("file://" + builders.CLIENT_CERT).
				WithClientKeyUrl("file://" + builders.CLIENT_KEY).
				Build(t)).
		Build()

	rawConf, err := json.Marshal(conf)
	require.NoError(t, err)

	_, err = acctman.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: rawConf,
	})
	require.NoError(t, err)

	// accounts
	wltUrl := ctx.Vault.URL + "/v1/unknown/wallet"

	_, err = acctman.Accounts(context.Background(), &proto.AccountsRequest{WalletUrl: wltUrl})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown wallet")
}
