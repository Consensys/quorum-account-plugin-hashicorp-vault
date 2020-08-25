package test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/testutil"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto_common"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func setupPluginSignerAndVaultAndFiles(t *testing.T, ctx *ITContext) {
	err := ctx.StartPlugin(t)
	require.NoError(t, err)

	acctConf := `{
	"address": "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
	"vaultAccount": {
		"SecretName": "myAcct",
		"SecretVersion": 0
	},
	"id": "afb297d8-1995-4212-974a-e861d7e31e19",
	"version": 1
}`
	ctx.CreateAccountConfigDirectory(t)
	err = ctx.WriteToAccountConfigDirectory(t, []byte(acctConf))
	require.NoError(t, err)

	var vaultBuilder VaultBuilder
	vaultBuilder.
		WithLoginHandler("myapprole").
		WithSignerHandler(t, HandlerData{
			SecretEnginePath: "engine",
			SecretPath:       "myAcct",
			SecretVersion:    0,
			SignResponse:     "f68df2227e39c9ba87baea5966f0c502b038031b10a39e96a721cd270700362d54bae75dcf035a180c17a3a8cf760bfa91a0a41969c0a1630ba6d20e06aa1a8501",
		}).
		WithSignerAccountCreationHandler(t, HandlerData{
			SecretEnginePath: "engine",
			SecretPath:       "newAcct",
		}).
		WithCaCert(CA_CERT).
		WithServerCert(SERVER_CERT).
		WithServerKey(SERVER_KEY)
	ctx.StartTLSVaultServer(t, vaultBuilder)

	wd, err := os.Getwd()
	require.NoError(t, err)
	vaultClientBuilder := &VaultClientBuilder{}
	vaultClientBuilder.
		WithVaultUrl(ctx.Vault.URL).
		WithSignerEngineName("engine").
		WithAccountDirectory(fmt.Sprintf("file://%v/%v", wd, ctx.AccountConfigDirectory)).
		WithRoleIdUrl("env://" + testutil.MY_ROLE_ID).
		WithSecretIdUrl("env://" + testutil.MY_SECRET_ID).
		WithApprolePath("myapprole").
		WithCaCertUrl(fmt.Sprintf("file://%v/%v", wd, CA_CERT)).
		WithClientCertUrl(fmt.Sprintf("file://%v/%v", wd, CLIENT_CERT)).
		WithClientKeyUrl(fmt.Sprintf("file://%v/%v", wd, CLIENT_KEY))

	conf := vaultClientBuilder.Build(t)

	rawConf, err := json.Marshal(&conf)
	require.NoError(t, err)

	_, err = ctx.AccountManager.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: rawConf,
	})
	require.NoError(t, err)
}

func TestPlugin_KV_Status_OK(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// status
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)

	require.Equal(t, "ok", resp.Status)
}
