package test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/testutil"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto_common"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

const mockedSig = "f68df2227e39c9ba87baea5966f0c502b038031b10a39e96a721cd270700362d54bae75dcf035a180c17a3a8cf760bfa91a0a41969c0a1630ba6d20e06aa1a8501"
const mockedSignerNewAccount = "1a282a0450374bc5c5402630a8082f13999ff67b"
const mockedSignerKeyToImport = "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"

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
			SignerResponse:   mockedSig,
		}).
		WithSignerAccountCreationHandler(t, HandlerData{
			SecretEnginePath:     "engine",
			SecretPath:           "newAcct",
			SignerCreatedAccount: mockedSignerNewAccount,
		}).
		WithSignerAccountImportHandler(t, HandlerData{
			SecretEnginePath:     "engine",
			SecretPath:           "importedAcct",
			SignerKeyToImport:    mockedSignerKeyToImport,
			SignerCreatedAccount: mockedSignerNewAccount,
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

func TestPlugin_Signer_Status_OK(t *testing.T) {
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

func TestPlugin_Signer_Accounts(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// accounts
	resp, err := ctx.AccountManager.Accounts(context.Background(), &proto.AccountsRequest{})
	require.NoError(t, err)

	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
	want := proto.Account{
		Address: addr,
		Url:     fmt.Sprintf("%v/v1/%v/accounts/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 0),
	}

	require.Len(t, resp.Accounts, 1)
	require.Equal(t, want, *resp.Accounts[0])
}

func TestPlugin_Signer_Contains_IsContained(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// contains
	toFind, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	resp, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{Address: toFind})
	require.NoError(t, err)
	require.True(t, resp.IsContained)
}

func TestPlugin_Signer_Contains_IsNotContained(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// contains
	toFind, _ := hex.DecodeString("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")

	resp, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{Address: toFind})
	require.NoError(t, err)
	require.False(t, resp.IsContained)
}

func TestPlugin_Signer_Sign(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	toSign := []byte{188, 76, 145, 93, 105, 137, 107, 25, 143, 2, 146, 167, 35, 115, 162, 189, 205, 13, 82, 188, 203, 252, 236, 17, 217, 200, 76, 15, 255, 113, 176, 188}
	wantSig, err := hex.DecodeString(mockedSig)
	require.NoError(t, err)

	resp, err := ctx.AccountManager.Sign(context.Background(), &proto.SignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.NoError(t, err)
	require.Equal(t, wantSig, resp.Sig)
}

func TestPlugin_Signer_Sign_UnknownAccount(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr, _ := hex.DecodeString("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")

	toSign := []byte{188, 76, 145, 93, 105, 137, 107, 25, 143, 2, 146, 167, 35, 115, 162, 189, 205, 13, 82, 188, 203, 252, 236, 17, 217, 200, 76, 15, 255, 113, 176, 188}

	_, err := ctx.AccountManager.Sign(context.Background(), &proto.SignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown account")
}

func TestPlugin_Signer_UnlockAndSign_NotSupported(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
	toSign := []byte{188, 76, 145, 93, 105, 137, 107, 25, 143, 2, 146, 167, 35, 115, 162, 189, 205, 13, 82, 188, 203, 252, 236, 17, 217, 200, 76, 15, 255, 113, 176, 188}

	_, err := ctx.AccountManager.UnlockAndSign(context.Background(), &proto.UnlockAndSignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = not supported when using quorum-signer secret engine")
}

func TestPlugin_Signer_Unlock_NotSupported(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  addr,
		Duration: 0,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = not supported when using quorum-signer secret engine")
}

func TestPlugin_Signer_Lock_NotSupported_NoOp(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// lock
	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	_, err := ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Address: addr,
	})
	require.NoError(t, err)
}

func TestPlugin_Signer_NewAccount(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// new account
	newAcctConf := `{
	"secretName": "newAcct",
	"overwriteProtection": {
		"currentVersion": 0
	}
}`

	files, _ := ioutil.ReadDir(ctx.AccountConfigDirectory)
	require.Len(t, files, 1)

	resp, err := ctx.AccountManager.NewAccount(context.Background(), &proto.NewAccountRequest{NewAccountConfig: []byte(newAcctConf)})
	require.NoError(t, err)

	wantUrl := fmt.Sprintf(ctx.Vault.URL + "/v1/engine/accounts/newAcct?version=0")

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
	require.Equal(t, "newAcct", gotContents.VaultAccount.SecretName)
	require.Equal(t, int64(0), gotContents.VaultAccount.SecretVersion)
}

func TestPlugin_Signer_NewAccount_AddedToAvailableAccounts(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// new account
	newAcctConf := `{
	"secretName": "newAcct",
	"overwriteProtection": {
		"currentVersion": 0
	}
}`

	newAccountResp, err := ctx.AccountManager.NewAccount(context.Background(), &proto.NewAccountRequest{NewAccountConfig: []byte(newAcctConf)})
	require.NoError(t, err)

	require.NotNil(t, newAccountResp)
	require.NotNil(t, newAccountResp.Account)

	// is contained
	containsResp, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{Address: newAccountResp.Account.Address})
	require.NoError(t, err)
	require.True(t, containsResp.IsContained)
}

func TestPlugin_Signer_ImportRawKey(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// new account
	newAcctConf := `{
	"secretName": "importedAcct",
	"overwriteProtection": {
		"currentVersion": 0
	}
}`

	files, _ := ioutil.ReadDir(ctx.AccountConfigDirectory)
	require.Len(t, files, 1)

	resp, err := ctx.AccountManager.ImportRawKey(context.Background(),
		&proto.ImportRawKeyRequest{
			RawKey:           mockedSignerKeyToImport,
			NewAccountConfig: []byte(newAcctConf),
		},
	)
	require.NoError(t, err)

	wantUrl := fmt.Sprintf(ctx.Vault.URL+"/v1/engine/accounts/importedAcct?version=%v", 0)

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

	require.Equal(t, mockedSignerNewAccount, gotContents.Address)
	require.Equal(t, "importedAcct", gotContents.VaultAccount.SecretName)
	require.Equal(t, int64(0), gotContents.VaultAccount.SecretVersion)
}

func TestPlugin_Signer_ImportRawKey_AddedToAvailableAccounts(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// new account
	newAcctConf := `{
	"secretName": "importedAcct",
	"overwriteProtection": {
		"currentVersion": 0
	}
}`

	importResp, err := ctx.AccountManager.ImportRawKey(context.Background(),
		&proto.ImportRawKeyRequest{
			RawKey:           mockedSignerKeyToImport,
			NewAccountConfig: []byte(newAcctConf),
		},
	)
	require.NoError(t, err)
	require.NotNil(t, importResp)

	require.NotNil(t, importResp)
	require.NotNil(t, importResp.Account)

	// is contained
	containsResp, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{Address: importResp.Account.Address})
	require.NoError(t, err)
	require.True(t, containsResp.IsContained)
}

func TestPlugin_Signer_ImportRawKey_ErrorIfAccountExists(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginSignerAndVaultAndFiles(t, ctx)

	// new account
	newAcctConf := `{
	"secretName": "importAcct",
	"overwriteProtection": {
		"currentVersion": 0
	}
}`

	files, _ := ioutil.ReadDir(ctx.AccountConfigDirectory)
	require.Len(t, files, 1)

	_, err := ctx.AccountManager.ImportRawKey(context.Background(),
		&proto.ImportRawKeyRequest{
			RawKey:           "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28",
			NewAccountConfig: []byte(newAcctConf),
		},
	)
	require.EqualError(t, err, "rpc error: code = Internal desc = account already exists")

	// ensure no new files were created
	files, _ = ioutil.ReadDir(ctx.AccountConfigDirectory)
	require.Len(t, files, 1)
}
