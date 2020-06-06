package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto_common"
	"github.com/stretchr/testify/require"
)

func setupPluginAndVaultAndFiles(t *testing.T, ctx *ITContext, args ...map[string]string) {
	err := ctx.StartPlugin(t)
	require.NoError(t, err)

	acctConf := `{
	"address": "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
	"vaultAccount": {
		"SecretName": "myAcct",
		"SecretVersion": 2
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
		WithHandler(t, HandlerData{
			SecretEnginePath: "engine",
			SecretPath:       "myAcct",
			SecretVersion:    2,
			AcctAddrResponse: "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
			PrivKeyResponse:  "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28",
		}).
		WithAccountCreationHandler(t, HandlerData{
			SecretEnginePath: "engine",
			SecretPath:       "newAcct",
		}).
		WithCaCert(CA_CERT).
		WithServerCert(SERVER_CERT).
		WithServerKey(SERVER_KEY)
	ctx.StartTLSVaultServer(t, vaultBuilder)

	vaultClientBuilder := &VaultClientBuilder{}
	vaultClientBuilder.
		WithVaultUrl(ctx.Vault.URL).
		WithKVEngineName("engine").
		WithAccountDirectory("file://" + ctx.AccountConfigDirectory).
		WithRoleIdUrl("env://" + MY_ROLE_ID).
		WithSecretIdUrl("env://" + MY_SECRET_ID).
		WithApprolePath("myapprole").
		WithCaCertUrl("file://" + CA_CERT).
		WithClientCertUrl("file://" + CLIENT_CERT).
		WithClientKeyUrl("file://" + CLIENT_KEY)

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
	ctx := new(ITContext)
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
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// status
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)

	require.Equal(t, "0 unlocked account(s)", resp.Status)
}

func TestPlugin_Accounts(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// accounts
	resp, err := ctx.AccountManager.Accounts(context.Background(), &proto.AccountsRequest{})
	require.NoError(t, err)

	want := proto.Account{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Url:     fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2),
	}

	require.Len(t, resp.Accounts, 1)
	require.Equal(t, want, *resp.Accounts[0])
}

func TestPlugin_Contains_IsContained(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// contains
	toFind := common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	resp, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{Address: toFind})
	require.NoError(t, err)
	require.True(t, resp.IsContained)
}

func TestPlugin_Contains_IsNotContained(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// contains
	toFind := common.Hex2Bytes("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")

	resp, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{Address: toFind})
	require.NoError(t, err)
	require.False(t, resp.IsContained)
}

func TestPlugin_Sign(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr := common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  acctAddr,
		Duration: 0,
	})
	require.NoError(t, err)

	toSign := crypto.Keccak256([]byte("to sign"))

	resp, err := ctx.AccountManager.Sign(context.Background(), &proto.SignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	want, _ := crypto.Sign(toSign, prv)

	require.Equal(t, want, resp.Sig)
}

func TestPlugin_Sign_Locked(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr := common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	toSign := crypto.Keccak256([]byte("to sign"))

	_, err := ctx.AccountManager.Sign(context.Background(), &proto.SignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = account locked")
}

func TestPlugin_Sign_UnknownAccount(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr := common.Hex2Bytes("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")

	toSign := crypto.Keccak256([]byte("to sign"))

	_, err := ctx.AccountManager.Sign(context.Background(), &proto.SignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown account")
}

func TestPlugin_UnlockAndSign_Locked(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr := common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", statusResp.Status)

	toSign := crypto.Keccak256([]byte("to sign"))

	resp, err := ctx.AccountManager.UnlockAndSign(context.Background(), &proto.UnlockAndSignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	want, _ := crypto.Sign(toSign, prv)
	require.Equal(t, want, resp.Sig)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", statusResp.Status)
}

func TestPlugin_UnlockAndSign_AlreadyUnlocked(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr := common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  acctAddr,
		Duration: 0,
	})

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", statusResp.Status)

	toSign := crypto.Keccak256([]byte("to sign"))

	resp, err := ctx.AccountManager.UnlockAndSign(context.Background(), &proto.UnlockAndSignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.NoError(t, err)

	prv, _ := crypto.ToECDSA(common.Hex2Bytes("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"))
	want, _ := crypto.Sign(toSign, prv)
	require.Equal(t, want, resp.Sig)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", statusResp.Status)
}

func TestPlugin_UnlockAndSign_UnknownAccount(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr := common.Hex2Bytes("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")

	toSign := crypto.Keccak256([]byte("to sign"))

	_, err := ctx.AccountManager.UnlockAndSign(context.Background(), &proto.UnlockAndSignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown account")
}

func TestPlugin_Unlock(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Duration: 0,
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)
}

func TestPlugin_TimedUnlock(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Duration: (1 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)
}

func TestPlugin_TimedUnlock_Cancel(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Duration: (1 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Duration: 0,
	})
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)
}

func TestPlugin_TimedUnlock_Extend(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Duration: (1 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Duration: (2 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)
}

func TestPlugin_TimedUnlock_Shorten(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// timed unlock
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Duration: (2 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Duration: (1 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)
}

func TestPlugin_UnlockAtStartup(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx, map[string]string{"unlock": "0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526,UnknownAcctShouldNotCauseError"})

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)
}

func TestPlugin_Lock(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// lock
	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Duration: 0,
	})
	require.NoError(t, err)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)

	_, err = ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)
}

func TestPlugin_Lock_MultipleTimes(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// lock
	_, err := ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
	})
	require.NoError(t, err)

	_, err = ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
	})
	require.NoError(t, err)
}

func TestPlugin_Lock_CancelsTimedUnlock(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// lock
	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
		Duration: time.Second.Nanoseconds(),
	})
	require.NoError(t, err)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)

	_, err = ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Address: common.Hex2Bytes("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	// sleep for more than the original timed unlock duration to make sure no unexpected behaviour occurs
	time.Sleep(2 * time.Second)
}

func TestPlugin_Lock_UnknownAccount(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// lock
	_, err := ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Address: common.Hex2Bytes("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"),
	})
	require.NoError(t, err)
}

func TestPlugin_NewAccount(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// new account
	newAcctConfTemplate := `{
	"secretName": "newAcct",
	"overwriteProtection": {
		"currentVersion": %v
	}
}`
	newAcctConf := fmt.Sprintf(newAcctConfTemplate, CAS_VALUE)

	files, _ := ioutil.ReadDir(ctx.AccountConfigDirectory)
	require.Len(t, files, 1)

	resp, err := ctx.AccountManager.NewAccount(context.Background(), &proto.NewAccountRequest{NewAccountConfig: []byte(newAcctConf)})
	require.NoError(t, err)

	wantUrl := fmt.Sprintf(ctx.Vault.URL+"/v1/engine/data/newAcct?version=%v", CAS_VALUE+1)

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
	require.Equal(t, int64(6), gotContents.VaultAccount.SecretVersion)
}

func TestPlugin_NewAccount_IncorrectCASValue(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// new account
	newAcctConfTemplate := `{
	"secretName": "newAcct",
	"overwriteProtection": {
		"currentVersion": %v
	}
}`
	newAcctConf := fmt.Sprintf(newAcctConfTemplate, CAS_VALUE+10)

	_, err := ctx.AccountManager.NewAccount(context.Background(), &proto.NewAccountRequest{NewAccountConfig: []byte(newAcctConf)})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to write secret to Vault")
	require.Contains(t, err.Error(), "invalid CAS value") // response from mock Vault server
}

func TestPlugin_NewAccount_AddedToAvailableAccounts(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// new account
	newAcctConfTemplate := `{
	"secretName": "newAcct",
	"overwriteProtection": {
		"currentVersion": %v
	}
}`
	newAcctConf := fmt.Sprintf(newAcctConfTemplate, CAS_VALUE)

	newAccountResp, err := ctx.AccountManager.NewAccount(context.Background(), &proto.NewAccountRequest{NewAccountConfig: []byte(newAcctConf)})
	require.NoError(t, err)

	require.NotNil(t, newAccountResp)
	require.NotNil(t, newAccountResp.Account)

	// is contained
	containsResp, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{Address: newAccountResp.Account.Address})
	require.NoError(t, err)
	require.True(t, containsResp.IsContained)
}

func TestPlugin_ImportRawKey(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// new account
	newAcctConfTemplate := `{
	"secretName": "newAcct",
	"overwriteProtection": {
		"currentVersion": %v
	}
}`
	newAcctConf := fmt.Sprintf(newAcctConfTemplate, CAS_VALUE)

	files, _ := ioutil.ReadDir(ctx.AccountConfigDirectory)
	require.Len(t, files, 1)

	resp, err := ctx.AccountManager.ImportRawKey(context.Background(),
		&proto.ImportRawKeyRequest{
			RawKey:           "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec",
			NewAccountConfig: []byte(newAcctConf),
		},
	)
	require.NoError(t, err)

	wantUrl := fmt.Sprintf(ctx.Vault.URL+"/v1/engine/data/newAcct?version=%v", CAS_VALUE+1)

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
	require.Equal(t, "newAcct", gotContents.VaultAccount.SecretName)
	require.Equal(t, int64(6), gotContents.VaultAccount.SecretVersion)
}

func TestPlugin_ImportRawKey_IncorrectCASValue(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// new account
	newAcctConfTemplate := `{
	"secretName": "newAcct",
	"overwriteProtection": {
		"currentVersion": %v
	}
}`
	newAcctConf := fmt.Sprintf(newAcctConfTemplate, CAS_VALUE+10)

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

func TestPlugin_ImportRawKey_AddedToAvailableAccounts(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	SetRoleID()
	SetSecretID()
	defer UnsetAll()

	setupPluginAndVaultAndFiles(t, ctx)

	// new account
	newAcctConfTemplate := `{
	"secretName": "newAcct",
	"overwriteProtection": {
		"currentVersion": %v
	}
}`
	newAcctConf := fmt.Sprintf(newAcctConfTemplate, CAS_VALUE)

	importResp, err := ctx.AccountManager.ImportRawKey(context.Background(),
		&proto.ImportRawKeyRequest{
			RawKey:           "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec",
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
