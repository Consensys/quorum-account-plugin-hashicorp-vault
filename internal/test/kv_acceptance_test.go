package test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/testutil"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto_common"
	"github.com/stretchr/testify/require"
)

func setupPluginKVAndVaultAndFiles(t *testing.T, ctx *ITContext, args ...map[string]string) {
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
		WithKVHandler(t, HandlerData{
			SecretEnginePath: "engine",
			SecretPath:       "myAcct",
			SecretVersion:    2,
			AcctAddrResponse: "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
			PrivKeyResponse:  "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28",
		}).
		WithKVAccountCreationHandler(t, HandlerData{
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
		WithKVEngineName("engine").
		WithAccountDirectory(fmt.Sprintf("file://%v/%v", wd, ctx.AccountConfigDirectory)).
		WithRoleIdUrl("env://" + testutil.MY_ROLE_ID).
		WithSecretIdUrl("env://" + testutil.MY_SECRET_ID).
		WithApprolePath("myapprole").
		WithCaCertUrl(fmt.Sprintf("file://%v/%v", wd, CA_CERT)).
		WithClientCertUrl(fmt.Sprintf("file://%v/%v", wd, CLIENT_CERT)).
		WithClientKeyUrl(fmt.Sprintf("file://%v/%v", wd, CLIENT_KEY))

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

func TestPlugin_KV_Status_AccountLockedByDefault(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// status
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)

	require.Equal(t, "0 unlocked account(s)", resp.Status)
}

func TestPlugin_KV_Accounts(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// accounts
	resp, err := ctx.AccountManager.Accounts(context.Background(), &proto.AccountsRequest{})
	require.NoError(t, err)

	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
	want := proto.Account{
		Address: addr,
		Url:     fmt.Sprintf("%v/v1/%v/data/%v?version=%v", ctx.Vault.URL, "engine", "myAcct", 2),
	}

	require.Len(t, resp.Accounts, 1)
	require.Equal(t, want, *resp.Accounts[0])
}

func TestPlugin_KV_Contains_IsContained(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// contains
	toFind, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	resp, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{Address: toFind})
	require.NoError(t, err)
	require.True(t, resp.IsContained)
}

func TestPlugin_KV_Contains_IsNotContained(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// contains
	toFind, _ := hex.DecodeString("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")

	resp, err := ctx.AccountManager.Contains(context.Background(), &proto.ContainsRequest{Address: toFind})
	require.NoError(t, err)
	require.False(t, resp.IsContained)
}

func TestPlugin_KV_Sign(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  acctAddr,
		Duration: 0,
	})
	require.NoError(t, err)

	toSign := []byte{188, 76, 145, 93, 105, 137, 107, 25, 143, 2, 146, 167, 35, 115, 162, 189, 205, 13, 82, 188, 203, 252, 236, 17, 217, 200, 76, 15, 255, 113, 176, 188}
	wantSig := []byte{21, 228, 169, 48, 162, 94, 71, 55, 85, 214, 104, 193, 92, 14, 27, 132, 111, 18, 108, 11, 194, 150, 169, 254, 177, 54, 67, 10, 14, 208, 100, 250, 123, 166, 26, 0, 44, 215, 237, 186, 32, 198, 241, 77, 206, 214, 249, 124, 212, 36, 249, 4, 171, 87, 68, 147, 238, 96, 8, 180, 122, 172, 175, 38, 1}

	resp, err := ctx.AccountManager.Sign(context.Background(), &proto.SignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.NoError(t, err)
	require.Equal(t, wantSig, resp.Sig)
}

func TestPlugin_KV_Sign_Locked(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	toSign := []byte{188, 76, 145, 93, 105, 137, 107, 25, 143, 2, 146, 167, 35, 115, 162, 189, 205, 13, 82, 188, 203, 252, 236, 17, 217, 200, 76, 15, 255, 113, 176, 188}

	_, err := ctx.AccountManager.Sign(context.Background(), &proto.SignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = account locked")
}

func TestPlugin_KV_Sign_UnknownAccount(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr, _ := hex.DecodeString("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")

	toSign := []byte{188, 76, 145, 93, 105, 137, 107, 25, 143, 2, 146, 167, 35, 115, 162, 189, 205, 13, 82, 188, 203, 252, 236, 17, 217, 200, 76, 15, 255, 113, 176, 188}

	_, err := ctx.AccountManager.Sign(context.Background(), &proto.SignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown account")
}

func TestPlugin_KV_UnlockAndSign_Locked(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", statusResp.Status)

	toSign := []byte{188, 76, 145, 93, 105, 137, 107, 25, 143, 2, 146, 167, 35, 115, 162, 189, 205, 13, 82, 188, 203, 252, 236, 17, 217, 200, 76, 15, 255, 113, 176, 188}
	wantSig := []byte{21, 228, 169, 48, 162, 94, 71, 55, 85, 214, 104, 193, 92, 14, 27, 132, 111, 18, 108, 11, 194, 150, 169, 254, 177, 54, 67, 10, 14, 208, 100, 250, 123, 166, 26, 0, 44, 215, 237, 186, 32, 198, 241, 77, 206, 214, 249, 124, 212, 36, 249, 4, 171, 87, 68, 147, 238, 96, 8, 180, 122, 172, 175, 38, 1}

	resp, err := ctx.AccountManager.UnlockAndSign(context.Background(), &proto.UnlockAndSignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.NoError(t, err)
	require.Equal(t, wantSig, resp.Sig)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", statusResp.Status)
}

func TestPlugin_KV_UnlockAndSign_AlreadyUnlocked(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  acctAddr,
		Duration: 0,
	})

	statusResp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", statusResp.Status)

	toSign := []byte{188, 76, 145, 93, 105, 137, 107, 25, 143, 2, 146, 167, 35, 115, 162, 189, 205, 13, 82, 188, 203, 252, 236, 17, 217, 200, 76, 15, 255, 113, 176, 188}
	wantSig := []byte{21, 228, 169, 48, 162, 94, 71, 55, 85, 214, 104, 193, 92, 14, 27, 132, 111, 18, 108, 11, 194, 150, 169, 254, 177, 54, 67, 10, 14, 208, 100, 250, 123, 166, 26, 0, 44, 215, 237, 186, 32, 198, 241, 77, 206, 214, 249, 124, 212, 36, 249, 4, 171, 87, 68, 147, 238, 96, 8, 180, 122, 172, 175, 38, 1}

	resp, err := ctx.AccountManager.UnlockAndSign(context.Background(), &proto.UnlockAndSignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.NoError(t, err)

	require.Equal(t, wantSig, resp.Sig)

	statusResp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", statusResp.Status)
}

func TestPlugin_KV_UnlockAndSign_UnknownAccount(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// sign hash
	acctAddr, _ := hex.DecodeString("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")

	toSign := []byte{188, 76, 145, 93, 105, 137, 107, 25, 143, 2, 146, 167, 35, 115, 162, 189, 205, 13, 82, 188, 203, 252, 236, 17, 217, 200, 76, 15, 255, 113, 176, 188}

	_, err := ctx.AccountManager.UnlockAndSign(context.Background(), &proto.UnlockAndSignRequest{
		Address: acctAddr,
		ToSign:  toSign,
	})
	require.EqualError(t, err, "rpc error: code = Internal desc = unknown account")
}

func TestPlugin_KV_Unlock(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// timed unlock
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  addr,
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

func TestPlugin_KV_TimedUnlock(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// timed unlock
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  addr,
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

func TestPlugin_KV_TimedUnlock_Cancel(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// timed unlock
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  addr,
		Duration: (1 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  addr,
		Duration: 0,
	})
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)
}

func TestPlugin_KV_TimedUnlock_Extend(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// timed unlock
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  addr,
		Duration: (1 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  addr,
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

func TestPlugin_KV_TimedUnlock_Shorten(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// timed unlock
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  addr,
		Duration: (10 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	_, err = ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  addr,
		Duration: (1 * time.Second).Nanoseconds(),
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)

	time.Sleep(2 * time.Second)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)
}

func TestPlugin_KV_UnlockAtStartup(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx, map[string]string{"unlock": "0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526,UnknownAcctShouldNotCauseError"})

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)
}

func TestPlugin_KV_Lock(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// lock
	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  addr,
		Duration: 0,
	})
	require.NoError(t, err)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)

	_, err = ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Address: addr,
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)
}

func TestPlugin_KV_Lock_MultipleTimes(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// lock
	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
	_, err := ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Address: addr,
	})
	require.NoError(t, err)

	_, err = ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Address: addr,
	})
	require.NoError(t, err)
}

func TestPlugin_KV_Lock_CancelsTimedUnlock(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// lock
	addr, _ := hex.DecodeString("dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
	_, err := ctx.AccountManager.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Address:  addr,
		Duration: time.Second.Nanoseconds(),
	})
	require.NoError(t, err)

	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "1 unlocked account(s): [0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526]", resp.Status)

	_, err = ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Address: addr,
	})
	require.NoError(t, err)

	resp, err = ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "0 unlocked account(s)", resp.Status)

	// sleep for more than the original timed unlock duration to make sure no unexpected behaviour occurs
	time.Sleep(2 * time.Second)
}

func TestPlugin_KV_Lock_UnknownAccount(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

	// lock
	addr, _ := hex.DecodeString("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")
	_, err := ctx.AccountManager.Lock(context.Background(), &proto.LockRequest{
		Address: addr,
	})
	require.NoError(t, err)
}

func TestPlugin_KV_NewAccount(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

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

func TestPlugin_KV_NewAccount_IncorrectCASValue(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

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

func TestPlugin_KV_NewAccount_AddedToAvailableAccounts(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

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

func TestPlugin_KV_ImportRawKey(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

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

func TestPlugin_KV_ImportRawKey_IncorrectCASValue(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

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

func TestPlugin_KV_ImportRawKey_AddedToAvailableAccounts(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

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

func TestPlugin_KV_ImportRawKey_ErrorIfAccountExists(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	testutil.SetRoleID()
	testutil.SetSecretID()
	defer testutil.UnsetAll()

	setupPluginKVAndVaultAndFiles(t, ctx)

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
