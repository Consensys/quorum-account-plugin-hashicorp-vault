// +build clefintegration

package integration

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_KV_Clef_CreateAccount_NewPath_ValidOverwriteProtection(t *testing.T) {
	dirs := prepareDirs(t, testDirName, t.Name())

	vaultPluginConf := createVaultKVPluginConfig(t, dirs.testout)
	pluginsConf := createPluginsConfig(
		t,
		dirs.testout,
		distDir,
		distVersion,
		vaultPluginConf)

	var vaultBuilder vaultBuilder
	vault := vaultBuilder.
		devMode("root").
		build(t, dirs.testout)

	defer vault.start(t)()

	var clefBuilder clefBuilder
	clef := clefBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer clef.start(t)()

	clef.ok(t)

	clefIPC := fmt.Sprintf("%v/clef.ipc", dirs.datadir)
	waitForClef(t, clefIPC)

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		buildWithClef(t, dirs.testout, dirs.datadir, clefIPC)

	defer quorum.start(t)()

	// create account
	newAccountConfigJson := `{
	  "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`
	paramsJSON := fmt.Sprintf(`[%v]`, newAccountConfigJson)

	req := NewRPCRequest(t, "plugin@account_newAccount", paramsJSON)
	resp := req.UnixDo(t, false, clef, clefIPC)

	acctAddr := resp["address"].(string)
	acctURL := resp["url"].(string)

	wantURL := fmt.Sprintf("http://%v/v1/%v/data/%v?version=%v", "localhost:8200", "secret", "myAcct", 1)
	require.Equal(t, wantURL, acctURL)

	// check that acct data is added to vault
	vaultResp := getKVSecret(t, "http://localhost:8200", "secret", "myAcct", 1, "root")
	require.Equal(t, acctAddr, "0x"+vaultResp.addr)
	require.NotEmpty(t, vaultResp.key)

	// check that file is created in acct dir
	targetDir := fmt.Sprintf("%v/plugin-accts", dirs.testout)

	files, err := findFile(targetDir, fmt.Sprintf("*%v", strings.TrimPrefix(acctAddr, "0x")))
	require.NoError(t, err)
	require.Len(t, files, 1, "multiple files match pattern - unsure of which to inspect")

	// check file contents
	contentsByt, err := ioutil.ReadFile(files[0])
	require.NoError(t, err)

	var contents map[string]interface{}
	err = json.Unmarshal(contentsByt, &contents)
	require.NoError(t, err)

	require.Equal(t, strings.TrimPrefix(acctAddr, "0x"), contents["Address"].(string), "data returned in RPC response and written to file are different")
	vaultData := contents["VaultAccount"].(map[string]interface{})

	require.Equal(t, float64(1), vaultData["SecretVersion"].(float64), "incorrect data written to file")
	require.Equal(t, "myAcct", vaultData["SecretName"].(string), "incorrect data written to file")

	// check that new account is available (check both eth_accounts and personal_listWallets)
	c := createWSQuorumClient(t, "ws://localhost:8546")

	// pre-push an approval for the list operation
	<-time.After(1 * time.Second)
	clef.y(t)
	<-time.After(1 * time.Second)

	var ethAcctsResp []string
	err = c.RPCCall(&ethAcctsResp, "eth_accounts")
	require.NoError(t, err)
	require.Len(t, ethAcctsResp, 1)
	require.Contains(t, ethAcctsResp, acctAddr)

	// pre-push an approval for the list operation
	<-time.After(1 * time.Second)
	clef.y(t)
	<-time.After(1 * time.Second)

	var personalListWalletsResp PersonalListWalletsResp
	err = c.RPCCall(&personalListWalletsResp, "personal_listWallets")
	require.NoError(t, err)

	wantWalletURL := fmt.Sprintf("extapi://%v", clefIPC)

	wantPersonalListWalletsResp := PersonalListWalletsResp{
		{
			Accounts: []Account{
				{
					Address: acctAddr,
					URL:     wantWalletURL,
				},
			},
			Status: "ok [version=6.0.0]",
			URL:    wantWalletURL,
		},
	}
	require.Equal(t, wantPersonalListWalletsResp, personalListWalletsResp)
}

func Test_KV_Clef_CreateAccount_NewPath_InvalidOverwriteProtection(t *testing.T) {
	dirs := prepareDirs(t, testDirName, t.Name())

	vaultPluginConf := createVaultKVPluginConfig(t, dirs.testout)
	pluginsConf := createPluginsConfig(
		t,
		dirs.testout,
		distDir,
		distVersion,
		vaultPluginConf)

	var vaultBuilder vaultBuilder
	vault := vaultBuilder.
		devMode("root").
		build(t, dirs.testout)

	defer vault.start(t)()

	var clefBuilder clefBuilder
	clef := clefBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer clef.start(t)()

	clef.ok(t)

	clefIPC := fmt.Sprintf("%v/clef.ipc", dirs.datadir)
	waitForClef(t, clefIPC)

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		buildWithClef(t, dirs.testout, dirs.datadir, clefIPC)

	defer quorum.start(t)()

	// create account
	newAccountConfigJson := `{
	  "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 1
		}
	}`
	paramsJSON := fmt.Sprintf(`[%v]`, newAccountConfigJson)

	req := NewRPCRequest(t, "plugin@account_newAccount", paramsJSON)
	respErr := req.UnixDoExpectError(t, clef, clefIPC)

	require.Contains(t, respErr, "rpc error: code = Internal")
	require.Contains(t, respErr, "check-and-set parameter did not match the current version")

	// check that no acct data is added to vault
	getKVSecretExpect404(t, "http://localhost:8200", "secret", "myAcct", 1, "root")

	// check that no file is created in acct dir
	targetDir := fmt.Sprintf("%v/plugin-accts", dirs.testout)

	files, err := findFile(targetDir, "*")
	require.NoError(t, err)
	require.Len(t, files, 0, "no files should have been created - ensure starting environment has no files")
}

func Test_KV_Clef_CreateAccount_ExistingPath_ValidOverwriteProtection(t *testing.T) {
	dirs := prepareDirs(t, testDirName, t.Name())

	vaultPluginConf := createVaultKVPluginConfig(t, dirs.testout)
	pluginsConf := createPluginsConfig(
		t,
		dirs.testout,
		distDir,
		distVersion,
		vaultPluginConf)

	var vaultBuilder vaultBuilder
	vault := vaultBuilder.
		devMode("root").
		build(t, dirs.testout)

	defer vault.start(t)()

	var clefBuilder clefBuilder
	clef := clefBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer clef.start(t)()

	clef.ok(t)

	clefIPC := fmt.Sprintf("%v/clef.ipc", dirs.datadir)
	waitForClef(t, clefIPC)

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		buildWithClef(t, dirs.testout, dirs.datadir, clefIPC)

	defer quorum.start(t)()

	// create account
	newAccountConfigJson := `{
	  "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`
	paramsJSON := fmt.Sprintf(`[%v]`, newAccountConfigJson)

	req := NewRPCRequest(t, "plugin@account_newAccount", paramsJSON)
	resp := req.UnixDo(t, false, clef, clefIPC)

	// create another account at the same path
	newAccountConfigJson = `{
	  "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 1
		}
	}`
	paramsJSON = fmt.Sprintf(`[%v]`, newAccountConfigJson)

	req = NewRPCRequest(t, "plugin@account_newAccount", paramsJSON)
	resp = req.UnixDo(t, false, clef, clefIPC)

	acctAddr := resp["address"].(string)
	acctURL := resp["url"].(string)

	wantURL := fmt.Sprintf("http://%v/v1/%v/data/%v?version=%v", "localhost:8200", "secret", "myAcct", 2)
	require.Equal(t, wantURL, acctURL)

	// check that acct data is added to vault
	vaultResp := getKVSecret(t, "http://localhost:8200", "secret", "myAcct", 2, "root")
	require.Equal(t, acctAddr, "0x"+vaultResp.addr)
	require.NotEmpty(t, vaultResp.key)

	// check that file is created in acct dir
	targetDir := fmt.Sprintf("%v/plugin-accts", dirs.testout)

	files, err := findFile(targetDir, fmt.Sprintf("*%v", strings.TrimPrefix(acctAddr, "0x")))
	require.NoError(t, err)
	require.Len(t, files, 1, "multiple files match pattern - unsure of which to inspect")

	// check file contents
	contentsByt, err := ioutil.ReadFile(files[0])
	require.NoError(t, err)

	var contents map[string]interface{}
	err = json.Unmarshal(contentsByt, &contents)
	require.NoError(t, err)

	require.Equal(t, strings.TrimPrefix(acctAddr, "0x"), contents["Address"].(string), "data returned in RPC response and written to file are different")
	vaultData := contents["VaultAccount"].(map[string]interface{})

	require.Equal(t, float64(2), vaultData["SecretVersion"].(float64), "incorrect data written to file")
	require.Equal(t, "myAcct", vaultData["SecretName"].(string), "incorrect data written to file")

	// check that new account is available (check both eth_accounts and personal_listWallets)
	c := createWSQuorumClient(t, "ws://localhost:8546")

	// pre-push an approval for the list operation
	<-time.After(1 * time.Second)
	clef.y(t)
	<-time.After(1 * time.Second)

	var ethAcctsResp []string
	err = c.RPCCall(&ethAcctsResp, "eth_accounts")
	require.NoError(t, err)
	require.Len(t, ethAcctsResp, 2)
	require.Contains(t, ethAcctsResp, acctAddr)

	// pre-push an approval for the list operation
	<-time.After(1 * time.Second)
	clef.y(t)
	<-time.After(1 * time.Second)

	var personalListWalletsResp PersonalListWalletsResp
	err = c.RPCCall(&personalListWalletsResp, "personal_listWallets")
	require.NoError(t, err)

	wantWalletURL := fmt.Sprintf("extapi://%v", clefIPC)

	require.Len(t, personalListWalletsResp, 1)
	require.Len(t, personalListWalletsResp[0].Accounts, 2)

	wantAcct := Account{
		Address: acctAddr,
		URL:     wantWalletURL,
	}

	require.Contains(t, personalListWalletsResp[0].Accounts, wantAcct)
}

func Test_KV_Clef_CreateAccount_ExistingPath_InvalidOverwriteProtection(t *testing.T) {
	dirs := prepareDirs(t, testDirName, t.Name())

	vaultPluginConf := createVaultKVPluginConfig(t, dirs.testout)
	pluginsConf := createPluginsConfig(
		t,
		dirs.testout,
		distDir,
		distVersion,
		vaultPluginConf)

	var vaultBuilder vaultBuilder
	vault := vaultBuilder.
		devMode("root").
		build(t, dirs.testout)

	defer vault.start(t)()

	var clefBuilder clefBuilder
	clef := clefBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer clef.start(t)()

	clef.ok(t)

	clefIPC := fmt.Sprintf("%v/clef.ipc", dirs.datadir)
	waitForClef(t, clefIPC)

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		buildWithClef(t, dirs.testout, dirs.datadir, clefIPC)

	defer quorum.start(t)()

	// create account
	newAccountConfigJson := `{
	  "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`
	paramsJSON := fmt.Sprintf(`[%v]`, newAccountConfigJson)

	req := NewRPCRequest(t, "plugin@account_newAccount", paramsJSON)
	req.UnixDo(t, false, clef, clefIPC)

	// create another account at the same path
	newAccountConfigJson = `{
	  "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`
	paramsJSON = fmt.Sprintf(`[%v]`, newAccountConfigJson)

	req = NewRPCRequest(t, "plugin@account_newAccount", paramsJSON)
	respErr := req.UnixDoExpectError(t, clef, clefIPC)

	require.Contains(t, respErr, "rpc error: code = Internal")
	require.Contains(t, respErr, "check-and-set parameter did not match the current version")

	// check that no acct data is added to vault
	getKVSecretExpect404(t, "http://localhost:8200", "secret", "myAcct", 2, "root")

	// check that no file is created in acct dir
	targetDir := fmt.Sprintf("%v/plugin-accts", dirs.testout)

	files, err := findFile(targetDir, "*")
	require.NoError(t, err)
	require.Len(t, files, 1, "no files should have been created - ensure starting environment has no files")
}

func Test_Signer_Clef_CreateAccount_NewPath(t *testing.T) {
	dirs := prepareDirs(t, testDirName, t.Name())

	vaultPluginConf := createVaultKVPluginConfig(t, dirs.testout)
	pluginsConf := createPluginsConfig(
		t,
		dirs.testout,
		distDir,
		distVersion,
		vaultPluginConf)

	var vaultBuilder vaultBuilder
	vault := vaultBuilder.
		devMode("root").
		build(t, dirs.testout)

	defer vault.start(t)()

	var clefBuilder clefBuilder
	clef := clefBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer clef.start(t)()

	clef.ok(t)

	clefIPC := fmt.Sprintf("%v/clef.ipc", dirs.datadir)
	waitForClef(t, clefIPC)

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		buildWithClef(t, dirs.testout, dirs.datadir, clefIPC)

	defer quorum.start(t)()

	// create account
	newAccountConfigJson := `{
	  "secretName": "myAcct"
	}`
	paramsJSON := fmt.Sprintf(`[%v]`, newAccountConfigJson)

	req := NewRPCRequest(t, "plugin@account_newAccount", paramsJSON)
	resp := req.UnixDo(t, false, clef, clefIPC)

	acctAddr := resp["address"].(string)
	acctURL := resp["url"].(string)

	wantURL := fmt.Sprintf("http://%v/v1/%v/data/%v?version=%v", "localhost:8200", "secret", "myAcct", 1)
	require.Equal(t, wantURL, acctURL)

	// check that acct data is added to vault
	vaultResp := getKVSecret(t, "http://localhost:8200", "secret", "myAcct", 1, "root")
	require.Equal(t, acctAddr, "0x"+vaultResp.addr)
	require.NotEmpty(t, vaultResp.key)

	// check that file is created in acct dir
	targetDir := fmt.Sprintf("%v/plugin-accts", dirs.testout)

	files, err := findFile(targetDir, fmt.Sprintf("*%v", strings.TrimPrefix(acctAddr, "0x")))
	require.NoError(t, err)
	require.Len(t, files, 1, "multiple files match pattern - unsure of which to inspect")

	// check file contents
	contentsByt, err := ioutil.ReadFile(files[0])
	require.NoError(t, err)

	var contents map[string]interface{}
	err = json.Unmarshal(contentsByt, &contents)
	require.NoError(t, err)

	require.Equal(t, strings.TrimPrefix(acctAddr, "0x"), contents["Address"].(string), "data returned in RPC response and written to file are different")
	vaultData := contents["VaultAccount"].(map[string]interface{})

	require.Equal(t, float64(1), vaultData["SecretVersion"].(float64), "incorrect data written to file")
	require.Equal(t, "myAcct", vaultData["SecretName"].(string), "incorrect data written to file")

	// check that new account is available (check both eth_accounts and personal_listWallets)
	c := createWSQuorumClient(t, "ws://localhost:8546")

	// pre-push an approval for the list operation
	<-time.After(1 * time.Second)
	clef.y(t)
	<-time.After(1 * time.Second)

	var ethAcctsResp []string
	err = c.RPCCall(&ethAcctsResp, "eth_accounts")
	require.NoError(t, err)
	require.Len(t, ethAcctsResp, 1)
	require.Contains(t, ethAcctsResp, acctAddr)

	// pre-push an approval for the list operation
	<-time.After(1 * time.Second)
	clef.y(t)
	<-time.After(1 * time.Second)

	var personalListWalletsResp PersonalListWalletsResp
	err = c.RPCCall(&personalListWalletsResp, "personal_listWallets")
	require.NoError(t, err)

	wantWalletURL := fmt.Sprintf("extapi://%v", clefIPC)

	wantPersonalListWalletsResp := PersonalListWalletsResp{
		{
			Accounts: []Account{
				{
					Address: acctAddr,
					URL:     wantWalletURL,
				},
			},
			Status: "ok [version=6.0.0]",
			URL:    wantWalletURL,
		},
	}
	require.Equal(t, wantPersonalListWalletsResp, personalListWalletsResp)
}

func Test_Signer_Clef_CreateAccount_ExistingPath_NotAllowed(t *testing.T) {
	dirs := prepareDirs(t, testDirName, t.Name())

	vaultPluginConf := createVaultKVPluginConfig(t, dirs.testout)
	pluginsConf := createPluginsConfig(
		t,
		dirs.testout,
		distDir,
		distVersion,
		vaultPluginConf)

	var vaultBuilder vaultBuilder
	vault := vaultBuilder.
		devMode("root").
		build(t, dirs.testout)

	defer vault.start(t)()

	var clefBuilder clefBuilder
	clef := clefBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer clef.start(t)()

	clef.ok(t)

	clefIPC := fmt.Sprintf("%v/clef.ipc", dirs.datadir)
	waitForClef(t, clefIPC)

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		buildWithClef(t, dirs.testout, dirs.datadir, clefIPC)

	defer quorum.start(t)()

	// create account
	newAccountConfigJson := `{
	  "secretName": "myAcct"
	}`
	paramsJSON := fmt.Sprintf(`[%v]`, newAccountConfigJson)

	req := NewRPCRequest(t, "plugin@account_newAccount", paramsJSON)
	req.UnixDo(t, false, clef, clefIPC)

	// create another account at the same path
	newAccountConfigJson = `{
	  "secretName": "myAcct"
	}`
	paramsJSON = fmt.Sprintf(`[%v]`, newAccountConfigJson)

	req = NewRPCRequest(t, "plugin@account_newAccount", paramsJSON)
	respErr := req.UnixDoExpectError(t, clef, clefIPC)

	require.Contains(t, respErr, "rpc error: code = Internal")
	require.Contains(t, respErr, "check-and-set parameter did not match the current version")

	// check that no acct data is added to vault
	getKVSecretExpect404(t, "http://localhost:8200", "secret", "myAcct", 2, "root")

	// check that no file is created in acct dir
	targetDir := fmt.Sprintf("%v/plugin-accts", dirs.testout)

	files, err := findFile(targetDir, "*")
	require.NoError(t, err)
	require.Len(t, files, 1, "no files should have been created - ensure starting environment has no files")
}
