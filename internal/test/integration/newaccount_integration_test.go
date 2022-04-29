// +build integration

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

func Test_KV_CreateAccount_NewPath_ValidOverwriteProtection(t *testing.T) {
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

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer quorum.start(t)()

	c := createWSQuorumClient(t, "ws://localhost:8546")

	var resp map[string]string

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`
	newAccountConfig, err := jsonUnmarshal(newAccountConfigJson)
	require.NoError(t, err)

	err = c.RPCCall(&resp, "plugin@account_newAccount", newAccountConfig)
	require.NoError(t, err)

	acctAddr := resp["address"]
	acctURL := resp["url"]

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

	require.Equal(t, strings.TrimPrefix(resp["address"], "0x"), contents["Address"].(string), "data returned in RPC response and written to file are different")
	vaultData := contents["VaultAccount"].(map[string]interface{})

	require.Equal(t, float64(1), vaultData["SecretVersion"].(float64), "incorrect data written to file")
	require.Equal(t, "myAcct", vaultData["SecretName"].(string), "incorrect data written to file")

	// check that new account is available (check both eth_accounts and personal_listWallets)
	var ethAcctsResp []string
	err = c.RPCCall(&ethAcctsResp, "eth_accounts")
	require.NoError(t, err)
	require.Len(t, ethAcctsResp, 1)
	require.Contains(t, ethAcctsResp, acctAddr)

	var personalListWalletsResp PersonalListWalletsResp
	err = c.RPCCall(&personalListWalletsResp, "personal_listWallets")
	require.NoError(t, err)
	require.Len(t, personalListWalletsResp, 1)

	wantPersonalListWalletsResp := PersonalListWalletsResp{
		{
			Accounts: []Account{
				{
					Address: resp["address"],
					URL:     resp["url"],
				},
			},
			Status: "0 unlocked account(s)",
			URL:    "plugin://account",
		},
	}
	require.Equal(t, wantPersonalListWalletsResp, personalListWalletsResp)
}

func Test_KV_CreateAccount_NewPath_InvalidOverwriteProtection(t *testing.T) {
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

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer quorum.start(t)()

	c := createWSQuorumClient(t, "ws://localhost:8546")

	var resp map[string]string

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 1
		}
	}`
	newAccountConfig, err := jsonUnmarshal(newAccountConfigJson)
	require.NoError(t, err)

	err = c.RPCCall(&resp, "plugin@account_newAccount", newAccountConfig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rpc error: code = Internal")
	require.Contains(t, err.Error(), "check-and-set parameter did not match the current version")

	// check that no acct data is added to vault
	getKVSecretExpect404(t, "http://localhost:8200", "secret", "myAcct", 1, "root")

	// check that no file is created in acct dir
	targetDir := fmt.Sprintf("%v/plugin-accts", dirs.testout)

	files, err := findFile(targetDir, "*")
	require.NoError(t, err)
	require.Len(t, files, 0, "no files should have been created - ensure starting environment has no files")
}

func Test_KV_CreateAccount_ExistingPath_ValidOverwriteProtection(t *testing.T) {
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

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer quorum.start(t)()

	c := createWSQuorumClient(t, "ws://localhost:8546")

	var resp map[string]string

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`
	newAccountConfig, err := jsonUnmarshal(newAccountConfigJson)
	require.NoError(t, err)

	err = c.RPCCall(&resp, "plugin@account_newAccount", newAccountConfig)
	require.NoError(t, err)

	// create another account at the same path
	newAccountConfigJson = `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 1
		}
	}`
	newAccountConfig, err = jsonUnmarshal(newAccountConfigJson)
	require.NoError(t, err)

	err = c.RPCCall(&resp, "plugin@account_newAccount", newAccountConfig)
	require.NoError(t, err)

	acctAddr := resp["address"]
	acctURL := resp["url"]

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

	require.Equal(t, strings.TrimPrefix(resp["address"], "0x"), contents["Address"].(string), "data returned in RPC response and written to file are different")
	vaultData := contents["VaultAccount"].(map[string]interface{})

	require.Equal(t, float64(2), vaultData["SecretVersion"].(float64), "incorrect data written to file")
	require.Equal(t, "myAcct", vaultData["SecretName"].(string), "incorrect data written to file")

	// check that new account is available (check both eth_accounts and personal_listWallets)
	var ethAcctsResp []string
	err = c.RPCCall(&ethAcctsResp, "eth_accounts")
	require.NoError(t, err)
	require.Len(t, ethAcctsResp, 2)
	require.Contains(t, ethAcctsResp, acctAddr)

	var personalListWalletsResp PersonalListWalletsResp
	err = c.RPCCall(&personalListWalletsResp, "personal_listWallets")
	require.NoError(t, err)
	require.Len(t, personalListWalletsResp, 1)

	require.Len(t, personalListWalletsResp[0].Accounts, 2)

	wantAcct := Account{
		Address: resp["address"],
		URL:     resp["url"],
	}

	require.Contains(t, personalListWalletsResp[0].Accounts, wantAcct)
	require.Equal(t, "0 unlocked account(s)", personalListWalletsResp[0].Status)
	require.Equal(t, "plugin://account", personalListWalletsResp[0].URL)
}

func Test_KV_CreateAccount_ExistingPath_InvalidOverwriteProtection(t *testing.T) {
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

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer quorum.start(t)()

	c := createWSQuorumClient(t, "ws://localhost:8546")

	var resp map[string]string

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`
	newAccountConfig, err := jsonUnmarshal(newAccountConfigJson)
	require.NoError(t, err)

	err = c.RPCCall(&resp, "plugin@account_newAccount", newAccountConfig)
	require.NoError(t, err)

	// create another account at the same path
	newAccountConfigJson = `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`
	newAccountConfig, err = jsonUnmarshal(newAccountConfigJson)
	require.NoError(t, err)

	err = c.RPCCall(&resp, "plugin@account_newAccount", newAccountConfig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rpc error: code = Internal")
	require.Contains(t, err.Error(), "check-and-set parameter did not match the current version")

	// check that no acct data is added to vault
	getKVSecretExpect404(t, "http://localhost:8200", "secret", "myAcct", 2, "root")

	// check that no file is created in acct dir
	targetDir := fmt.Sprintf("%v/plugin-accts", dirs.testout)

	files, err := findFile(targetDir, "*")
	require.NoError(t, err)
	require.Len(t, files, 1, "no file should have been created - ensure starting environment has no files")
}

func Test_Signer_CreateAccount_NewPath(t *testing.T) {
	dirs := prepareDirs(t, testDirName, t.Name())

	vaultPluginConf := createVaultSignerPluginConfig(t, dirs.testout)
	pluginsConf := createPluginsConfig(
		t,
		dirs.testout,
		distDir,
		distVersion,
		vaultPluginConf)

	var vaultBuilder vaultBuilder
	vault := vaultBuilder.
		devMode("root").
		withPlugins().
		build(t, dirs.testout)

	defer vault.start(t)()

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer quorum.start(t)()

	c := createWSQuorumClient(t, "ws://localhost:8546")

	enableSignerPlugin(t, "http://localhost:8200", "root")

	var resp map[string]string

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct"
	}`
	newAccountConfig, err := jsonUnmarshal(newAccountConfigJson)
	require.NoError(t, err)

	err = c.RPCCall(&resp, "plugin@account_newAccount", newAccountConfig)
	require.NoError(t, err)

	acctAddr := resp["address"]
	acctURL := resp["url"]

	wantURL := fmt.Sprintf("http://%v/v1/%v/accounts/%v?version=%v", "localhost:8200", "quorum-signer", "myAcct", 0)
	require.Equal(t, wantURL, acctURL)

	// check that acct data is added to vault
	vaultResp := getSignerSecret(t, "http://localhost:8200", "quorum-signer", "myAcct", "root")
	require.Equal(t, acctAddr, "0x"+vaultResp.addr)

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

	require.Equal(t, strings.TrimPrefix(resp["address"], "0x"), contents["Address"].(string), "data returned in RPC response and written to file are different")
	vaultData := contents["VaultAccount"].(map[string]interface{})

	require.Equal(t, float64(0), vaultData["SecretVersion"].(float64), "incorrect data written to file")
	require.Equal(t, "myAcct", vaultData["SecretName"].(string), "incorrect data written to file")

	// check that new account is available (check both eth_accounts and personal_listWallets)
	var ethAcctsResp []string
	err = c.RPCCall(&ethAcctsResp, "eth_accounts")
	require.NoError(t, err)
	require.Len(t, ethAcctsResp, 1)
	require.Contains(t, ethAcctsResp, acctAddr)

	var personalListWalletsResp PersonalListWalletsResp
	err = c.RPCCall(&personalListWalletsResp, "personal_listWallets")
	require.NoError(t, err)
	require.Len(t, personalListWalletsResp, 1)

	wantPersonalListWalletsResp := PersonalListWalletsResp{
		{
			Accounts: []Account{
				{
					Address: resp["address"],
					URL:     resp["url"],
				},
			},
			Status: "ok",
			URL:    "plugin://account",
		},
	}
	require.Equal(t, wantPersonalListWalletsResp, personalListWalletsResp)
}

func Test_Signer_CreateAccount_ExistingPath_NotAllowed(t *testing.T) {
	dirs := prepareDirs(t, testDirName, t.Name())

	vaultPluginConf := createVaultSignerPluginConfig(t, dirs.testout)
	pluginsConf := createPluginsConfig(
		t,
		dirs.testout,
		distDir,
		distVersion,
		vaultPluginConf)

	var vaultBuilder vaultBuilder
	vault := vaultBuilder.
		devMode("root").
		withPlugins().
		build(t, dirs.testout)

	defer vault.start(t)()

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		addEnv("HASHICORP_TOKEN", "root").
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer quorum.start(t)()

	c := createWSQuorumClient(t, "ws://localhost:8546")

	enableSignerPlugin(t, "http://localhost:8200", "root")

	var resp map[string]string

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct"
	}`
	newAccountConfig, err := jsonUnmarshal(newAccountConfigJson)
	require.NoError(t, err)

	err = c.RPCCall(&resp, "plugin@account_newAccount", newAccountConfig)
	require.NoError(t, err)

	//create another account at the same path
	err = c.RPCCallWithTimeout(5*time.Second, &resp, "plugin@account_newAccount", newAccountConfig)
	require.Error(t, err)

	require.Contains(t, err.Error(), "rpc error: code = Internal desc = unable to create new account in Vault")
	require.Contains(t, err.Error(), "updating existing secrets is not supported")
}
