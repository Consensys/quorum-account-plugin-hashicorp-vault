// +build integration

package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_KV_UnlockAccount(t *testing.T) {
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

	var unlockResp interface{}
	err = c.RPCCall(&unlockResp, "personal_unlockAccount", acctAddr, "", 0)
	require.NoError(t, err)

	err = c.RPCCall(&personalListWalletsResp, "personal_listWallets")
	require.NoError(t, err)
	require.Len(t, personalListWalletsResp, 1)

	wantPersonalListWalletsResp = PersonalListWalletsResp{
		{
			Accounts: []Account{
				{
					Address: resp["address"],
					URL:     resp["url"],
				},
			},
			Status: fmt.Sprintf("1 unlocked account(s): [%v]", resp["address"]),
			URL:    "plugin://account",
		},
	}
	require.Equal(t, wantPersonalListWalletsResp, personalListWalletsResp)
}

func Test_KV_TimedUnlockAccount(t *testing.T) {
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

	var unlockResp interface{}
	err = c.RPCCall(&unlockResp, "personal_unlockAccount", acctAddr, "", 5)
	require.NoError(t, err)

	err = c.RPCCall(&personalListWalletsResp, "personal_listWallets")
	require.NoError(t, err)
	require.Len(t, personalListWalletsResp, 1)

	wantPersonalListWalletsResp = PersonalListWalletsResp{
		{
			Accounts: []Account{
				{
					Address: resp["address"],
					URL:     resp["url"],
				},
			},
			Status: fmt.Sprintf("1 unlocked account(s): [%v]", resp["address"]),
			URL:    "plugin://account",
		},
	}
	require.Equal(t, wantPersonalListWalletsResp, personalListWalletsResp)

	<-time.After(5 * time.Second)

	err = c.RPCCall(&personalListWalletsResp, "personal_listWallets")
	require.NoError(t, err)
	require.Len(t, personalListWalletsResp, 1)

	wantPersonalListWalletsResp = PersonalListWalletsResp{
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

func Test_Signer_UnlockAccount_NotAllowed(t *testing.T) {
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

	var unlockResp interface{}
	err = c.RPCCall(&unlockResp, "personal_unlockAccount", acctAddr, "", 0)
	require.EqualError(t, err, "rpc error: code = Internal desc = not supported when using quorum-signer secret engine")
}
