// +build integration

package integration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_KV_Sign(t *testing.T) {
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

	rawKey := "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"
	addr := "0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526"

	err = c.RPCCall(&resp, "plugin@account_importRawKey", rawKey, newAccountConfig)
	require.NoError(t, err)

	var unlockResp interface{}
	err = c.RPCCall(&unlockResp, "personal_unlockAccount", addr, "", 0)
	require.NoError(t, err)

	// wait for the account to be unlocked and quorum to update
	time.Sleep(100 * time.Millisecond)

	var signResp string

	toSign := "0xaaaaaa"
	wantSig := "0xf1ad7640b894cc835d0707e9827e1ce8f91eccc8da5525fd42396b12acf5ab501352e07d9c8d1c4bbc458dd4c9fde729fbefc46fd4c9ee2df92a75c66d22e7281c"

	err = c.RPCCall(&signResp, "eth_sign", addr, toSign)
	require.NoError(t, err)

	require.Equal(t, wantSig, signResp)
}

func Test_KV_Sign_Locked(t *testing.T) {
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

	rawKey := "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"
	addr := "0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526"

	err = c.RPCCall(&resp, "plugin@account_importRawKey", rawKey, newAccountConfig)
	require.NoError(t, err)

	var signResp string

	toSign := "0xaaaaaa"

	err = c.RPCCall(&signResp, "eth_sign", addr, toSign)
	require.EqualError(t, err, "rpc error: code = Internal desc = account locked")
}

func Test_KV_PersonalSign(t *testing.T) {
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

	rawKey := "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"
	addr := "0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526"

	err = c.RPCCall(&resp, "plugin@account_importRawKey", rawKey, newAccountConfig)
	require.NoError(t, err)

	var signResp string

	toSign := "0xaaaaaa"
	wantSig := "0xf1ad7640b894cc835d0707e9827e1ce8f91eccc8da5525fd42396b12acf5ab501352e07d9c8d1c4bbc458dd4c9fde729fbefc46fd4c9ee2df92a75c66d22e7281c"

	err = c.RPCCall(&signResp, "personal_sign", toSign, addr, "")
	require.NoError(t, err)

	require.Equal(t, wantSig, signResp)
}

func Test_Signer_Sign(t *testing.T) {
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

	rawKey := "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"
	addr := "0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526"

	err = c.RPCCall(&resp, "plugin@account_importRawKey", rawKey, newAccountConfig)
	require.NoError(t, err)

	var signResp string

	toSign := "0xaaaaaa"
	wantSig := "0xf1ad7640b894cc835d0707e9827e1ce8f91eccc8da5525fd42396b12acf5ab501352e07d9c8d1c4bbc458dd4c9fde729fbefc46fd4c9ee2df92a75c66d22e7281c"

	err = c.RPCCall(&signResp, "eth_sign", addr, toSign)
	require.NoError(t, err)

	require.Equal(t, wantSig, signResp)
}

func Test_Signer_PersonalSign(t *testing.T) {
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

	rawKey := "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28"
	addr := "0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526"

	err = c.RPCCall(&resp, "plugin@account_importRawKey", rawKey, newAccountConfig)
	require.NoError(t, err)

	var signResp string

	toSign := "0xaaaaaa"
	wantSig := "0xf1ad7640b894cc835d0707e9827e1ce8f91eccc8da5525fd42396b12acf5ab501352e07d9c8d1c4bbc458dd4c9fde729fbefc46fd4c9ee2df92a75c66d22e7281c"

	err = c.RPCCall(&signResp, "personal_sign", toSign, addr, "")
	require.NoError(t, err)

	require.Equal(t, wantSig, signResp)
}
