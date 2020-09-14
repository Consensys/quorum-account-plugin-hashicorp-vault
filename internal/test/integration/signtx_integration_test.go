// +build integration

package integration

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_KV_SignTransaction(t *testing.T) {
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

	var signResp map[string]interface{}

	toSign := map[string]string{
		"from":     addr,
		"input":    "0xaaaaaa",
		"gas":      "0x1",
		"gasPrice": "0x1",
		"nonce":    "0x0",
	}

	wantSig := "0xf84c800101808083aaaaaa1ba0c9a5a5d650054f774166502a9ea3b9582302e9d2ccc086501c4735cc781d290aa05cc50d82e1112b1a08a5d9054a45b653f76935de3f015a6177adb56b344d5e04"
	err = c.RPCCall(&signResp, "eth_signTransaction", toSign)
	require.NoError(t, err)

	fmt.Println(signResp)

	require.Equal(t, wantSig, signResp["raw"])
}

func Test_KV_SignTransaction_Locked(t *testing.T) {
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

	var signResp map[string]interface{}

	toSign := map[string]string{
		"from":     addr,
		"input":    "0xaaaaaa",
		"gas":      "0x1",
		"gasPrice": "0x1",
		"nonce":    "0x0",
	}

	err = c.RPCCall(&signResp, "eth_signTransaction", toSign)
	require.EqualError(t, err, "rpc error: code = Internal desc = account locked")
}

func Test_KV_PersonalSignTransaction(t *testing.T) {
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

	var signResp map[string]interface{}

	toSign := map[string]string{
		"from":     addr,
		"input":    "0xaaaaaa",
		"gas":      "0x1",
		"gasPrice": "0x1",
		"nonce":    "0x0",
	}

	wantSig := "0xf84c800101808083aaaaaa1ba0c9a5a5d650054f774166502a9ea3b9582302e9d2ccc086501c4735cc781d290aa05cc50d82e1112b1a08a5d9054a45b653f76935de3f015a6177adb56b344d5e04"
	err = c.RPCCall(&signResp, "personal_signTransaction", toSign, "")
	require.NoError(t, err)

	fmt.Println(signResp)

	require.Equal(t, wantSig, signResp["raw"])
}

func Test_Signer_SignTransaction(t *testing.T) {
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

	var signResp map[string]interface{}

	toSign := map[string]string{
		"from":     addr,
		"input":    "0xaaaaaa",
		"gas":      "0x1",
		"gasPrice": "0x1",
		"nonce":    "0x0",
	}

	wantSig := "0xf84c800101808083aaaaaa1ba0c9a5a5d650054f774166502a9ea3b9582302e9d2ccc086501c4735cc781d290aa05cc50d82e1112b1a08a5d9054a45b653f76935de3f015a6177adb56b344d5e04"
	err = c.RPCCall(&signResp, "eth_signTransaction", toSign)
	require.NoError(t, err)

	fmt.Println(signResp)

	require.Equal(t, wantSig, signResp["raw"])
}

func Test_Signer_PersonalSignTransaction_NotAllowed(t *testing.T) {
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

	var signResp map[string]interface{}

	toSign := map[string]string{
		"from":     addr,
		"input":    "0xaaaaaa",
		"gas":      "0x1",
		"gasPrice": "0x1",
		"nonce":    "0x0",
	}

	err = c.RPCCall(&signResp, "personal_signTransaction", toSign, "")
	require.EqualError(t, err, "rpc error: code = Internal desc = not supported when using quorum-signer secret engine")
}
