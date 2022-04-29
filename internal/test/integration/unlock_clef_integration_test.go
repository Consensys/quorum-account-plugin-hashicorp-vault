// +build clefintegration

package integration

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_KV_Clef_UnlockAccount(t *testing.T) {
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
		stdioUI().
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer clef.start(t)()

	clefIPC := fmt.Sprintf("%v/clef.ipc", dirs.datadir)
	waitForClef(t, clefIPC)

	go stdioListener(clef.stdio)

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		buildWithClef(t, dirs.testout, dirs.datadir, clefIPC)

	defer quorum.start(t)()

	c := createWSQuorumClient(t, "ws://localhost:8546")

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`

	paramsJSON := fmt.Sprintf(`[%v]`, newAccountConfigJson)

	req := NewRPCRequest(t, "plugin@account_newAccount", paramsJSON)
	resp := req.UnixDo(t, true, clef, clefIPC)

	addr := resp["address"].(string)

	var unlockResp interface{}
	err := c.RPCCall(&unlockResp, "personal_unlockAccount", addr, "", 0)
	require.EqualError(t, err, "unlock only supported for keystore or plugin wallets")
}

func Test_Signer_Clef_UnlockAccount(t *testing.T) {
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

	var clefBuilder clefBuilder
	clef := clefBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		stdioUI().
		build(t, dirs.testout, dirs.datadir, pluginsConf)

	defer clef.start(t)()

	clefIPC := fmt.Sprintf("%v/clef.ipc", dirs.datadir)
	waitForClef(t, clefIPC)

	go stdioListener(clef.stdio)

	var quorumBuilder quorumBuilder
	quorum := quorumBuilder.
		addEnv("PRIVATE_CONFIG", "ignore").
		buildWithClef(t, dirs.testout, dirs.datadir, clefIPC)

	defer quorum.start(t)()

	c := createWSQuorumClient(t, "ws://localhost:8546")

	enableSignerPlugin(t, "http://localhost:8200", "root")

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct"
	}`

	paramsJSON := fmt.Sprintf(`[%v]`, newAccountConfigJson)

	req := NewRPCRequest(t, "plugin@account_newAccount", paramsJSON)
	resp := req.UnixDo(t, true, clef, clefIPC)

	addr := resp["address"].(string)

	var unlockResp interface{}
	err := c.RPCCall(&unlockResp, "personal_unlockAccount", addr, "", 0)
	require.EqualError(t, err, "unlock only supported for keystore or plugin wallets")
}
