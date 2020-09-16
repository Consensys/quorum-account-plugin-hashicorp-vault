package integration

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_KV_Clef_ImportAccount_NotSupported(t *testing.T) {
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

	rawKey := "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"

	paramsJSON := fmt.Sprintf(`["%v", %v]`, rawKey, newAccountConfigJson)

	req := NewRPCRequest(t, "plugin@account_importRawKey", paramsJSON)
	respErr := req.UnixDoExpectError(t, clef, clefIPC)

	require.Contains(t, respErr, "not supported")
}

func Test_Signer_Clef_ImportAccount_NotSupported(t *testing.T) {
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

	rawKey := "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"

	paramsJSON := fmt.Sprintf(`["%v", %v]`, rawKey, newAccountConfigJson)

	req := NewRPCRequest(t, "plugin@account_importRawKey", paramsJSON)
	respErr := req.UnixDoExpectError(t, clef, clefIPC)

	require.Contains(t, respErr, "not supported")
}
