// +build clefintegration

package integration

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_KV_Clef_SignTransaction(t *testing.T) {
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

	var signResp map[string]interface{}

	toSign := map[string]string{
		"from":     addr,
		"input":    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"gas":      "0x1",
		"gasPrice": "0x1",
		"nonce":    "0x0",
	}

	err := c.RPCCall(&signResp, "eth_signTransaction", toSign)
	require.NoError(t, err)

	sig := signResp["raw"].(string)

	require.True(t, strings.HasPrefix(sig, "0x"))
	h, err := hex.DecodeString(strings.TrimPrefix(sig, "0x"))
	require.NoError(t, err)
	require.NotEmpty(t, h)
}

func Test_KV_Clef_PersonalSignTransaction_NotSupported(t *testing.T) {
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

	var signResp map[string]interface{}

	toSign := map[string]string{
		"from":     addr,
		"input":    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"gas":      "0x1",
		"gasPrice": "0x1",
		"nonce":    "0x0",
	}

	err := c.RPCCall(&signResp, "personal_signTransaction", toSign, "")
	require.EqualError(t, err, "password-operations not supported on external signers")
}

func Test_Signer_Clef_SignTransaction(t *testing.T) {
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

	var signResp map[string]interface{}

	toSign := map[string]string{
		"from":     addr,
		"input":    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"gas":      "0x1",
		"gasPrice": "0x1",
		"nonce":    "0x0",
	}

	err := c.RPCCall(&signResp, "eth_signTransaction", toSign)
	require.NoError(t, err)

	sig := signResp["raw"].(string)

	require.True(t, strings.HasPrefix(sig, "0x"))
	h, err := hex.DecodeString(strings.TrimPrefix(sig, "0x"))
	require.NoError(t, err)
	require.NotEmpty(t, h)
}

func Test_Signer_Clef_PersonalSignTransaction(t *testing.T) {
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

	var signResp map[string]interface{}

	toSign := map[string]string{
		"from":     addr,
		"input":    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"gas":      "0x1",
		"gasPrice": "0x1",
		"nonce":    "0x0",
	}

	err := c.RPCCall(&signResp, "personal_signTransaction", toSign, "")
	require.EqualError(t, err, "password-operations not supported on external signers")
}
