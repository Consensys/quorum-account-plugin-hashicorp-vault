//go:build clefintegration
// +build clefintegration

package integration

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_KV_Clef_Sign(t *testing.T) {
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

	var signResp string

	toSign := "0xaaaaaa"

	err := c.RPCCall(&signResp, "eth_sign", addr, toSign)
	require.NoError(t, err)

	require.True(t, strings.HasPrefix(signResp, "0x"))
	h, err := hex.DecodeString(strings.TrimPrefix(signResp, "0x"))
	require.NoError(t, err)
	require.Len(t, h, 65)
}

func Test_KV_Clef_PersonalSign_NotSupported(t *testing.T) {
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

	var signResp string

	toSign := "0xaaaaaa"

	err := c.RPCCall(&signResp, "personal_sign", toSign, addr, "")
	require.EqualError(t, err, "password-operations not supported on external signers")
}

func Test_Signer_Clef_Sign(t *testing.T) {
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

	var signResp string

	toSign := "0xaaaaaa"

	err := c.RPCCall(&signResp, "eth_sign", addr, toSign)
	require.NoError(t, err)

	require.True(t, strings.HasPrefix(signResp, "0x"))
	h, err := hex.DecodeString(strings.TrimPrefix(signResp, "0x"))
	require.NoError(t, err)
	require.Len(t, h, 65)
}

func Test_Signer_Clef_PersonalSign_NotSupported(t *testing.T) {
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

	var signResp string

	toSign := "0xaaaaaa"

	err := c.RPCCall(&signResp, "personal_sign", toSign, addr, "")
	require.EqualError(t, err, "password-operations not supported on external signers")
}
