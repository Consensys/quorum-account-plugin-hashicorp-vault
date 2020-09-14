// +build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_CLI_KV_ImportAccount_NewPath_ValidOverwriteProtection(t *testing.T) {
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

	rawKey := "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"
	wantAddr := "0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5" // addr derived from the rawKey

	rawKeyFile := fmt.Sprintf("%v/raw.key", dirs.testout)
	err := ioutil.WriteFile(rawKeyFile, []byte(rawKey), 0700)
	require.NoError(t, err)

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`

	var quorumBuilder quorumBuilder
	quorum, outBuf := quorumBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		buildAccountPluginCLICmd(t, "import", rawKeyFile, dirs.testout, pluginsConf, newAccountConfigJson)

	defer quorum.start(t)()

	<-time.After(2 * time.Second)

	out := outBuf.String()

	addrRegex := regexp.MustCompile("Public address of the account:\\s*(0x[0-9a-fA-F]{40})\\s*\\n")
	require.Regexp(t, addrRegex, out)

	addrMatches := addrRegex.FindStringSubmatch(out)
	acctAddr := strings.ToLower(addrMatches[1])
	require.Equal(t, wantAddr, acctAddr)

	urlRegex := regexp.MustCompile("Account URL:\\s*([0-9a-zA-Z/:?=].+)\\s*\\n")
	require.Regexp(t, urlRegex, out)

	urlMatches := urlRegex.FindStringSubmatch(out)
	acctURL := urlMatches[1]

	wantURL := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", "localhost:8200", "secret", "myAcct", 1)
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
}

func Test_CLI_KV_ImportAccount_NewPath_InvalidOverwriteProtection(t *testing.T) {
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

	rawKey := "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"

	rawKeyFile := fmt.Sprintf("%v/raw.key", dirs.testout)
	err := ioutil.WriteFile(rawKeyFile, []byte(rawKey), 0700)
	require.NoError(t, err)

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 1
		}
	}`

	var quorumBuilder quorumBuilder
	quorum, outBuf := quorumBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		buildAccountPluginCLICmd(t, "import", rawKeyFile, dirs.testout, pluginsConf, newAccountConfigJson)

	defer quorum.start(t)()

	<-time.After(2 * time.Second)

	out := outBuf.String()

	require.Contains(t, out, "check-and-set parameter did not match the current version")

	// check that no acct data is added to vault
	getKVSecretExpect404(t, "http://localhost:8200", "secret", "myAcct", 1, "root")

	// check that no file is created in acct dir
	targetDir := fmt.Sprintf("%v/plugin-accts", dirs.testout)

	files, err := findFile(targetDir, "*")
	require.NoError(t, err)
	require.Len(t, files, 0, "no files should have been created - ensure starting environment has no files")
}

func Test_CLI_KV_ImportAccount_ExistingPath_ValidOverwriteProtection(t *testing.T) {
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

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`

	var quorumBuilder quorumBuilder
	quorum, outBuf := quorumBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		buildAccountPluginCLICmd(t, "new", "", dirs.testout, pluginsConf, newAccountConfigJson)

	defer quorum.start(t)()

	<-time.After(2 * time.Second)

	// create another account
	rawKey := "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"
	wantAddr := "0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5" // addr derived from the rawKey

	rawKeyFile := fmt.Sprintf("%v/raw.key", dirs.testout)
	err := ioutil.WriteFile(rawKeyFile, []byte(rawKey), 0700)
	require.NoError(t, err)

	newAccountConfigJson = `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 1
		}
	}`

	quorum, outBuf = quorumBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		buildAccountPluginCLICmd(t, "import", rawKeyFile, dirs.testout, pluginsConf, newAccountConfigJson)

	defer quorum.start(t)()

	<-time.After(2 * time.Second)

	out := outBuf.String()

	addrRegex := regexp.MustCompile("Public address of the account:\\s*(0x[0-9a-fA-F]{40})\\s*\\n")
	require.Regexp(t, addrRegex, out)

	addrMatches := addrRegex.FindStringSubmatch(out)
	acctAddr := strings.ToLower(addrMatches[1])
	require.Equal(t, wantAddr, acctAddr)

	urlRegex := regexp.MustCompile("Account URL:\\s*([0-9a-zA-Z/:?=].+)\\s*\\n")
	require.Regexp(t, urlRegex, out)

	urlMatches := urlRegex.FindStringSubmatch(out)
	acctURL := urlMatches[1]

	wantURL := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", "localhost:8200", "secret", "myAcct", 2)
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
}

func Test_CLI_KV_ImportAccount_ExistingPath_InvalidOverwriteProtection(t *testing.T) {
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

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`

	var quorumBuilder quorumBuilder
	quorum, outBuf := quorumBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		buildAccountPluginCLICmd(t, "new", "", dirs.testout, pluginsConf, newAccountConfigJson)

	defer quorum.start(t)()

	<-time.After(2 * time.Second)

	// create another account
	rawKey := "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"

	rawKeyFile := fmt.Sprintf("%v/raw.key", dirs.testout)
	err := ioutil.WriteFile(rawKeyFile, []byte(rawKey), 0700)
	require.NoError(t, err)

	newAccountConfigJson = `{
	   "secretName": "myAcct",
		"overwriteProtection": {
			"currentVersion": 0
		}
	}`

	quorum, outBuf = quorumBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		buildAccountPluginCLICmd(t, "import", rawKeyFile, dirs.testout, pluginsConf, newAccountConfigJson)

	defer quorum.start(t)()

	<-time.After(2 * time.Second)

	out := outBuf.String()

	require.Contains(t, out, "check-and-set parameter did not match the current version")

	// check that no acct data is added to vault
	getKVSecretExpect404(t, "http://localhost:8200", "secret", "myAcct", 2, "root")

	// check that no file is created in acct dir
	targetDir := fmt.Sprintf("%v/plugin-accts", dirs.testout)

	files, err := findFile(targetDir, "*")
	require.NoError(t, err)
	require.Len(t, files, 1, "no file should have been created - ensure starting environment has no files")
}

func Test_CLI_Signer_ImportAccount_NewPath(t *testing.T) {
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

	<-time.After(2 * time.Second)
	enableSignerPlugin(t, "http://localhost:8200", "root")

	rawKey := "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"
	wantAddr := "0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5" // addr derived from the rawKey

	rawKeyFile := fmt.Sprintf("%v/raw.key", dirs.testout)
	err := ioutil.WriteFile(rawKeyFile, []byte(rawKey), 0700)
	require.NoError(t, err)

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct"
	}`

	var quorumBuilder quorumBuilder
	quorum, outBuf := quorumBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		buildAccountPluginCLICmd(t, "import", rawKeyFile, dirs.testout, pluginsConf, newAccountConfigJson)

	defer quorum.start(t)()

	<-time.After(2 * time.Second)

	out := outBuf.String()

	addrRegex := regexp.MustCompile("Public address of the account:\\s*(0x[0-9a-fA-F]{40})\\s*\\n")
	require.Regexp(t, addrRegex, out)

	addrMatches := addrRegex.FindStringSubmatch(out)
	acctAddr := strings.ToLower(addrMatches[1])
	require.Equal(t, wantAddr, acctAddr)

	urlRegex := regexp.MustCompile("Account URL:\\s*([0-9a-zA-Z/:?=].+)\\s*\\n")
	require.Regexp(t, urlRegex, out)

	urlMatches := urlRegex.FindStringSubmatch(out)
	acctURL := urlMatches[1]

	wantURL := fmt.Sprintf("%v/v1/%v/accounts/%v?version=%v", "localhost:8200", "quorum-signer", "myAcct", 0)
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

	require.Equal(t, strings.TrimPrefix(acctAddr, "0x"), contents["Address"].(string), "data returned in RPC response and written to file are different")
	vaultData := contents["VaultAccount"].(map[string]interface{})

	require.Equal(t, float64(0), vaultData["SecretVersion"].(float64), "incorrect data written to file")
	require.Equal(t, "myAcct", vaultData["SecretName"].(string), "incorrect data written to file")
}

func Test_CLI_Signer_ImportAccount_ExistingPath_NotAllowed(t *testing.T) {
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

	<-time.After(2 * time.Second)
	enableSignerPlugin(t, "http://localhost:8200", "root")

	// create account
	newAccountConfigJson := `{
	   "secretName": "myAcct"
	}`

	var quorumBuilder quorumBuilder
	quorum, outBuf := quorumBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		buildAccountPluginCLICmd(t, "new", "", dirs.testout, pluginsConf, newAccountConfigJson)

	defer quorum.start(t)()

	<-time.After(2 * time.Second)

	// create another account
	rawKey := "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"

	rawKeyFile := fmt.Sprintf("%v/raw.key", dirs.testout)
	err := ioutil.WriteFile(rawKeyFile, []byte(rawKey), 0700)
	require.NoError(t, err)

	newAccountConfigJson = `{
	   "secretName": "myAcct"
	}`

	quorum, outBuf = quorumBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		buildAccountPluginCLICmd(t, "import", rawKeyFile, dirs.testout, pluginsConf, newAccountConfigJson)

	defer quorum.start(t)()

	<-time.After(10 * time.Second)

	out := outBuf.String()

	require.Contains(t, out, "rpc error: code = Internal desc = unable to create new account in Vault")
	require.Contains(t, out, "updating existing secrets is not supported")

	// check that no acct data is added to vault
	getSignerSecretExpect404(t, "http://localhost:8200", "secret", "myAcct", "root")

	// check that no file is created in acct dir
	targetDir := fmt.Sprintf("%v/plugin-accts", dirs.testout)

	files, err := findFile(targetDir, "*")
	require.NoError(t, err)
	require.Len(t, files, 1, "no file should have been created - ensure starting environment has no files")
}
