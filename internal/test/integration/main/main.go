package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testDirName = strconv.FormatInt(time.Now().UnixNano(), 10)
var distDir = getEnvOrFallback("PLUGIN_DIST", "/Users/chris/Work/quorum-account-plugin-hashicorp-vault/build/dist")
var distVersion = getEnvOrFallback("PLUGIN_VERSION", "0.2.1-SNAPSHOT")

func getEnvOrFallback(env, fallback string) string {
	if val, ok := os.LookupEnv(env); ok {
		return val
	} else {
		return fallback
	}
}

func main() {
	dirs := prepareDirs(testDirName)

	vaultPluginConf := createVaultKVPluginConfig(dirs.testout)
	pluginsConf := createPluginsConfig(
		dirs.testout,
		distDir,
		distVersion,
		vaultPluginConf)

	var clefBuilder clefBuilder
	clef := clefBuilder.
		addEnv("HASHICORP_TOKEN", "root").
		stdioUI().
		build(dirs.testout, dirs.datadir, pluginsConf)

	defer clef.start()()

	clefIPC := fmt.Sprintf("%v/clef.ipc", dirs.datadir)
	waitForClef(clefIPC)

	stdioListener(clef.stdio)
}

func stdioListener(stdio stdioPipes) {
	log.Println("starting clef stdio listener")
	defer log.Println("stopped clef stdio listener")

	jsonDecoder := json.NewDecoder(stdio.stdoutPipe)
	var req map[string]interface{}

	for {
		err := jsonDecoder.Decode(&req)
		if err != nil {
			panic(err)
		}

		method, ok := req["method"]
		if !ok {
			log.Printf("cannot handle received stdio %v", req)
		}

		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
		}

		switch method {
		case "ui_approveNewAccount":
			log.Println("Received ui_approveNewAccount")
			resp["result"] = ApprovalResponse{Approved: true}
		case "ui_onInputRequired":
			log.Println("Received ui_onInputRequired")
			resp["result"] = InputResponse{Text: ""}
		}

		jsonResp, err := json.Marshal(resp)
		if err != nil {
			panic(err)
		}

		n, err := stdio.stdinPipe.Write(jsonResp)
		if err != nil {
			panic(err)
		}
		if n == 0 {
			panic("nothing written")
		}
	}
}

type ApprovalResponse struct {
	Approved bool
}

type InputResponse struct {
	Text string
}

type clef struct {
	cmd   *exec.Cmd
	stdio stdioPipes
}

func (c *clef) start() func() {
	err := c.cmd.Start()
	if err != nil {
		panic(err)
	}

	interrupt := func() {
		err := c.cmd.Process.Signal(os.Interrupt)
		if err != nil {
			panic(err)
		}
	}

	return interrupt
}

// ok sends ok to the cmd's stdin
func (c *clef) ok(t *testing.T) {
	_, err := io.WriteString(c.stdio.stdinPipe, "ok\n")
	require.NoError(t, err)
}

// y sends y to the cmd's stdin
func (c *clef) y(t *testing.T) {
	_, err := io.WriteString(c.stdio.stdinPipe, "y\n")
	require.NoError(t, err)
}

type clefBuilder struct {
	env  []string
	args []string
}

func (b *clefBuilder) addEnv(key, value string) *clefBuilder {
	b.env = append(b.env, fmt.Sprintf("%v=%v", key, value))
	return b
}

func (b *clefBuilder) stdioUI() *clefBuilder {
	b.args = append(b.args, "--stdio-ui")
	return b
}

func (b *clefBuilder) build(testout, datadir, pluginsConf string) clef {
	// random, empty, keystore so default keystore is not used
	stdKeystore := fmt.Sprintf("/tmp/acct-plugin-tests/%v", rand.Int())

	args := b.args
	args = append(args,
		"--auditlog",
		fmt.Sprintf("%v/clefaudit.log", testout),
		"--ipcpath",
		datadir,
		"--keystore",
		stdKeystore,
		"--plugins",
		fmt.Sprintf("file://%v", pluginsConf),
		"--plugins.skipverify",
	)

	log.Printf("preparing to start: clef %v", strings.Join(args, " "))

	cmd := exec.Command("clef", args...)

	outfile := fmt.Sprintf("%v/clef.out", testout)
	log.Printf("clef log file: path=%v", outfile)
	out, err := os.Create(outfile)
	if err != nil {
		panic(err)
	}

	var stdioui bool
	for _, arg := range args {
		if arg == "--stdio-ui" {
			stdioui = true
		}
	}

	cmd.Env = b.env

	var stdio stdioPipes

	if stdioui {
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			panic(err)
		}
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			panic(err)
		}
		cmd.Stderr = out

		stdio = stdioPipes{
			stdinPipe:  stdinPipe,
			stdoutPipe: stdoutPipe,
		}
	} else {
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			panic(err)
		}
		cmd.Stdout = out
		cmd.Stderr = out

		stdio = stdioPipes{
			stdinPipe: stdinPipe,
		}
	}

	return clef{cmd: cmd, stdio: stdio}
}

type stdioPipes struct {
	stdinPipe  io.WriteCloser
	stdoutPipe io.ReadCloser
}

func waitForClef(clefIPC string) {
	var (
		attempt     = 0
		maxAttempts = 10
		waitPeriod  = time.Second
	)

	for {
		attempt++
		<-time.After(waitPeriod)

		log.Printf("checking Clef IPC server is up: attempt %v/%v", attempt, maxAttempts)

		if _, err := os.Stat(clefIPC); err == nil {
			log.Printf("Clef IPC server is up: attempt %v/%v", attempt, maxAttempts)
			break
		} else if os.IsNotExist(err) {
			log.Printf("Clef IPC server is not up: attempt %v/%v", attempt, maxAttempts)
		} else {
			log.Printf("Clef IPC server is not up: attempt %v/%v, err = %v", attempt, maxAttempts, err)
		}

		if attempt == maxAttempts {
			panic("Clef IPC server retries exceeded")
		}
	}
}

func prepareDirs(suiteName string) dirs {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	testoutRoot := fmt.Sprintf("%v/testout", wd)
	if _, err := os.Stat(testoutRoot); os.IsNotExist(err) {
		log.Printf("creating testout root dir: path=%v", testoutRoot)
		err = os.Mkdir(testoutRoot, 0700)
		if err != nil {
			panic(err)
		}
	} else {
		log.Printf("testout root dir already exists: path=%v", testoutRoot)
	}

	testout := fmt.Sprintf("%v/%v", testoutRoot, suiteName)
	if _, err := os.Stat(testout); os.IsNotExist(err) {
		log.Printf("creating testout dir: path=%v", testout)
		err = os.Mkdir(testout, 0700)
		if err != nil {
			panic(err)
		}
	} else {
		log.Printf("testout dir already exists: path=%v", testout)
	}

	//log.Printf("creating currentTestout dir: path=%v", testout)
	//err = os.Mkdir(testout, 0700)
	//if err != nil {
	//	panic(err)
	//}

	// we have to hash the testName when creating the dataDir as IPC paths cannot exceed 104 chars
	datadir := fmt.Sprintf("/tmp/acct-plugin-tests/datadir/%v", suiteName)

	return dirs{
		testout: testout,
		datadir: datadir,
	}
}

type dirs struct {
	testout string
	datadir string
}

func createPluginsConfig(testout string, baseDir string, version string, vaultPluginConfig string) string {
	outfile := fmt.Sprintf("%v/plugins.json", testout)
	log.Printf("creating %v", outfile)
	out, err := os.Create(outfile)
	if err != nil {
		panic(err)
	}

	conf := fmt.Sprintf(`{
    "baseDir": "%v",
    "providers": {
        "account": {
            "name": "quorum-account-plugin-hashicorp-vault",
            "version": "%v",
            "config": "file://%v"
        }
    }
}`, baseDir, version, vaultPluginConfig)

	src := strings.NewReader(conf)

	_, err = io.Copy(out, src)
	if err != nil {
		panic(err)
	}

	return outfile
}

func createVaultKVPluginConfig(testout string) string {
	outfile := fmt.Sprintf("%v/vault-plugin-for-quorum.json", testout)
	log.Printf("creating %v", outfile)
	out, err := os.Create(outfile)
	if err != nil {
		panic(err)
	}

	conf := fmt.Sprintf(`{
    "vault": "http://localhost:8200",
    "kvEngineName": "secret",
    "accountDirectory": "file://%v/plugin-accts",
    "authentication": {
        "token": "env://HASHICORP_TOKEN"
    }
}`, testout)

	src := strings.NewReader(conf)

	_, err = io.Copy(out, src)
	if err != nil {
		panic(err)
	}

	return outfile
}

func createVaultSignerPluginConfig(testout string) string {
	outfile := fmt.Sprintf("%v/vault-plugin-for-quorum.json", testout)
	log.Printf("creating %v", outfile)
	out, err := os.Create(outfile)
	if err != nil {
		panic(err)
	}

	conf := fmt.Sprintf(`{
    "vault": "http://localhost:8200",
    "quorumSignerEngineName": "quorum-signer",
    "accountDirectory": "file://%v/plugin-accts",
    "authentication": {
        "token": "env://HASHICORP_TOKEN"
    }
}`, testout)

	src := strings.NewReader(conf)

	_, err = io.Copy(out, src)
	if err != nil {
		panic(err)
	}

	return outfile
}
