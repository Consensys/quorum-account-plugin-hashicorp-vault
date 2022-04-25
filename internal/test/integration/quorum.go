package integration

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type quorum struct {
	cmd *exec.Cmd
	out io.Reader
}

func (q *quorum) start(t *testing.T) func() {
	waitForLog := func(logMsg string, timeout time.Duration) {
		log.Println("waiting for quorum to start")
		ch := make(chan struct{})

		go func() {
			var (
				dump []byte
				err  error
			)
			for {
				dump, err = io.ReadAll(q.out)
				if err != nil {
					log.Println("err reading quorum log, err:", err)
					ch <- struct{}{}
					return
				}
				if strings.Contains(string(dump), logMsg) {
					log.Println("quorum account plugin registered")
					ch <- struct{}{}
					return
				}
				// wait a bit before trying again
				time.Sleep(100 * time.Millisecond)
			}
		}()

		select {
		case <-time.After(timeout):
			log.Println("timeout reached")
		case <-ch:
		}

		log.Println("assuming quorum has started")
	}

	err := q.cmd.Start()
	require.NoError(t, err)

	waitForLog("registered account plugin with account backend", 5*time.Second)

	interrupt := func() {
		if q.cmd.ProcessState == nil {
			err := q.cmd.Process.Signal(os.Interrupt)
			require.NoError(t, err)
		}
	}

	return interrupt
}

func (q *quorum) wait(_ *testing.T) {
	err := q.cmd.Wait()
	log.Printf("quorum exited, err=%v\n", err)
}

type quorumBuilder struct {
	env []string
}

func (b *quorumBuilder) addEnv(key, value string) *quorumBuilder {
	b.env = append(b.env, fmt.Sprintf("%v=%v", key, value))
	return b
}

func (b *quorumBuilder) build(t *testing.T, testout, datadir, pluginsConf string) quorum {
	args := []string{
		"--allow-insecure-unlock",
		"--nodiscover",
		"--verbosity",
		"5",
		"--networkid",
		"10",
		"--raft",
		"--raftjoinexisting",
		"1",
		"--datadir",
		datadir,
		"--ws",
		"--ws.api",
		"eth,personal,plugin@account",
		"--plugins",
		fmt.Sprintf("file://%v", pluginsConf),
		"--plugins.skipverify",
	}

	log.Printf("preparing to start: geth %v", strings.Join(args, " "))

	cmd := exec.Command("geth", args...)

	outfile := fmt.Sprintf("%v/quorum.log", testout)
	log.Printf("quorum log file: path=%v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

	// write output to file for debugging, write output to byte buffer for waiting on startup
	buf := new(bytes.Buffer)
	w := io.MultiWriter(out, buf)

	cmd.Stdout = w
	cmd.Stderr = w

	cmd.Env = b.env

	return quorum{cmd: cmd, out: buf}
}

func (b *quorumBuilder) buildWithClef(t *testing.T, testout, datadir, clefIPC string) quorum {
	args := []string{
		"--allow-insecure-unlock",
		"--nodiscover",
		"--verbosity",
		"5",
		"--networkid",
		"10",
		"--raft",
		"--raftjoinexisting",
		"1",
		"--datadir",
		datadir,
		"--ws",
		"--ws.api",
		"eth,personal,plugin@account",
		"--signer",
		clefIPC,
	}

	log.Printf("preparing to start: geth %v", strings.Join(args, " "))

	cmd := exec.Command("geth", args...)

	outfile := fmt.Sprintf("%v/quorum.log", testout)
	log.Printf("quorum log file: path=%v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

	// write output to file for debugging, write output to byte buffer for waiting on startup
	buf := new(bytes.Buffer)
	w := io.MultiWriter(out, buf)

	cmd.Stdout = w
	cmd.Stderr = w

	cmd.Env = b.env

	return quorum{cmd: cmd, out: buf}
}

func (b *quorumBuilder) buildAccountPluginCLICmd(t *testing.T, subCmd, importKey, testout, pluginsConf, newAccountConf string) (quorum, *bytes.Buffer) {
	args := []string{
		"account",
		"plugin",
		subCmd,
		"--plugins",
		fmt.Sprintf("file://%v", pluginsConf),
		"--plugins.skipverify",
		"--plugins.account.config",
		newAccountConf,
		importKey,
	}

	log.Printf("preparing to start: geth %v", strings.Join(args, " "))

	cmd := exec.Command("geth", args...)

	outfile := fmt.Sprintf("%v/quorum.log", testout)
	log.Printf("quorum log file: path=%v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

	// write output to file for debugging, write output to byte buffer for waiting on startup and asserting on CLI output
	buf := new(bytes.Buffer)
	cliBuf := new(bytes.Buffer)
	w := io.MultiWriter(out, buf, cliBuf)

	cmd.Stdout = w
	cmd.Stderr = w

	cmd.Env = b.env

	return quorum{cmd: cmd, out: buf}, cliBuf
}

func createPluginsConfig(t *testing.T, testout string, baseDir string, version string, vaultPluginConfig string) string {
	outfile := fmt.Sprintf("%v/plugins.json", testout)
	log.Printf("creating %v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

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
	require.NoError(t, err)

	return outfile
}

func createVaultKVPluginConfig(t *testing.T, testout string) string {
	outfile := fmt.Sprintf("%v/vault-plugin-for-quorum.json", testout)
	log.Printf("creating %v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

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
	require.NoError(t, err)

	return outfile
}

func createVaultSignerPluginConfig(t *testing.T, testout string) string {
	outfile := fmt.Sprintf("%v/vault-plugin-for-quorum.json", testout)
	log.Printf("creating %v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

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
	require.NoError(t, err)

	return outfile
}
