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

	"github.com/stretchr/testify/require"
)

type quorum struct {
	cmd *exec.Cmd
}

func (q *quorum) start(t *testing.T) func() {
	err := q.cmd.Start()
	require.NoError(t, err)

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
	fmt.Printf("quorum exited, err=%v\n", err)
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

	outfile := fmt.Sprintf("%v/quorum.out", testout)
	log.Printf("quorum log file: path=%v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

	cmd.Stdout = out
	cmd.Stderr = out

	cmd.Env = b.env

	return quorum{cmd: cmd}
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

	outfile := fmt.Sprintf("%v/quorum.out", testout)
	log.Printf("quorum log file: path=%v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

	cmd.Stdout = out
	cmd.Stderr = out

	cmd.Env = b.env

	return quorum{cmd: cmd}
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

	outfile := fmt.Sprintf("%v/quorum.out", testout)
	log.Printf("quorum log file: path=%v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

	// write output to file for debugging, write output to byte buffer for asserting on CLI output
	buf := new(bytes.Buffer)
	w := io.MultiWriter(out, buf)

	cmd.Stdout = w
	cmd.Stderr = w

	cmd.Env = b.env

	return quorum{cmd: cmd}, buf
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
