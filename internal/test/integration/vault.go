package integration

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"os/exec"
	"testing"
)

type vault struct {
	cmd *exec.Cmd
}

func (v *vault) start(t *testing.T) func() {
	err := v.cmd.Start()
	require.NoError(t, err)

	interrupt := func() {
		err := v.cmd.Process.Signal(os.Interrupt)
		require.NoError(t, err)
	}

	return interrupt
}

type vaultBuilder struct {
	devArgs []string
}

func (b *vaultBuilder) devMode(rootToken string) *vaultBuilder {
	b.devArgs = []string{
		"server",
		"-dev",
		"-dev-root-token-id=" + rootToken,
	}
	return b
}

func (b *vaultBuilder) withPlugins() *vaultBuilder {
	b.devArgs = append(b.devArgs, "-dev-plugin-dir="+vaultPluginDir)
	return b
}

func (b *vaultBuilder) build(t *testing.T, testout string) vault {
	cmd := exec.Command(
		"vault",
		b.devArgs...,
	)

	outfile := fmt.Sprintf("%v/vault.out", testout)
	log.Printf("vault log file: path=%v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

	cmd.Stdout = out
	cmd.Stderr = out

	return vault{cmd: cmd}
}
