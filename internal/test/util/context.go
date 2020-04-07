package util

import (
	"errors"
	"io/ioutil"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hashicorp/go-plugin"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/test/builders"
	"github.com/stretchr/testify/require"
)

type ITContext struct {
	Client                 *plugin.GRPCClient
	Server                 *plugin.GRPCServer
	Vault                  *httptest.Server
	AccountConfigDirectory string
	AccountManager         *hashicorpPluginGRPCClient
}

// starts a plugin server and client, returning the client
func (c *ITContext) StartPlugin(t *testing.T) error {
	client, server := plugin.TestPluginGRPCConn(t, map[string]plugin.Plugin{
		"impl": new(testableHashicorpPlugin),
	})

	c.Client = client
	c.Server = server

	raw, err := client.Dispense("impl")
	if err != nil {
		return err
	}

	acctman, ok := raw.(hashicorpPluginGRPCClient)
	if !ok {
		return errors.New("unable to get plugin grpc client")
	}
	c.AccountManager = &acctman
	return nil
}

func (c *ITContext) StartTLSVaultServer(t *testing.T, b builders.VaultBuilder) {
	vault := b.Build(t)
	vault.StartTLS()
	c.Vault = vault
}

func (c *ITContext) CreateAccountConfigDirectory(t *testing.T) {
	dir, err := ioutil.TempDir(".", "temp-acctconf")
	require.NoError(t, err)
	c.AccountConfigDirectory = dir
}

func (c *ITContext) WriteToAccountConfigDirectory(t *testing.T, d []byte) error {
	if c.AccountConfigDirectory == "" {
		return errors.New("accountConfigDirectory not set in context")
	}

	tmpFile, err := ioutil.TempFile(c.AccountConfigDirectory, "")
	require.NoError(t, err)

	_, err = tmpFile.Write(d)
	require.NoError(t, err)

	err = tmpFile.Close()
	require.NoError(t, err)

	return nil
}

func (c *ITContext) Cleanup() {
	if c.Client != nil {
		c.Client.Close()
	}
	if c.Server != nil {
		c.Server.Stop()
	}
	if c.Vault != nil {
		c.Vault.Close()
	}
	if c.AccountConfigDirectory != "" {
		os.RemoveAll(c.AccountConfigDirectory)
	}
}
