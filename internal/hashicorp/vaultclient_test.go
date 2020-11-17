package hashicorp

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/ConsenSys/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/stretchr/testify/require"
)

func TestVaultClient_LoadAccounts_AccountDirectoryCreatedIfDoesntExist(t *testing.T) {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	require.NoError(t, err)

	dir := fmt.Sprintf("%v/accts-%x", os.TempDir(), buf)
	defer os.RemoveAll(dir)

	acctDir, err := url.Parse(dir)
	require.NoError(t, err)

	acctDirPath := acctDir.Host + "/" + acctDir.Path
	_, err = os.Stat(acctDirPath)
	require.True(t, os.IsNotExist(err))

	c := vaultClient{
		accountDirectory: acctDir,
	}

	result, err := c.loadAccounts()
	require.Len(t, result, 0)
	require.NoError(t, err)

	_, err = os.Stat(acctDirPath)
	require.DirExists(t, acctDirPath)
}

func TestConvertTLSConfig(t *testing.T) {
	caCert, _ := url.Parse("file:///leading/slash/ca.cert")
	clientCert, _ := url.Parse("file://path/to/client.cert")
	clientKey, _ := url.Parse("file://path/to/client.key")

	tls := config.VaultClientTLS{
		CaCert:     caCert,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	}

	got := convertTLSConfig(tls)

	require.Equal(t, "/leading/slash/ca.cert", got.CACert)
	require.Equal(t, "path/to/client.cert", got.ClientCert)
	require.Equal(t, "path/to/client.key", got.ClientKey)
}

func TestConvertTLSConfigNoUrls(t *testing.T) {
	emptyUrl, _ := url.Parse("")

	tls := config.VaultClientTLS{
		CaCert:     emptyUrl,
		ClientCert: emptyUrl,
		ClientKey:  emptyUrl,
	}

	got := convertTLSConfig(tls)

	require.Equal(t, "", got.CACert)
	require.Equal(t, "", got.ClientCert)
	require.Equal(t, "", got.ClientKey)
}
