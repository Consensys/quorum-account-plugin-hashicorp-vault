package hashicorp

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVaultClient_LoadWallets_AccountDirectoryCreatedIfDoesntExist(t *testing.T) {
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

	result, err := c.loadWallets()
	require.Len(t, result, 0)
	require.NoError(t, err)

	_, err = os.Stat(acctDirPath)
	require.DirExists(t, acctDirPath)
}
