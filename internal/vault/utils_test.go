package vault

import (
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/stretchr/testify/require"
)

const walletScheme = "wlt"

func TestMakeWalletUrl_ReplacesSchemeAndAddsAuthorizationInformation(t *testing.T) {
	userInfo := "foo"
	strUrl := "http://url:1"

	want := accounts.URL{
		Scheme: walletScheme,
		Path:   "foo@url:1",
	}

	got, err := MakeWalletUrl(walletScheme, userInfo, strUrl)

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestMakeWalletUrl_ErrorIfInvalidUrl(t *testing.T) {
	userInfo := "authid"
	noSchemeUrl := "url:1"

	_, err := MakeWalletUrl(walletScheme, userInfo, noSchemeUrl)

	require.Error(t, err)
}
