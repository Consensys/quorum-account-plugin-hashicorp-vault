package vault

import (
	"github.com/ethereum/go-ethereum/accounts"
	"testing"
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

	if err != nil {
		t.Fatal(err)
	}

	if want != got {
		t.Fatalf("want: %v, got: %v", want, got)
	}
}

func TestMakeWalletUrl_ErrorIfInvalidUrl(t *testing.T) {
	userInfo := "authid"
	noSchemeUrl := "url:1"

	_, err := MakeWalletUrl(walletScheme, userInfo, noSchemeUrl)

	if err == nil {
		t.Fatal("error expected")
	}
}
