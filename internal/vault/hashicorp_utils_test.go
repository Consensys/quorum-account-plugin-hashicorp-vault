package vault

import (
	"github.com/ethereum/go-ethereum/accounts"
	"testing"
)

func TestMakeWalletUrl_ReplacesSchemeAndAddsAuthorizationInformation(t *testing.T) {
	strUrl := "http://url:1"
	authId := "foo"

	want := accounts.URL{
		Scheme: WalletScheme,
		Path:   "foo@url:1",
	}

	got, err := MakeWalletUrl(strUrl, authId)

	if err != nil {
		t.Fatal(err)
	}

	if want != got {
		t.Fatalf("want: %v, got: %v", want, got)
	}
}

func TestMakeWalletUrl_ErrorIfInvalidUrl(t *testing.T) {
	noSchemeUrl := "url:1"
	authId := "authid"

	_, err := MakeWalletUrl(noSchemeUrl, authId)

	if err == nil {
		t.Fatal("error expected")
	}
}
