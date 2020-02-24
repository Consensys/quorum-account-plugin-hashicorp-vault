package config

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestNewAccount_UnmarshalJSON(t *testing.T) {
	b := []byte(`{
		"vault": "http://vault:1111",
		"secretEnginePath": "engine",
		"secretPath": "secret",
		"insecureSkipCAS": true,
		"casValue": 10
	}`)

	want := NewAccount{
		Vault: &url.URL{
			Scheme: "http",
			Host:   "vault:1111",
		},
		SecretEnginePath: "engine",
		SecretPath:       "secret",
		InsecureSkipCAS:  true,
		CASValue:         10,
	}

	var got NewAccount

	err := json.Unmarshal(b, &got)

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestAccountFileJSON_AccountURL(t *testing.T) {
	conf := AccountFileJSON{
		Address: "hexpubkey",
		VaultAccount: vaultAccountJSON{
			SecretEnginePath: "engine",
			SecretPath:       "path",
			SecretVersion:    10,
		},
		ID:      "id",
		Version: 1,
	}

	vaultUrl := "http://vault:1111"

	want := accounts.URL{
		Scheme: "http",
		Path:   "vault:1111/v1/engine/path?version=10",
	}

	got, err := conf.AccountURL(vaultUrl)

	require.NoError(t, err)
	require.Equal(t, want, got)
}
