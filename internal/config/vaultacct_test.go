package config

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/stretchr/testify/require"
)

func TestNewAccount_UnmarshalJSON(t *testing.T) {
	b := []byte(`{
		"secretName": "secret",
		"overwriteProtection": {
			"insecureDisable": true,
			"currentVersion": 10
		}
	}`)

	want := NewAccount{
		SecretName: "secret",
		OverwriteProtection: OverwriteProtection{
			InsecureDisable: true,
			CurrentVersion:  10,
		},
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
			SecretName:    "path",
			SecretVersion: 10,
		},
		Version: 1,
	}

	vaultUrl := "http://vault:1111"

	want := accounts.URL{
		Scheme: "http",
		Path:   "vault:1111/v1/engine/data/path?version=10",
	}

	got, err := conf.AccountURL(vaultUrl, "engine")

	require.NoError(t, err)
	require.Equal(t, want, got)
}
