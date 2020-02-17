package config

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestVaultClient_UnmarshalJSON(t *testing.T) {

	b := []byte(`{
		"vault": "http://vault:1111",
		"accountDirectory": "file:///path/to/dir",
		"unlock": [
			"0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5",
			"0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526"
		],
		"authorization": {
			"roleId": "env://MY_ROLE_ID",
			"secretId": "env://MY_SECRET_ID",
			"approlePath": "my-role"
		},
		"tls": {
			"caCert": "file:///path/to/ca.pem",
			"clientCert": "file:///path/to/client.pem",
			"clientKey": "file:///path/to/client.key"
		}
	}`)

	want := VaultClient{
		Vault: url.URL{
			Scheme: "http",
			Host:   "vault:1111",
		},
		AccountDirectory: url.URL{
			Scheme: "file",
			Path:   "/path/to/dir",
		},
		Unlock: []string{
			"0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5",
			"0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526",
		},
		Authorization: vaultClientAuthorization{
			RoleId: environmentVariable{
				Scheme: "env",
				Host:   "MY_ROLE_ID",
			},
			SecretId: environmentVariable{
				Scheme: "env",
				Host:   "MY_SECRET_ID",
			},
			ApprolePath: "my-role",
		},
		TLS: vaultClientTLS{
			CaCert: url.URL{
				Scheme: "file",
				Path:   "/path/to/ca.pem",
			},
			ClientCert: url.URL{
				Scheme: "file",
				Path:   "/path/to/client.pem",
			},
			ClientKey: url.URL{
				Scheme: "file",
				Path:   "/path/to/client.key",
			},
		},
	}

	var got VaultClient

	err := json.Unmarshal(b, &got)

	require.NoError(t, err)
	require.IsType(t, VaultClient{}, got)
	require.Equal(t, want, got)
}
