package config

import (
	"encoding/json"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVaultClient_UnmarshalJSON(t *testing.T) {
	b := []byte(`{
		"vault": "http://vault:1111",
	    "kvEngineName": "kv-engine",
		"quorumSignerEngineName": "signer-engine",
		"accountDirectory": "file:///path/to/dir/",
		"unlock": [
			"0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5",
			"0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526"
		],
		"authentication": {
			"token": "env://MY_TOKEN",
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
		VaultClientBase: VaultClientBase{
			Vault: &url.URL{
				Scheme: "http",
				Host:   "vault:1111",
			},
			AccountDirectory: &url.URL{
				Scheme: "file",
				Path:   "/path/to/dir/",
			},
			Authentication: VaultClientAuthentication{
				Token: &EnvironmentVariable{
					Scheme: "env",
					Host:   "MY_TOKEN",
				},
				RoleId: &EnvironmentVariable{
					Scheme: "env",
					Host:   "MY_ROLE_ID",
				},
				SecretId: &EnvironmentVariable{
					Scheme: "env",
					Host:   "MY_SECRET_ID",
				},
				ApprolePath: "my-role",
			},
			TLS: VaultClientTLS{
				CaCert: &url.URL{
					Scheme: "file",
					Path:   "/path/to/ca.pem",
				},
				ClientCert: &url.URL{
					Scheme: "file",
					Path:   "/path/to/client.pem",
				},
				ClientKey: &url.URL{
					Scheme: "file",
					Path:   "/path/to/client.key",
				},
			},
		},
		KVEngineName:           "kv-engine",
		QuorumSignerEngineName: "signer-engine",
		Unlock: []string{
			"0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5",
			"0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526",
		},
	}

	var got VaultClient

	err := json.Unmarshal(b, &got)

	require.NoError(t, err)
	require.EqualValues(t, want, got)
}

func TestVaultClient_UnmarshalJSON_AddsTrailingSlashToAcctDir(t *testing.T) {
	b := []byte(`{
		"vault": "http://vault:1111",
		"kvEngineName": "kv-engine",
		"quorumSignerEngineName": "signer-engine",
		"accountDirectory": "file:///path/to/dir",
		"unlock": [
			"0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5",
			"0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526"
		],
		"authentication": {
			"token": "env://MY_TOKEN",
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
		VaultClientBase: VaultClientBase{
			Vault: &url.URL{
				Scheme: "http",
				Host:   "vault:1111",
			},
			AccountDirectory: &url.URL{
				Scheme: "file",
				Path:   "/path/to/dir/",
			},
			Authentication: VaultClientAuthentication{
				Token: &EnvironmentVariable{
					Scheme: "env",
					Host:   "MY_TOKEN",
				},
				RoleId: &EnvironmentVariable{
					Scheme: "env",
					Host:   "MY_ROLE_ID",
				},
				SecretId: &EnvironmentVariable{
					Scheme: "env",
					Host:   "MY_SECRET_ID",
				},
				ApprolePath: "my-role",
			},
			TLS: VaultClientTLS{
				CaCert: &url.URL{
					Scheme: "file",
					Path:   "/path/to/ca.pem",
				},
				ClientCert: &url.URL{
					Scheme: "file",
					Path:   "/path/to/client.pem",
				},
				ClientKey: &url.URL{
					Scheme: "file",
					Path:   "/path/to/client.key",
				},
			},
		},
		KVEngineName:           "kv-engine",
		QuorumSignerEngineName: "signer-engine",
		Unlock: []string{
			"0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5",
			"0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526",
		},
	}

	var got VaultClient

	err := json.Unmarshal(b, &got)

	require.NoError(t, err)
	require.EqualValues(t, want, got)
}

func TestEnvironmentVariable_IsSet(t *testing.T) {
	u, err := url.Parse("env://TEST_ENV")
	require.NoError(t, err)

	env := EnvironmentVariable(*u)
	require.False(t, env.IsSet())

	os.Setenv("TEST_ENV", "val")
	defer os.Unsetenv("TEST_ENV")

	require.True(t, env.IsSet())
}

func TestEnvironmentVariable_IsSet_Empty(t *testing.T) {
	u, err := url.Parse("env://")
	require.NoError(t, err)

	env := EnvironmentVariable(*u)
	require.False(t, env.IsSet())
}

func TestEnvironmentVariable_Get(t *testing.T) {
	u, err := url.Parse("env://TEST_ENV")
	require.NoError(t, err)

	env := EnvironmentVariable(*u)
	require.Empty(t, env.Get())

	os.Setenv("TEST_ENV", "val")
	defer os.Unsetenv("TEST_ENV")

	require.Equal(t, "val", env.Get())
}
