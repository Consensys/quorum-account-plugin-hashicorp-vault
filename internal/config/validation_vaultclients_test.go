package config

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

var env = environmentHelper{}

func minimumValidClientConfig() *vaultClientBuilder {
	var vaultClientBuilder vaultClientBuilder
	return vaultClientBuilder.
		withVaultUrl("http://vault:1111").
		withAccountDirectory("file:///path/to/dir").
		withRoleIdUrl("env://" + MY_ROLE_ID).
		withSecretIdUrl("env://" + MY_SECRET_ID).
		withApprolePath("myapprole")
}

func TestVaultClients_Validate_MinimumValidConfig(t *testing.T) {
	defer env.unsetAll()
	env.setRoleID()
	env.setSecretID()

	var vaultClientsBuilder vaultClientsBuilder

	var vaultClients = vaultClientsBuilder.
		vaultClient(minimumValidClientConfig().build(t)).
		build()

	err := vaultClients.Validate()
	require.NoError(t, err)
}

func TestVaultClients_Validate_VaultUrl_Valid(t *testing.T) {
	defer env.unsetAll()
	env.setRoleID()
	env.setSecretID()

	vaultUrls := []string{
		"http://vault",
		"https://vault:1111",
		"http://127.0.0.1:1111",
	}
	for _, u := range vaultUrls {
		t.Run(u, func(t *testing.T) {
			vc := minimumValidClientConfig().
				withVaultUrl(u).
				build(t)

			var vaultClientsBuilder vaultClientsBuilder
			vaultClients := vaultClientsBuilder.vaultClient(vc).build()

			gotErr := vaultClients.Validate()
			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClients_Validate_VaultUrl_Invalid(t *testing.T) {
	wantErrMsg := fmt.Sprintf("invalid config: array index 0: %v", invalidVaultUrl)

	vaultUrls := []string{
		"",
		"noscheme",
	}
	for _, u := range vaultUrls {
		t.Run(u, func(t *testing.T) {
			vc := minimumValidClientConfig().
				withVaultUrl(u).
				build(t)

			var vaultClientsBuilder vaultClientsBuilder
			vaultClients := vaultClientsBuilder.vaultClient(vc).build()

			gotErr := vaultClients.Validate()
			require.EqualError(t, gotErr, wantErrMsg)
		})
	}
}

func TestVaultClients_Validate_AccountDirectory_Valid(t *testing.T) {
	defer env.unsetAll()
	env.setRoleID()
	env.setSecretID()

	acctDirUrls := []string{
		"file:///absolute/path/to/dir",
		"file://../relative/path/to/dir",
		"file://withhost/path",
		"file://nopath",
	}
	for _, u := range acctDirUrls {
		t.Run(u, func(t *testing.T) {
			vc := minimumValidClientConfig().
				withAccountDirectory(u).
				build(t)

			var vaultClientsBuilder vaultClientsBuilder
			vaultClients := vaultClientsBuilder.vaultClient(vc).build()

			gotErr := vaultClients.Validate()
			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClients_Validate_AccountDirectory_Invalid(t *testing.T) {
	wantErrMsg := fmt.Sprintf("invalid config: array index 0: %v", invalidAccountDirectory)

	acctDirUrls := []string{
		"",
		"relative/no/scheme",
		"/absolute/no/scheme",
		"http://notfilescheme",
	}
	for _, u := range acctDirUrls {
		t.Run(u, func(t *testing.T) {
			vc := minimumValidClientConfig().
				withAccountDirectory(u).
				build(t)

			var vaultClientsBuilder vaultClientsBuilder
			vaultClients := vaultClientsBuilder.vaultClient(vc).build()

			gotErr := vaultClients.Validate()
			require.EqualError(t, gotErr, wantErrMsg)
		})
	}
}

func TestVaultClients_Validate_Authentication_Valid(t *testing.T) {
	var auths = map[string]struct {
		tokenUrl    string
		roleIdUrl   string
		secretIdUrl string
		approlePath string
		setEnvFuncs []func()
	}{
		"token": {
			tokenUrl:    "env://" + MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){env.setToken},
		},
		"token_all_envs": {
			tokenUrl:    "env://" + MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){env.setToken, env.setRoleID, env.setSecretID},
		},
		"approle": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + MY_ROLE_ID,
			secretIdUrl: "env://" + MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.setRoleID, env.setSecretID},
		},
		"approle_all_envs": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + MY_ROLE_ID,
			secretIdUrl: "env://" + MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.setToken, env.setRoleID, env.setSecretID},
		},
	}

	for name, tt := range auths {
		t.Run(name, func(t *testing.T) {
			for _, setEnvFunc := range tt.setEnvFuncs {
				setEnvFunc()
			}

			vc := minimumValidClientConfig().
				withTokenUrl(tt.tokenUrl).
				withRoleIdUrl(tt.roleIdUrl).
				withSecretIdUrl(tt.secretIdUrl).
				withApprolePath(tt.approlePath).
				build(t)

			var vaultClientsBuilder vaultClientsBuilder
			vaultClients := vaultClientsBuilder.vaultClient(vc).build()

			gotErr := vaultClients.Validate()

			env.unsetAll()

			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClients_Validate_Authentication_Invalid(t *testing.T) {
	wantErrMsg := fmt.Sprintf("invalid config: array index 0: %v", invalidAuthentication)

	var auths = map[string]struct {
		tokenUrl    string
		roleIdUrl   string
		secretIdUrl string
		approlePath string
		setEnvFuncs []func()
	}{
		"all_set": {
			tokenUrl:    "env://" + MY_TOKEN,
			roleIdUrl:   "env://" + MY_ROLE_ID,
			secretIdUrl: "env://" + MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.setToken, env.setRoleID, env.setSecretID},
		},
		"none_set": {
			tokenUrl:    "",
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){},
		},
		"approle_no_path": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + MY_ROLE_ID,
			secretIdUrl: "env://" + MY_SECRET_ID,
			approlePath: "",
			setEnvFuncs: []func(){env.setToken, env.setRoleID, env.setSecretID},
		},
		"approle_only_role_id": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + MY_ROLE_ID,
			secretIdUrl: "",
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.setToken, env.setRoleID, env.setSecretID},
		},
		"approle_only_secret_id": {
			tokenUrl:    "",
			roleIdUrl:   "",
			secretIdUrl: "env://" + MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.setToken, env.setRoleID, env.setSecretID},
		},
		"token_approle_path": {
			tokenUrl:    "env://" + MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.setToken, env.setRoleID, env.setSecretID},
		},
		"token_no_env": {
			tokenUrl:    "env://" + MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){},
		},
		"token_incorrect_env": {
			tokenUrl:    "env://" + MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){env.setRoleID, env.setSecretID},
		},
		"approle_no_env": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + MY_ROLE_ID,
			secretIdUrl: "env://" + MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){},
		},
		"approle_incorrect_env": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + MY_ROLE_ID,
			secretIdUrl: "env://" + MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.setToken},
		},
	}

	for name, tt := range auths {
		t.Run(name, func(t *testing.T) {
			for _, setEnvFunc := range tt.setEnvFuncs {
				setEnvFunc()
			}

			vc := minimumValidClientConfig().
				withTokenUrl(tt.tokenUrl).
				withRoleIdUrl(tt.roleIdUrl).
				withSecretIdUrl(tt.secretIdUrl).
				withApprolePath(tt.approlePath).
				build(t)

			var vaultClientsBuilder vaultClientsBuilder
			vaultClients := vaultClientsBuilder.vaultClient(vc).build()

			gotErr := vaultClients.Validate()

			env.unsetAll()

			require.EqualError(t, gotErr, wantErrMsg)
		})
	}
}

func TestVaultClients_Validate_TLS_Valid(t *testing.T) {
	defer env.unsetAll()
	env.setRoleID()
	env.setSecretID()

	var tls = map[string]struct {
		caCert     string
		clientCert string
		clientKey  string
	}{
		"none": {
			caCert:     "",
			clientCert: "",
			clientKey:  "",
		},
		"1-way": {
			caCert:     "file://../ca.cert",
			clientCert: "",
			clientKey:  "",
		},
		"2-way": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file:///path/to/client.key",
		},
		"relative": {
			caCert:     "file://ca.cert",
			clientCert: "file://client.cert",
			clientKey:  "file://client.key",
		},
		"relative_dir": {
			caCert:     "file://path/to/ca.cert",
			clientCert: "file://path/to/client.cert",
			clientKey:  "file://path/to/client.key",
		},
		"relative_up": {
			caCert:     "file://../ca.cert",
			clientCert: "file://../client.cert",
			clientKey:  "file://../client.key",
		},
	}

	for name, tt := range tls {
		t.Run(name, func(t *testing.T) {
			vc := minimumValidClientConfig().
				withCaCertUrl(tt.caCert).
				withClientCertUrl(tt.clientCert).
				withClientKeyUrl(tt.clientKey).
				build(t)

			var vaultClientsBuilder vaultClientsBuilder
			vaultClients := vaultClientsBuilder.vaultClient(vc).build()

			gotErr := vaultClients.Validate()
			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClients_Validate_TLS_Invalid(t *testing.T) {
	defer env.unsetAll()
	env.setRoleID()
	env.setSecretID()

	var tls = map[string]struct {
		caCert     string
		clientCert string
		clientKey  string
		wantErr    string
	}{
		"caCert_scheme": {
			caCert:     "path/to/ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file:///path/to/client.key",
			wantErr:    invalidCaCert,
		},
		"caCert_empty": {
			caCert:     "file://",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file:///path/to/client.key",
			wantErr:    invalidCaCert,
		},
		"clientCert_scheme": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "path/to/client.cert",
			clientKey:  "file:///path/to/client.key",
			wantErr:    invalidClientCert,
		},
		"clientCert_empty": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file://",
			clientKey:  "file:///path/to/client.key",
			wantErr:    invalidClientCert,
		},
		"clientKey_scheme": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "path/to/client.key",
			wantErr:    invalidClientKey,
		},
		"clientKey_empty": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file://",
			wantErr:    invalidClientKey,
		},
	}

	for name, tt := range tls {
		t.Run(name, func(t *testing.T) {
			vc := minimumValidClientConfig().
				withCaCertUrl(tt.caCert).
				withClientCertUrl(tt.clientCert).
				withClientKeyUrl(tt.clientKey).
				build(t)

			var vaultClientsBuilder vaultClientsBuilder
			vaultClients := vaultClientsBuilder.vaultClient(vc).build()

			gotErr := vaultClients.Validate()

			wantErrMsg := fmt.Sprintf("invalid config: array index 0: %v", tt.wantErr)
			require.EqualError(t, gotErr, wantErrMsg)
		})
	}
}
