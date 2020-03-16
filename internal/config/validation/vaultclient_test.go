package validation

import (
	"testing"

	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/config"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/test/builders"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/test/env"
	"github.com/stretchr/testify/require"
)

func minimumValidClientConfig() *builders.VaultClientBuilder {
	var vaultClientBuilder builders.VaultClientBuilder
	return vaultClientBuilder.
		WithVaultUrl("http://vault:1111").
		WithAccountDirectory("file:///path/to/dir").
		WithRoleIdUrl("env://" + env.MY_ROLE_ID).
		WithSecretIdUrl("env://" + env.MY_SECRET_ID).
		WithApprolePath("myapprole")
}

func TestVaultClients_Validate_MinimumValidConfig(t *testing.T) {
	defer env.UnsetAll()
	env.SetRoleID()
	env.SetSecretID()

	vaultClient := minimumValidClientConfig().Build(t)

	err := vaultClient.Validate()
	require.NoError(t, err)
}

func TestVaultClients_Validate_VaultUrl_Valid(t *testing.T) {
	defer env.UnsetAll()
	env.SetRoleID()
	env.SetSecretID()

	vaultUrls := []string{
		"http://vault",
		"https://vault:1111",
		"http://127.0.0.1:1111",
	}
	for _, u := range vaultUrls {
		t.Run(u, func(t *testing.T) {
			vaultClient := minimumValidClientConfig().
				WithVaultUrl(u).
				Build(t)

			gotErr := vaultClient.Validate()
			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClients_Validate_VaultUrl_Invalid(t *testing.T) {
	wantErrMsg := config.InvalidVaultUrl

	vaultUrls := []string{
		"",
		"noscheme",
	}
	for _, u := range vaultUrls {
		t.Run(u, func(t *testing.T) {
			vaultClient := minimumValidClientConfig().
				WithVaultUrl(u).
				Build(t)

			gotErr := vaultClient.Validate()
			require.EqualError(t, gotErr, wantErrMsg)
		})
	}
}

func TestVaultClients_Validate_AccountDirectory_Valid(t *testing.T) {
	defer env.UnsetAll()
	env.SetRoleID()
	env.SetSecretID()

	acctDirUrls := []string{
		"file:///absolute/path/to/dir",
		"file://../relative/path/to/dir",
		"file://Withhost/path",
		"file://nopath",
	}
	for _, u := range acctDirUrls {
		t.Run(u, func(t *testing.T) {
			vaultClient := minimumValidClientConfig().
				WithAccountDirectory(u).
				Build(t)

			gotErr := vaultClient.Validate()
			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClients_Validate_AccountDirectory_Invalid(t *testing.T) {
	wantErrMsg := config.InvalidAccountDirectory

	acctDirUrls := []string{
		"",
		"relative/no/scheme",
		"/absolute/no/scheme",
		"http://notfilescheme",
	}
	for _, u := range acctDirUrls {
		t.Run(u, func(t *testing.T) {
			vaultClient := minimumValidClientConfig().
				WithAccountDirectory(u).
				Build(t)

			gotErr := vaultClient.Validate()
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
			tokenUrl:    "env://" + env.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){env.SetToken},
		},
		"token_all_envs": {
			tokenUrl:    "env://" + env.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){env.SetToken, env.SetRoleID, env.SetSecretID},
		},
		"approle": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + env.MY_ROLE_ID,
			secretIdUrl: "env://" + env.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.SetRoleID, env.SetSecretID},
		},
		"approle_all_envs": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + env.MY_ROLE_ID,
			secretIdUrl: "env://" + env.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.SetToken, env.SetRoleID, env.SetSecretID},
		},
	}

	for name, tt := range auths {
		t.Run(name, func(t *testing.T) {
			for _, setEnvFunc := range tt.setEnvFuncs {
				setEnvFunc()
			}

			vaultClient := minimumValidClientConfig().
				WithTokenUrl(tt.tokenUrl).
				WithRoleIdUrl(tt.roleIdUrl).
				WithSecretIdUrl(tt.secretIdUrl).
				WithApprolePath(tt.approlePath).
				Build(t)

			gotErr := vaultClient.Validate()

			env.UnsetAll()

			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClients_Validate_Authentication_Invalid(t *testing.T) {
	wantErrMsg := config.InvalidAuthentication

	var auths = map[string]struct {
		tokenUrl    string
		roleIdUrl   string
		secretIdUrl string
		approlePath string
		setEnvFuncs []func()
	}{
		"all_set": {
			tokenUrl:    "env://" + env.MY_TOKEN,
			roleIdUrl:   "env://" + env.MY_ROLE_ID,
			secretIdUrl: "env://" + env.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.SetToken, env.SetRoleID, env.SetSecretID},
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
			roleIdUrl:   "env://" + env.MY_ROLE_ID,
			secretIdUrl: "env://" + env.MY_SECRET_ID,
			approlePath: "",
			setEnvFuncs: []func(){env.SetToken, env.SetRoleID, env.SetSecretID},
		},
		"approle_only_role_id": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + env.MY_ROLE_ID,
			secretIdUrl: "",
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.SetToken, env.SetRoleID, env.SetSecretID},
		},
		"approle_only_secret_id": {
			tokenUrl:    "",
			roleIdUrl:   "",
			secretIdUrl: "env://" + env.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.SetToken, env.SetRoleID, env.SetSecretID},
		},
		"token_approle_path": {
			tokenUrl:    "env://" + env.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.SetToken, env.SetRoleID, env.SetSecretID},
		},
		"token_no_env": {
			tokenUrl:    "env://" + env.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){},
		},
		"token_incorrect_env": {
			tokenUrl:    "env://" + env.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){env.SetRoleID, env.SetSecretID},
		},
		"approle_no_env": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + env.MY_ROLE_ID,
			secretIdUrl: "env://" + env.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){},
		},
		"approle_incorrect_env": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + env.MY_ROLE_ID,
			secretIdUrl: "env://" + env.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){env.SetToken},
		},
	}

	for name, tt := range auths {
		t.Run(name, func(t *testing.T) {
			for _, setEnvFunc := range tt.setEnvFuncs {
				setEnvFunc()
			}

			vaultClient := minimumValidClientConfig().
				WithTokenUrl(tt.tokenUrl).
				WithRoleIdUrl(tt.roleIdUrl).
				WithSecretIdUrl(tt.secretIdUrl).
				WithApprolePath(tt.approlePath).
				Build(t)

			gotErr := vaultClient.Validate()

			env.UnsetAll()

			require.EqualError(t, gotErr, wantErrMsg)
		})
	}
}

func TestVaultClients_Validate_TLS_Valid(t *testing.T) {
	defer env.UnsetAll()
	env.SetRoleID()
	env.SetSecretID()

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
			vaultClient := minimumValidClientConfig().
				WithCaCertUrl(tt.caCert).
				WithClientCertUrl(tt.clientCert).
				WithClientKeyUrl(tt.clientKey).
				Build(t)

			gotErr := vaultClient.Validate()
			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClients_Validate_TLS_Invalid(t *testing.T) {
	defer env.UnsetAll()
	env.SetRoleID()
	env.SetSecretID()

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
			wantErr:    config.InvalidCaCert,
		},
		"caCert_empty": {
			caCert:     "file://",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file:///path/to/client.key",
			wantErr:    config.InvalidCaCert,
		},
		"clientCert_scheme": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "path/to/client.cert",
			clientKey:  "file:///path/to/client.key",
			wantErr:    config.InvalidClientCert,
		},
		"clientCert_empty": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file://",
			clientKey:  "file:///path/to/client.key",
			wantErr:    config.InvalidClientCert,
		},
		"clientKey_scheme": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "path/to/client.key",
			wantErr:    config.InvalidClientKey,
		},
		"clientKey_empty": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file://",
			wantErr:    config.InvalidClientKey,
		},
	}

	for name, tt := range tls {
		t.Run(name, func(t *testing.T) {
			vaultClient := minimumValidClientConfig().
				WithCaCertUrl(tt.caCert).
				WithClientCertUrl(tt.clientCert).
				WithClientKeyUrl(tt.clientKey).
				Build(t)

			gotErr := vaultClient.Validate()

			require.EqualError(t, gotErr, tt.wantErr)
		})
	}
}
