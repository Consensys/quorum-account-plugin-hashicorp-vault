package validation

import (
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/test"
	"testing"

	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/stretchr/testify/require"
)

func minimumValidClientConfig() *test.VaultClientBuilder {
	var vaultClientBuilder test.VaultClientBuilder
	return vaultClientBuilder.
		WithVaultUrl("http://vault:1111").
		WithKVEngineName("engine").
		WithAccountDirectory("file:///path/to/dir").
		WithRoleIdUrl("env://" + test.MY_ROLE_ID).
		WithSecretIdUrl("env://" + test.MY_SECRET_ID).
		WithApprolePath("myapprole")
}

func TestVaultClient_Validate_MinimumValidConfig(t *testing.T) {
	defer test.UnsetAll()
	test.SetRoleID()
	test.SetSecretID()

	vaultClient := minimumValidClientConfig().Build(t)

	err := vaultClient.Validate()
	require.NoError(t, err)
}

func TestVaultClient_Validate_VaultUrl_Valid(t *testing.T) {
	defer test.UnsetAll()
	test.SetRoleID()
	test.SetSecretID()

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

func TestVaultClient_Validate_VaultUrl_Invalid(t *testing.T) {
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

func TestVaultClient_Validate_KVEngineName_Invalid(t *testing.T) {
	wantErrMsg := config.InvalidKVEngineName

	vaultClient := minimumValidClientConfig().
		WithKVEngineName("").
		Build(t)

	gotErr := vaultClient.Validate()
	require.EqualError(t, gotErr, wantErrMsg)
}

func TestVaultClient_Validate_AccountDirectory_Valid(t *testing.T) {
	defer test.UnsetAll()
	test.SetRoleID()
	test.SetSecretID()

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

func TestVaultClient_Validate_AccountDirectory_Invalid(t *testing.T) {
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

func TestVaultClient_Validate_Authentication_Valid(t *testing.T) {
	var auths = map[string]struct {
		tokenUrl    string
		roleIdUrl   string
		secretIdUrl string
		approlePath string
		setEnvFuncs []func()
	}{
		"token": {
			tokenUrl:    "env://" + test.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){test.SetToken},
		},
		"token_all_envs": {
			tokenUrl:    "env://" + test.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){test.SetToken, test.SetRoleID, test.SetSecretID},
		},
		"approle": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + test.MY_ROLE_ID,
			secretIdUrl: "env://" + test.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){test.SetRoleID, test.SetSecretID},
		},
		"approle_all_envs": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + test.MY_ROLE_ID,
			secretIdUrl: "env://" + test.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){test.SetToken, test.SetRoleID, test.SetSecretID},
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

			test.UnsetAll()

			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClient_Validate_Authentication_Invalid(t *testing.T) {
	wantErrMsg := config.InvalidAuthentication

	var auths = map[string]struct {
		tokenUrl    string
		roleIdUrl   string
		secretIdUrl string
		approlePath string
		setEnvFuncs []func()
	}{
		"all_set": {
			tokenUrl:    "env://" + test.MY_TOKEN,
			roleIdUrl:   "env://" + test.MY_ROLE_ID,
			secretIdUrl: "env://" + test.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){test.SetToken, test.SetRoleID, test.SetSecretID},
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
			roleIdUrl:   "env://" + test.MY_ROLE_ID,
			secretIdUrl: "env://" + test.MY_SECRET_ID,
			approlePath: "",
			setEnvFuncs: []func(){test.SetToken, test.SetRoleID, test.SetSecretID},
		},
		"approle_only_role_id": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + test.MY_ROLE_ID,
			secretIdUrl: "",
			approlePath: "myapprole",
			setEnvFuncs: []func(){test.SetToken, test.SetRoleID, test.SetSecretID},
		},
		"approle_only_secret_id": {
			tokenUrl:    "",
			roleIdUrl:   "",
			secretIdUrl: "env://" + test.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){test.SetToken, test.SetRoleID, test.SetSecretID},
		},
		"token_approle_path": {
			tokenUrl:    "env://" + test.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "myapprole",
			setEnvFuncs: []func(){test.SetToken, test.SetRoleID, test.SetSecretID},
		},
		"token_no_env": {
			tokenUrl:    "env://" + test.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){},
		},
		"token_incorrect_env": {
			tokenUrl:    "env://" + test.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){test.SetRoleID, test.SetSecretID},
		},
		"approle_no_env": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + test.MY_ROLE_ID,
			secretIdUrl: "env://" + test.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){},
		},
		"approle_incorrect_env": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + test.MY_ROLE_ID,
			secretIdUrl: "env://" + test.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){test.SetToken},
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

			test.UnsetAll()

			require.EqualError(t, gotErr, wantErrMsg)
		})
	}
}

func TestVaultClient_Validate_TLS_Valid(t *testing.T) {
	defer test.UnsetAll()
	test.SetRoleID()
	test.SetSecretID()

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

func TestVaultClient_Validate_TLS_Invalid(t *testing.T) {
	defer test.UnsetAll()
	test.SetRoleID()
	test.SetSecretID()

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
