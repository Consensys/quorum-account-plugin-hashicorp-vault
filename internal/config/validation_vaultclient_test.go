package config

import (
	"net/url"
	"testing"

	"github.com/consensys/quorum-account-plugin-hashicorp-vault/internal/testutil"
	"github.com/stretchr/testify/require"
)

func envVar(t *testing.T, envVarURL string) *EnvironmentVariable {
	u, err := url.Parse(envVarURL)
	require.NoError(t, err)
	env := EnvironmentVariable(*u)
	return &env
}

func minimumValidClientConfig(t *testing.T) VaultClient {
	var token EnvironmentVariable
	vault, _ := url.Parse("http://vault:1111")
	accountDirectory, _ := url.Parse("file:///path/to/dir")
	emptyUrl, _ := url.Parse("")

	return VaultClient{
		Vault:            vault,
		KVEngineName:     "engine",
		AccountDirectory: accountDirectory,
		Authentication: VaultClientAuthentication{
			Token:       &token,
			RoleId:      envVar(t, "env://"+testutil.MY_ROLE_ID),
			SecretId:    envVar(t, "env://"+testutil.MY_SECRET_ID),
			ApprolePath: "myapprole",
		},
		TLS: VaultClientTLS{
			CaCert:     emptyUrl,
			ClientCert: emptyUrl,
			ClientKey:  emptyUrl,
		},
	}
}

func TestVaultClient_Validate_MinimumValidConfig(t *testing.T) {
	defer testutil.UnsetAll()
	testutil.SetRoleID()
	testutil.SetSecretID()

	vaultClient := minimumValidClientConfig(t)

	err := vaultClient.Validate()
	require.NoError(t, err)
}

func TestVaultClient_Validate_VaultUrl_Valid(t *testing.T) {
	defer testutil.UnsetAll()
	testutil.SetRoleID()
	testutil.SetSecretID()

	vaultUrls := []string{
		"http://vault",
		"https://vault:1111",
		"http://127.0.0.1:1111",
	}
	for _, u := range vaultUrls {
		t.Run(u, func(t *testing.T) {
			vaultClient := minimumValidClientConfig(t)

			vaultURL, err := url.Parse(u)
			require.NoError(t, err)
			vaultClient.Vault = vaultURL

			gotErr := vaultClient.Validate()
			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClient_Validate_VaultUrl_Invalid(t *testing.T) {
	wantErrMsg := "vault must be a valid HTTP/HTTPS url"

	vaultUrls := []string{
		"",
		"noscheme",
	}
	for _, u := range vaultUrls {
		t.Run(u, func(t *testing.T) {
			vaultClient := minimumValidClientConfig(t)

			vaultURL, err := url.Parse(u)
			require.NoError(t, err)
			vaultClient.Vault = vaultURL

			gotErr := vaultClient.Validate()
			require.EqualError(t, gotErr, wantErrMsg)
		})
	}
}

func TestVaultClient_Validate_KVEngineName_Invalid(t *testing.T) {
	wantErrMsg := "kvEngineName must be set"

	vaultClient := minimumValidClientConfig(t)
	vaultClient.KVEngineName = ""

	gotErr := vaultClient.Validate()
	require.EqualError(t, gotErr, wantErrMsg)
}

func TestVaultClient_Validate_AccountDirectory_Valid(t *testing.T) {
	defer testutil.UnsetAll()
	testutil.SetRoleID()
	testutil.SetSecretID()

	vaultClient := minimumValidClientConfig(t)

	acctDir, err := url.Parse("file:///absolute/path/to/dir")
	require.NoError(t, err)
	vaultClient.AccountDirectory = acctDir

	gotErr := vaultClient.Validate()
	require.NoError(t, gotErr)
}

func TestVaultClient_Validate_AccountDirectory_Invalid(t *testing.T) {
	wantErrMsg := "accountDirectory must be a valid absolute file url"

	acctDirUrls := []string{
		"",
		"file://../relative/path/to/dir",
		"file://Withhost/path",
		"file://nopath",
		"relative/no/scheme",
		"/absolute/no/scheme",
		"http://notfilescheme",
	}
	for _, u := range acctDirUrls {
		t.Run(u, func(t *testing.T) {
			vaultClient := minimumValidClientConfig(t)

			acctDir, err := url.Parse(u)
			require.NoError(t, err)
			vaultClient.AccountDirectory = acctDir

			gotErr := vaultClient.Validate()
			require.EqualError(t, gotErr, wantErrMsg)
		})
	}
}

func TestVaultClient_Validate_AccountDirectory_NilInvalid(t *testing.T) {
	wantErrMsg := "accountDirectory must be a valid absolute file url"

	vaultClient := minimumValidClientConfig(t)
	vaultClient.AccountDirectory = nil

	gotErr := vaultClient.Validate()
	require.EqualError(t, gotErr, wantErrMsg)
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
			tokenUrl:    "env://" + testutil.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){testutil.SetToken},
		},
		"token_all_envs": {
			tokenUrl:    "env://" + testutil.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){testutil.SetToken, testutil.SetRoleID, testutil.SetSecretID},
		},
		"approle": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + testutil.MY_ROLE_ID,
			secretIdUrl: "env://" + testutil.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){testutil.SetRoleID, testutil.SetSecretID},
		},
		"approle_all_envs": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + testutil.MY_ROLE_ID,
			secretIdUrl: "env://" + testutil.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){testutil.SetToken, testutil.SetRoleID, testutil.SetSecretID},
		},
	}

	for name, tt := range auths {
		t.Run(name, func(t *testing.T) {
			for _, setEnvFunc := range tt.setEnvFuncs {
				setEnvFunc()
			}

			vaultClient := minimumValidClientConfig(t)

			vaultClient.Authentication.Token = envVar(t, tt.tokenUrl)
			vaultClient.Authentication.RoleId = envVar(t, tt.roleIdUrl)
			vaultClient.Authentication.SecretId = envVar(t, tt.secretIdUrl)
			vaultClient.Authentication.ApprolePath = tt.approlePath

			gotErr := vaultClient.Validate()

			testutil.UnsetAll()

			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClient_Validate_Authentication_Invalid(t *testing.T) {
	wantErrMsg := "authentication must contain roleId, secretId and approlePath OR only token, and the given environment variables must be set"

	var auths = map[string]struct {
		tokenUrl    string
		roleIdUrl   string
		secretIdUrl string
		approlePath string
		setEnvFuncs []func()
	}{
		"all_set": {
			tokenUrl:    "env://" + testutil.MY_TOKEN,
			roleIdUrl:   "env://" + testutil.MY_ROLE_ID,
			secretIdUrl: "env://" + testutil.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){testutil.SetToken, testutil.SetRoleID, testutil.SetSecretID},
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
			roleIdUrl:   "env://" + testutil.MY_ROLE_ID,
			secretIdUrl: "env://" + testutil.MY_SECRET_ID,
			approlePath: "",
			setEnvFuncs: []func(){testutil.SetToken, testutil.SetRoleID, testutil.SetSecretID},
		},
		"approle_only_role_id": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + testutil.MY_ROLE_ID,
			secretIdUrl: "",
			approlePath: "myapprole",
			setEnvFuncs: []func(){testutil.SetToken, testutil.SetRoleID, testutil.SetSecretID},
		},
		"approle_only_secret_id": {
			tokenUrl:    "",
			roleIdUrl:   "",
			secretIdUrl: "env://" + testutil.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){testutil.SetToken, testutil.SetRoleID, testutil.SetSecretID},
		},
		"token_approle_path": {
			tokenUrl:    "env://" + testutil.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "myapprole",
			setEnvFuncs: []func(){testutil.SetToken, testutil.SetRoleID, testutil.SetSecretID},
		},
		"token_no_env": {
			tokenUrl:    "env://" + testutil.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){},
		},
		"token_incorrect_env": {
			tokenUrl:    "env://" + testutil.MY_TOKEN,
			roleIdUrl:   "",
			secretIdUrl: "",
			approlePath: "",
			setEnvFuncs: []func(){testutil.SetRoleID, testutil.SetSecretID},
		},
		"approle_no_env": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + testutil.MY_ROLE_ID,
			secretIdUrl: "env://" + testutil.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){},
		},
		"approle_incorrect_env": {
			tokenUrl:    "",
			roleIdUrl:   "env://" + testutil.MY_ROLE_ID,
			secretIdUrl: "env://" + testutil.MY_SECRET_ID,
			approlePath: "myapprole",
			setEnvFuncs: []func(){testutil.SetToken},
		},
	}

	for name, tt := range auths {
		t.Run(name, func(t *testing.T) {
			for _, setEnvFunc := range tt.setEnvFuncs {
				setEnvFunc()
			}

			vaultClient := minimumValidClientConfig(t)

			vaultClient.Authentication.Token = envVar(t, tt.tokenUrl)
			vaultClient.Authentication.RoleId = envVar(t, tt.roleIdUrl)
			vaultClient.Authentication.SecretId = envVar(t, tt.secretIdUrl)
			vaultClient.Authentication.ApprolePath = tt.approlePath

			gotErr := vaultClient.Validate()

			testutil.UnsetAll()

			require.EqualError(t, gotErr, wantErrMsg)
		})
	}
}

func TestVaultClient_Validate_TLS_Valid(t *testing.T) {
	defer testutil.UnsetAll()
	testutil.SetRoleID()
	testutil.SetSecretID()

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
			caCert:     "file:///path/to/ca.cert",
			clientCert: "",
			clientKey:  "",
		},
		"2-way": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file:///path/to/client.key",
		},
	}

	for name, tt := range tls {
		t.Run(name, func(t *testing.T) {
			caCert, _ := url.Parse(tt.caCert)
			clientCert, _ := url.Parse(tt.clientCert)
			clientKey, _ := url.Parse(tt.clientKey)

			vaultClient := minimumValidClientConfig(t)

			vaultClient.TLS.CaCert = caCert
			vaultClient.TLS.ClientCert = clientCert
			vaultClient.TLS.ClientKey = clientKey

			gotErr := vaultClient.Validate()
			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClient_Validate_TLS_Invalid(t *testing.T) {
	defer testutil.UnsetAll()
	testutil.SetRoleID()
	testutil.SetSecretID()

	var tls = map[string]struct {
		caCert     string
		clientCert string
		clientKey  string
		wantErr    string
	}{
		"caCert_relative": {
			caCert:     "file://ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file:///path/to/client.key",
			wantErr:    "caCert must be a valid absolute file url",
		},
		"caCert_scheme": {
			caCert:     "path/to/ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file:///path/to/client.key",
			wantErr:    "caCert must be a valid absolute file url",
		},
		"caCert_empty": {
			caCert:     "file://",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file:///path/to/client.key",
			wantErr:    "caCert must be a valid absolute file url",
		},
		"clientCert_relative": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file://client.cert",
			clientKey:  "file:///path/to/client.key",
			wantErr:    "clientCert must be a valid absolute file url",
		},
		"clientCert_scheme": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "path/to/client.cert",
			clientKey:  "file:///path/to/client.key",
			wantErr:    "clientCert must be a valid absolute file url",
		},
		"clientCert_empty": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file://",
			clientKey:  "file:///path/to/client.key",
			wantErr:    "clientCert must be a valid absolute file url",
		},
		"clientKey_relative": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file://client.key",
			wantErr:    "clientKey must be a valid absolute file url",
		},
		"clientKey_scheme": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "path/to/client.key",
			wantErr:    "clientKey must be a valid absolute file url",
		},
		"clientKey_empty": {
			caCert:     "file:///path/to/ca.cert",
			clientCert: "file:///path/to/client.cert",
			clientKey:  "file://",
			wantErr:    "clientKey must be a valid absolute file url",
		},
	}

	for name, tt := range tls {
		t.Run(name, func(t *testing.T) {
			var (
				caCert     *url.URL
				clientCert *url.URL
				clientKey  *url.URL
			)
			if tt.caCert != "" {
				caCert, _ = url.Parse(tt.caCert)
			}
			if tt.clientCert != "" {
				clientCert, _ = url.Parse(tt.clientCert)
			}
			if tt.clientKey != "" {
				clientKey, _ = url.Parse(tt.clientKey)
			}

			vaultClient := minimumValidClientConfig(t)

			vaultClient.TLS.CaCert = caCert
			vaultClient.TLS.ClientCert = clientCert
			vaultClient.TLS.ClientKey = clientKey

			gotErr := vaultClient.Validate()

			require.EqualError(t, gotErr, tt.wantErr)
		})
	}
}
