package manager

import (
	"encoding/json"
	"fmt"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/config"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/test/utils"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	caCert     = "../test/data/tls/caRoot.pem"
	clientCert = "../test/data/tls/quorum-client-chain.pem"
	clientKey  = "../test/data/tls/quorum-client.key"
	serverCert = "../test/data/tls/localhost-with-san-chain.pem"
	serverKey  = "../test/data/tls/localhost-with-san.key"

	clientToken       = "token"
	authID            = "FOO"
	nonDefaultApprole = "somepath"
)

var (
	prefixedRoleIDEnv   = fmt.Sprintf("%v_%v", authID, DefaultRoleIDEnv)
	prefixedSecretIDEnv = fmt.Sprintf("%v_%v", authID, DefaultSecretIDEnv)
	prefixedTokenEnv    = fmt.Sprintf("%v_%v", authID, DefaultTokenEnv)
)

func TestNewAuthenticatedClient_InvalidApproleCredentials(t *testing.T) {
	tests := []struct {
		name        string
		usingAuthID bool
		toSet       []string
		wantErr     error
	}{
		{
			name:    "none set",
			toSet:   []string{},
			wantErr: noHashicorpEnvSetErr{roleIdEnv: DefaultRoleIDEnv, secretIdEnv: DefaultSecretIDEnv, tokenEnv: DefaultTokenEnv},
		},
		{
			name:    "only role-id",
			toSet:   []string{DefaultRoleIDEnv},
			wantErr: invalidApproleAuthErr{roleIdEnv: DefaultRoleIDEnv, secretIdEnv: DefaultSecretIDEnv},
		},
		{
			name:    "only secret-id",
			toSet:   []string{DefaultSecretIDEnv},
			wantErr: invalidApproleAuthErr{roleIdEnv: DefaultRoleIDEnv, secretIdEnv: DefaultSecretIDEnv},
		},
		{
			name:    "approle auth preferred (role-id)",
			toSet:   []string{DefaultRoleIDEnv, DefaultTokenEnv},
			wantErr: invalidApproleAuthErr{roleIdEnv: DefaultRoleIDEnv, secretIdEnv: DefaultSecretIDEnv},
		},
		{
			name:    "approle auth preferred (secret-id)",
			toSet:   []string{DefaultSecretIDEnv, DefaultTokenEnv},
			wantErr: invalidApproleAuthErr{roleIdEnv: DefaultRoleIDEnv, secretIdEnv: DefaultSecretIDEnv},
		},
		{
			name:        "authID none set",
			usingAuthID: true,
			toSet:       []string{},
			wantErr:     noHashicorpEnvSetErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv, tokenEnv: prefixedTokenEnv},
		},
		{
			name:        "authID default set",
			usingAuthID: true,
			toSet:       []string{DefaultRoleIDEnv, DefaultSecretIDEnv, DefaultTokenEnv},
			wantErr:     noHashicorpEnvSetErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv, tokenEnv: prefixedTokenEnv},
		},
		{
			name:        "authID only prefixed role-id",
			usingAuthID: true,
			toSet:       []string{prefixedRoleIDEnv},
			wantErr:     invalidApproleAuthErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv},
		},
		{
			name:        "authID only secret-id",
			usingAuthID: true,
			toSet:       []string{prefixedSecretIDEnv},
			wantErr:     invalidApproleAuthErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv},
		},
		{
			name:        "authID approle auth preferred (role-id)",
			usingAuthID: true,
			toSet:       []string{prefixedRoleIDEnv, prefixedTokenEnv},
			wantErr:     invalidApproleAuthErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv},
		},
		{
			name:        "authID approle auth preferred (secret-id)",
			usingAuthID: true,
			toSet:       []string{prefixedSecretIDEnv, prefixedTokenEnv},
			wantErr:     invalidApproleAuthErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unsetFn := utils.SetEnvironmentVariables(tt.toSet...)

			var conf config.VaultAuth
			if tt.usingAuthID {
				conf.AuthID = authID
			}

			_, err := newAuthenticatedClient("", conf, config.TLS{})

			assert.EqualError(t, err, tt.wantErr.Error())
			unsetFn()
		})
	}
}

func TestNewAuthenticatedClient_Approle_NonDefaultApprolePath(t *testing.T) {
	tests := []struct {
		name   string
		authID bool
		tls    bool
	}{
		{
			name:   "authID tls",
			authID: true,
			tls:    true,
		},
		{
			name:   "authID no tls",
			authID: true,
			tls:    false,
		},
		{
			name:   "no authID tls",
			authID: false,
			tls:    true,
		},
		{
			name:   "no authID no tls",
			authID: false,
			tls:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				roleID, secretID string
				authConf         config.VaultAuth
				tlsConf          config.TLS
				vault            *httptest.Server
				err              error
			)

			authConf = config.VaultAuth{
				ApprolePath: nonDefaultApprole,
			}

			if tt.authID {
				authConf.AuthID = authID

				roleID = prefixedRoleIDEnv
				secretID = prefixedSecretIDEnv
			} else {
				roleID = DefaultRoleIDEnv
				secretID = DefaultSecretIDEnv
			}
			unsetFn := utils.SetEnvironmentVariables(roleID, secretID)

			authVaultHandler := utils.PathHandler{
				Path: fmt.Sprintf("/v1/auth/%v/login", nonDefaultApprole),
				Handler: func(w http.ResponseWriter, r *http.Request) {
					// check that the correct credentials are included in the login request
					var body map[string]interface{}
					err := json.NewDecoder(r.Body).Decode(&body)
					require.NoError(t, err)
					require.Contains(t, body, "role_id")
					require.Equal(t, body["role_id"].(string), roleID)
					require.Contains(t, body, "secret_id")
					require.Equal(t, body["secret_id"].(string), secretID)

					// respond to the login request
					vaultResponse := &api.Secret{Auth: &api.SecretAuth{ClientToken: clientToken}}
					b, _ := json.Marshal(vaultResponse)
					_, _ = w.Write(b)
				},
			}

			// check that the clientToken is attached to requests
			checkerHandler := utils.PathHandler{
				Path: "/v1/check",
				Handler: func(w http.ResponseWriter, r *http.Request) {
					// check that the correct credentials are included in the login request
					err := utils.RequireRequestIsAuthenticated(r, clientToken)
					require.NoError(t, err)
				},
			}

			handlers := []utils.PathHandler{
				authVaultHandler,
				checkerHandler,
			}

			if tt.tls {
				tlsConf = config.TLS{
					CaCert:     caCert,
					ClientCert: clientCert,
					ClientKey:  clientKey,
				}
				vault, err = utils.SetupMockTLSVaultServer(caCert, serverCert, serverKey, handlers...)
				require.NoError(t, err)
			} else {
				vault, err = utils.SetupMockVaultServer(handlers...)
				require.NoError(t, err)
			}

			got, err := newAuthenticatedClient(vault.URL, authConf, tlsConf)
			require.NoError(t, err)
			require.Equal(t, clientToken, got.Token())

			// make a request to the checker handler to ensure the auth token is being used
			_, err = got.Logical().Read("check")
			require.NoError(t, err)

			unsetFn()
		})
	}
}

func TestNewAuthenticatedClient_Approle_DefaultApprolePath(t *testing.T) {
	tests := []struct {
		name   string
		authID bool
		tls    bool
	}{
		{
			name:   "authID tls",
			authID: true,
			tls:    true,
		},
		{
			name:   "authID no tls",
			authID: true,
			tls:    false,
		},
		{
			name:   "no authID tls",
			authID: false,
			tls:    true,
		},
		{
			name:   "no authID no tls",
			authID: false,
			tls:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				roleID, secretID string
				authConf         config.VaultAuth
				tlsConf          config.TLS
				vault            *httptest.Server
				err              error
			)

			if tt.authID {
				authConf.AuthID = authID

				roleID = prefixedRoleIDEnv
				secretID = prefixedSecretIDEnv
			} else {
				roleID = DefaultRoleIDEnv
				secretID = DefaultSecretIDEnv
			}
			unsetFn := utils.SetEnvironmentVariables(roleID, secretID)

			authVaultHandler := utils.PathHandler{
				Path: "/v1/auth/approle/login",
				Handler: func(w http.ResponseWriter, r *http.Request) {
					// check that the correct credentials are included in the login request
					var body map[string]interface{}
					err := json.NewDecoder(r.Body).Decode(&body)
					require.NoError(t, err)
					require.Contains(t, body, "role_id")
					require.Equal(t, body["role_id"].(string), roleID)
					require.Contains(t, body, "secret_id")
					require.Equal(t, body["secret_id"].(string), secretID)

					// respond to the login request
					vaultResponse := &api.Secret{Auth: &api.SecretAuth{ClientToken: clientToken}}
					b, _ := json.Marshal(vaultResponse)
					_, _ = w.Write(b)
				},
			}

			// check that the clientToken is attached to requests
			checkerHandler := utils.PathHandler{
				Path: "/v1/check",
				Handler: func(w http.ResponseWriter, r *http.Request) {
					// check that the correct credentials are included in the login request
					err := utils.RequireRequestIsAuthenticated(r, clientToken)
					require.NoError(t, err)
				},
			}

			handlers := []utils.PathHandler{
				authVaultHandler,
				checkerHandler,
			}

			if tt.tls {
				tlsConf = config.TLS{
					CaCert:     caCert,
					ClientCert: clientCert,
					ClientKey:  clientKey,
				}
				vault, err = utils.SetupMockTLSVaultServer(caCert, serverCert, serverKey, handlers...)
				require.NoError(t, err)
			} else {
				vault, err = utils.SetupMockVaultServer(handlers...)
				require.NoError(t, err)
			}

			got, err := newAuthenticatedClient(vault.URL, authConf, tlsConf)
			require.NoError(t, err)
			require.Equal(t, clientToken, got.Token())

			// make a request to the checker handler to ensure the auth token is being used
			_, err = got.Logical().Read("check")
			require.NoError(t, err)

			unsetFn()
		})
	}
}

func TestNewAuthenticatedClient_Token(t *testing.T) {
	tests := []struct {
		name   string
		authID bool
		tls    bool
	}{
		{
			name:   "authID tls",
			authID: true,
			tls:    true,
		},
		{
			name:   "authID no tls",
			authID: true,
			tls:    false,
		},
		{
			name:   "no authID tls",
			authID: false,
			tls:    true,
		},
		{
			name:   "no authID no tls",
			authID: false,
			tls:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				tokenEnv string
				authConf config.VaultAuth
				tlsConf  config.TLS
				vault    *httptest.Server
				err      error
			)

			if tt.authID {
				authConf.AuthID = authID

				tokenEnv = prefixedTokenEnv
			} else {
				tokenEnv = DefaultTokenEnv
			}
			unsetFn := utils.SetEnvironmentVariables(tokenEnv)

			// check that the clientToken is attached to requests
			checkerHandler := utils.PathHandler{
				Path: "/v1/check",
				Handler: func(w http.ResponseWriter, r *http.Request) {
					// check that the correct credentials are included in the login request
					err := utils.RequireRequestIsAuthenticated(r, tokenEnv)
					require.NoError(t, err)
				},
			}

			handlers := []utils.PathHandler{
				checkerHandler,
			}

			if tt.tls {
				tlsConf = config.TLS{
					CaCert:     caCert,
					ClientCert: clientCert,
					ClientKey:  clientKey,
				}
				vault, err = utils.SetupMockTLSVaultServer(caCert, serverCert, serverKey, handlers...)
				require.NoError(t, err)
			} else {
				vault, err = utils.SetupMockVaultServer(handlers...)
				require.NoError(t, err)
			}

			got, err := newAuthenticatedClient(vault.URL, authConf, tlsConf)
			require.NoError(t, err)
			require.Equal(t, tokenEnv, got.Token())

			// make a request to the checker handler to ensure the auth token is being used
			_, err = got.Logical().Read("check")
			require.NoError(t, err)

			unsetFn()
		})
	}
}
