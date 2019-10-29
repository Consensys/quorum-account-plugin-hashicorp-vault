package manager

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goquorum/quorum-plugin-hashicorp-vault-account-manager/internal/config"
	"github.com/goquorum/quorum-plugin-hashicorp-vault-account-manager/internal/test/utils"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
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
			unsetFn()

			assert.EqualError(t, err, tt.wantErr.Error())
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
					if assert.NoError(t, err) {
						if assert.Contains(t, body, "role_id") {
							assert.Equal(t, body["role_id"].(string), roleID)
						}
						if assert.Contains(t, body, "secret_id") {
							assert.Equal(t, body["secret_id"].(string), secretID)
						}
					}

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
					assert.NoError(t, err)
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
				if err != nil {
					unsetFn()
				}
			} else {
				vault, err = utils.SetupMockVaultServer(handlers...)
				if err != nil {
					unsetFn()
				}
			}

			got, err := newAuthenticatedClient(vault.URL, authConf, tlsConf)
			if assert.NoError(t, err) {
				if assert.Equal(t, clientToken, got.Token()) {
					// make a request to the checker handler to ensure the auth token is being used
					_, err = got.Logical().Read("check")
					assert.NoError(t, err)
				}
			}

			unsetFn()
			vault.Close()
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
					if assert.NoError(t, err) {
						if assert.Contains(t, body, "role_id") {
							assert.Equal(t, body["role_id"].(string), roleID)
						}
						if assert.Contains(t, body, "secret_id") {
							assert.Equal(t, body["secret_id"].(string), secretID)
						}
					}

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
					assert.NoError(t, err)
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
				if err != nil {
					unsetFn()
				}
			} else {
				vault, err = utils.SetupMockVaultServer(handlers...)
				if err != nil {
					unsetFn()
				}
			}

			got, err := newAuthenticatedClient(vault.URL, authConf, tlsConf)

			if assert.NoError(t, err) {
				if assert.Equal(t, clientToken, got.Token()) {
					// make a request to the checker handler to ensure the auth token is being used
					_, err = got.Logical().Read("check")
					assert.NoError(t, err)
				}
			}

			unsetFn()
			vault.Close()
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
					assert.NoError(t, err)
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
				if err != nil {
					unsetFn()
				}
			} else {
				vault, err = utils.SetupMockVaultServer(handlers...)
				if err != nil {
					unsetFn()
				}
			}

			got, err := newAuthenticatedClient(vault.URL, authConf, tlsConf)

			if assert.NoError(t, err) {
				if assert.Equal(t, tokenEnv, got.Token()) {
					// make a request to the checker handler to ensure the auth token is being used
					_, err = got.Logical().Read("check")
					assert.NoError(t, err)
				}
			}

			unsetFn()
			vault.Close()
		})
	}
}

func TestNewAuthenticatedClient_RenewsToken(t *testing.T) {
	var (
		authConf config.VaultAuth
		tlsConf  config.TLS
		vault    *httptest.Server
		err      error
	)

	unsetFn := utils.SetEnvironmentVariables(DefaultRoleIDEnv, DefaultSecretIDEnv)

	authVaultHandler := utils.PathHandler{
		Path: "/v1/auth/approle/login",
		Handler: func(w http.ResponseWriter, r *http.Request) {
			// respond to the login request
			vaultResponse := &api.Secret{
				Auth: &api.SecretAuth{
					ClientToken:   clientToken,
					Renewable:     true,
					LeaseDuration: 1,
				},
			}
			b, _ := json.Marshal(vaultResponse)
			_, _ = w.Write(b)
		},
	}

	var renews int

	renewHandler := utils.PathHandler{
		Path: "/v1/auth/token/renew-self",
		Handler: func(w http.ResponseWriter, r *http.Request) {
			// record that a reauth request has been made
			renews++

			// check that the correct credentials are included in the login request
			err := utils.RequireRequestIsAuthenticated(r, clientToken)
			assert.NoError(t, err)

			vaultResponse := &api.Secret{
				Auth: &api.SecretAuth{
					ClientToken:   clientToken,
					Renewable:     true,
					LeaseDuration: 1,
				},
			}
			b, _ := json.Marshal(vaultResponse)
			_, _ = w.Write(b)
		},
	}

	handlers := []utils.PathHandler{
		authVaultHandler,
		renewHandler,
	}

	vault, err = utils.SetupMockVaultServer(handlers...)
	if err != nil {
		unsetFn()
	}

	_, err = newAuthenticatedClient(vault.URL, authConf, tlsConf)
	if assert.NoError(t, err) {
		time.Sleep(1 * time.Second)
		assert.Equal(t, 2, renews, fmt.Sprintf("expected 2 renews before timeout, got %v", renews))
	}

	unsetFn()
	vault.Close()
}

func TestNewAuthenticatedClient_ReauthsWhenTokenExpires(t *testing.T) {
	var (
		authConf config.VaultAuth
		tlsConf  config.TLS
		vault    *httptest.Server
		err      error
	)

	unsetFn := utils.SetEnvironmentVariables(DefaultRoleIDEnv, DefaultSecretIDEnv)

	var (
		auths  int
		renews int
	)

	authVaultHandler := utils.PathHandler{
		Path: "/v1/auth/approle/login",
		Handler: func(w http.ResponseWriter, r *http.Request) {
			auths++

			// respond to the login request
			vaultResponse := &api.Secret{
				Auth: &api.SecretAuth{
					ClientToken:   clientToken,
					Renewable:     true,
					LeaseDuration: 1,
				},
			}
			b, _ := json.Marshal(vaultResponse)
			_, _ = w.Write(b)
		},
	}

	renewHandler := utils.PathHandler{
		Path: "/v1/auth/token/renew-self",
		Handler: func(w http.ResponseWriter, r *http.Request) {
			// record that a reauth request has been made
			renews++

			// check that the correct credentials are included in the login request
			err := utils.RequireRequestIsAuthenticated(r, clientToken)
			assert.NoError(t, err)

			// every second renewed token is non-renewable (similar to if token expires), so client should reauthenticate next time round
			renewable := (renews % 2) == 0

			vaultResponse := &api.Secret{
				Auth: &api.SecretAuth{
					ClientToken:   clientToken,
					Renewable:     renewable,
					LeaseDuration: 2,
				},
			}
			b, _ := json.Marshal(vaultResponse)
			_, _ = w.Write(b)
		},
	}

	handlers := []utils.PathHandler{
		authVaultHandler,
		renewHandler,
	}

	vault, err = utils.SetupMockVaultServer(handlers...)
	if err != nil {
		unsetFn()
	}

	_, err = newAuthenticatedClient(vault.URL, authConf, tlsConf)
	if assert.NoError(t, err) {
		time.Sleep(1 * time.Second)
		assert.Equal(t, 2, renews, fmt.Sprintf("expected 2 renews before timeout, got %v", renews))
		assert.Equal(t, 2, auths, fmt.Sprintf("expected 2 auths before timeout, got %v", auths))
	}

	unsetFn()
	vault.Close()
}
