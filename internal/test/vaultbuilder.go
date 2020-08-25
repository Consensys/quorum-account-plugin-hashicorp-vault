package test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/stretchr/testify/require"
)

const (
	CA_CERT     = "testdata/tls/caRoot.pem"
	CLIENT_CERT = "testdata/tls/quorum-client-chain.pem"
	CLIENT_KEY  = "testdata/tls/quorum-client.key"
	SERVER_CERT = "testdata/tls/localhost-with-san-chain.pem"
	SERVER_KEY  = "testdata/tls/localhost-with-san.key"

	AUTH_TOKEN = "authToken"
	CAS_VALUE  = 5
)

// builder for a mock Vault HTTPS server
type VaultBuilder struct {
	handlers   map[string]http.HandlerFunc
	caCert     string
	serverCert string
	serverKey  string
}

func (b *VaultBuilder) WithLoginHandler(approlePath string) *VaultBuilder {
	if b.handlers == nil {
		b.handlers = make(map[string]http.HandlerFunc)
	}
	path := fmt.Sprintf("/v1/auth/%v/login", approlePath)
	handler := func(w http.ResponseWriter, r *http.Request) {
		vaultResponse := &api.Secret{Auth: &api.SecretAuth{ClientToken: AUTH_TOKEN}}
		b, _ := json.Marshal(vaultResponse)
		_, _ = w.Write(b)
	}
	b.handlers[path] = handler
	return b
}

type HandlerData struct {
	SecretEnginePath, SecretPath, AcctAddrResponse, PrivKeyResponse string
	SignerResponse, SignerKeyToImport, SignerCreatedAccount         string
	SecretVersion                                                   int
}

func (b *VaultBuilder) WithKVHandler(t *testing.T, d HandlerData) *VaultBuilder {
	if b.handlers == nil {
		b.handlers = make(map[string]http.HandlerFunc)
	}
	path := fmt.Sprintf("/v1/%v/data/%v", d.SecretEnginePath, d.SecretPath)

	handler := func(w http.ResponseWriter, r *http.Request) {
		// check plugin has correctly authenticated the request
		header := map[string][]string(r.Header)
		requestTokens := header[consts.AuthHeaderName]
		require.Equal(t, AUTH_TOKEN, requestTokens[0])

		require.Equal(t, r.URL.Query().Get("version"), "2")

		vaultResponse := &api.Secret{
			Data: map[string]interface{}{
				"data": map[string]interface{}{
					d.AcctAddrResponse: d.PrivKeyResponse,
				},
			},
		}
		b, _ := json.Marshal(vaultResponse)
		_, _ = w.Write(b)
	}

	b.handlers[path] = handler
	return b
}

func (b *VaultBuilder) WithSignerHandler(t *testing.T, d HandlerData) *VaultBuilder {
	if b.handlers == nil {
		b.handlers = make(map[string]http.HandlerFunc)
	}
	path := fmt.Sprintf("/v1/%v/sign/%v", d.SecretEnginePath, d.SecretPath)

	handler := func(w http.ResponseWriter, r *http.Request) {
		// check plugin has correctly authenticated the request
		header := map[string][]string(r.Header)
		requestTokens := header[consts.AuthHeaderName]
		require.Equal(t, AUTH_TOKEN, requestTokens[0])

		vaultResponse := &api.Secret{
			Data: map[string]interface{}{
				"sig": d.SignerResponse,
			},
		}
		b, _ := json.Marshal(vaultResponse)
		_, _ = w.Write(b)
	}

	b.handlers[path] = handler
	return b
}

func (b *VaultBuilder) WithKVAccountCreationHandler(t *testing.T, d HandlerData) *VaultBuilder {
	if b.handlers == nil {
		b.handlers = make(map[string]http.HandlerFunc)
	}
	path := fmt.Sprintf("/v1/%v/data/%v", d.SecretEnginePath, d.SecretPath)

	handler := func(w http.ResponseWriter, r *http.Request) {
		// check plugin has correctly authenticated the request
		header := map[string][]string(r.Header)
		requestTokens := header[consts.AuthHeaderName]
		require.Equal(t, AUTH_TOKEN, requestTokens[0])

		vaultResponse := new(api.Secret)

		switch r.Method {
		case http.MethodPut: // account creation
			b, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)
			body := make(map[string]interface{})
			require.NoError(t, json.Unmarshal(b, &body))

			// if using CAS then only accept request if correct value has been provided
			opts := body["options"].(map[string]interface{})
			cas := opts["cas"]
			if cas != float64(CAS_VALUE) {
				http.Error(w, "invalid CAS value", http.StatusBadRequest)
				return
			}

			data := body["data"].(map[string]interface{})
			require.Len(t, data, 1)
			for k, v := range data {
				require.Len(t, k, 2*20) // 20-byte address equates to 40 hexadecimal digits
				require.NotEmpty(t, v)
			}

			// create response which contains new secret version
			vaultResponse.Data = map[string]interface{}{
				"version": CAS_VALUE + 1,
			}

		case http.MethodGet: // account retrieval
			http.Error(w, "retrieval of created account not implemented by mock server", http.StatusNotImplemented)
			return
		}

		b, _ := json.Marshal(vaultResponse)
		_, _ = w.Write(b)
	}

	b.handlers[path] = handler
	return b
}

func (b *VaultBuilder) WithSignerAccountCreationHandler(t *testing.T, d HandlerData) *VaultBuilder {
	if b.handlers == nil {
		b.handlers = make(map[string]http.HandlerFunc)
	}
	path := fmt.Sprintf("/v1/%v/accounts/%v", d.SecretEnginePath, d.SecretPath)

	handler := func(w http.ResponseWriter, r *http.Request) {
		// check plugin has correctly authenticated the request
		header := map[string][]string(r.Header)
		requestTokens := header[consts.AuthHeaderName]
		require.Equal(t, AUTH_TOKEN, requestTokens[0])

		vaultResponse := new(api.Secret)

		switch r.Method {
		case http.MethodPut: // account creation
			b, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)
			body := make(map[string]interface{})
			require.NoError(t, json.Unmarshal(b, &body))

			require.Len(t, body, 0)

			vaultResponse.Data = map[string]interface{}{
				"addr": d.SignerCreatedAccount,
			}

		case http.MethodGet: // account retrieval
			http.Error(w, "retrieval of created account not implemented by mock server", http.StatusNotImplemented)
			return
		}

		b, _ := json.Marshal(vaultResponse)
		_, _ = w.Write(b)
	}

	b.handlers[path] = handler
	return b
}

func (b *VaultBuilder) WithSignerAccountImportHandler(t *testing.T, d HandlerData) *VaultBuilder {
	if b.handlers == nil {
		b.handlers = make(map[string]http.HandlerFunc)
	}
	path := fmt.Sprintf("/v1/%v/accounts/%v", d.SecretEnginePath, d.SecretPath)

	handler := func(w http.ResponseWriter, r *http.Request) {
		// check plugin has correctly authenticated the request
		header := map[string][]string(r.Header)
		requestTokens := header[consts.AuthHeaderName]
		require.Equal(t, AUTH_TOKEN, requestTokens[0])

		vaultResponse := new(api.Secret)

		switch r.Method {
		case http.MethodPut: // account creation
			b, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)
			body := make(map[string]interface{})
			require.NoError(t, json.Unmarshal(b, &body))

			require.Len(t, body, 1)
			data := body["import"].(string)
			require.Equal(t, d.SignerKeyToImport, data)

			vaultResponse.Data = map[string]interface{}{
				"addr": d.SignerCreatedAccount,
			}

		case http.MethodGet: // account retrieval
			http.Error(w, "retrieval of created account not implemented by mock server", http.StatusNotImplemented)
			return
		}

		b, _ := json.Marshal(vaultResponse)
		_, _ = w.Write(b)
	}

	b.handlers[path] = handler
	return b
}

func (b *VaultBuilder) WithCaCert(s string) *VaultBuilder {
	b.caCert = s
	return b
}

func (b *VaultBuilder) WithServerCert(s string) *VaultBuilder {
	b.serverCert = s
	return b
}

func (b *VaultBuilder) WithServerKey(s string) *VaultBuilder {
	b.serverKey = s
	return b
}

func (b *VaultBuilder) Build(t *testing.T) *httptest.Server {
	require.True(t, len(b.handlers) > 0)

	mux := http.NewServeMux()
	for path, handler := range b.handlers {
		mux.HandleFunc(path, handler)
	}
	vaultServer := httptest.NewUnstartedServer(mux)

	// read TLS certs
	rootCert, err := ioutil.ReadFile(b.caCert)
	require.NoError(t, err)
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(rootCert)

	cert, err := ioutil.ReadFile(b.serverCert)
	require.NoError(t, err)

	key, err := ioutil.ReadFile(b.serverKey)
	require.NoError(t, err)

	keypair, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	vaultServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{keypair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	return vaultServer
}
