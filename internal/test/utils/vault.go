package utils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"

	"github.com/hashicorp/vault/sdk/helper/consts"
)

type PathHandler struct {
	Path    string
	Handler http.HandlerFunc
}

func SetupMockTLSVaultServer(caCert, serverCert, serverKey string, handlers ...PathHandler) (*httptest.Server, error) {
	var vaultServer *httptest.Server

	if len(handlers) == 0 {
		return nil, errors.New("no handlers defined")
	} else {
		mux := http.NewServeMux()
		for i := range handlers {
			mux.HandleFunc(handlers[i].Path, handlers[i].Handler)
		}
		vaultServer = httptest.NewUnstartedServer(mux)
	}

	// read TLS certs
	rootCert, err := ioutil.ReadFile(caCert)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(rootCert)

	cert, err := ioutil.ReadFile(serverCert)
	if err != nil {
		return nil, err
	}

	key, err := ioutil.ReadFile(serverKey)
	if err != nil {
		return nil, err
	}

	keypair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	serverTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{keypair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	// add TLS config to server and start
	vaultServer.TLS = serverTlsConfig
	vaultServer.StartTLS()

	return vaultServer, nil
}

func SetupMockVaultServer(handlers ...PathHandler) (*httptest.Server, error) {
	var vaultServer *httptest.Server

	if len(handlers) == 0 {
		return nil, errors.New("no handlers defined")
	} else {
		mux := http.NewServeMux()
		for i := range handlers {
			mux.HandleFunc(handlers[i].Path, handlers[i].Handler)
		}
		vaultServer = httptest.NewServer(mux)
	}

	return vaultServer, nil
}

func RequireRequestIsAuthenticated(r *http.Request, token string) error {
	header := map[string][]string(r.Header)
	requestTokens := header[consts.AuthHeaderName]

	if len(requestTokens) != 1 {
		return fmt.Errorf("want 1 element in header[%v], got %v", consts.AuthHeaderName, len(requestTokens))
	}
	if token != requestTokens[0] {
		return fmt.Errorf("incorrect auth token for request: want %v, got %v", token, requestTokens[0])
	}
	return nil
}
