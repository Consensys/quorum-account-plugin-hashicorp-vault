package utils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
)

type PathHandler struct {
	Path    string
	Handler http.HandlerFunc
}

func SetupMockTLSVaultServer(handlers ...PathHandler) (*httptest.Server, error) {
	var vaultServer *httptest.Server

	if len(handlers) == 0 {
		return nil, errors.New("no handlers defined")
	} else if len(handlers) == 1 {
		vaultServer = httptest.NewUnstartedServer(handlers[0].Handler)
	} else {
		mux := http.NewServeMux()
		for i := range handlers {
			mux.HandleFunc(handlers[i].Path, handlers[i].Handler)
		}
		vaultServer = httptest.NewUnstartedServer(mux)
	}

	// read TLS certs
	rootCert, err := ioutil.ReadFile(CaCert)
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

const (
	CaCert     = "test/data/tls/caRoot.pem"
	ClientCert = "test/data/tls/quorum-client-chain.pem"
	ClientKey  = "test/data/tls/quorum-client.key"
	serverCert = "test/data/tls/localhost-with-san-chain.pem"
	serverKey  = "test/data/tls/localhost-with-san.key"
)
