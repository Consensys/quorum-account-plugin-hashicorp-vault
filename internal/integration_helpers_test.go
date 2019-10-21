package internal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	iproto "github.com/goquorum/quorum-plugin-definitions/initializer/go/proto"
	sproto "github.com/goquorum/quorum-plugin-definitions/signer/go/proto"
	"github.com/hashicorp/go-plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// testableSignerPluginImpl is a SignerPluginImpl but provides a simple gRPC client implementation for integration testing without needing the geth side
type testableSignerPluginImpl struct {
	SignerPluginImpl
}

func (testableSignerPluginImpl) GRPCClient(ctx context.Context, b *plugin.GRPCBroker, cc *grpc.ClientConn) (interface{}, error) {
	//return sproto.NewSignerClient(cc), nil
	return newInitializerSignerClient(cc)
}

type InitializerSignerClient struct {
	iproto.PluginInitializerClient
	sproto.SignerClient
}

func newInitializerSignerClient(cc *grpc.ClientConn) (interface{}, error) {
	initializerClient := iproto.NewPluginInitializerClient(cc)
	signerClient := sproto.NewSignerClient(cc)

	return InitializerSignerClient{
		PluginInitializerClient: initializerClient,
		SignerClient:            signerClient,
	}, nil
}

// set the given environment variables with their own names.  Caller should call returned function when finished to unset the env variables
func setEnvironmentVariables(toSet ...string) func() {
	for _, s := range toSet {
		os.Setenv(s, s)
	}

	return func() {
		for _, s := range toSet {
			os.Unsetenv(s)
		}
	}
}

type pathHandler struct {
	path    string
	handler http.HandlerFunc
}

func newPathHandler(path string, handler http.HandlerFunc) pathHandler {
	return pathHandler{
		path:    path,
		handler: handler,
	}
}

func setupMockTLSVaultServer(t *testing.T, handlers ...pathHandler) *httptest.Server {
	testrequire := require.New(t)

	var vaultServer *httptest.Server

	testrequire.NotZero(len(handlers))
	if len(handlers) == 1 {
		vaultServer = httptest.NewUnstartedServer(handlers[0].handler)
	} else {
		mux := http.NewServeMux()
		for i := range handlers {
			mux.HandleFunc(handlers[i].path, handlers[i].handler)
		}
		vaultServer = httptest.NewUnstartedServer(mux)
	}

	// read TLS certs
	rootCert, err := ioutil.ReadFile(caCert)
	testrequire.NoError(err)
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(rootCert)

	cert, err := ioutil.ReadFile(serverCert)
	testrequire.NoError(err)

	key, err := ioutil.ReadFile(serverKey)
	testrequire.NoError(err)

	keypair, err := tls.X509KeyPair(cert, key)
	testrequire.NoError(err)

	serverTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{keypair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	// add TLS config to server and start
	vaultServer.TLS = serverTlsConfig
	vaultServer.StartTLS()

	return vaultServer
}

const (
	caCert     = "testdata/caRoot.pem"
	clientCert = "testdata/quorum-client-chain.pem"
	clientKey  = "testdata/quorum-client.key"
	serverCert = "testdata/localhost-with-san-chain.pem"
	serverKey  = "testdata/localhost-with-san.key"
)
