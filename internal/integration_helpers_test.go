package internal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/config"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/utils"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	iproto "github.com/goquorum/quorum-plugin-definitions/initializer/go/proto"
	sproto "github.com/goquorum/quorum-plugin-definitions/signer/go/proto"
	"github.com/hashicorp/go-plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// testableSignerPluginImpl is a HashicorpVaultAccountManagerPlugin but provides a simple gRPC client implementation for integration testing without needing the geth side
type testableSignerPluginImpl struct {
	HashicorpVaultAccountManagerPlugin
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
	caCert     = "test/data/tls/caRoot.pem"
	clientCert = "test/data/tls/quorum-client-chain.pem"
	clientKey  = "test/data/tls/quorum-client.key"
	serverCert = "test/data/tls/localhost-with-san-chain.pem"
	serverKey  = "test/data/tls/localhost-with-san.key"
)

func makeWalletUrl(scheme string, vaultUrl string, acctConfig config.AccountConfig) (accounts.URL, error) {
	url, err := utils.ToUrl(vaultUrl)
	if err != nil {
		return accounts.URL{}, err
	}

	wltPath := fmt.Sprintf(
		"%v/v1/%v/data/%v?version=%v#addr=%v",
		url.Path,
		acctConfig.VaultSecret.PathParams.SecretEnginePath,
		acctConfig.VaultSecret.PathParams.SecretPath,
		acctConfig.VaultSecret.PathParams.SecretVersion,
		acctConfig.Address,
	)

	if authID := acctConfig.VaultSecret.AuthID; authID != "" {
		wltPath = fmt.Sprintf("%v@%v", authID, wltPath)
	}

	return accounts.URL{Scheme: scheme, Path: wltPath}, nil
}
