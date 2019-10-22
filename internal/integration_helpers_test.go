package internal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	iproto "github.com/goquorum/quorum-plugin-definitions/initializer/go/proto"
	sproto "github.com/goquorum/quorum-plugin-definitions/signer/go/proto"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/hashicorp"
	"github.com/hashicorp/go-plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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
	caCert     = "vault/testdata/tls/caRoot.pem"
	clientCert = "vault/testdata/tls/quorum-client-chain.pem"
	clientKey  = "vault/testdata/tls/quorum-client.key"
	serverCert = "vault/testdata/tls/localhost-with-san-chain.pem"
	serverKey  = "vault/testdata/tls/localhost-with-san.key"
)

func makeWalletUrl(scheme string, userInfo string, vaultUrl string, acctConfig hashicorp.AccountConfig) (accounts.URL, error) {
	url, err := vault.ToUrl(vaultUrl)
	if err != nil {
		return accounts.URL{}, err
	}

	wltPath := fmt.Sprintf(
		"%v/v1/%v/data/%v?version=%v#addr=%v",
		url.Path,
		acctConfig.HashicorpVault.PathParams.SecretEnginePath,
		acctConfig.HashicorpVault.PathParams.SecretPath,
		acctConfig.HashicorpVault.PathParams.SecretVersion,
		acctConfig.Address,
	)

	if userInfo != "" {
		wltPath = fmt.Sprintf("%v@%v", userInfo, wltPath)
	}

	return accounts.URL{Scheme: scheme, Path: wltPath}, nil
}

var (
	acct1JsonConfig = []byte(`{
  "address": "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
  "hashicorpvault": {
    "pathparams": {
      "secretenginepath": "kv",
      "secretpath": "kvacct",
      "secretversion": 1
    },
    "authid": "FOO"
  },
  "id": "afb297d8-1995-4212-974a-e861d7e31e19",
  "version": 1
}`)
	acct2JsonConfig = []byte(`{
  "address": "4d6d744b6da435b5bbdde2526dc20e9a41cb72e5",
  "hashicorpvault": {
    "pathparams": {
      "secretenginepath": "engine",
      "secretpath": "engineacct",
      "secretversion": 2
    },
    "authid": "FOO"
  },
  "id": "d88bd481-4db4-4ee5-8ea6-84042d2fb0cf",
  "version": 1
}`)
)
