package hashicorp

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type acct struct {
	addr, key string
}

var (
	acct1Data = acct{
		addr: "0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5",
		key:  "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec",
	}
	acct2Data = acct{
		addr: "0x2332f90a329c2c55ba120b1449d36a144d1f9fe4",
		key:  "0xf979964ba371b55ad7ae4502d21a617c3434224291a84559e73ef69fd0629dbc",
	}
	acct3Data = acct{
		addr: "0x992d7a8fca612c963796ecbfe78b300370b9545a",
		key:  "0xeaa0bddeae4ec6aca7a77da41e898a82133adc6e0ac6816c32433d0f739005e7",
	}
	acct4Data = acct{
		addr: "0x39ac8f3ae3681b4422fdf808ae18ba4365e37da8",
		key:  "0x8bd76e8a5a3945ac6f482f842bc43cf0a51b13bdf378ea8f1d46ee906ccd1cde",
	}
	acct1 = accounts.Account{
		Address: common.HexToAddress(acct1Data.addr),
		URL:     accounts.URL{Scheme: AcctScheme, Path: "testdata/acctconfig/acct1.json"},
	}
	acct2 = accounts.Account{
		Address: common.HexToAddress(acct2Data.addr),
		URL:     accounts.URL{Scheme: AcctScheme, Path: "testdata/acctconfig/acct2.json"},
	}
	acct3 = accounts.Account{
		Address: common.HexToAddress(acct3Data.addr),
		URL:     accounts.URL{Scheme: AcctScheme, Path: "testdata/acctconfig/acct3.json"},
	}
	acct4 = accounts.Account{
		Address: common.HexToAddress(acct4Data.addr),
		URL:     accounts.URL{Scheme: AcctScheme, Path: "testdata/acctconfig/acct4.json"},
	}
)

type testHashicorpWalletBuilder struct {
	config  HashicorpWalletConfig
	backend *Backend
}

func (b *testHashicorpWalletBuilder) withBasicConfig() {
	b.config = HashicorpWalletConfig{
		VaultUrl:         "http://url:1",
		AccountConfigDir: "/path/to/acctconfigdir",
		//ApprolePath: "",
		//CaCert: "",
		//ClientCert: "",
		//ClientKey: "",
		//Unlock: "",
		//AuthorizationID: "",
	}

	b.backend = &Backend{}
}

func (b *testHashicorpWalletBuilder) withApprolePath(approlePath string) {
	b.config.ApprolePath = approlePath
}

func (b *testHashicorpWalletBuilder) withAuthorizationID(authorizationID string) {
	b.config.AuthorizationID = authorizationID
}

func (b *testHashicorpWalletBuilder) withMutualTLSConfig(caCert, clientCert, clientKey string) {
	b.config.CaCert = caCert
	b.config.ClientCert = clientCert
	b.config.ClientKey = clientKey
}

func (b *testHashicorpWalletBuilder) withAccountConfigDir(accountConfigDir string) {
	b.config.AccountConfigDir = accountConfigDir
}

func (b *testHashicorpWalletBuilder) build(t *testing.T) *wallet {
	w, err := NewHashicorpWallet(b.config, b.backend, false)
	require.NoError(t, err)

	return w
}

type acctAndKey struct {
	acct accounts.Account
	key  *ecdsa.PrivateKey
}

func addUnlockedAccts(t *testing.T, w *wallet, acctAndKeys ...acctAndKey) {
	u := make(map[common.Address]*unlocked)

	for _, a := range acctAndKeys {
		addAcct(t, w, a.acct)
		u[a.acct.Address] = &unlocked{Key: &keystore.Key{
			Address:    a.acct.Address,
			PrivateKey: a.key,
		}}
	}

	w.unlocked = u
}

func addLockedAccts(t *testing.T, w *wallet, accts ...accounts.Account) {
	for _, a := range accts {
		addAcct(t, w, a)
	}
}

func addAcct(t *testing.T, w *wallet, acct accounts.Account) {
	w.cache.ByAddr[acct.Address] = append(w.cache.ByAddr[acct.Address], acct)
	w.cache.All = append(w.cache.All, acct)
}

const (
	vaultNotFoundStatusCode int = 404
)

func setupMockErrorCodeVaultServerAndRegisterWithWallet(w *wallet, statusCode int) func() {
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
	}))

	w.config.VaultUrl = vaultServer.URL

	return vaultServer.Close
}

func setupMockErrorCodeVaultServerAndRegisterWithWalletAndOpen(t *testing.T, w *wallet, statusCode int) func() {
	cleanup := setupMockErrorCodeVaultServerAndRegisterWithWallet(w, statusCode)

	if err := w.Open(""); err != nil {
		cleanup()
		t.Fatal(err)
	}

	return cleanup
}

func createSimpleHandler(response []byte) pathHandler {
	return pathHandler{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(response)
		}),
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

func setupMockVaultServerAndRegisterWithWalletAndOpen(t *testing.T, w *wallet, handlers ...pathHandler) func() {
	cleanup := setupMockVaultServerAndRegisterWithWallet(t, w, handlers...)

	if err := w.Open(""); err != nil {
		cleanup()
		t.Fatal(err)
	}

	return cleanup
}

// create a new mock server which uses handler for all calls, updating w's config to use the mock server when opened.  Caller should call returned function when finished to shut down the mock server.
func setupMockVaultServerAndRegisterWithWallet(t *testing.T, w *wallet, handlers ...pathHandler) func() {
	vaultServer := setupMockVaultServer(t, handlers...)

	w.config.VaultUrl = vaultServer.URL
	return vaultServer.Close
}

func setupMockTLSVaultServerAndRegisterWithWallet(t *testing.T, w *wallet, handlers ...pathHandler) func() {
	vaultServer := setupMockTLSVaultServer(t, handlers...)

	w.config.VaultUrl = vaultServer.URL
	return vaultServer.Close
}

// create a new mock server which uses handler for all calls, updating w's config to use the mock server when opened.  Caller should call returned function when finished to shut down the mock server.
func setupMockVaultServer(t *testing.T, handlers ...pathHandler) *httptest.Server {
	var vaultServer *httptest.Server

	require.NotZero(t, len(handlers))
	if len(handlers) == 1 {
		vaultServer = httptest.NewServer(handlers[0].handler)
	} else {
		mux := http.NewServeMux()
		for i := range handlers {
			mux.HandleFunc(handlers[i].path, handlers[i].handler)
		}
		vaultServer = httptest.NewServer(mux)
	}

	return vaultServer
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

const arbitraryPath = "some/arbitrary/path"

// make an arbitrary read request using the Vault client setup in the wallet
func makeArbitraryRequestUsingVaultClient(t *testing.T, w *wallet) {
	_, err := w.client.Logical().Read(arbitraryPath)
	require.NoError(t, err)
}
