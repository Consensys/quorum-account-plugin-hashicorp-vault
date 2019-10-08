package hashicorp

import (
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type acct struct {
	addr, key string
}

var (
	acct1 = acct{
		addr: "0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5",
		key:  "0xa0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec",
	}
	acct2 = acct{
		addr: "0x2332f90a329c2c55ba120b1449d36a144d1f9fe4",
		key:  "0xf979964ba371b55ad7ae4502d21a617c3434224291a84559e73ef69fd0629dbc",
	}
	acct3 = acct{
		addr: "0x992d7a8fca612c963796ecbfe78b300370b9545a",
		key:  "0xeaa0bddeae4ec6aca7a77da41e898a82133adc6e0ac6816c32433d0f739005e7",
	}
	acct4 = acct{
		addr: "0x39ac8f3ae3681b4422fdf808ae18ba4365e37da8",
		key:  "0x8bd76e8a5a3945ac6f482f842bc43cf0a51b13bdf378ea8f1d46ee906ccd1cde",
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

func (b *testHashicorpWalletBuilder) withAuthorizationID(authorizationID string) {
	b.config.AuthorizationID = authorizationID
}

func (b *testHashicorpWalletBuilder) build(t *testing.T) *wallet {
	w, err := NewHashicorpWallet(b.config, b.backend, false)
	if err != nil {
		t.Fatal(err)
	}

	return w
}

func addUnlockedAccts(t *testing.T, w *wallet, accts []string) {
	addLockedAccts(t, w, accts)

	u := make(map[common.Address]*unlocked)

	for _, a := range accts {
		u[common.HexToAddress(a)] = &unlocked{}
	}

	w.unlocked = u
}

func addLockedAccts(t *testing.T, w *wallet, accts []string) {
	for _, a := range accts {
		addAcct(t, w, a)
	}
}

func addAcct(t *testing.T, w *wallet, acct string) {
	if !common.IsHexAddress(acct) {
		t.Fatalf("invalid hex address: %v", acct)
	}

	addr := common.HexToAddress(acct)

	w.cache.ByAddr[addr] = []accounts.Account{}
	w.cache.All = append(w.cache.All, accounts.Account{Address: addr})
}

func setupMockSealedVaultServer(w *wallet) func() {
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))

	w.config.VaultUrl = vaultServer.URL

	return vaultServer.Close
}

func setupMockSealedVaultServerAndOpen(t *testing.T, w *wallet) func() {
	cleanup := setupMockSealedVaultServer(w)

	if err := w.Open(""); err != nil {
		cleanup()
		t.Fatal(err)
	}

	return cleanup
}

// create a new mock server which returns mockResponse for all calls, updating w's config to use the mock server when opened.  Caller should call returned function when finished to shut down the mock server.
// TODO make createSimpleHandler so that uses of this can be replaced with setupMockVaultServer2
func setupMockVaultServer(w *wallet, mockResponse []byte) func() {
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(mockResponse)
	}))

	w.config.VaultUrl = vaultServer.URL

	return vaultServer.Close
}

func setupMock404VaultServer(w *wallet) func() {
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		//w.Write(mockResponse)
	}))

	w.config.VaultUrl = vaultServer.URL

	return vaultServer.Close
}

// create a new mock server which uses handler for all calls, updating w's config to use the mock server when opened.  Caller should call returned function when finished to shut down the mock server.
func setupMockVaultServer2(w *wallet, handler http.HandlerFunc) func() {
	vaultServer := httptest.NewServer(handler)

	w.config.VaultUrl = vaultServer.URL

	return vaultServer.Close
}

func setupMockVaultServerAndOpen(t *testing.T, w *wallet, mockResponse []byte) func() {
	cleanup := setupMockVaultServer(w, mockResponse)

	if err := w.Open(""); err != nil {
		cleanup()
		t.Fatal(err)
	}

	return cleanup
}

func setupMock404VaultServerAndOpen(t *testing.T, w *wallet) func() {
	cleanup := setupMock404VaultServer(w)

	if err := w.Open(""); err != nil {
		cleanup()
		t.Fatal(err)
	}

	return cleanup
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

// make an arbitrary read request using the Vault client setup in the wallet
func makeArbitraryRequestUsingVaultClient(t *testing.T, w *wallet) {
	_, err := w.client.Logical().Read("some/arbitrary/path")

	if err != nil {
		t.Fatal(err)
	}
}
