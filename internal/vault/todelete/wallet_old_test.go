package todelete

//
//import (
//	"encoding/json"
//	"fmt"
//	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
//	"github.com/hashicorp/vault/api"
//	"net/http"
//	"net/http/httptest"
//	"testing"
//)
//
////func createWalletForTesting(contains []accounts.Account, unlockedKeys map[common.Address]*ecdsa.PrivateKey) *wallet {
////	// empty structs required to prevent seg violations
////	ac := &accountCache{}
////	ac.watcher = &watcher{}
////	ac.watcher.ac = ac
////	ac.watcher.ev = make(chan notify.EventInfo, 10)
////	ac.watcher.quit = make(chan struct{})
////
////	// populate the cache
////	ac.all = contains
////
////	byAddr := make(map[common.Address][]accounts.Account)
////
////	for _, acct := range contains {
////		if _, ok := byAddr[acct.Address]; ok {
////			byAddr[acct.Address] = append(byAddr[acct.Address], acct)
////		} else {
////			byAddr[acct.Address] = []accounts.Account{acct}
////		}
////	}
////
////	ac.byAddr = byAddr
////
////	u := make(map[common.Address]*unlocked)
////
////	for a, k := range unlockedKeys {
////		u[a] = &unlocked{Key: &keystore.Key{PrivateKey: k}}
////	}
////
////	return &wallet{
////		vault: &hashicorpService{
////			cache: ac,
////			unlocked: u,
////		},
////	}
////}
////
////func TestVaultWallet_URL(t *testing.T) {
////	in := accounts.URL{Scheme: "http", Path: "url"}
////	w := wallet{url: in}
////
////	got := w.URL()
////
////	if in.Cmp(got) != 0 {
////		t.Fatalf("want: %v, got: %v", in, got)
////	}
////}
////
//// makeMockHashicorpService creates a new httptest.Server which responds with mockResponse for all requests.  A default Hashicorp api.Client with URL updated with the httptest.Server's URL is returned.  The Close() function for the httptest.Server and should be executed before test completion (probably best to defer as soon as it is returned)
//func makeMockHashicorpClient(t *testing.T, mockResponse []byte) (*api.Client, func()) {
//	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		w.Write(mockResponse)
//	}))
//
//	//create default client and update URL to use mock vault server
//	config := api.DefaultConfig()
//	config.Address = vaultServer.URL
//	client, err := api.NewClient(config)
//
//	if err != nil {
//		t.Fatalf("err creating client: %v", err)
//	}
//
//	return client, vaultServer.Close
//}
//
//type handlerData struct {
//	secretName string
//	resp       map[string]string
//}
//
//func setupTestVaultServer(t *testing.T, handlerData []handlerData) (*httptest.Server, func()) {
//	makeSecretResponse := func(keyValPairs map[string]string) []byte {
//		resp := api.Secret{
//			Data: map[string]interface{}{
//				"data": keyValPairs,
//			},
//		}
//
//		b, err := json.Marshal(resp)
//
//		if err != nil {
//			t.Fatal(err)
//		}
//
//		return b
//	}
//
//	makeHealthResponse := func() []byte {
//		healthResponse := api.HealthResponse{Initialized: true, Sealed: false}
//
//		b, err := json.Marshal(healthResponse)
//
//		if err != nil {
//			t.Fatalf("err marshalling mock response: %v", err)
//		}
//
//		return b
//	}
//
//	var vaultServer *httptest.Server
//
//	switch len(handlerData) {
//	case 1:
//		vaultServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//			w.Write(makeSecretResponse(handlerData[0].resp))
//		}))
//	default:
//		mux := http.NewServeMux()
//
//		for _, d := range handlerData {
//			d := d // function literals are only evaluated when called so redeclare to create a separate copy for each loop iteration, see https://stackoverflow.com/questions/48627636/golang-api-only-matches-last-route
//
//			path := fmt.Sprintf("/v1/kv/data/%s", d.secretName)
//
//			mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
//				w.Write(makeSecretResponse(d.resp))
//			})
//		}
//
//		mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
//			w.Write(makeHealthResponse())
//		})
//
//		vaultServer = httptest.NewServer(mux)
//	}
//
//	return vaultServer, vaultServer.Close
//}
//
//func setHashicorpWalletClientForServer(t *testing.T, w *vault.wallet, server *httptest.Server) {
//	//create default Hashicorp Vault client and update URL to use our test server
//	config := api.DefaultConfig()
//	config.Address = server.URL
//	client, err := api.NewClient(config)
//
//	if err != nil {
//		t.Fatalf("err creating client: %v", err)
//	}
//
//	w.client = client
//}
//
////
////func TestVaultWallet_Status_Hashicorp_ClosedWhenServiceHasNoClient(t *testing.T) {
////	w := wallet{vault: &hashicorpService{cache: &accountCache{}}}
////
////	status, err := w.Status()
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if status != closed {
////		t.Fatalf("want: %v, got: %v", closed, status)
////	}
////}
////
////func TestVaultWallet_Status_Hashicorp_HealthcheckSuccessful(t *testing.T) {
////	const (
////		uninitialised = "uninitialized"
////		sealed        = "sealed"
////		open          = "open"
////	)
////
////	makeMockHashicorpResponse := func(t *testing.T, vaultStatus string) []byte {
////		var vaultResponse api.HealthResponse
////
////		switch vaultStatus {
////		case uninitialised:
////			vaultResponse.Initialized = false
////		case sealed:
////			vaultResponse.Initialized = true
////			vaultResponse.Sealed = true
////		case open:
////			vaultResponse.Initialized = true
////			vaultResponse.Sealed = false
////		}
////
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatalf("err marshalling mock response: %v", err)
////		}
////
////		return b
////	}
////
////	tests := []struct {
////		vaultStatus string
////		want        string
////		wantErr     error
////	}{
////		{vaultStatus: uninitialised, want: hashicorpUninitialized, wantErr: hashicorpUninitializedErr},
////		{vaultStatus: sealed, want: hashicorpSealed, wantErr: hashicorpSealedErr},
////		{vaultStatus: open, want: open, wantErr: nil},
////	}
////
////	for _, tt := range tests {
////		t.Run(tt.vaultStatus, func(t *testing.T) {
////			b := makeMockHashicorpResponse(t, tt.vaultStatus)
////			c, cleanup := makeMockHashicorpClient(t, b)
////			defer cleanup()
////
////			w := wallet{
////				vault: &hashicorpService{client: c, cache: &accountCache{}},
////			}
////
////			status, err := w.Status()
////
////			if tt.wantErr != err {
////				t.Fatalf("want: %v, got: %v", tt.wantErr, err)
////			}
////
////			if tt.want != status {
////				t.Fatalf("want: %v, got: %v", tt.want, status)
////			}
////		})
////	}
////}
////
////func TestVaultWallet_Status_Hashicorp_HealthcheckFailed(t *testing.T) {
////	b := []byte("this is not the bytes for an api.HealthResponse and will cause a client error")
////
////	c, cleanup := makeMockHashicorpClient(t, b)
////	defer cleanup()
////
////	w := wallet{
////		vault: &hashicorpService{client: c, cache: &accountCache{}},
////	}
////
////	status, err := w.Status()
////
////	if _, ok := err.(hashicorpHealthcheckErr); !ok {
////		t.Fatal("returned error should be of type hashicorpHealthcheckErr")
////	}
////
////	if status != hashicorpHealthcheckFailed {
////		t.Fatalf("want: %v, got: %v", hashicorpHealthcheckFailed, status)
////	}
////}
////
////func TestVaultWallet_Open_Hashicorp_ReturnsErrIfAlreadyOpen(t *testing.T) {
////	w := wallet{vault: &hashicorpService{client: &api.Client{}}}
////
////	if err := w.Open(""); err != accounts.ErrWalletAlreadyOpen {
////		t.Fatalf("want: %v, got: %v", accounts.ErrWalletAlreadyOpen, err)
////	}
////}
////
////func TestVaultWallet_Open_Hashicorp_CreatesClientFromConfig(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	server, serverClose := setupTestVaultServer(t, []handlerData{
////		{resp: map[string]string{"myData": "value"}},
////	})
////	defer serverClose()
////
////	config := HashicorpClientConfig{
////		Url: server.URL,
////	}
////
////	w := wallet{vault: &hashicorpService{config: config}, backend: &Backend{updateFeed: event.Feed{}}}
////
////	if err := w.Open(""); err != nil {
////		t.Fatalf("error: %v", err)
////	}
////
////	v, ok := w.vault.(*hashicorpService)
////
////	if !ok {
////		t.Fatal("type assertion failed")
////	}
////
////	got := v.client
////
////	if got == nil {
////		t.Fatal("client not created")
////	}
////
////	if got.Address() != config.Url {
////		t.Fatalf("address: want: %v, got: %v", config.Url, got.Address())
////	}
////
////	// make a request to the vault server using the client to verify client config was correctly applied
////	resp, err := got.Logical().Read("some/arbitrary/path")
////
////	if err != nil {
////		t.Fatalf("error making request using created client: %v", err)
////	}
////
////	if resp == nil {
////		t.Fatalf("no response received")
////	}
////}
////
////func TestVaultWallet_Open_Hashicorp_CreatesTLSClientFromConfig(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	// create mock server which responds to all requests with an empty secret
////	mockResponse := api.Secret{}
////	b, err := json.Marshal(mockResponse)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	vaultServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
////		w.Write(b)
////	}))
////
////	// read TLS certs
////	rootCert, err := ioutil.ReadFile("testdata/caRoot.pem")
////
////	if err != nil {
////		t.Error(err)
////	}
////
////	certPool := x509.NewCertPool()
////	certPool.AppendCertsFromPEM(rootCert)
////
////	cert, err := ioutil.ReadFile("testdata/localhost-with-san-chain.pem")
////
////	if err != nil {
////		t.Error(err)
////	}
////
////	key, err := ioutil.ReadFile("testdata/localhost-with-san.key")
////
////	if err != nil {
////		t.Error(err)
////	}
////
////	keypair, err := tls.X509KeyPair(cert, key)
////
////	if err != nil {
////		t.Error(err)
////	}
////
////	serverTlsConfig := &tls.Config{
////		Certificates: []tls.Certificate{keypair},
////		ClientAuth:   tls.RequireAndVerifyClientCert,
////		ClientCAs:    certPool,
////	}
////
////	// add TLS config to server and start
////	vaultServer.TLS = serverTlsConfig
////
////	vaultServer.StartTLS()
////	defer vaultServer.Close()
////
////	// create wallet with config and open
////	config := HashicorpClientConfig{
////		Url:        vaultServer.URL,
////		CaCert:     "testdata/caRoot.pem",
////		ClientCert: "testdata/quorum-client-chain.pem",
////		ClientKey:  "testdata/quorum-client.key",
////	}
////
////	w := wallet{vault: &hashicorpService{config: config}, backend: &Backend{updateFeed: event.Feed{}}}
////
////	if err := w.Open(""); err != nil {
////		t.Fatalf("error: %v", err)
////	}
////
////	// verify created client uses config
////	v, ok := w.vault.(*hashicorpService)
////
////	if !ok {
////		t.Fatal("type assertion failed")
////	}
////
////	got := v.client
////
////	if got == nil {
////		t.Fatal("client not created")
////	}
////
////	if got.Address() != vaultServer.URL {
////		t.Fatalf("address: want: %v, got: %v", vaultServer.URL, got.Address())
////	}
////
////	// make a request to the vault server using the client - if TLS was applied correctly on the client then the request will be allowed
////	if _, err := got.Logical().Read("some/arbitrary/path"); err != nil {
////		t.Fatalf("error making request using created client: %v", err)
////	}
////}
////
////func TestVaultWallet_Open_Hashicorp_ClientAuthenticatesUsingEnvVars(t *testing.T) {
////	const (
////		myToken        = "myToken"
////		myRoleId       = "myRoleId"
////		mySecretId     = "mySecretId"
////		myApproleToken = "myApproleToken"
////	)
////
////	setAndHandleErrors := func(t *testing.T, env, val string) {
////		if err := os.Setenv(env, val); err != nil {
////			t.Fatal(err)
////		}
////	}
////
////	set := func(t *testing.T, env string) {
////		switch env {
////		case api.EnvVaultToken:
////			setAndHandleErrors(t, api.EnvVaultToken, myToken)
////		case RoleIDEnv:
////			setAndHandleErrors(t, RoleIDEnv, myRoleId)
////		case SecretIDEnv:
////			setAndHandleErrors(t, SecretIDEnv, mySecretId)
////		}
////	}
////
////	// makeMockApproleVaultServer creates an httptest.Server for handling approle auth requests.  The server and its Close function are returned.  Close must be called to ensure the server is stopped (best to defer the function as soon as it is returned).
////	//
////	// The server will expose only the path /v1/auth/{approlePath}/login.  If approlePath = "" then the default value of "approle" will be used.  The server will respond with an api.Secret containing the provided token.
////	makeMockApproleVaultServer := func(t *testing.T, approlePath string) (*httptest.Server, func()) {
////
////		vaultResponse := &api.Secret{Auth: &api.SecretAuth{ClientToken: myApproleToken}}
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatal(err)
////		}
////
////		if approlePath == "" {
////			approlePath = "approle"
////		}
////
////		mux := http.NewServeMux()
////		mux.HandleFunc(fmt.Sprintf("/v1/auth/%v/login", approlePath), func(w http.ResponseWriter, r *http.Request) {
////			w.Write(b)
////		})
////
////		vaultServer := httptest.NewServer(mux)
////
////		return vaultServer, vaultServer.Close
////	}
////
////	tests := map[string]struct {
////		envVars   []string
////		approle   string
////		wantToken string
////	}{
////		"token auth":           {envVars: []string{api.EnvVaultToken}, wantToken: myToken},
////		"default approle auth": {envVars: []string{RoleIDEnv, SecretIDEnv}, wantToken: myApproleToken},
////		"custom approle auth":  {envVars: []string{RoleIDEnv, SecretIDEnv}, approle: "nondefault", wantToken: myApproleToken},
////	}
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			//initialize environment
////			os.Clearenv()
////			for _, e := range tt.envVars {
////				set(t, e)
////				defer os.Unsetenv(e)
////			}
////
////			vaultServer, cleanup := makeMockApproleVaultServer(t, tt.approle)
////			defer cleanup()
////
////			config := HashicorpClientConfig{
////				Url:     vaultServer.URL,
////				Approle: tt.approle,
////			}
////
////			w := wallet{vault: &hashicorpService{config: config}, backend: &Backend{updateFeed: event.Feed{}}}
////
////			if err := w.Open(""); err != nil {
////				t.Fatalf("error: %v", err)
////			}
////
////			// verify the client is set up as expected
////			v, ok := w.vault.(*hashicorpService)
////
////			if !ok {
////				t.Fatal("type assertion failed")
////			}
////
////			got := v.client
////
////			if got == nil {
////				t.Fatal("client not created")
////			}
////
////			if tt.wantToken != got.Token() {
////				t.Fatalf("incorrect client token: want: %v, got: %v", tt.wantToken, got.Token())
////			}
////		})
////	}
////}
////
////func TestVaultWallet_Open_Hashicorp_ErrAuthenticatingClient(t *testing.T) {
////	const (
////		myToken    = "myToken"
////		myRoleId   = "myRoleId"
////		mySecretId = "mySecretId"
////	)
////
////	setAndHandleErrors := func(t *testing.T, env, val string) {
////		if err := os.Setenv(env, val); err != nil {
////			t.Fatal(err)
////		}
////	}
////
////	set := func(t *testing.T, env string) {
////		switch env {
////		case api.EnvVaultToken:
////			setAndHandleErrors(t, api.EnvVaultToken, myToken)
////		case RoleIDEnv:
////			setAndHandleErrors(t, RoleIDEnv, myRoleId)
////		case SecretIDEnv:
////			setAndHandleErrors(t, SecretIDEnv, mySecretId)
////		}
////	}
////
////	tests := map[string]struct {
////		envVars []string
////		want    error
////	}{
////		"no auth provided":    {envVars: []string{}, want: noHashicorpEnvSetErr},
////		"only role id":        {envVars: []string{RoleIDEnv}, want: invalidApproleAuthErr},
////		"only secret id":      {envVars: []string{SecretIDEnv}, want: invalidApproleAuthErr},
////		"role id and token":   {envVars: []string{api.EnvVaultToken, RoleIDEnv}, want: invalidApproleAuthErr},
////		"secret id and token": {envVars: []string{api.EnvVaultToken, SecretIDEnv}, want: invalidApproleAuthErr},
////	}
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			//initialize environment
////			os.Clearenv()
////			for _, e := range tt.envVars {
////				set(t, e)
////				defer os.Unsetenv(e)
////			}
////
////			config := HashicorpClientConfig{
////				Url: "http://url:1",
////			}
////
////			w := wallet{vault: &hashicorpService{config: config}}
////
////			if err := w.Open(""); err != tt.want {
////				t.Fatalf("want error: %v\ngot: %v", tt.want, err)
////			}
////		})
////	}
////}
////
////// Note: This is an integration test, as such the scope of the test is large.  It covers the Backend, wallet and hashicorpService
////func TestVaultWallet_Open_Hashicorp_SendsEventToBackendSubscribers(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	walletConfig := HashicorpWalletConfig{
////		Client: HashicorpClientConfig{
////			Url: "http://url:1",
////		},
////	}
////
////	b := NewHashicorpBackend([]HashicorpWalletConfig{walletConfig}, "")
////
////	if len(b.wallets) != 1 {
////		t.Fatalf("NewHashicorpBackend: incorrect number of wallets created: want 1, got: %v", len(b.wallets))
////	}
////
////	subscriber := make(chan accounts.WalletEvent, 1)
////	b.Subscribe(subscriber)
////
////	if b.updateScope.Count() != 1 {
////		t.Fatalf("incorrect number of subscribers for backend: want: %v, got: %v", 1, b.updateScope.Count())
////	}
////
////	if err := b.wallets[0].Open(""); err != nil {
////		t.Fatalf("error: %v", err)
////	}
////
////	if len(subscriber) != 1 {
////		t.Fatal("event not added to subscriber")
////	}
////
////	got := <-subscriber
////
////	want := accounts.WalletEvent{Wallet: b.wallets[0], Kind: accounts.WalletOpened}
////
////	if !reflect.DeepEqual(want, got) {
////		t.Fatalf("want: %v, got: %v", want, got)
////	}
////}
////
////type accountsByUrl []accounts.Account
////
////func (a accountsByUrl) Len() int {
////	return len(a)
////}
////
////func (a accountsByUrl) Less(i, j int) bool {
////	return (a[i].URL).Cmp(a[j].URL) < 0
////}
////
////func (a accountsByUrl) Swap(i, j int) {
////	a[i], a[j] = a[j], a[i]
////}
////
////func acctsEqual(a, b []accounts.Account) bool {
////	if len(a) != len(b) {
////		return false
////	}
////
////	sort.Sort(accountsByUrl(a))
////	sort.Sort(accountsByUrl(b))
////
////	equal := func(a, b accounts.Account) bool {
////		return a.Address == b.Address && (a.URL == b.URL || a.URL == accounts.URL{} || b.URL == accounts.URL{})
////	}
////
////	for i := 0; i < len(a); i++ {
////		if !equal(a[i], b[i]) {
////			return false
////		}
////	}
////
////	return true
////}
////
////type keysByD []*ecdsa.PrivateKey
////
////func (k keysByD) Len() int {
////	return len(k)
////}
////
////func (k keysByD) Less(i, j int) bool {
////	return (k[i].D).Cmp(k[j].D) < 0
////}
////
////func (k keysByD) Swap(i, j int) {
////	k[i], k[j] = k[j], k[i]
////}
////
////func keysEqual(a, b []*ecdsa.PrivateKey) bool {
////	if len(a) != len(b) {
////		return false
////	}
////
////	sort.Sort(keysByD(a))
////	sort.Sort(keysByD(b))
////
////	equal := func(a, b *ecdsa.PrivateKey) bool {
////		return a.D.Cmp(b.D) == 0
////	}
////
////	for i := 0; i < len(a); i++ {
////		if !equal(a[i], b[i]) {
////			return false
////		}
////	}
////
////	return true
////}
////
////func TestVaultWallet_Close_Hashicorp_ReturnsStateToBeforeOpen(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	const (
////		addr1 = "addr1"
////		key1  = "key1"
////	)
////
////	server, closeServer := setupTestVaultServer(
////		t,
////		[]handlerData{
////			{secretName: addr1, resp: map[string]string{"addr": "ed9d02e382b34818e88b88a309c7fe71e65f419d"}},
////			{secretName: key1, resp: map[string]string{"key": "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"}},
////		},
////	)
////	defer closeServer()
////
////	config := HashicorpWalletConfig{
////		Client:  HashicorpClientConfig{Url: server.URL},
////		Secrets: []HashicorpSecretConfig{{AddressSecret: addr1, AddressSecretVersion: 1, PrivateKeySecret: key1, PrivateKeySecretVersion: 1, SecretEngine: "kv"}},
////	}
////
////	w, err := newHashicorpWallet(config, &Backend{updateFeed: event.Feed{}}, "", false)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	unopened, err := newHashicorpWallet(config, &Backend{updateFeed: event.Feed{}}, "", false)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	cmpOpts := []cmp.Option{
////		cmp.AllowUnexported(wallet{}, hashicorpService{}),
////		cmpopts.IgnoreUnexported(Backend{}, sync.RWMutex{}),
////	}
////
////	if diff := cmp.Diff(unopened, w, cmpOpts...); diff != "" {
////		t.Fatalf("wallets mismatch (-want +got):\n%s", diff)
////	}
////
////	if err := w.Open(""); err != nil {
////		t.Fatalf("error: %v", err)
////	}
////
////	if cmp.Equal(unopened, w, cmpOpts...) {
////		t.Fatal("no difference was detected between the opened and unopened wallets")
////	}
////
////	if err := w.Close(); err != nil {
////		t.Fatalf("error: %v", err)
////	}
////
////	if diff := cmp.Diff(unopened, w, cmpOpts...); diff != "" {
////		t.Fatalf("wallets mismatch (-want +got):\n%s", diff)
////	}
////}
////
////func TestVaultWallet_Accounts_Hashicorp_ReturnsCopyOfAccountsInWallet(t *testing.T) {
////	want := []accounts.Account{{URL: accounts.URL{Scheme: "http", Path: "url:1"}}}
////
////	ac := &accountCache{}
////	ac.all = want
////	ac.watcher = &watcher{}
////	ac.watcher.ac = ac
////	ac.watcher.ev = make(chan notify.EventInfo, 10)
////	ac.watcher.quit = make(chan struct{})
////
////	w := wallet{
////		vault: &hashicorpService{cache: ac},
////	}
////
////	got := w.Accounts()
////
////	//v := w.vault.(*hashicorpService)
////
////	if !cmp.Equal(want, got) {
////		t.Fatalf("want: %v, got: %v", want, got)
////	}
////
////	got[0].URL = accounts.URL{Scheme: "http", Path: "changed:1"}
////
////	if cmp.Equal(want, got) {
////		t.Fatalf("changes to the returned accounts should not change the wallet's record of accounts")
////	}
////}
////
////func TestVaultWallet_Contains(t *testing.T) {
////	makeAcct := func(addr, url string) accounts.Account {
////		var u accounts.URL
////
////		if url != "" {
////			//to parse a string url as an accounts.URL it must first be in json format
////			toParse := fmt.Sprintf("\"%v\"", url)
////
////			if err := u.UnmarshalJSON([]byte(toParse)); err != nil {
////				t.Fatal(err)
////			}
////		}
////
////		return accounts.Account{Address: common.StringToAddress(addr), URL: u}
////	}
////
////	tests := map[string]struct {
////		accts  []accounts.Account
////		toFind accounts.Account
////		want   bool
////	}{
////		"same addr and url":  {accts: []accounts.Account{makeAcct("addr1", "http://url:1")}, toFind: makeAcct("addr1", "http://url:1"), want: true},
////		"same addr no url":   {accts: []accounts.Account{makeAcct("addr1", "http://url:1")}, toFind: makeAcct("addr1", ""), want: true},
////		"multiple":           {accts: []accounts.Account{makeAcct("addr1", "http://url:1"), makeAcct("addr2", "http://url:2")}, toFind: makeAcct("addr2", "http://url:2"), want: true},
////		"same addr diff url": {accts: []accounts.Account{makeAcct("addr1", "http://url:1")}, toFind: makeAcct("addr1", "http://url:2"), want: false},
////		"diff addr same url": {accts: []accounts.Account{makeAcct("addr1", "http://url:1")}, toFind: makeAcct("addr2", "http://url:1"), want: false},
////		"diff addr no url":   {accts: []accounts.Account{makeAcct("addr1", "http://url:1")}, toFind: makeAcct("addr2", ""), want: false},
////		"diff addr diff url": {accts: []accounts.Account{makeAcct("addr1", "http://url:1")}, toFind: makeAcct("addr2", "http://url:2"), want: false},
////		"no accts":           {toFind: makeAcct("addr1", "http://url:1"), want: false},
////	}
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			ac := &accountCache{}
////			ac.all = tt.accts
////			ac.watcher = &watcher{}
////			ac.watcher.ac = ac
////			ac.watcher.ev = make(chan notify.EventInfo, 10)
////			ac.watcher.quit = make(chan struct{})
////
////			w := wallet{
////				vault: &hashicorpService{cache: ac},
////			}
////
////			got := w.Contains(tt.toFind)
////
////			if tt.want != got {
////				t.Fatalf("want: %v, got: %v", tt.want, got)
////			}
////		})
////	}
////}
////
////func TestVaultWallet_SignHash_Hashicorp_ErrorIfAccountNotKnown(t *testing.T) {
////	w := createWalletForTesting([]accounts.Account{}, nil)
////
////	acct := accounts.Account{Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")}
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	if _, err := w.SignHash(acct, toSign); err != accounts.ErrUnknownAccount {
////		t.Fatalf("incorrect error returned:\nwant: %v\ngot : %v", accounts.ErrUnknownAccount, err)
////	}
////}
////
////func TestVaultWallet_SignHash_Hashicorp_SignsWithInMemoryKeyIfAvailableAndDoesNotZeroKey(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct := accounts.Account{
////		Address: addr,
////		URL:     url,
////	}
////
////	key, err := crypto.HexToECDSA("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1")
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct}, map[common.Address]*ecdsa.PrivateKey{addr: key})
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	got, err := w.SignHash(acct, toSign)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	want, err := crypto.Sign(toSign, key)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if !bytes.Equal(want, got) {
////		t.Fatalf("incorrect signHash result:\nwant: %v\ngot : %v", want, got)
////	}
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) == 0 {
////		t.Fatal("unlocked key was zeroed after use")
////	}
////
////	for _, u := range unlocked {
////		key := u.PrivateKey
////		if key == nil || key.D.Int64() == 0 {
////			t.Fatal("unlocked key was zeroed after use")
////		}
////	}
////}
////
////func TestVaultWallet_SignHash_Hashicorp_ErrorIfSigningKeyIsNotRelatedToProvidedAccount(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	unrelatedKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	// the key retrieved from the vault this account is not the correct match (i.e. the address is not derivable from this key).  This situation could occur if the incorrect secret name or versions are configured (i.e. configuring node1Addr and node2Key together)
////	w := createWalletForTesting([]accounts.Account{acct}, map[common.Address]*ecdsa.PrivateKey{addr: unrelatedKey})
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	_, err = w.SignHash(acct, toSign)
////
////	if err != incorrectKeyForAddrErr {
////		t.Fatalf("want err: %v\ngot err : %v", incorrectKeyForAddrErr, err)
////	}
////}
////
////func TestVaultWallet_SignHash_Hashicorp_ErrorIfAmbiguousAccount(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////
////	url1 := accounts.URL{Scheme: "http", Path: "url:1"}
////	url2 := accounts.URL{Scheme: "http", Path: "url:2"}
////
////	acct1 := accounts.Account{Address: addr, URL: url1}
////	acct2 := accounts.Account{Address: addr, URL: url2}
////
////	// Two accounts have the same address but different URLs
////	w := createWalletForTesting([]accounts.Account{acct1, acct2}, nil)
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	// The provided account does not specify the exact account to use as no URL is provided
////	acct := accounts.Account{
////		Address: addr,
////	}
////
////	_, err := w.SignHash(acct, toSign)
////	e := err.(*AmbiguousAddrError)
////
////	want := []accounts.Account{acct1, acct2}
////
////	if diff := cmp.Diff(want, e.Matches); diff != "" {
////		t.Fatalf("ambiguous accounts mismatch (-want +got):\n%s", diff)
////	}
////}
////
////func TestVaultWallet_SignHash_Hashicorp_AmbiguousAccountAllowedIfOnlyOneAccountWithGivenAddress(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct1 := accounts.Account{Address: addr, URL: url}
////
////	key, err := crypto.HexToECDSA("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1")
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct1}, map[common.Address]*ecdsa.PrivateKey{addr: key})
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	// The provided account does not specify the exact account to use as no URL is provided
////	acct := accounts.Account{
////		Address: addr,
////	}
////
////	got, err := w.SignHash(acct, toSign)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	want, err := crypto.Sign(toSign, key)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if !bytes.Equal(want, got) {
////		t.Fatalf("incorrect signHash result:\nwant: %v\ngot : %v", want, got)
////	}
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) == 0 {
////		t.Fatal("unlocked key was zeroed after use")
////	}
////
////	for _, u := range unlocked {
////		key := u.PrivateKey
////		if key == nil || key.D.Int64() == 0 {
////			t.Fatal("unlocked key was zeroed after use")
////		}
////	}
////}
////
////func TestVaultWallet_SignHash_Hashicorp_ErrorIfAccountLocked(t *testing.T) {
////	acct := accounts.Account{
////		Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////		URL:     accounts.URL{Scheme: "http", Path: "url:1"},
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	_, err := w.SignHash(acct, toSign)
////
////	if _, ok := err.(*accounts.AuthNeededError); !ok {
////		t.Fatal("sign should have failed due to locked account")
////	}
////
////	unlockedKeys := w.vault.(*hashicorpService).unlocked
////
////	if len(unlockedKeys) != 0 {
////		t.Fatal("account should not have been unlocked")
////	}
////}
////
////func TestVaultWallet_SignTx_Hashicorp_UsesDifferentSigners(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct := accounts.Account{
////		Address: addr,
////		URL:     url,
////	}
////
////	key, err := crypto.HexToECDSA("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1")
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct}, map[common.Address]*ecdsa.PrivateKey{addr: key})
////
////	makePublicTx := func() *types.Transaction {
////		return types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////	}
////
////	makePrivateTx := func() *types.Transaction {
////		tx := makePublicTx()
////		tx.SetPrivate()
////		return tx
////	}
////
////	tests := map[string]struct {
////		toSign  *types.Transaction
////		signer  types.Signer
////		chainID *big.Int
////	}{
////		"private tx no chainID uses QuorumPrivateTxSigner":  {toSign: makePrivateTx(), signer: types.QuorumPrivateTxSigner{}},
////		"private tx and chainID uses QuorumPrivateTxSigner": {toSign: makePrivateTx(), signer: types.QuorumPrivateTxSigner{}, chainID: big.NewInt(1)},
////		"public tx no chainID uses HomesteadSigner":         {toSign: makePublicTx(), signer: types.HomesteadSigner{}},
////		"public tx and chainID uses EIP155Signer":           {toSign: makePublicTx(), signer: types.NewEIP155Signer(big.NewInt(1)), chainID: big.NewInt(1)},
////	}
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			got, err := w.SignTx(acct, tt.toSign, tt.chainID)
////
////			if err != nil {
////				t.Fatalf("error signing tx: %v", err)
////			}
////
////			h := tt.signer.Hash(tt.toSign)
////			wantSignature, err := crypto.Sign(h[:], key)
////
////			if err != nil {
////				t.Fatal(err)
////			}
////
////			var toSignCpy types.Transaction
////			toSignCpy = *tt.toSign
////			want, err := toSignCpy.WithSignature(tt.signer, wantSignature)
////
////			if err != nil {
////				t.Fatal(err)
////			}
////
////			if !reflect.DeepEqual(want, got) {
////				t.Fatalf("incorrect signTx result :\nwant: %v\ngot : %v", want, got)
////			}
////		})
////	}
////}
////
////func TestVaultWallet_SignTx_Hashicorp_ErrorIfAccountNotKnown(t *testing.T) {
////	w := createWalletForTesting([]accounts.Account{}, nil)
////
////	acct := accounts.Account{Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")}
////
////	toSign := &types.Transaction{}
////
////	if _, err := w.SignTx(acct, toSign, nil); err != accounts.ErrUnknownAccount {
////		t.Fatalf("incorrect error returned:\nwant: %v\ngot : %v", accounts.ErrUnknownAccount, err)
////	}
////}
////
////func TestVaultWallet_SignTx_Hashicorp_SignsWithInMemoryKeyIfAvailableAndDoesNotZeroKey(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct := accounts.Account{
////		Address: addr,
////		URL:     url,
////	}
////
////	key, err := crypto.HexToECDSA("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1")
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct}, map[common.Address]*ecdsa.PrivateKey{addr: key})
////
////	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////
////	got, err := w.SignTx(acct, toSign, nil)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	wantSigner := types.HomesteadSigner{}
////	h := wantSigner.Hash(toSign)
////	wantSignature, err := crypto.Sign(h[:], key)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	var toSignCpy types.Transaction
////	toSignCpy = *toSign
////	want, err := toSignCpy.WithSignature(wantSigner, wantSignature)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if !reflect.DeepEqual(want, got) {
////		t.Fatalf("incorrect signTx result :\nwant: %v\ngot : %v", want, got)
////	}
////
////	unlockedKeys := w.vault.(*hashicorpService).unlocked
////
////	if len(unlockedKeys) == 0 || unlockedKeys[acct.Address] == nil || unlockedKeys[acct.Address].PrivateKey == nil || unlockedKeys[acct.Address].PrivateKey.D.Int64() == 0 {
////		t.Fatal("unlocked key was zeroed after use")
////	}
////}
////
////func TestVaultWallet_SignTx_Hashicorp_ErrorIfSigningKeyIsNotRelatedToProvidedAccount(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	unrelatedKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	// the key retrieved from the vault this account is not the correct match (i.e. the address is not derivable from this key).  This situation could occur if the incorrect secret name or versions are configured (i.e. configuring node1Addr and node2Key together)
////	w := createWalletForTesting([]accounts.Account{acct}, map[common.Address]*ecdsa.PrivateKey{addr: unrelatedKey})
////
////	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////
////	_, err = w.SignTx(acct, toSign, nil)
////
////	if err != incorrectKeyForAddrErr {
////		t.Fatalf("want err: %v\ngot err : %v", incorrectKeyForAddrErr, err)
////	}
////}
////
////func TestVaultWallet_SignTx_Hashicorp_ErrorIfAmbiguousAccount(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////
////	url1 := accounts.URL{Scheme: "http", Path: "url:1"}
////	url2 := accounts.URL{Scheme: "http", Path: "url:2"}
////
////	acct1 := accounts.Account{Address: addr, URL: url1}
////	acct2 := accounts.Account{Address: addr, URL: url2}
////
////	// Two accounts have the same address but different URLs
////	w := createWalletForTesting([]accounts.Account{acct1, acct2}, nil)
////
////	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////
////	// The provided account does not specify the exact account to use as no URL is provided
////	acct := accounts.Account{
////		Address: addr,
////	}
////
////	_, err := w.SignTx(acct, toSign, nil)
////	e := err.(*AmbiguousAddrError)
////
////	want := []accounts.Account{acct1, acct2}
////
////	if diff := cmp.Diff(want, e.Matches); diff != "" {
////		t.Fatalf("ambiguous accounts mismatch (-want +got):\n%s", diff)
////	}
////}
////
////func TestVaultWallet_SignTx_Hashicorp_AmbiguousAccountAllowedIfOnlyOneAccountWithGivenAddress(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct1 := accounts.Account{Address: addr, URL: url}
////
////	key, err := crypto.HexToECDSA("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1")
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct1}, map[common.Address]*ecdsa.PrivateKey{addr: key})
////
////	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////
////	// The provided account does not specify the exact account to use as no URL is provided
////	acct := accounts.Account{
////		Address: addr,
////	}
////
////	got, err := w.SignTx(acct, toSign, nil)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	wantSigner := types.HomesteadSigner{}
////	h := wantSigner.Hash(toSign)
////	wantSignature, err := crypto.Sign(h[:], key)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	var toSignCpy types.Transaction
////	toSignCpy = *toSign
////	want, err := toSignCpy.WithSignature(wantSigner, wantSignature)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if !reflect.DeepEqual(want, got) {
////		t.Fatalf("incorrect signTx result :\nwant: %v\ngot : %v", want, got)
////	}
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) == 0 {
////		t.Fatal("unlocked key was zeroed after use")
////	}
////
////	for _, u := range unlocked {
////		key := u.PrivateKey
////		if key == nil || key.D.Int64() == 0 {
////			t.Fatal("unlocked key was zeroed after use")
////		}
////	}
////}
////
////func TestVaultWallet_SignTx_Hashicorp_ErrorIfAccountLocked(t *testing.T) {
////	acct := accounts.Account{
////		Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////		URL:     accounts.URL{Scheme: "http", Path: "url:1"},
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////
////	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////
////	_, err := w.SignTx(acct, toSign, nil)
////
////	if _, ok := err.(*accounts.AuthNeededError); !ok {
////		t.Fatal("sign should have failed due to locked account")
////	}
////
////	unlockedKeys := w.vault.(*hashicorpService).unlocked
////
////	if len(unlockedKeys) != 0 {
////		t.Fatal("account should not have been unlocked")
////	}
////}
////
////func TestVaultWallet_SignHashWithPassphrase_Hashicorp_ErrorIfAccountNotKnown(t *testing.T) {
////	w := createWalletForTesting([]accounts.Account{}, nil)
////
////	acct := accounts.Account{Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")}
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	if _, err := w.SignHashWithPassphrase(acct, "", toSign); err != accounts.ErrUnknownAccount {
////		t.Fatalf("incorrect error returned:\nwant: %v\ngot : %v", accounts.ErrUnknownAccount, err)
////	}
////}
////
////func TestVaultWallet_SignHashWithPassphrase_Hashicorp_SignsWithInMemoryKeyIfAvailableAndDoesNotZeroKey(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct := accounts.Account{
////		Address: addr,
////		URL:     url,
////	}
////
////	key, err := crypto.HexToECDSA("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1")
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct}, map[common.Address]*ecdsa.PrivateKey{addr: key})
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	got, err := w.SignHashWithPassphrase(acct, "", toSign)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	want, err := crypto.Sign(toSign, key)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if !bytes.Equal(want, got) {
////		t.Fatalf("incorrect signHash result:\nwant: %v\ngot : %v", want, got)
////	}
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) == 0 {
////		t.Fatal("unlocked key was zeroed after use")
////	}
////
////	for _, u := range unlocked {
////		key := u.PrivateKey
////		if key == nil || key.D.Int64() == 0 {
////			t.Fatal("unlocked key was zeroed after use")
////		}
////	}
////}
////
////func TestVaultWallet_SignHashWithPassphrase_Hashicorp_ErrorIfSigningKeyIsNotRelatedToProvidedAccount(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	unrelatedKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	// the key retrieved from the vault this account is not the correct match (i.e. the address is not derivable from this key).  This situation could occur if the incorrect secret name or versions are configured (i.e. configuring node1Addr and node2Key together)
////	w := createWalletForTesting([]accounts.Account{acct}, map[common.Address]*ecdsa.PrivateKey{addr: unrelatedKey})
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	_, err = w.SignHashWithPassphrase(acct, "", toSign)
////
////	if err != incorrectKeyForAddrErr {
////		t.Fatalf("want err: %v\ngot err : %v", incorrectKeyForAddrErr, err)
////	}
////}
////
////func TestVaultWallet_SignHashWithPassphrase_Hashicorp_ErrorIfAmbiguousAccount(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////
////	url1 := accounts.URL{Scheme: "http", Path: "url:1"}
////	url2 := accounts.URL{Scheme: "http", Path: "url:2"}
////
////	acct1 := accounts.Account{Address: addr, URL: url1}
////	acct2 := accounts.Account{Address: addr, URL: url2}
////
////	// Two accounts have the same address but different URLs
////	w := createWalletForTesting([]accounts.Account{acct1, acct2}, nil)
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	// The provided account does not specify the exact account to use as no URL is provided
////	acct := accounts.Account{
////		Address: addr,
////	}
////
////	_, err := w.SignHashWithPassphrase(acct, "", toSign)
////	e := err.(*AmbiguousAddrError)
////
////	want := []accounts.Account{acct1, acct2}
////
////	if diff := cmp.Diff(want, e.Matches); diff != "" {
////		t.Fatalf("ambiguous accounts mismatch (-want +got):\n%s", diff)
////	}
////}
////
////func TestVaultWallet_SignHashWithPassphrase_Hashicorp_AmbiguousAccountAllowedIfOnlyOneAccountWithGivenAddress(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct1 := accounts.Account{Address: addr, URL: url}
////
////	key, err := crypto.HexToECDSA("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1")
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct1}, map[common.Address]*ecdsa.PrivateKey{addr: key})
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	// The provided account does not specify the exact account to use as no URL is provided
////	acct := accounts.Account{
////		Address: addr,
////	}
////
////	got, err := w.SignHashWithPassphrase(acct, "", toSign)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	want, err := crypto.Sign(toSign, key)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if !bytes.Equal(want, got) {
////		t.Fatalf("incorrect signHash result:\nwant: %v\ngot : %v", want, got)
////	}
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) == 0 {
////		t.Fatal("unlocked key was zeroed after use")
////	}
////
////	for _, u := range unlocked {
////		key := u.PrivateKey
////		if key == nil || key.D.Int64() == 0 {
////			t.Fatal("unlocked key was zeroed after use")
////		}
////	}
////}
////
////// TODO change account urls from http urls to filepath urls
////
////func TestVaultWallet_SignHashWithPassphrase_Hashicorp_LockedAccountIsUnlockedOnlyForDurationOfSign(t *testing.T) {
////	makeMockHashicorpResponse := func(t *testing.T, hexKey string) []byte {
////		var vaultResponse api.Secret
////
////		vaultResponse.Data = map[string]interface{}{
////			"data": map[string]interface{}{
////				"key": hexKey,
////			},
////		}
////
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatalf("err marshalling mock response: %v", err)
////		}
////
////		return b
////	}
////
////	acct := accounts.Account{
////		Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////		URL:     accounts.URL{Scheme: keystore.KeyStoreScheme, Path: "testdata/keystore/vaultsecret.json"},
////	}
////
////	hexKey := "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"
////	key, err := crypto.HexToECDSA(hexKey)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	client, cleanup := makeMockHashicorpClient(t, makeMockHashicorpResponse(t, hexKey))
////	defer cleanup()
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////	w.vault.(*hashicorpService).client = client
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	got, err := w.SignHashWithPassphrase(acct, "", toSign)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	want, err := crypto.Sign(toSign, key)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if !bytes.Equal(want, got) {
////		t.Fatalf("incorrect signHash result:\nwant: %v\ngot : %v", want, got)
////	}
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) != 0 {
////		t.Fatal("unlocked key should not be stored after use")
////	}
////}
////
////func TestVaultWallet_SignTxWithPassphrase_Hashicorp_UsesDifferentSigners(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct := accounts.Account{
////		Address: addr,
////		URL:     url,
////	}
////
////	key, err := crypto.HexToECDSA("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1")
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct}, map[common.Address]*ecdsa.PrivateKey{addr: key})
////
////	makePublicTx := func() *types.Transaction {
////		return types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////	}
////
////	makePrivateTx := func() *types.Transaction {
////		tx := makePublicTx()
////		tx.SetPrivate()
////		return tx
////	}
////
////	tests := map[string]struct {
////		toSign  *types.Transaction
////		signer  types.Signer
////		chainID *big.Int
////	}{
////		"private tx no chainID uses QuorumPrivateTxSigner":  {toSign: makePrivateTx(), signer: types.QuorumPrivateTxSigner{}},
////		"private tx and chainID uses QuorumPrivateTxSigner": {toSign: makePrivateTx(), signer: types.QuorumPrivateTxSigner{}, chainID: big.NewInt(1)},
////		"public tx no chainID uses HomesteadSigner":         {toSign: makePublicTx(), signer: types.HomesteadSigner{}},
////		"public tx and chainID uses EIP155Signer":           {toSign: makePublicTx(), signer: types.NewEIP155Signer(big.NewInt(1)), chainID: big.NewInt(1)},
////	}
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			got, err := w.SignTxWithPassphrase(acct, "", tt.toSign, tt.chainID)
////
////			if err != nil {
////				t.Fatalf("error signing tx: %v", err)
////			}
////
////			h := tt.signer.Hash(tt.toSign)
////			wantSignature, err := crypto.Sign(h[:], key)
////
////			if err != nil {
////				t.Fatal(err)
////			}
////
////			var toSignCpy types.Transaction
////			toSignCpy = *tt.toSign
////			want, err := toSignCpy.WithSignature(tt.signer, wantSignature)
////
////			if err != nil {
////				t.Fatal(err)
////			}
////
////			if !reflect.DeepEqual(want, got) {
////				t.Fatalf("incorrect signTx result :\nwant: %v\ngot : %v", want, got)
////			}
////		})
////	}
////}
////
////func TestVaultWallet_SignTxWithPassphrase_Hashicorp_ErrorIfAccountNotKnown(t *testing.T) {
////	w := createWalletForTesting([]accounts.Account{}, nil)
////
////	acct := accounts.Account{Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")}
////
////	toSign := &types.Transaction{}
////
////	if _, err := w.SignTxWithPassphrase(acct, "", toSign, nil); err != accounts.ErrUnknownAccount {
////		t.Fatalf("incorrect error returned:\nwant: %v\ngot : %v", accounts.ErrUnknownAccount, err)
////	}
////}
////
////func TestVaultWallet_SignTxWithPassphrase_Hashicorp_SignsWithInMemoryKeyIfAvailableAndDoesNotZeroKey(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct := accounts.Account{
////		Address: addr,
////		URL:     url,
////	}
////
////	key, err := crypto.HexToECDSA("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1")
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct}, map[common.Address]*ecdsa.PrivateKey{addr: key})
////
////	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////
////	got, err := w.SignTxWithPassphrase(acct, "", toSign, nil)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	wantSigner := types.HomesteadSigner{}
////	h := wantSigner.Hash(toSign)
////	wantSignature, err := crypto.Sign(h[:], key)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	var toSignCpy types.Transaction
////	toSignCpy = *toSign
////	want, err := toSignCpy.WithSignature(wantSigner, wantSignature)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if !reflect.DeepEqual(want, got) {
////		t.Fatalf("incorrect signTx result :\nwant: %v\ngot : %v", want, got)
////	}
////
////	unlockedKeys := w.vault.(*hashicorpService).unlocked
////
////	if len(unlockedKeys) == 0 || unlockedKeys[acct.Address] == nil || unlockedKeys[acct.Address].PrivateKey == nil || unlockedKeys[acct.Address].PrivateKey.D.Int64() == 0 {
////		t.Fatal("unlocked key was zeroed after use")
////	}
////}
////
////func TestVaultWallet_SignTxWithPassphrase_Hashicorp_ErrorIfSigningKeyIsNotRelatedToProvidedAccount(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	unrelatedKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	// the key retrieved from the vault this account is not the correct match (i.e. the address is not derivable from this key).  This situation could occur if the incorrect secret name or versions are configured (i.e. configuring node1Addr and node2Key together)
////	w := createWalletForTesting([]accounts.Account{acct}, map[common.Address]*ecdsa.PrivateKey{addr: unrelatedKey})
////
////	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////
////	_, err = w.SignTxWithPassphrase(acct, "", toSign, nil)
////
////	if err != incorrectKeyForAddrErr {
////		t.Fatalf("want err: %v\ngot err : %v", incorrectKeyForAddrErr, err)
////	}
////}
////
////func TestVaultWallet_SignTxWithPassphrase_Hashicorp_ErrorIfAmbiguousAccount(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////
////	url1 := accounts.URL{Scheme: "http", Path: "url:1"}
////	url2 := accounts.URL{Scheme: "http", Path: "url:2"}
////
////	acct1 := accounts.Account{Address: addr, URL: url1}
////	acct2 := accounts.Account{Address: addr, URL: url2}
////
////	// Two accounts have the same address but different URLs
////	w := createWalletForTesting([]accounts.Account{acct1, acct2}, nil)
////
////	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////
////	// The provided account does not specify the exact account to use as no URL is provided
////	acct := accounts.Account{
////		Address: addr,
////	}
////
////	_, err := w.SignTxWithPassphrase(acct, "", toSign, nil)
////	e := err.(*AmbiguousAddrError)
////
////	want := []accounts.Account{acct1, acct2}
////
////	if diff := cmp.Diff(want, e.Matches); diff != "" {
////		t.Fatalf("ambiguous accounts mismatch (-want +got):\n%s", diff)
////	}
////}
////
////func TestVaultWallet_SignTxWithPassphrase_Hashicorp_AmbiguousAccountAllowedIfOnlyOneAccountWithGivenAddress(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: "http", Path: "url:1"}
////	acct1 := accounts.Account{Address: addr, URL: url}
////
////	key, err := crypto.HexToECDSA("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1")
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	w := createWalletForTesting([]accounts.Account{acct1}, map[common.Address]*ecdsa.PrivateKey{addr: key})
////
////	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////
////	// The provided account does not specify the exact account to use as no URL is provided
////	acct := accounts.Account{
////		Address: addr,
////	}
////
////	got, err := w.SignTxWithPassphrase(acct, "", toSign, nil)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	wantSigner := types.HomesteadSigner{}
////	h := wantSigner.Hash(toSign)
////	wantSignature, err := crypto.Sign(h[:], key)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	var toSignCpy types.Transaction
////	toSignCpy = *toSign
////	want, err := toSignCpy.WithSignature(wantSigner, wantSignature)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if !reflect.DeepEqual(want, got) {
////		t.Fatalf("incorrect signTx result :\nwant: %v\ngot : %v", want, got)
////	}
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) == 0 {
////		t.Fatal("unlocked key was zeroed after use")
////	}
////
////	for _, u := range unlocked {
////		key := u.PrivateKey
////		if key == nil || key.D.Int64() == 0 {
////			t.Fatal("unlocked key was zeroed after use")
////		}
////	}
////}
////
////func TestVaultWallet_SignTxWithPassphrase_Hashicorp_LockedAccountIsUnlockedOnlyForDurationOfSign(t *testing.T) {
////	makeMockHashicorpResponse := func(t *testing.T, hexKey string) []byte {
////		var vaultResponse api.Secret
////
////		vaultResponse.Data = map[string]interface{}{
////			"data": map[string]interface{}{
////				"key": hexKey,
////			},
////		}
////
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatalf("err marshalling mock response: %v", err)
////		}
////
////		return b
////	}
////
////	acct := accounts.Account{
////		Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////		URL:     accounts.URL{Scheme: keystore.KeyStoreScheme, Path: "testdata/keystore/vaultsecret.json"},
////	}
////
////	hexKey := "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"
////	key, err := crypto.HexToECDSA(hexKey)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	client, cleanup := makeMockHashicorpClient(t, makeMockHashicorpResponse(t, hexKey))
////	defer cleanup()
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////	w.vault.(*hashicorpService).client = client
////
////	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
////
////	got, err := w.SignTxWithPassphrase(acct, "", toSign, nil)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	wantSigner := types.HomesteadSigner{}
////	h := wantSigner.Hash(toSign)
////	wantSignature, err := crypto.Sign(h[:], key)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	var toSignCpy types.Transaction
////	toSignCpy = *toSign
////	want, err := toSignCpy.WithSignature(wantSigner, wantSignature)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if !reflect.DeepEqual(want, got) {
////		t.Fatalf("incorrect signTx result :\nwant: %v\ngot : %v", want, got)
////	}
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) != 0 {
////		t.Fatal("unlocked key should not be stored after use")
////	}
////}
////
////func TestVaultWallet_TimedUnlock_Hashicorp_StoresKeyInMemoryThenZeroesAfterSpecifiedDuration(t *testing.T) {
////	makeMockHashicorpResponse := func(t *testing.T, hexKey string) []byte {
////		var vaultResponse api.Secret
////
////		vaultResponse.Data = map[string]interface{}{
////			"data": map[string]interface{}{
////				"key": hexKey,
////			},
////		}
////
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatalf("err marshalling mock response: %v", err)
////		}
////
////		return b
////	}
////
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: keystore.KeyStoreScheme, Path: "testdata/keystore/vaultsecret.json"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	hexKey := "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"
////
////	client, cleanup := makeMockHashicorpClient(t, makeMockHashicorpResponse(t, hexKey))
////	defer cleanup()
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////	w.vault.(*hashicorpService).client = client
////
////	d := 100 * time.Millisecond
////
////	if err := w.TimedUnlock(accounts.Account{Address: addr}, d); err != nil {
////		t.Fatalf("error unlocking: %v", err)
////	}
////
////	// close the vault server to make sure that the wallet has stored the key in its memory
////	cleanup()
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	_, err := w.SignHash(acct, toSign)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	// sleep to allow the unlock to time out
////	time.Sleep(2 * d)
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) != 0 {
////		t.Fatal("unlocked key should not be stored after timeout")
////	}
////}
////
////func TestVaultWallet_TimedUnlock_Hashicorp_IfAlreadyUnlockedThenOverridesExistingDuration_DurationShortened(t *testing.T) {
////	makeMockHashicorpResponse := func(t *testing.T, hexKey string) []byte {
////		var vaultResponse api.Secret
////
////		vaultResponse.Data = map[string]interface{}{
////			"data": map[string]interface{}{
////				"key": hexKey,
////			},
////		}
////
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatalf("err marshalling mock response: %v", err)
////		}
////
////		return b
////	}
////
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: keystore.KeyStoreScheme, Path: "testdata/keystore/vaultsecret.json"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	hexKey := "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"
////
////	client, cleanup := makeMockHashicorpClient(t, makeMockHashicorpResponse(t, hexKey))
////	defer cleanup()
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////	w.vault.(*hashicorpService).client = client
////
////	a := accounts.Account{Address: addr}
////
////	d := 50 * time.Millisecond
////
////	if err := w.TimedUnlock(a, 10*d); err != nil {
////		t.Fatalf("error unlocking: %v", err)
////	}
////	time.Sleep(d) // sleep for a short period to apply the first timed unlock
////	if err := w.TimedUnlock(a, d); err != nil {
////		t.Fatalf("error unlocking: %v", err)
////	}
////
////	// close the vault server to make sure that the wallet has stored the key in its memory
////	cleanup()
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	_, err := w.SignHash(acct, toSign)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	// sleep to allow the unlock to time out
////	time.Sleep(2 * d)
////	time.Sleep(2 * d)
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) != 0 {
////		t.Fatal("unlocked key should not be stored after timeout")
////	}
////}
////
////func TestVaultWallet_TimedUnlock_Hashicorp_IfAlreadyUnlockedThenOverridesExistingDuration_DurationLengthened(t *testing.T) {
////	makeMockHashicorpResponse := func(t *testing.T, hexKey string) []byte {
////		var vaultResponse api.Secret
////
////		vaultResponse.Data = map[string]interface{}{
////			"data": map[string]interface{}{
////				"key": hexKey,
////			},
////		}
////
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatalf("err marshalling mock response: %v", err)
////		}
////
////		return b
////	}
////
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: keystore.KeyStoreScheme, Path: "testdata/keystore/vaultsecret.json"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	hexKey := "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"
////
////	client, cleanup := makeMockHashicorpClient(t, makeMockHashicorpResponse(t, hexKey))
////	defer cleanup()
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////	w.vault.(*hashicorpService).client = client
////
////	a := accounts.Account{Address: addr}
////
////	d := 50 * time.Millisecond
////
////	if err := w.TimedUnlock(a, 3*d); err != nil {
////		t.Fatalf("error unlocking: %v", err)
////	}
////	time.Sleep(d) // sleep for a short period to apply the first timed unlock
////	if err := w.TimedUnlock(a, 6*d); err != nil {
////		t.Fatalf("error unlocking: %v", err)
////	}
////
////	// close the vault server to make sure that the wallet has stored the key in its memory
////	cleanup()
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	if _, err := w.SignHash(acct, toSign); err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	// sleep for longer than initial unlock duration then make sure we can sign indicating the initial unlock was overriden
////	time.Sleep(3 * d)
////
////	if _, err := w.SignHash(acct, toSign); err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	// sleep enough time to let the second unlock timeout
////	time.Sleep(6 * d)
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) != 0 {
////		t.Fatal("unlocked key should not be stored after timeout")
////	}
////}
////
////func TestVaultWallet_TimedUnlock_Hashicorp_ErrorIfSigningAfterUnlockTimedOut(t *testing.T) {
////	makeMockHashicorpResponse := func(t *testing.T, hexKey string) []byte {
////		var vaultResponse api.Secret
////
////		vaultResponse.Data = map[string]interface{}{
////			"data": map[string]interface{}{
////				"key": hexKey,
////			},
////		}
////
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatalf("err marshalling mock response: %v", err)
////		}
////
////		return b
////	}
////
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: keystore.KeyStoreScheme, Path: "testdata/keystore/vaultsecret.json"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	hexKey := "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"
////
////	client, cleanup := makeMockHashicorpClient(t, makeMockHashicorpResponse(t, hexKey))
////	defer cleanup()
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////	w.vault.(*hashicorpService).client = client
////
////	d := 50 * time.Millisecond
////
////	if err := w.TimedUnlock(accounts.Account{Address: addr}, d); err != nil {
////		t.Fatalf("error unlocking: %v", err)
////	}
////
////	// sleep to allow the unlock to time out
////	time.Sleep(2 * d)
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) != 0 {
////		t.Fatal("unlocked key should not be stored after timeout")
////	}
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	_, err := w.SignHash(acct, toSign)
////
////	if _, ok := err.(*accounts.AuthNeededError); !ok {
////		t.Fatal("sign should have failed due to locked account")
////	}
////
////	unlocked = w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) != 0 {
////		t.Fatal("unlocked key should not be stored after timeout")
////	}
////}
////
////func TestVaultWallet_TimedUnlock_Hashicorp_DurationZeroUnlocksIndefinitely(t *testing.T) {
////	makeMockHashicorpResponse := func(t *testing.T, hexKey string) []byte {
////		var vaultResponse api.Secret
////
////		vaultResponse.Data = map[string]interface{}{
////			"data": map[string]interface{}{
////				"key": hexKey,
////			},
////		}
////
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatalf("err marshalling mock response: %v", err)
////		}
////
////		return b
////	}
////
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: keystore.KeyStoreScheme, Path: "testdata/keystore/vaultsecret.json"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	hexKey := "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"
////
////	client, cleanup := makeMockHashicorpClient(t, makeMockHashicorpResponse(t, hexKey))
////	defer cleanup()
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////	w.vault.(*hashicorpService).client = client
////
////	if err := w.TimedUnlock(accounts.Account{Address: addr}, 0); err != nil {
////		t.Fatalf("error unlocking: %v", err)
////	}
////
////	// close the vault server to make sure that the wallet has stored the key in its memory
////	cleanup()
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////
////	_, err := w.SignHash(acct, toSign)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	// sleep to check if the unlock times out
////	time.Sleep(100 * time.Millisecond)
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) == 0 {
////		t.Fatal("indefinitely unlocked key should not have been zeroed")
////	}
////}
////
////func TestVaultWallet_TimedUnlock_Hashicorp_TryingToTimedUnlockAnIndefinitelyUnlockedKeyDoesNothing(t *testing.T) {
////	makeMockHashicorpResponse := func(t *testing.T, hexKey string) []byte {
////		var vaultResponse api.Secret
////
////		vaultResponse.Data = map[string]interface{}{
////			"data": map[string]interface{}{
////				"key": hexKey,
////			},
////		}
////
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatalf("err marshalling mock response: %v", err)
////		}
////
////		return b
////	}
////
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: keystore.KeyStoreScheme, Path: "testdata/keystore/vaultsecret.json"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	hexKey := "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"
////
////	client, cleanup := makeMockHashicorpClient(t, makeMockHashicorpResponse(t, hexKey))
////	defer cleanup()
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////	w.vault.(*hashicorpService).client = client
////
////	// unlock indefinitely
////	if err := w.TimedUnlock(accounts.Account{Address: addr}, 0); err != nil {
////		t.Fatalf("error unlocking: %v", err)
////	}
////
////	d := 50 * time.Millisecond
////
////	if err := w.TimedUnlock(accounts.Account{Address: addr}, d); err != nil {
////		t.Fatalf("error unlocking: %v", err)
////	}
////
////	// sleep to make sure that the time out was not applied to the indefinitely unlocked key
////	time.Sleep(2 * d)
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////	_, err := w.SignHash(acct, toSign)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) == 0 {
////		t.Fatal("indefinitely unlocked key should not be have been zeroed after new timeout")
////	}
////
////	if unlocked[addr].PrivateKey == nil || unlocked[addr].PrivateKey.D.Int64() == 0 {
////		t.Fatal("indefinitely unlocked key should not be have been zeroed after new timeout")
////	}
////}
////
////func TestVaultWallet_Lock_Hashicorp_LockIndefinitelyUnlockedKey(t *testing.T) {
////	makeMockHashicorpResponse := func(t *testing.T, hexKey string) []byte {
////		var vaultResponse api.Secret
////
////		vaultResponse.Data = map[string]interface{}{
////			"data": map[string]interface{}{
////				"key": hexKey,
////			},
////		}
////
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatalf("err marshalling mock response: %v", err)
////		}
////
////		return b
////	}
////
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: keystore.KeyStoreScheme, Path: "testdata/keystore/vaultsecret.json"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	hexKey := "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"
////
////	client, cleanup := makeMockHashicorpClient(t, makeMockHashicorpResponse(t, hexKey))
////	defer cleanup()
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////	w.vault.(*hashicorpService).client = client
////
////	d := 10 * time.Millisecond
////
////	// unlock indefinitely
////	if err := w.TimedUnlock(accounts.Account{Address: addr}, 0); err != nil {
////		t.Fatalf("error unlocking: %v", err)
////	}
////
////	// sleep to make sure that the time out is applied
////	time.Sleep(d)
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////	_, err := w.SignHash(acct, toSign)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) == 0 || unlocked[addr].PrivateKey == nil || unlocked[addr].PrivateKey.D.Int64() == 0 {
////		t.Fatal("unlocked key should not have been zeroed")
////	}
////
////	if err := w.Lock(accounts.Account{Address: addr}); err != nil {
////		t.Fatalf("error locking: %v", err)
////	}
////
////	unlocked = w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) != 0 {
////		t.Fatal("unlocked key should have been zeroed during lock")
////	}
////}
////
////func TestVaultWallet_Lock_Hashicorp_LockTimedUnlockedKey(t *testing.T) {
////	makeMockHashicorpResponse := func(t *testing.T, hexKey string) []byte {
////		var vaultResponse api.Secret
////
////		vaultResponse.Data = map[string]interface{}{
////			"data": map[string]interface{}{
////				"key": hexKey,
////			},
////		}
////
////		b, err := json.Marshal(vaultResponse)
////
////		if err != nil {
////			t.Fatalf("err marshalling mock response: %v", err)
////		}
////
////		return b
////	}
////
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: keystore.KeyStoreScheme, Path: "testdata/keystore/vaultsecret.json"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	hexKey := "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"
////
////	client, cleanup := makeMockHashicorpClient(t, makeMockHashicorpResponse(t, hexKey))
////	defer cleanup()
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////	w.vault.(*hashicorpService).client = client
////
////	d := 10 * time.Millisecond
////
////	if err := w.TimedUnlock(accounts.Account{Address: addr}, 10*d); err != nil {
////		t.Fatalf("error unlocking: %v", err)
////	}
////
////	// sleep to make sure that the time out is applied
////	time.Sleep(d)
////
////	toSign := crypto.Keccak256([]byte("to_sign"))
////	_, err := w.SignHash(acct, toSign)
////
////	if err != nil {
////		t.Fatalf("error signing hash: %v", err)
////	}
////
////	unlocked := w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) == 0 || unlocked[addr].PrivateKey == nil || unlocked[addr].PrivateKey.D.Int64() == 0 {
////		t.Fatal("unlocked key should not have been zeroed")
////	}
////
////	if err := w.Lock(accounts.Account{Address: addr}); err != nil {
////		t.Fatalf("error locking: %v", err)
////	}
////
////	unlocked = w.vault.(*hashicorpService).unlocked
////
////	if len(unlocked) != 0 {
////		t.Fatal("unlocked key should have been zeroed during lock")
////	}
////
////	// sleep for initial timed unlock duration to make sure timed lock was cancelled and does not cause a panic
////	time.Sleep(15 * d)
////}
////
////func TestVaultWallet_Lock_Hashicorp_LockAlreadyLockedKeyDoesNothing(t *testing.T) {
////	addr := common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d")
////	url := accounts.URL{Scheme: keystore.KeyStoreScheme, Path: "testdata/keystore/vaultsecret.json"}
////	acct := accounts.Account{Address: addr, URL: url}
////
////	w := createWalletForTesting([]accounts.Account{acct}, nil)
////
////	if err := w.Lock(accounts.Account{Address: addr}); err != nil {
////		t.Fatalf("error locking: %v", err)
////	}
////}
////
////func TestVaultWallet_Store_Hashicorp_KeyAndAddressWrittenToVault(t *testing.T) {
////	mux := http.NewServeMux()
////
////	const (
////		secretEngine = "kv"
////		addr1        = "addr1"
////		key1         = "key1"
////	)
////
////	makeVaultResponse := func(version int) []byte {
////		resp := api.Secret{
////			Data: map[string]interface{}{
////				"version": version,
////			},
////		}
////
////		b, err := json.Marshal(resp)
////
////		if err != nil {
////			t.Fatal(err)
////		}
////
////		return b
////	}
////
////	var (
////		writtenAddr, writtenKey string
////	)
////
////	const (
////		addrVersion = 2
////		keyVersion  = 5
////	)
////
////	mux.HandleFunc(fmt.Sprintf("/v1/%s/data/%s", secretEngine, addr1), func(w http.ResponseWriter, r *http.Request) {
////		body := makeVaultResponse(addrVersion)
////		w.Write(body)
////
////		reqBody, err := ioutil.ReadAll(r.Body)
////		if err != nil {
////			t.Fatal(err)
////		}
////
////		var data map[string]interface{}
////		if err := json.Unmarshal(reqBody, &data); err != nil {
////			t.Fatal(err)
////		}
////
////		d := data["data"]
////		dd := d.(map[string]interface{})
////		writtenAddr = dd["secret"].(string)
////	})
////
////	mux.HandleFunc(fmt.Sprintf("/v1/%s/data/%s", secretEngine, key1), func(w http.ResponseWriter, r *http.Request) {
////		body := makeVaultResponse(keyVersion)
////		w.Write(body)
////
////		reqBody, err := ioutil.ReadAll(r.Body)
////		if err != nil {
////			t.Fatal(err)
////		}
////
////		var data map[string]interface{}
////		if err := json.Unmarshal(reqBody, &data); err != nil {
////			t.Fatal(err)
////		}
////
////		d := data["data"]
////		dd := d.(map[string]interface{})
////		writtenKey = dd["secret"].(string)
////
////		//hasWrittenKey = true
////	})
////
////	vaultServer := httptest.NewServer(mux)
////	defer vaultServer.Close()
////
////	//create default client and update URL to use mock vault server
////	config := api.DefaultConfig()
////	config.Address = vaultServer.URL
////	client, err := api.NewClient(config)
////
////	if err != nil {
////		t.Fatalf("err creating client: %v", err)
////	}
////
////	parseURL := func(u string) accounts.URL {
////		parts := strings.Split(u, "://")
////		if len(parts) != 2 || parts[0] == "" {
////			t.Fatal("protocol scheme missing")
////		}
////		return accounts.URL{Scheme: parts[0], Path: parts[1]}
////	}
////
////	w := wallet{
////		url: parseURL(vaultServer.URL),
////		vault: &hashicorpService{
////			client: client,
////			secrets: []HashicorpSecretConfig{
////				{
////					AddressSecret:    addr1,
////					PrivateKeySecret: key1,
////					SecretEngine:     secretEngine,
////				},
////			},
////		},
////	}
////
////	toStore, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	wantAddr := crypto.PubkeyToAddress(toStore.PublicKey)
////
////	addr, urls, err := w.Store(toStore)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	if !cmp.Equal(wantAddr, addr) {
////		t.Fatalf("incorrect address returned\nwant: %v\ngot : %v", wantAddr, addr)
////	}
////
////	if len(urls) != 2 {
////		t.Fatalf("urls should have been returned for 2 new secrets, got: %v\nurls = %+v", len(urls), urls)
////	}
////
////	wantAddrUrl := fmt.Sprintf("%v/v1/%s/data/%s?version=%v", vaultServer.URL, secretEngine, addr1, addrVersion)
////
////	if urls[0] != wantAddrUrl {
////		t.Fatalf("incorrect url for created address: want: %v, got: %v", wantAddrUrl, urls[0])
////	}
////
////	wantKeyUrl := fmt.Sprintf("%v/v1/%s/data/%s?version=%v", vaultServer.URL, secretEngine, key1, keyVersion)
////
////	if urls[1] != wantKeyUrl {
////		t.Fatalf("incorrect url for key: want: %v, got: %v", wantKeyUrl, urls[1])
////	}
////
////	wantWrittenAddr := strings.TrimPrefix(wantAddr.Hex(), "0x")
////
////	if !cmp.Equal(wantWrittenAddr, writtenAddr) {
////		t.Fatalf("incorrect address hex written to Vault\nwant: %v\ngot : %v", wantWrittenAddr, writtenAddr)
////	}
////
////	wantWrittenKey := hex.EncodeToString(crypto.FromECDSA(toStore))
////
////	if !cmp.Equal(wantWrittenKey, writtenKey) {
////		t.Fatalf("incorrect key hex written to Vault\nwant: %v\ngot : %v", wantWrittenKey, writtenKey)
////	}
////}
////
////func TestVaultWallet_Store_Hashicorp_UrlsOfWrittenSecretsAreIncludedInError(t *testing.T) {
////	mux := http.NewServeMux()
////
////	const (
////		secretEngine = "kv"
////		addr1        = "addr1"
////		notFound = "notFound"
////	)
////
////	makeVaultResponse := func(version int) []byte {
////		resp := api.Secret{
////			Data: map[string]interface{}{
////				"version": version,
////			},
////		}
////
////		b, err := json.Marshal(resp)
////
////		if err != nil {
////			t.Fatal(err)
////		}
////
////		return b
////	}
////
////	const addrVersion = 2
////
////	mux.HandleFunc(fmt.Sprintf("/v1/%s/data/%s", secretEngine, addr1), func(w http.ResponseWriter, r *http.Request) {
////		body := makeVaultResponse(addrVersion)
////		w.Write(body)
////	})
////
////	mux.HandleFunc(fmt.Sprintf("/v1/%s/data/%s", secretEngine, notFound), func(w http.ResponseWriter, r *http.Request) {
////		w.WriteHeader(404)
////	})
////
////	vaultServer := httptest.NewServer(mux)
////	defer vaultServer.Close()
////
////	//create default client and update URL to use mock vault server
////	config := api.DefaultConfig()
////	config.Address = vaultServer.URL
////	client, err := api.NewClient(config)
////
////	if err != nil {
////		t.Fatalf("err creating client: %v", err)
////	}
////
////	parseURL := func(u string) accounts.URL {
////		parts := strings.Split(u, "://")
////		if len(parts) != 2 || parts[0] == "" {
////			t.Fatal("protocol scheme missing")
////		}
////		return accounts.URL{Scheme: parts[0], Path: parts[1]}
////	}
////
////	w := wallet{
////		url: parseURL(vaultServer.URL),
////		vault: &hashicorpService{
////			client: client,
////			secrets: []HashicorpSecretConfig{
////				{
////					AddressSecret:    addr1,
////					PrivateKeySecret: notFound,
////					SecretEngine:     secretEngine,
////				},
////			},
////		},
////	}
////
////	toStore, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	wantErr := acctStoreErr{
////		storedUrls: []string{fmt.Sprintf("%v/v1/%v/data/%v?version=%v", vaultServer.URL, secretEngine, addr1, addrVersion)},
////	}
////
////	_, _, e := w.Store(toStore)
////
////	ae, ok := e.(acctStoreErr)
////
////	if !ok {
////		t.Fatalf("incorrect error type returned")
////	}
////
////	if !cmp.Equal(wantErr.storedUrls, ae.storedUrls) {
////		t.Fatalf("incorrect stored secrets data in error\nwant: %v\ngot : %v", wantErr.storedUrls, ae.storedUrls)
////	}
////}
////
////type hashicorpSecretConfigByAddressSecret []HashicorpSecretConfig
////
////func (s hashicorpSecretConfigByAddressSecret) Len() int {
////	return len(s)
////}
////
////func (s hashicorpSecretConfigByAddressSecret) Less(i, j int) bool {
////	return s[i].AddressSecret < s[j].AddressSecret
////}
////
////func (s hashicorpSecretConfigByAddressSecret) Swap(i, j int) {
////	s[i], s[j] = s[j], s[i]
////}
////
////func toCacheEqual(a, b []HashicorpSecretConfig) bool {
////	if len(a) != len(b) {
////		return false
////	}
////
////	sort.Sort(hashicorpSecretConfigByAddressSecret(a))
////	sort.Sort(hashicorpSecretConfigByAddressSecret(b))
////
////	for i := 0; i < len(a); i++ {
////		if a[i] != b[i] {
////			return false
////		}
////	}
////
////	return true
////}
////
////type cacheTestCase struct {
////	secrets     []HashicorpSecretConfig
////	unlockAll   bool
////	wantAccts   []accounts.Account
////	wantKeys    []*ecdsa.PrivateKey
////	wantToCache []HashicorpSecretConfig
////}
////
////func setupCacheTestCases(t *testing.T) (*httptest.Server, func(), map[string]cacheTestCase) {
////	makeSecret := func(addrName, keyName string) HashicorpSecretConfig {
////		return HashicorpSecretConfig{AddressSecret: addrName, AddressSecretVersion: 1, PrivateKeySecret: keyName, PrivateKeySecretVersion: 1, SecretEngine: "kv"}
////	}
////
////	makeUrl := func(secretName string) accounts.URL {
////		return accounts.URL{Scheme: "http", Path: fmt.Sprintf("%v/v1/kv/data/%v?version=1", "%v", secretName)}
////	}
////
////	makeKey := func(hex string) *ecdsa.PrivateKey {
////		key, err := crypto.HexToECDSA(hex)
////
////		if err != nil {
////			t.Fatal(err)
////		}
////
////		return key
////	}
////
////	const (
////		key1           = "key1"
////		key2           = "key2"
////		addr1          = "addr1"
////		addr2          = "addr2"
////		multiValSecret = "multiValSec"
////	)
////
////	server, closeServer := setupTestVaultServer(
////		t,
////		[]handlerData{
////			{secretName: addr1, resp: map[string]string{"addr": "ed9d02e382b34818e88b88a309c7fe71e65f419d"}},
////			{secretName: key1, resp: map[string]string{"key": "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"}},
////			{secretName: addr2, resp: map[string]string{"addr": "ca843569e3427144cead5e4d5999a3d0ccf92b8e"}},
////			{secretName: key2, resp: map[string]string{"otherKey": "4762e04d10832808a0aebdaa79c12de54afbe006bfffd228b3abcc494fe986f9"}},
////			{secretName: multiValSecret, resp: map[string]string{
////				"key":      "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1",
////				"otherKey": "4762e04d10832808a0aebdaa79c12de54afbe006bfffd228b3abcc494fe986f9",
////			},
////			},
////		},
////	)
////
////	tests := map[string]cacheTestCase{
////		"gets acct": {
////			secrets:   []HashicorpSecretConfig{makeSecret(addr1, "")},
////			unlockAll: false,
////			wantAccts: []accounts.Account{{
////				Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////				URL:     makeUrl(addr1),
////			}},
////			wantKeys:    []*ecdsa.PrivateKey{},
////			wantToCache: []HashicorpSecretConfig{},
////		},
////		"does not get acct when vault secret has multiple values": {
////			secrets:     []HashicorpSecretConfig{makeSecret(multiValSecret, "")},
////			unlockAll:   false,
////			wantAccts:   []accounts.Account{},
////			wantKeys:    []*ecdsa.PrivateKey{},
////			wantToCache: []HashicorpSecretConfig{makeSecret(multiValSecret, "")},
////		},
////		"gets good accts and ignores unretrievable accts": {
////			secrets:   []HashicorpSecretConfig{makeSecret(multiValSecret, ""), makeSecret(addr1, "")},
////			unlockAll: false,
////			wantAccts: []accounts.Account{{
////				Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////				URL:     makeUrl(addr1),
////			}},
////			wantKeys:    []*ecdsa.PrivateKey{},
////			wantToCache: []HashicorpSecretConfig{makeSecret(multiValSecret, "")},
////		},
////		"gets accts regardless of keyvalue key in vault response": {
////			secrets:   []HashicorpSecretConfig{makeSecret(addr1, ""), makeSecret(addr2, "")},
////			unlockAll: false,
////			wantAccts: []accounts.Account{
////				{
////					Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////					URL:     makeUrl(addr1),
////				},
////				{
////					Address: common.HexToAddress("ca843569e3427144cead5e4d5999a3d0ccf92b8e"),
////					URL:     makeUrl(addr2),
////				},
////			},
////			wantKeys:    []*ecdsa.PrivateKey{},
////			wantToCache: []HashicorpSecretConfig{},
////		},
////		"unlockAll gets acct and key": {
////			secrets:   []HashicorpSecretConfig{makeSecret(addr1, key1)},
////			unlockAll: true,
////			wantAccts: []accounts.Account{
////				{
////					Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////					URL:     makeUrl(addr1),
////				},
////			},
////			wantKeys: []*ecdsa.PrivateKey{
////				makeKey("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"),
////			},
////			wantToCache: []HashicorpSecretConfig{},
////		},
////		"unlockAll gets acct but not key when key secret has multiple values": {
////			secrets:   []HashicorpSecretConfig{makeSecret(addr1, multiValSecret)},
////			unlockAll: true,
////			wantAccts: []accounts.Account{
////				{
////					Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////					URL:     makeUrl(addr1),
////				},
////			},
////			wantKeys:    []*ecdsa.PrivateKey{},
////			wantToCache: []HashicorpSecretConfig{makeSecret(addr1, multiValSecret)},
////		},
////		"unlockAll gets good keys and ignores unretrievable keys": {
////			secrets:   []HashicorpSecretConfig{makeSecret(addr1, multiValSecret), makeSecret(addr2, key2)},
////			unlockAll: true,
////			wantAccts: []accounts.Account{
////				{
////					Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////					URL:     makeUrl(addr1),
////				},
////				{
////					Address: common.HexToAddress("ca843569e3427144cead5e4d5999a3d0ccf92b8e"),
////					URL:     makeUrl(addr2),
////				},
////			},
////			wantKeys: []*ecdsa.PrivateKey{
////				makeKey("4762e04d10832808a0aebdaa79c12de54afbe006bfffd228b3abcc494fe986f9"),
////			},
////			wantToCache: []HashicorpSecretConfig{makeSecret(addr1, multiValSecret)},
////		},
////		"unlockAll gets keys regardless of keyvalue key in vault response": {
////			secrets:   []HashicorpSecretConfig{makeSecret(addr1, key1), makeSecret(addr2, key2)},
////			unlockAll: true,
////			wantAccts: []accounts.Account{
////				{
////					Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////					URL:     makeUrl(addr1),
////				},
////				{
////					Address: common.HexToAddress("ca843569e3427144cead5e4d5999a3d0ccf92b8e"),
////					URL:     makeUrl(addr2),
////				},
////			},
////			wantKeys: []*ecdsa.PrivateKey{
////				makeKey("e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"),
////				makeKey("4762e04d10832808a0aebdaa79c12de54afbe006bfffd228b3abcc494fe986f9"),
////			},
////			wantToCache: []HashicorpSecretConfig{},
////		},
////	}
////
////	return server, closeServer, tests
////}
////
////func setupReunlockCacheTestCase(t *testing.T) (*httptest.Server, func(), cacheTestCase) {
////	makeSecret := func(addrName, keyName string) HashicorpSecretConfig {
////		return HashicorpSecretConfig{AddressSecret: addrName, AddressSecretVersion: 1, PrivateKeySecret: keyName, PrivateKeySecretVersion: 1, SecretEngine: "kv"}
////	}
////
////	const (
////		key1  = "key1"
////		addr1 = "addr1"
////	)
////
////	server, closeServer := setupTestVaultServer(
////		t,
////		[]handlerData{
////			{secretName: addr1, resp: map[string]string{"addr": "ed9d02e382b34818e88b88a309c7fe71e65f419d"}},
////			{secretName: key1, resp: map[string]string{"key": "e6181caaffff94a09d7e332fc8da9884d99902c7874eb74354bdcadf411929f1"}},
////		},
////	)
////
////	test := cacheTestCase{
////		secrets:   []HashicorpSecretConfig{makeSecret(addr1, key1)},
////		unlockAll: true,
////		wantAccts: []accounts.Account{
////			{
////				Address: common.HexToAddress("ed9d02e382b34818e88b88a309c7fe71e65f419d"),
////				URL:     accounts.URL{Scheme: "http", Path: fmt.Sprintf("%v/v1/kv/data/%v?version=1", "%v", addr1)},
////			},
////		},
////		wantKeys:    []*ecdsa.PrivateKey{},
////		wantToCache: []HashicorpSecretConfig{},
////	}
////
////	return server, closeServer, test
////}
////
////func setupWalletWithNoClient(t *testing.T, url string, unlockAll bool, secrets []HashicorpSecretConfig) *wallet {
////	wltConfig := HashicorpWalletConfig{
////		Client: HashicorpClientConfig{
////			Url:       url,
////			UnlockAll: unlockAll,
////		},
////		Secrets: secrets,
////	}
////
////	w, err := newHashicorpWallet(wltConfig, &Backend{updateFeed: event.Feed{}}, "",  false)
////
////	if err != nil {
////		t.Fatal(err)
////	}
////
////	return w
////}
////
////func validateCacheTestCase(t *testing.T, w *wallet, serverUrl string, test cacheTestCase) {
////	gotAccts := getAccounts(t, w)
////
////	// populate the format string acct urls defined in the test cases with the current server url
////	serverUrl = strings.TrimPrefix(serverUrl, "http://")
////	wantAcctsWithUrl := []accounts.Account{}
////	for _, acct := range test.wantAccts {
////		acct.URL.Path = fmt.Sprintf(acct.URL.Path, serverUrl)
////		wantAcctsWithUrl = append(wantAcctsWithUrl, acct)
////	}
////
////	if !acctsEqual(wantAcctsWithUrl, gotAccts) {
////		t.Fatalf("wallet accounts do not equal wanted accounts\nwant: %v\ngot : %v", wantAcctsWithUrl, gotAccts)
////	}
////
////	gotKeys := getRetrievedKeys(t, w)
////
////	if !keysEqual(test.wantKeys, gotKeys) {
////		t.Fatalf("keys in vaultService do not equal wanted keys\nwant: %v\ngot : %v", test.wantKeys, gotKeys)
////	}
////
////	keyHandlers := getKeyHandlers(t, w)
////
////	for _, h := range keyHandlers {
////		if h.cancel != nil {
////			t.Fatalf("keys retrieved by the retrieval loop should be indefinitely unlocked")
////		}
////	}
////
////	toCache := w.vault.(*hashicorpService).toCache
////
////	if !toCacheEqual(test.wantToCache, toCache) {
////		t.Fatalf("toCache not updated correctly\nwant: %v\ngot : %v", test.wantToCache, toCache)
////	}
////}
////
////func TestVaultWallet_Status_Hashicorp_UpdatesCache(t *testing.T) {
////	server, closeServer, tests := setupCacheTestCases(t)
////	defer closeServer()
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			w := setupWalletWithNoClient(t, server.URL, tt.unlockAll, tt.secrets)
////			setHashicorpWalletClientForServer(t, w, server)
////
////			if _, err := w.Status(); err != nil {
////				t.Fatal(err)
////			}
////
////			validateCacheTestCase(t, w, server.URL, tt)
////		})
////	}
////}
////
////func TestVaultWallet_Status_Hashicorp_UpdatesCache_UnlockAllDoesNotReunlockLockedAccounts(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	server, closeServer, test := setupReunlockCacheTestCase(t)
////	defer closeServer()
////
////	w := setupWalletWithNoClient(t, server.URL, test.unlockAll, test.secrets)
////
////	if err := w.Open(""); err != nil {
////		t.Fatal(err)
////	}
////
////	if len(getRetrievedKeys(t, w)) != 1 {
////		t.Fatal("account not unlocked on open")
////	}
////
////	// call the method under test
////	acct := test.wantAccts[0]
////	acct.URL.Path = fmt.Sprintf(acct.URL.Path, strings.TrimPrefix(server.URL, "http://"))
////
////	if err := w.Lock(acct); err != nil {
////		t.Fatal(err)
////	}
////	if _, err := w.Status(); err != nil {
////		t.Fatal(err)
////	}
////
////	// assertions
////	validateCacheTestCase(t, w, server.URL, test)
////}
////
////func TestVaultWallet_Open_Hashicorp_UpdatesCache(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	server, closeServer, tests := setupCacheTestCases(t)
////	defer closeServer()
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			w := setupWalletWithNoClient(t, server.URL, tt.unlockAll, tt.secrets)
////
////			if err := w.Open(""); err != nil {
////				t.Fatalf("error opening wallet: %v", err.Error())
////			}
////
////			validateCacheTestCase(t, w, server.URL, tt)
////		})
////	}
////}
////
////func TestVaultWallet_Accounts_Hashicorp_UpdatesCache(t *testing.T) {
////	server, closeServer, tests := setupCacheTestCases(t)
////	defer closeServer()
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			w := setupWalletWithNoClient(t, server.URL, tt.unlockAll, tt.secrets)
////			setHashicorpWalletClientForServer(t, w, server)
////
////			w.Accounts()
////
////			validateCacheTestCase(t, w, server.URL, tt)
////		})
////	}
////}
////
////func TestVaultWallet_Accounts_Hashicorp_UpdatesCache_UnlockAllDoesNotReunlockLockedAccounts(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	server, closeServer, test := setupReunlockCacheTestCase(t)
////	defer closeServer()
////
////	w := setupWalletWithNoClient(t, server.URL, test.unlockAll, test.secrets)
////
////	if err := w.Open(""); err != nil {
////		t.Fatal(err)
////	}
////
////	if len(getRetrievedKeys(t, w)) != 1 {
////		t.Fatal("account not unlocked on open")
////	}
////
////	// call the method under test
////	acct := test.wantAccts[0]
////	acct.URL.Path = fmt.Sprintf(acct.URL.Path, strings.TrimPrefix(server.URL, "http://"))
////
////	if err := w.Lock(acct); err != nil {
////		t.Fatal(err)
////	}
////	w.Accounts()
////
////	// assertions
////	validateCacheTestCase(t, w, server.URL, test)
////}
////
////func TestVaultWallet_Contains_Hashicorp_UpdatesCache(t *testing.T) {
////	server, closeServer, tests := setupCacheTestCases(t)
////	defer closeServer()
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			w := setupWalletWithNoClient(t, server.URL, tt.unlockAll, tt.secrets)
////			setHashicorpWalletClientForServer(t, w, server)
////
////			w.Contains(accounts.Account{})
////
////			validateCacheTestCase(t, w, server.URL, tt)
////		})
////	}
////}
////
////func TestVaultWallet_Contains_Hashicorp_UpdatesCache_UnlockAllDoesNotReunlockLockedAccounts(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	server, serverClose, test := setupReunlockCacheTestCase(t)
////	defer serverClose()
////
////	w := setupWalletWithNoClient(t, server.URL, test.unlockAll, test.secrets)
////
////	if err := w.Open(""); err != nil {
////		t.Fatal(err)
////	}
////
////	if len(getRetrievedKeys(t, w)) != 1 {
////		t.Fatal("account not unlocked on open")
////	}
////
////	// call the method under test
////	acct := test.wantAccts[0]
////	acct.URL.Path = fmt.Sprintf(acct.URL.Path, strings.TrimPrefix(server.URL, "http://"))
////
////	if err := w.Lock(acct); err != nil {
////		t.Fatal(err)
////	}
////	w.Contains(accounts.Account{})
////
////	// assertions
////	validateCacheTestCase(t, w, server.URL, test)
////}
////
////func TestVaultWallet_SignHash_Hashicorp_UpdatesCache(t *testing.T) {
////	server, closeServer, tests := setupCacheTestCases(t)
////	defer closeServer()
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			w := setupWalletWithNoClient(t, server.URL, tt.unlockAll, tt.secrets)
////			setHashicorpWalletClientForServer(t, w, server)
////
////			w.SignHash(accounts.Account{}, []byte("toSign"))
////
////			validateCacheTestCase(t, w, server.URL, tt)
////		})
////	}
////}
////
////func TestVaultWallet_SignHash_Hashicorp_UpdatesCache_UnlockAllDoesNotReunlockLockedAccounts(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	server, serverClose, test := setupReunlockCacheTestCase(t)
////	defer serverClose()
////
////	w := setupWalletWithNoClient(t, server.URL, test.unlockAll, test.secrets)
////
////	if err := w.Open(""); err != nil {
////		t.Fatal(err)
////	}
////
////	if len(getRetrievedKeys(t, w)) != 1 {
////		t.Fatal("account not unlocked on open")
////	}
////
////	// call the method under test
////	acct := test.wantAccts[0]
////	acct.URL.Path = fmt.Sprintf(acct.URL.Path, strings.TrimPrefix(server.URL, "http://"))
////
////	if err := w.Lock(acct); err != nil {
////		t.Fatal(err)
////	}
////	w.SignHash(accounts.Account{}, []byte("toSign"))
////
////	// assertions
////	validateCacheTestCase(t, w, server.URL, test)
////}
////
////func TestVaultWallet_SignTx_Hashicorp_UpdatesCache(t *testing.T) {
////	server, closeServer, tests := setupCacheTestCases(t)
////	defer closeServer()
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			w := setupWalletWithNoClient(t, server.URL, tt.unlockAll, tt.secrets)
////			setHashicorpWalletClientForServer(t, w, server)
////
////			w.SignTx(accounts.Account{}, nil, nil)
////
////			validateCacheTestCase(t, w, server.URL, tt)
////		})
////	}
////}
////
////func TestVaultWallet_SignTx_Hashicorp_UpdatesCache_UnlockAllDoesNotReunlockLockedAccounts(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	server, serverClose, test := setupReunlockCacheTestCase(t)
////	defer serverClose()
////
////	w := setupWalletWithNoClient(t, server.URL, test.unlockAll, test.secrets)
////
////	if err := w.Open(""); err != nil {
////		t.Fatal(err)
////	}
////
////	if len(getRetrievedKeys(t, w)) != 1 {
////		t.Fatal("account not unlocked on open")
////	}
////
////	// call the method under test
////	acct := test.wantAccts[0]
////	acct.URL.Path = fmt.Sprintf(acct.URL.Path, strings.TrimPrefix(server.URL, "http://"))
////
////	if err := w.Lock(acct); err != nil {
////		t.Fatal(err)
////	}
////	w.SignTx(accounts.Account{}, nil, nil)
////
////	// assertions
////	validateCacheTestCase(t, w, server.URL, test)
////}
////
////func TestVaultWallet_SignHashWithPassphrase_Hashicorp_UpdatesCache(t *testing.T) {
////	server, closeServer, tests := setupCacheTestCases(t)
////	defer closeServer()
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			w := setupWalletWithNoClient(t, server.URL, tt.unlockAll, tt.secrets)
////			setHashicorpWalletClientForServer(t, w, server)
////
////			w.SignHashWithPassphrase(accounts.Account{}, "", []byte("toSign"))
////
////			validateCacheTestCase(t, w, server.URL, tt)
////		})
////	}
////}
////
////func TestVaultWallet_SignHashWithPassphrase_Hashicorp_UpdatesCache_UnlockAllDoesNotReunlockLockedAccounts(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	server, serverClose, test := setupReunlockCacheTestCase(t)
////	defer serverClose()
////
////	w := setupWalletWithNoClient(t, server.URL, test.unlockAll, test.secrets)
////
////	if err := w.Open(""); err != nil {
////		t.Fatal(err)
////	}
////
////	if len(getRetrievedKeys(t, w)) != 1 {
////		t.Fatal("account not unlocked on open")
////	}
////
////	// call the method under test
////	acct := test.wantAccts[0]
////	acct.URL.Path = fmt.Sprintf(acct.URL.Path, strings.TrimPrefix(server.URL, "http://"))
////
////	if err := w.Lock(acct); err != nil {
////		t.Fatal(err)
////	}
////	w.SignHashWithPassphrase(accounts.Account{}, "", []byte("toSign"))
////
////	// assertions
////	validateCacheTestCase(t, w, server.URL, test)
////}
////
////func TestVaultWallet_SignTxWithPassphrase_Hashicorp_UpdatesCache(t *testing.T) {
////	server, closeServer, tests := setupCacheTestCases(t)
////	defer closeServer()
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			w := setupWalletWithNoClient(t, server.URL, tt.unlockAll, tt.secrets)
////			setHashicorpWalletClientForServer(t, w, server)
////
////			w.SignTxWithPassphrase(accounts.Account{}, "", nil, nil)
////
////			validateCacheTestCase(t, w, server.URL, tt)
////		})
////	}
////}
////
////func TestVaultWallet_SignTxWithPassphrase_Hashicorp_UpdatesCache_UnlockAllDoesNotReunlockLockedAccounts(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	server, serverClose, test := setupReunlockCacheTestCase(t)
////	defer serverClose()
////
////	w := setupWalletWithNoClient(t, server.URL, test.unlockAll, test.secrets)
////
////	if err := w.Open(""); err != nil {
////		t.Fatal(err)
////	}
////
////	if len(getRetrievedKeys(t, w)) != 1 {
////		t.Fatal("account not unlocked on open")
////	}
////
////	// call the method under test
////	acct := test.wantAccts[0]
////	acct.URL.Path = fmt.Sprintf(acct.URL.Path, strings.TrimPrefix(server.URL, "http://"))
////
////	if err := w.Lock(acct); err != nil {
////		t.Fatal(err)
////	}
////	w.SignTxWithPassphrase(accounts.Account{}, "", nil, nil)
////
////	// assertions
////	validateCacheTestCase(t, w, server.URL, test)
////}
////
////func TestVaultWallet_TimedUnlock_Hashicorp_UpdatesCache(t *testing.T) {
////	server, closeServer, tests := setupCacheTestCases(t)
////	defer closeServer()
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			w := setupWalletWithNoClient(t, server.URL, tt.unlockAll, tt.secrets)
////			setHashicorpWalletClientForServer(t, w, server)
////
////			w.TimedUnlock(accounts.Account{}, 0)
////
////			validateCacheTestCase(t, w, server.URL, tt)
////		})
////	}
////}
////
////func TestVaultWallet_TimedUnlock_Hashicorp_UpdatesCache_UnlockAllDoesNotReunlockLockedAccounts(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	server, serverClose, test := setupReunlockCacheTestCase(t)
////	defer serverClose()
////
////	w := setupWalletWithNoClient(t, server.URL, test.unlockAll, test.secrets)
////
////	if err := w.Open(""); err != nil {
////		t.Fatal(err)
////	}
////
////	if len(getRetrievedKeys(t, w)) != 1 {
////		t.Fatal("account not unlocked on open")
////	}
////
////	// call the method under test
////	acct := test.wantAccts[0]
////	acct.URL.Path = fmt.Sprintf(acct.URL.Path, strings.TrimPrefix(server.URL, "http://"))
////
////	if err := w.Lock(acct); err != nil {
////		t.Fatal(err)
////	}
////	w.TimedUnlock(accounts.Account{}, 0)
////
////	// assertions
////	validateCacheTestCase(t, w, server.URL, test)
////}
////
////func TestVaultWallet_Lock_Hashicorp_UpdatesCache(t *testing.T) {
////	server, closeServer, tests := setupCacheTestCases(t)
////	defer closeServer()
////
////	for name, tt := range tests {
////		t.Run(name, func(t *testing.T) {
////			w := setupWalletWithNoClient(t, server.URL, tt.unlockAll, tt.secrets)
////			setHashicorpWalletClientForServer(t, w, server)
////
////			w.Lock(accounts.Account{})
////
////			validateCacheTestCase(t, w, server.URL, tt)
////		})
////	}
////}
////
////func TestVaultWallet_Lock_Hashicorp_UpdatesCache_UnlockAllDoesNotReunlockLockedAccounts(t *testing.T) {
////	if err := os.Setenv(api.EnvVaultToken, "mytoken"); err != nil {
////		t.Fatal(err)
////	}
////
////	server, serverClose, test := setupReunlockCacheTestCase(t)
////	defer serverClose()
////
////	w := setupWalletWithNoClient(t, server.URL, test.unlockAll, test.secrets)
////
////	if err := w.Open(""); err != nil {
////		t.Fatal(err)
////	}
////
////	if len(getRetrievedKeys(t, w)) != 1 {
////		t.Fatal("account not unlocked on open")
////	}
////
////	// call the method under test
////	acct := test.wantAccts[0]
////	acct.URL.Path = fmt.Sprintf(acct.URL.Path, strings.TrimPrefix(server.URL, "http://"))
////
////	if err := w.Lock(acct); err != nil {
////		t.Fatal(err)
////	}
////	w.Lock(accounts.Account{})
////
////	// assertions
////	validateCacheTestCase(t, w, server.URL, test)
////}
