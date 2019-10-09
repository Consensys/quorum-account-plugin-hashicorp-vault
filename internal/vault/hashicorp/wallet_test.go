package hashicorp

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/cache"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/stretchr/testify/require"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestWallet_URL(t *testing.T) {
	u := accounts.URL{Scheme: WalletScheme, Path: "foo"}
	w := wallet{url: u}

	got := w.URL()

	require.Equal(t, u, got)
}

func TestNewHashicorpWallet(t *testing.T) {
	t.Fatal("implement me")
}

func TestWallet_Status_ClosedByDefault(t *testing.T) {
	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	got, err := w.Status()
	want := closed

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestWallet_Status_VaultAndAcctStatus(t *testing.T) {
	defer setEnvironmentVariables(DefaultTokenEnv)()

	// order is not guaranteed in slices so account for any ordering in the returned status message
	manyAcctRegex := fmt.Sprintf(
		"^Unlocked:.(%v|%v),.(%v|%v);.Locked:.(%v|%v),.(%v|%v)$",
		acct1Data.addr,
		acct2Data.addr,
		acct1Data.addr,
		acct2Data.addr,
		acct3Data.addr,
		acct4Data.addr,
		acct3Data.addr,
		acct4Data.addr,
	)

	tests := []struct {
		name                string
		healthResponse      api.HealthResponse
		doBadHealthResponse bool
		lockedAccts         []accounts.Account
		unlockedAccts       []acctAndKey
		want                string
		wantErr             error
	}{
		{
			name:                "healthcheck error",
			doBadHealthResponse: true,
			want:                "",
			wantErr:             fmt.Errorf("%v", hashicorpHealthcheckFailed),
		},
		{
			name:           "uninitialised no accts",
			healthResponse: api.HealthResponse{Initialized: false},
			want:           "",
			wantErr:        hashicorpUninitializedErr,
		},
		{
			name:           "sealed no accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: true},
			want:           "",
			wantErr:        hashicorpSealedErr,
		},
		{
			name:           "ok no accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: false},
			want:           "",
			wantErr:        nil,
		},
		{
			name:           "uninitialised unlocked accts",
			healthResponse: api.HealthResponse{Initialized: false},
			unlockedAccts:  []acctAndKey{{acct: acct1}},
			want:           fmt.Sprintf("Unlocked: %v", acct1Data.addr),
			wantErr:        hashicorpUninitializedErr,
		},
		{
			name:           "sealed unlocked accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: true},
			unlockedAccts:  []acctAndKey{{acct: acct1}},
			want:           fmt.Sprintf("Unlocked: %v", acct1Data.addr),
			wantErr:        hashicorpSealedErr,
		},
		{
			name:           "ok unlocked accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: false},
			unlockedAccts:  []acctAndKey{{acct: acct1}},
			want:           fmt.Sprintf("Unlocked: %v", acct1Data.addr),
			wantErr:        nil,
		},
		{
			name:           "uninitialised locked accts",
			healthResponse: api.HealthResponse{Initialized: false},
			lockedAccts:    []accounts.Account{acct1},
			want:           fmt.Sprintf("Locked: %v", acct1Data.addr),
			wantErr:        hashicorpUninitializedErr,
		},
		{
			name:           "sealed locked accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: true},
			unlockedAccts:  []acctAndKey{{acct: acct1}},
			lockedAccts:    []accounts.Account{acct2},
			want:           fmt.Sprintf("Unlocked: %v; Locked: %v", acct1Data.addr, acct2Data.addr),
			wantErr:        hashicorpSealedErr,
		},
		{
			name:           "ok locked accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: false},
			unlockedAccts:  []acctAndKey{{acct: acct1}},
			lockedAccts:    []accounts.Account{acct2},
			want:           fmt.Sprintf("Unlocked: %v; Locked: %v", acct1Data.addr, acct2Data.addr),
			wantErr:        nil,
		},
		{
			name:           "uninitialised both accts",
			healthResponse: api.HealthResponse{Initialized: false},
			unlockedAccts:  []acctAndKey{{acct: acct1}},
			lockedAccts:    []accounts.Account{acct2},
			want:           fmt.Sprintf("Unlocked: %v; Locked: %v", acct1Data.addr, acct2Data.addr),
			wantErr:        hashicorpUninitializedErr,
		},
		{
			name:           "sealed both accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: true},
			unlockedAccts:  []acctAndKey{{acct: acct1}},
			lockedAccts:    []accounts.Account{acct2},
			want:           fmt.Sprintf("Unlocked: %v; Locked: %v", acct1Data.addr, acct2Data.addr),
			wantErr:        hashicorpSealedErr,
		},
		{
			name:           "ok both accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: false},
			unlockedAccts:  []acctAndKey{{acct: acct1}},
			lockedAccts:    []accounts.Account{acct2},
			want:           fmt.Sprintf("Unlocked: %v; Locked: %v", acct1Data.addr, acct2Data.addr),
			wantErr:        nil,
		},
		{
			name:           "ok many accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: false},
			unlockedAccts:  []acctAndKey{{acct: acct1}, {acct: acct2}},
			lockedAccts:    []accounts.Account{acct3, acct4},
			want:           manyAcctRegex,
			wantErr:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var builder testHashicorpWalletBuilder
			builder.withBasicConfig()
			w := builder.build(t)

			var cleanup func()

			if tt.doBadHealthResponse {
				cleanup = setupMockErrorCodeVaultServerAndRegisterWithWalletAndOpen(t, w, vaultNotFoundStatusCode)
			} else {
				b, err := json.Marshal(tt.healthResponse)
				require.NoError(t, err)

				cleanup = setupMockVaultServerAndRegisterWithWalletAndOpen(t, w, createSimpleHandler(b))
			}

			addUnlockedAccts(t, w, tt.unlockedAccts...)
			addLockedAccts(t, w, tt.lockedAccts...)

			got, err := w.Status()
			cleanup()

			if strings.HasPrefix(tt.want, "^") {
				// regex has been provided
				require.Regexp(t, regexp.MustCompile(tt.want), got)
			} else {
				require.Equal(t, tt.want, got)
			}

			if tt.doBadHealthResponse {
				// in this case the Vault client library returns its own error - we ignore their error to prevent coupling the test to their implementation
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr.Error())
			} else {
				require.Equal(t, tt.wantErr, err)
			}
		})
	}
}

func TestWallet_Open_ErrorIfAlreadyOpen(t *testing.T) {
	defer setEnvironmentVariables(DefaultTokenEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	var err error

	err = w.Open("")
	require.NoError(t, err)

	err = w.Open("")
	want := accounts.ErrWalletAlreadyOpen
	require.EqualError(t, err, want.Error())
}

func TestWallet_Open_ValidatesAuthenticationCredentials(t *testing.T) {
	// for tests using the authorizationID
	const authorizationID = "FOO"
	prefixedRoleIDEnv := fmt.Sprintf("%v_%v", authorizationID, DefaultRoleIDEnv)
	prefixedSecretIDEnv := fmt.Sprintf("%v_%v", authorizationID, DefaultSecretIDEnv)
	prefixedTokenEnv := fmt.Sprintf("%v_%v", authorizationID, DefaultTokenEnv)

	tests := []struct {
		name            string
		authorizationID string
		toSet           []string
		wantErr         error
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
			name:            "authID none set",
			authorizationID: authorizationID,
			toSet:           []string{},
			wantErr:         noHashicorpEnvSetErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv, tokenEnv: prefixedTokenEnv},
		},
		{
			name:            "authID default set",
			authorizationID: authorizationID,
			toSet:           []string{DefaultRoleIDEnv, DefaultSecretIDEnv, DefaultTokenEnv},
			wantErr:         noHashicorpEnvSetErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv, tokenEnv: prefixedTokenEnv},
		},
		{
			name:            "authID only prefixed role-id",
			authorizationID: authorizationID,
			toSet:           []string{prefixedRoleIDEnv},
			wantErr:         invalidApproleAuthErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv},
		},
		{
			name:            "authID only secret-id",
			authorizationID: authorizationID,
			toSet:           []string{prefixedSecretIDEnv},
			wantErr:         invalidApproleAuthErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv},
		},
		{
			name:            "authID approle auth preferred (role-id)",
			authorizationID: authorizationID,
			toSet:           []string{prefixedRoleIDEnv, prefixedTokenEnv},
			wantErr:         invalidApproleAuthErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv},
		},
		{
			name:            "authID approle auth preferred (secret-id)",
			authorizationID: authorizationID,
			toSet:           []string{prefixedSecretIDEnv, prefixedTokenEnv},
			wantErr:         invalidApproleAuthErr{roleIdEnv: prefixedRoleIDEnv, secretIdEnv: prefixedSecretIDEnv},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := setEnvironmentVariables(tt.toSet...)

			var builder testHashicorpWalletBuilder
			builder.withBasicConfig()
			builder.withAuthorizationID(tt.authorizationID)
			w := builder.build(t)

			err := w.Open("")
			cleanup()

			require.EqualError(t, err, tt.wantErr.Error())
		})
	}
}

func TestWallet_Open_CreatesTokenAuthenticatedClient(t *testing.T) {
	defer setEnvironmentVariables(DefaultTokenEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	var requestTokens []string

	authCheckHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := map[string][]string(r.Header)
		requestTokens = header[consts.AuthHeaderName]
	})

	defer setupMockVaultServerAndRegisterWithWallet(t, w, pathHandler{handler: authCheckHandler})()

	err := w.Open("")
	require.NoError(t, err)

	makeArbitraryRequestUsingVaultClient(t, w)
	require.Len(t, requestTokens, 1)
	require.Equal(t, DefaultTokenEnv, requestTokens[0])
}

func TestWallet_Open_CreatesApproleAuthenticatedClient(t *testing.T) {
	defer setEnvironmentVariables(DefaultRoleIDEnv, DefaultSecretIDEnv)()
	customApprolePath := "somepath"

	tests := []struct {
		name                     string
		isUsingCustomApprolePath bool
	}{
		{
			name:                     "default approle path",
			isUsingCustomApprolePath: false,
		},
		{
			name:                     "custom approle path",
			isUsingCustomApprolePath: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var builder testHashicorpWalletBuilder
			builder.withBasicConfig()

			if tt.isUsingCustomApprolePath {
				builder.withApprolePath(customApprolePath)
			}

			w := builder.build(t)

			mockToken := "mock_token"
			var requestTokens []string

			approleHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				vaultResponse := &api.Secret{Auth: &api.SecretAuth{ClientToken: mockToken}}
				b, err := json.Marshal(vaultResponse)
				require.NoError(t, err)
				_, _ = w.Write(b)
			})
			authCheckHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				header := map[string][]string(r.Header)
				requestTokens = header[consts.AuthHeaderName]
			})

			approlePath := "approle"
			if tt.isUsingCustomApprolePath {
				approlePath = customApprolePath
			}

			loginPath := fmt.Sprintf("/v1/auth/%v/login", approlePath)
			authCheckPath := fmt.Sprintf("/v1/%v", arbitraryPath)
			defer setupMockVaultServerAndRegisterWithWallet(
				t,
				w,
				newPathHandler(loginPath, approleHandler),
				newPathHandler(authCheckPath, authCheckHandler),
			)()

			err := w.Open("")
			require.NoError(t, err)

			makeArbitraryRequestUsingVaultClient(t, w)
			require.Len(t, requestTokens, 1)
			require.Equal(t, mockToken, requestTokens[0])
		})
	}
}

func TestWallet_Open_CreatesHttpsClientIfConfigured(t *testing.T) {
	defer setEnvironmentVariables(DefaultTokenEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	builder.withMutualTLSConfig(caCert, clientCert, clientKey)
	w := builder.build(t)

	var requestTokens []string

	authCheckHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := map[string][]string(r.Header)
		requestTokens = header[consts.AuthHeaderName]
	})

	defer setupMockTLSVaultServerAndRegisterWithWallet(t, w, pathHandler{handler: authCheckHandler})()

	err := w.Open("")
	require.NoError(t, err)

	makeArbitraryRequestUsingVaultClient(t, w)
	require.Len(t, requestTokens, 1)
	require.Equal(t, DefaultTokenEnv, requestTokens[0])
}

func TestWallet_Open_SendsEventToSubscribers(t *testing.T) {
	t.Fatal("implement me")
}

func TestWallet_Open_Status_StatusReturnsClosedAndErrorIfOpenFailedDueToAuth(t *testing.T) {
	defer setEnvironmentVariables(DefaultRoleIDEnv, DefaultSecretIDEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	defer setupMockErrorCodeVaultServerAndRegisterWithWallet(w, vaultNotFoundStatusCode)()

	openErr := w.Open("")
	require.Error(t, openErr)

	status, statusErr := w.status()
	require.Equal(t, status, closed)
	require.Error(t, statusErr)
	require.EqualError(t, statusErr, openErr.Error())
}

func TestWallet_Close_ResetsVaultClient(t *testing.T) {
	defer setEnvironmentVariables(DefaultTokenEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	err := w.Open("")
	require.NoError(t, err)

	err = w.Close()
	require.NoError(t, err)
	require.Nil(t, w.client)

	status, err := w.Status()
	require.Equal(t, closed, status)
	require.NoError(t, err)
}

func TestWallet_Accounts_ReturnsCopy(t *testing.T) {
	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	addLockedAccts(t, w, acct1, acct2)

	got := w.Accounts()
	require.Len(t, got, 2)
	require.Contains(t, got, acct1, acct2)

	// change got
	got = append(got, acct3)
	require.Len(t, got, 3)
	require.Contains(t, got, acct1, acct2, acct3)

	unchanged := w.Accounts()
	require.Len(t, unchanged, 2)
	require.Contains(t, unchanged, acct1, acct2)
}

func TestWallet_Contains(t *testing.T) {
	tests := []struct {
		name      string
		contained []accounts.Account
		toFind    accounts.Account
		want      bool
	}{
		{
			name:      "same addr and url",
			contained: []accounts.Account{acct1, acct2},
			toFind:    acct1,
			want:      true,
		},
		{
			name:      "same addr no url",
			contained: []accounts.Account{acct1, acct2},
			toFind: accounts.Account{
				Address: acct1.Address,
				URL:     accounts.URL{},
			},
			want: true,
		},
		{
			name:      "same addr diff url",
			contained: []accounts.Account{acct1, acct2},
			toFind: accounts.Account{
				Address: acct1.Address,
				URL:     acct3.URL,
			},
			want: false,
		},
		{
			name:      "diff addr same url",
			contained: []accounts.Account{acct1, acct2},
			toFind: accounts.Account{
				Address: acct3.Address,
				URL:     acct1.URL,
			},
			want: false,
		},
		{
			name:      "diff addr no url",
			contained: []accounts.Account{acct1, acct2},
			toFind: accounts.Account{
				Address: acct3.Address,
				URL:     accounts.URL{},
			},
			want: false,
		},
		{
			name:      "diff addr diff url",
			contained: []accounts.Account{acct1, acct2},
			toFind:    acct3,
			want:      false,
		},
		{
			name:      "no accounts contained",
			contained: []accounts.Account{},
			toFind:    acct1,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var builder testHashicorpWalletBuilder
			builder.withBasicConfig()
			w := builder.build(t)
			addLockedAccts(t, w, tt.contained...)

			got := w.Contains(tt.toFind)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestWallet_Derive_NotSupported(t *testing.T) {
	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	_, err := w.Derive(accounts.DerivationPath{}, true)
	require.EqualError(t, err, accounts.ErrNotSupported.Error())
}

func TestWallet_SignHash_SignHashWithPassphrase_ErrorIfUnknownAccount(t *testing.T) {
	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	var (
		toSign = []byte("to sign")
		err    error
	)

	_, err = w.SignHash(acct1, toSign)
	require.EqualError(t, err, accounts.ErrUnknownAccount.Error())

	_, err = w.SignHashWithPassphrase(acct1, "pwd", toSign)
	require.EqualError(t, err, accounts.ErrUnknownAccount.Error())
}

func TestWallet_SignHash_SignHashWithPassphrase_ErrorIfAmbiguousAccount(t *testing.T) {
	defer setEnvironmentVariables(DefaultTokenEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	acct1DiffUrl := accounts.Account{
		Address: acct1.Address,
		URL:     acct2.URL,
	}
	addLockedAccts(t, w, acct1, acct1DiffUrl)

	err := w.Open("")
	require.NoError(t, err)

	toSign := []byte("to sign")

	// This account does not specify the exact account to use as no URL is provided
	ambiguousAcct := accounts.Account{Address: acct1.Address}

	_, err = w.SignHash(ambiguousAcct, toSign)
	require.IsType(t, &cache.AmbiguousAddrError{}, err)
	ambigErr, _ := err.(*cache.AmbiguousAddrError)
	require.Equal(t, ambigErr.Addr, acct1.Address)
	require.Contains(t, ambigErr.Matches, acct1, acct1DiffUrl)

	_, err = w.SignHashWithPassphrase(ambiguousAcct, "pwd", toSign)
	require.IsType(t, &cache.AmbiguousAddrError{}, err)
	pwdAmbigErr, _ := err.(*cache.AmbiguousAddrError)
	require.Equal(t, pwdAmbigErr.Addr, acct1.Address)
	require.Contains(t, pwdAmbigErr.Matches, acct1, acct1DiffUrl)
}

func TestWallet_SignHash_SignHashWithPassphrase_AmbiguousAccountAllowedIfOnlyOneAccountWithGivenAddress(t *testing.T) {
	defer setEnvironmentVariables(DefaultTokenEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	prv, err := crypto.HexToECDSA(acct1Data.key)
	require.NoError(t, err)

	// add an unlocked acct to the wallet so that we can test the signHash method
	addUnlockedAccts(t, w, acctAndKey{acct: acct1, key: prv})

	err = w.Open("")
	require.NoError(t, err)

	toSign := crypto.Keccak256([]byte("to sign"))

	want, err := crypto.Sign(toSign, prv)
	require.NoError(t, err)

	// This account does not specify the exact account to use as no URL is provided
	ambiguousAcct := accounts.Account{Address: acct1.Address}

	got, err := w.SignHash(ambiguousAcct, toSign)
	require.NoError(t, err)
	require.Equal(t, want, got)

	pwdGot, err := w.SignHashWithPassphrase(ambiguousAcct, "pwd", toSign)
	require.NoError(t, err)
	require.Equal(t, want, pwdGot)
}

func TestVaultWallet_SignHash_Hashicorp_SignsWithInMemoryKeyIfAvailableAndDoesNotZeroKey(t *testing.T) {
	t.Fatal("implement me")
}

func TestVaultWallet_SignHash_Hashicorp_ErrorIfSigningKeyIsNotRelatedToProvidedAccount(t *testing.T) {
	t.Fatal("implement me")
}

func TestWallet_SignHash_CannotUnlockAccounts(t *testing.T) {
	defer setEnvironmentVariables(DefaultTokenEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	addLockedAccts(t, w, acct1)

	var (
		toSign = []byte("to sign")
		err    error
	)

	err = w.Open("")
	require.NoError(t, err)

	_, err = w.SignHash(acct1, toSign)
	require.EqualError(t, err, keystore.ErrLocked.Error())
}

func TestWallet_SignHashWithPassphrase_CanUnlockAccounts(t *testing.T) {
	defer setEnvironmentVariables(DefaultTokenEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	builder.withAccountConfigDir("testdata/acctconfig")
	w := builder.build(t)

	toSign := crypto.Keccak256([]byte("to sign"))

	prv, err := crypto.HexToECDSA(acct1Data.key)
	require.NoError(t, err)
	want, err := crypto.Sign(toSign, prv)
	require.NoError(t, err)

	var vaultResponse api.Secret
	vaultResponse.Data = map[string]interface{}{
		"data": map[string]interface{}{
			acct1Data.addr: acct1Data.key,
		},
	}
	b, err := json.Marshal(vaultResponse)
	require.NoError(t, err)

	defer setupMockVaultServerAndRegisterWithWalletAndOpen(t, w, createSimpleHandler(b))()

	got, err := w.SignHashWithPassphrase(acct1, "", toSign)
	require.NoError(t, err)
	require.Equal(t, want, got)

	// account should be locked after use
	require.Len(t, w.unlocked, 0)
}
