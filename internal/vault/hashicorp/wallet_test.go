package hashicorp

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/stretchr/testify/require"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestHashicorpWallet_URL(t *testing.T) {
	u := accounts.URL{Scheme: WalletScheme, Path: "foo"}
	w := wallet{url: u}

	got := w.URL()

	require.Equal(t, u, got)
}

func TestNewHashicorpWallet(t *testing.T) {
	t.Fatal("implement me")
}

func TestHashicorpWallet_Status_ClosedByDefault(t *testing.T) {
	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	got, err := w.Status()
	want := closed

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestHashicorpWallet_Status_VaultAndAcctStatus(t *testing.T) {
	defer setEnvironmentVariables(DefaultTokenEnv)()

	// order is not guaranteed in slices so account for any ordering in the returned status message
	manyAcctRegex := fmt.Sprintf(
		"^Unlocked:.(%v|%v),.(%v|%v);.Locked:.(%v|%v),.(%v|%v)$",
		acct1.addr,
		acct2.addr,
		acct1.addr,
		acct2.addr,
		acct3.addr,
		acct4.addr,
		acct3.addr,
		acct4.addr,
	)

	tests := []struct {
		name                string
		healthResponse      api.HealthResponse
		doBadHealthResponse bool
		lockedAccts         []string
		unlockedAccts       []string
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
			unlockedAccts:  []string{acct1.addr},
			want:           fmt.Sprintf("Unlocked: %v", acct1.addr),
			wantErr:        hashicorpUninitializedErr,
		},
		{
			name:           "sealed unlocked accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: true},
			unlockedAccts:  []string{acct1.addr},
			want:           fmt.Sprintf("Unlocked: %v", acct1.addr),
			wantErr:        hashicorpSealedErr,
		},
		{
			name:           "ok unlocked accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: false},
			unlockedAccts:  []string{acct1.addr},
			want:           fmt.Sprintf("Unlocked: %v", acct1.addr),
			wantErr:        nil,
		},
		{
			name:           "uninitialised locked accts",
			healthResponse: api.HealthResponse{Initialized: false},
			lockedAccts:    []string{acct1.addr},
			want:           fmt.Sprintf("Locked: %v", acct1.addr),
			wantErr:        hashicorpUninitializedErr,
		},
		{
			name:           "sealed locked accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: true},
			unlockedAccts:  []string{acct1.addr},
			lockedAccts:    []string{acct2.addr},
			want:           fmt.Sprintf("Unlocked: %v; Locked: %v", acct1.addr, acct2.addr),
			wantErr:        hashicorpSealedErr,
		},
		{
			name:           "ok locked accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: false},
			unlockedAccts:  []string{acct1.addr},
			lockedAccts:    []string{acct2.addr},
			want:           fmt.Sprintf("Unlocked: %v; Locked: %v", acct1.addr, acct2.addr),
			wantErr:        nil,
		},
		{
			name:           "uninitialised both accts",
			healthResponse: api.HealthResponse{Initialized: false},
			unlockedAccts:  []string{acct1.addr},
			lockedAccts:    []string{acct2.addr},
			want:           fmt.Sprintf("Unlocked: %v; Locked: %v", acct1.addr, acct2.addr),
			wantErr:        hashicorpUninitializedErr,
		},
		{
			name:           "sealed both accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: true},
			unlockedAccts:  []string{acct1.addr},
			lockedAccts:    []string{acct2.addr},
			want:           fmt.Sprintf("Unlocked: %v; Locked: %v", acct1.addr, acct2.addr),
			wantErr:        hashicorpSealedErr,
		},
		{
			name:           "ok both accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: false},
			unlockedAccts:  []string{acct1.addr},
			lockedAccts:    []string{acct2.addr},
			want:           fmt.Sprintf("Unlocked: %v; Locked: %v", acct1.addr, acct2.addr),
			wantErr:        nil,
		},
		{
			name:           "ok many accts",
			healthResponse: api.HealthResponse{Initialized: true, Sealed: false},
			unlockedAccts:  []string{acct1.addr, acct2.addr},
			lockedAccts:    []string{acct3.addr, acct4.addr},
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
				cleanup = setupMock404VaultServerAndOpen(t, w)
			} else {
				b, err := json.Marshal(tt.healthResponse)
				require.NoError(t, err)

				cleanup = setupMockVaultServerAndOpen(t, w, b)
			}

			addUnlockedAccts(t, w, tt.unlockedAccts)
			addLockedAccts(t, w, tt.lockedAccts)

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

func TestHashicorpWallet_Open_ErrorIfAlreadyOpen(t *testing.T) {
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

func TestHashicorpWallet_Open_ValidatesAuthenticationCredentials(t *testing.T) {
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

func TestHashicorpWallet_Open_UsesDefaultApprolePath(t *testing.T) {
	t.Fatal("implement me")
}

func TestHashicorpWallet_Open_UsesConfiguredApprolePath(t *testing.T) {
	t.Fatal("implement me")
}

func TestHashicorpWallet_Open_CreatesTokenAuthenticatedClient(t *testing.T) {
	defer setEnvironmentVariables(DefaultTokenEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	var handlerInvoked bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerInvoked = true

		header := map[string][]string(r.Header)
		token := header[consts.AuthHeaderName]

		require.Len(t, token, 1)
		require.Equal(t, DefaultTokenEnv, token[0])
	})

	defer setupMockVaultServer2(w, handler)()

	err := w.Open("")

	require.NoError(t, err)

	makeArbitraryRequestUsingVaultClient(t, w)
	require.True(t, handlerInvoked, "test incomplete as no request made to Vault")
}

func TestHashicorpWallet_Open_CreatesTokenAuthenticatedClient_AuthID(t *testing.T) {
	t.Fatal("implement me")
}

func TestHashicorpWallet_Open_CreatesAppRoleAuthenticatedClient(t *testing.T) {
	t.Fatal("implement me")
}

func TestHashicorpWallet_Open_CreatesAppRoleAuthenticatedClient_AuthID(t *testing.T) {
	t.Fatal("implement me")
}

func TestHashicorpWallet_Open_CreatesHttpsClientIfConfigured(t *testing.T) {
	t.Fatal("implement me")
}

func TestHashicorpWallet_Open_SendsEventToSubscribers(t *testing.T) {
	t.Fatal("implement me")
}
