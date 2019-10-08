// Long running Hashicorp Vault tests
// +build integration

package todelete

import (
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/hashicorp"
	"strings"
	"testing"
)

func TestHashicorpWallet_Status_ClosedIfOpenFailsDueToVaultError(t *testing.T) {
	defer vault.setEnvironmentVariables(hashicorp.DefaultRoleIDEnv, hashicorp.DefaultSecretIDEnv)()

	var builder vault.testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	defer vault.setupMockSealedVaultServer(w)()

	wantErr := w.Open("")

	if wantErr == nil {
		t.Fatal("expected error")
	}

	got, gotErr := w.Status()
	want := vault.closed

	if want != got {
		t.Fatalf("want: %v, got: %v", want, got)
	}

	if wantErr != gotErr {
		t.Fatalf("want: %v, got: %v", wantErr, gotErr)
	}

	wantMsg := "Vault is sealed"
	if strings.Contains(gotErr.Error(), wantMsg) {
		t.Fatalf("want error containing: %v, got: %v", wantMsg, gotErr)
	}
}

func TestHashicorpWallet_Status_VaultHealthcheckError(t *testing.T) {
	defer vault.setEnvironmentVariables(hashicorp.DefaultTokenEnv)()

	var builder vault.testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	defer vault.setupMockSealedVaultServerAndOpen(t, w)()

	got, err := w.Status()
	want := ""

	if want != got {
		t.Fatalf("want: %v, got: %v", want, got)
	}

	if _, ok := err.(vault.hashicorpHealthcheckErr); !ok {
		t.Fatalf("want: %T, got: %T", vault.hashicorpHealthcheckErr{}, err)
	}
}
