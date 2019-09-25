// Long running Hashicorp Vault tests
// +build integration

package vault

import (
	"strings"
	"testing"
)

func TestHashicorpWallet_Status_ClosedIfOpenFailsDueToVaultError(t *testing.T) {
	defer setEnvironmentVariables(DefaultRoleIDEnv, DefaultSecretIDEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	defer setupMockSealedVaultServer(w)()

	wantErr := w.Open("")

	if wantErr == nil {
		t.Fatal("expected error")
	}

	got, gotErr := w.Status()
	want := closed

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
	defer setEnvironmentVariables(DefaultTokenEnv)()

	var builder testHashicorpWalletBuilder
	builder.withBasicConfig()
	w := builder.build(t)

	defer setupMockSealedVaultServerAndOpen(t, w)()

	got, err := w.Status()
	want := ""

	if want != got {
		t.Fatalf("want: %v, got: %v", want, got)
	}

	if _, ok := err.(hashicorpHealthcheckErr); !ok {
		t.Fatalf("want: %T, got: %T", hashicorpHealthcheckErr{}, err)
	}
}
