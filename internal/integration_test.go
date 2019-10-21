package internal

import (
	"context"
	"encoding/json"
	"fmt"
	iproto "github.com/goquorum/quorum-plugin-definitions/initializer/go/proto"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/hashicorp"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func Test(t *testing.T) {
	defer setEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultSecretIDEnv),
	)()

	client, server := plugin.TestPluginGRPCConn(t, map[string]plugin.Plugin{
		"signer": new(testableSignerPluginImpl),
	})
	defer client.Close()
	defer server.Stop()

	authVaultHandler := pathHandler{
		path: "/v1/auth/approle/login",
		handler: func(w http.ResponseWriter, r *http.Request) {
			vaultResponse := &api.Secret{Auth: &api.SecretAuth{ClientToken: "logintoken"}}
			b, err := json.Marshal(vaultResponse)
			require.NoError(t, err)
			_, _ = w.Write(b)
		},
	}

	vaultHandlers := []pathHandler{
		authVaultHandler,
	}

	vault := setupMockTLSVaultServer(t, vaultHandlers...)
	defer vault.Close()

	raw, err := client.Dispense("signer")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	impl, ok := raw.(InitializerSignerClient)
	if !ok {
		t.Fatalf("bad: %#v", raw)
	}

	pluginConfig := hashicorp.HashicorpAccountStoreConfig{
		Vaults: []hashicorp.VaultConfig{{
			Addr: vault.URL,
			TLS: hashicorp.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "/Users/chrishounom/quorum-plugin-hashicorp-account-store/internal/testdata",
			Unlock:           "",
			Auth: []hashicorp.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}
	rawPluginConfig, err := json.Marshal(pluginConfig)
	require.NoError(t, err)

	_, err = impl.Init(context.Background(), &iproto.PluginInitialization_Request{
		RawConfiguration: rawPluginConfig,
	})
	require.NoError(t, err)

}
