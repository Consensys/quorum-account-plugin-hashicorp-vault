package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	iproto "github.com/goquorum/quorum-plugin-definitions/initializer/go/proto"
	"github.com/goquorum/quorum-plugin-definitions/signer/go/proto"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/hashicorp"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T, pluginConfig hashicorp.HashicorpAccountStoreConfig) (InitializerSignerClient, string, func()) {
	authVaultHandler := pathHandler{
		path: "/v1/auth/approle/login",
		handler: func(w http.ResponseWriter, r *http.Request) {
			vaultResponse := &api.Secret{Auth: &api.SecretAuth{ClientToken: "logintoken"}}
			b, err := json.Marshal(vaultResponse)
			require.NoError(t, err)
			_, _ = w.Write(b)
		},
	}

	acct1VaultHandler := pathHandler{
		path: "/v1/kv/data/kvacct",
		handler: func(w http.ResponseWriter, r *http.Request) {
			vaultResponse := &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"dc99ddec13457de6c0f6bb8e6cf3955c86f55526": "7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28",
					},
				},
			}
			b, err := json.Marshal(vaultResponse)
			require.NoError(t, err)
			_, _ = w.Write(b)
		},
	}

	acct2VaultHandler := pathHandler{
		path: "/v1/engine/data/engineacct",
		handler: func(w http.ResponseWriter, r *http.Request) {
			vaultResponse := &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"4d6d744b6da435b5bbdde2526dc20e9a41cb72e5": "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec",
					},
				},
			}
			b, err := json.Marshal(vaultResponse)
			require.NoError(t, err)
			_, _ = w.Write(b)
		},
	}

	vaultHandlers := []pathHandler{
		authVaultHandler,
		acct1VaultHandler,
		acct2VaultHandler,
	}
	vault := setupMockTLSVaultServer(t, vaultHandlers...)

	client, server := plugin.TestPluginGRPCConn(t, map[string]plugin.Plugin{
		"signer": new(testableSignerPluginImpl),
	})

	toClose := func() {
		client.Close()
		server.Stop()
		vault.Close()
	}

	raw, err := client.Dispense("signer")
	if err != nil {
		toClose()
		t.Fatal(err)
	}

	impl, ok := raw.(InitializerSignerClient)
	if !ok {
		toClose()
		t.Fatalf("bad: %#v", raw)
	}

	// update provided config to use the url of the mocked vault server
	pluginConfig.Vaults[0].Addr = vault.URL
	rawPluginConfig, err := json.Marshal(pluginConfig)
	if err != nil {
		toClose()
		t.Fatal(err)
	}

	_, err = impl.Init(context.Background(), &iproto.PluginInitialization_Request{
		RawConfiguration: rawPluginConfig,
	})
	if err != nil {
		toClose()
		t.Fatal(err)
	}

	return impl, vault.URL, toClose
}

func Test_UnlocksAccountsAtStartup(t *testing.T) {
	defer setEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultSecretIDEnv),
	)()

	// comma-separated list of hex addresses to be unlocked at startup
	unlockOnStartup := "0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526, 	bad , 4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"

	pluginConfig := hashicorp.HashicorpAccountStoreConfig{
		Vaults: []hashicorp.VaultConfig{{
			Addr: "", // this will be populated once the mock vault server is started
			TLS: hashicorp.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "vault/testdata/acctconfig",
			Unlock:           unlockOnStartup,
			Auth: []hashicorp.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, toClose := setup(t, pluginConfig)
	defer toClose()

	acctConfig := readConfigFromFile(t, "dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
	status := getStatus(t, &impl, vaultUrl, "FOO", acctConfig)
	require.Equal(t, "Unlocked", status, "account should be unlocked")

	acctConfig = readConfigFromFile(t, "4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")
	status = getStatus(t, &impl, vaultUrl, "FOO", acctConfig)
	require.Equal(t, "Unlocked", status, "account should be unlocked")

	acctConfig = readConfigFromFile(t, "1c15560b23dfa9a19e9739cc866c7f1f2e5da7b7")
	status = getStatus(t, &impl, vaultUrl, "BAR", acctConfig)
	require.Equal(t, "Locked", status, "account should not have been unlocked")
}

func readConfigFromFile(t *testing.T, addr string) hashicorp.AccountConfig {
	fileBytes, err := ioutil.ReadFile(fmt.Sprintf("vault/testdata/acctconfig/%v", addr))
	require.NoError(t, err)

	var config hashicorp.AccountConfig
	err = json.Unmarshal(fileBytes, &config)
	require.NoError(t, err)

	return config
}

func getStatus(t *testing.T, client *InitializerSignerClient, vaultUrl string, authID string, acctConfig hashicorp.AccountConfig) string {
	url, err := makeWalletUrl(
		hashicorp.WalletScheme,
		authID,
		vaultUrl,
		acctConfig,
	)
	require.NoError(t, err)

	resp, err := client.Status(context.Background(), &proto.StatusRequest{
		WalletUrl: url.String(),
	})
	require.NoError(t, err)

	return resp.Status
}
