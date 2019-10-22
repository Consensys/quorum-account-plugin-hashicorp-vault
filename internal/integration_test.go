package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

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

	// create temporary acctconfigdir
	dir, err := ioutil.TempDir("vault/testdata", "acctconfig")
	if err != nil {
		toClose()
		t.Fatal(err)
	}

	toCloseAndDelete := func() {
		client.Close()
		server.Stop()
		vault.Close()
		os.RemoveAll(dir)
	}

	// add 2 acctconfigs to acctconfigdir
	tmpfile, err := ioutil.TempFile(dir, "")
	if err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}
	if _, err := tmpfile.Write(acct1JsonConfig); err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}

	tmpfile2, err := ioutil.TempFile(dir, "")
	if err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}
	if _, err := tmpfile2.Write(acct2JsonConfig); err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}
	if err := tmpfile2.Close(); err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}

	// update provided config to use the url of the mocked vault server and the temp acctconfigdir
	pluginConfig.Vaults[0].Addr = vault.URL
	pluginConfig.Vaults[0].AccountConfigDir = dir
	rawPluginConfig, err := json.Marshal(pluginConfig)
	if err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}

	_, err = impl.Init(context.Background(), &iproto.PluginInitialization_Request{
		RawConfiguration: rawPluginConfig,
	})
	if err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}

	return impl, vault.URL, toCloseAndDelete
}

func Test_GetEventStream_InformsCallerOfAddedRemovedOrEditedWallets(t *testing.T) {
	defer setEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultSecretIDEnv),
	)()

	pluginConfig := hashicorp.HashicorpAccountStoreConfig{
		Vaults: []hashicorp.VaultConfig{{
			Addr: "", // this will be populated once the mock vault server is started
			TLS: hashicorp.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []hashicorp.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	req := &proto.GetEventStreamRequest{}
	stream, err := impl.GetEventStream(context.Background(), req)
	require.NoError(t, err)

	respChan := make(chan *proto.GetEventStreamResponse)
	errChan := make(chan error)

	// we start a separate goroutine to receive events from the stream.  stream.Recv() blocks until there are msgs to retrieve.
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				errChan <- err
			} else {
				respChan <- resp
			}
		}
	}()

	// setup adds 2 valid configs to the acctconfigdir so we check that 2 events have been streamed to the caller
	select {
	case resp := <-respChan:
		require.Equal(t, proto.GetEventStreamResponse_WALLET_ARRIVED, resp.WalletEvent)
	case err := <-errChan:
		t.Fatalf("error receiving msgs from stream: %v", err)
	}

	select {
	case resp := <-respChan:
		require.Equal(t, proto.GetEventStreamResponse_WALLET_ARRIVED, resp.WalletEvent)
	case err := <-errChan:
		t.Fatalf("error receiving msgs from stream: %v", err)
	}

	// wait some time to make sure no other events have been streamed
	select {
	case resp := <-respChan:
		t.Fatalf("should not have received any more events from plugin: %v", *resp)
	case err := <-errChan:
		t.Fatalf("should not have received any more events from plugin: error receiving msg: %v", err)
	case <-time.After(5 * time.Millisecond):
		// no events, test successful
	}

	// add another config file

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

func Test_Contains(t *testing.T) {
	defer setEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultSecretIDEnv),
	)()

	pluginConfig := hashicorp.HashicorpAccountStoreConfig{
		Vaults: []hashicorp.VaultConfig{{
			Addr: "", // this will be populated once the mock vault server is started
			TLS: hashicorp.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "vault/testdata/acctconfig",
			Unlock:           "",
			Auth: []hashicorp.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, toClose := setup(t, pluginConfig)
	defer toClose()

	acctConfig := readConfigFromFile(t, "dc99ddec13457de6c0f6bb8e6cf3955c86f55526")

	// account can be found providing just addr or addr and url
	require.True(t, contains(t, &impl, vaultUrl, "FOO", acctConfig, "dc99ddec13457de6c0f6bb8e6cf3955c86f55526", "hashiacct:///Users/chrishounsom/quorum-plugin-hashicorp-account-store/internal/vault/testdata/acctconfig/dc99ddec13457de6c0f6bb8e6cf3955c86f55526"))
	require.True(t, contains(t, &impl, vaultUrl, "FOO", acctConfig, "dc99ddec13457de6c0f6bb8e6cf3955c86f55526", ""))
}

// TODO(cjh) get the event stream in order to keep an up to date list of wallets instead of having to read files to get url each time.  Reading files can be a way to test the event stream itself.

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

func contains(t *testing.T, client *InitializerSignerClient, vaultUrl string, authID string, acctConfig hashicorp.AccountConfig, acctAddr string, acctUrl string) bool {
	url, err := makeWalletUrl(
		hashicorp.WalletScheme,
		authID,
		vaultUrl,
		acctConfig,
	)
	require.NoError(t, err)

	resp, err := client.Contains(context.Background(), &proto.ContainsRequest{
		WalletUrl: url.String(),
		Account: &proto.Account{
			Address: common.HexToAddress(acctAddr).Bytes(),
			Url:     acctUrl,
		},
	})
	require.NoError(t, err)

	return resp.IsContained
}
