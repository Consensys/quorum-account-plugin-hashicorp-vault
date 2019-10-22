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

func setup(t *testing.T, pluginConfig hashicorp.HashicorpAccountStoreConfig) (InitializerSignerClient, string, string, func()) {
	authVaultHandler := pathHandler{
		path: "/v1/auth/approle/login",
		handler: func(w http.ResponseWriter, r *http.Request) {
			vaultResponse := &api.Secret{Auth: &api.SecretAuth{ClientToken: "logintoken"}}
			b, _ := json.Marshal(vaultResponse)
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
			b, _ := json.Marshal(vaultResponse)
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
			b, _ := json.Marshal(vaultResponse)
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
	if _, err := addTempFile(dir, acct1JsonConfig); err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}
	if _, err := addTempFile(dir, acct2JsonConfig); err != nil {
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

	return impl, vault.URL, dir, toCloseAndDelete
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

	impl, _, dir, toClose := setup(t, pluginConfig)
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
		require.Equal(t, proto.GetEventStreamResponse_WALLET_ARRIVED, resp.WalletEvent, fmt.Sprintf("incorrect event for wallet: %v", resp.WalletUrl))
	case err := <-errChan:
		t.Fatalf("error receiving msgs from stream: %v", err)
	}

	select {
	case resp := <-respChan:
		require.Equal(t, proto.GetEventStreamResponse_WALLET_ARRIVED, resp.WalletEvent, fmt.Sprintf("incorrect event for wallet: %v", resp.WalletUrl))
	case err := <-errChan:
		t.Fatalf("error receiving msgs from stream: %v", err)
	}

	// wait some time to make sure no other events have been streamed
	select {
	case resp := <-respChan:
		t.Fatalf("should not have received any more events from plugin: %v", *resp)
	case err := <-errChan:
		t.Fatalf("should not have received any more events from plugin: error receiving msg: %v", err)
	case <-time.After(2500 * time.Millisecond):
		// no events, test successful
	}

	// add another config file and check that the corresponding event is streamed to caller
	filepath, err := addTempFile(dir, acct3JsonConfig)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-respChan:
		require.Equal(t, proto.GetEventStreamResponse_WALLET_ARRIVED, resp.WalletEvent, fmt.Sprintf("incorrect event for wallet: %v", resp.WalletUrl))
	case err := <-errChan:
		t.Fatalf("error receiving msgs from stream: %v", err)
	}
	// wait some time to make sure no other events have been streamed
	select {
	case resp := <-respChan:
		t.Fatalf("should not have received any more events from plugin: %v", *resp)
	case err := <-errChan:
		t.Fatalf("should not have received any more events from plugin: error receiving msg: %v", err)
	case <-time.After(2500 * time.Millisecond):
		// no events, test successful
	}

	// edit the file.  The old wallet should be dropped and the updated wallet added. Check that both these events are streamed to the caller.
	// (Note the order of the events received __IS__ dependent on the contents of the files.  Wallets are added or dropped in URL order so make sure that the URL of the updated wallet will be alphabetically after that of the original wallet.)
	if err := ioutil.WriteFile(filepath, acct4JsonConfig, 0644); err != nil {
		t.Fatalf("unable to update file %v: %v", filepath, err)
	}
	select {
	case resp := <-respChan:
		require.Equal(t, proto.GetEventStreamResponse_WALLET_DROPPED, resp.WalletEvent, fmt.Sprintf("incorrect event for wallet: %v", resp.WalletUrl))
	case err := <-errChan:
		t.Fatalf("error receiving msgs from stream: %v", err)
	}
	select {
	case resp := <-respChan:
		require.Equal(t, proto.GetEventStreamResponse_WALLET_ARRIVED, resp.WalletEvent, fmt.Sprintf("incorrect event for wallet: %v", resp.WalletUrl))
	case err := <-errChan:
		t.Fatalf("error receiving msgs from stream: %v", err)
	}
	// wait some time to make sure no other events have been streamed
	select {
	case resp := <-respChan:
		t.Fatalf("should not have received any more events from plugin: %v", *resp)
	case err := <-errChan:
		t.Fatalf("should not have received any more events from plugin: error receiving msg: %v", err)
	case <-time.After(2500 * time.Millisecond):
		// no events, test successful
	}

	// delete the file and check that a dropped event is streamed to the caller
	if err := os.Remove(filepath); err != nil {
		t.Fatalf("unable to remove file %v: %v", filepath, err)
	}
	select {
	case resp := <-respChan:
		require.Equal(t, proto.GetEventStreamResponse_WALLET_DROPPED, resp.WalletEvent, fmt.Sprintf("incorrect event for wallet: %v", resp.WalletUrl))
	case err := <-errChan:
		t.Fatalf("error receiving msgs from stream: %v", err)
	}
	// wait some time to make sure no other events have been streamed
	select {
	case resp := <-respChan:
		t.Fatalf("should not have received any more events from plugin: %v", *resp)
	case err := <-errChan:
		t.Fatalf("should not have received any more events from plugin: error receiving msg: %v", err)
	case <-time.After(2500 * time.Millisecond):
		// no events, test successful
	}
}

func Test_UnlockAccountsAtStartup(t *testing.T) {
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
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           unlockOnStartup,
			Auth: []hashicorp.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	require.Equal(t, "Unlocked", statusDelegate(t, &impl, vaultUrl, acct1JsonConfig), "account should be unlocked")

	require.Equal(t, "Unlocked", statusDelegate(t, &impl, vaultUrl, acct2JsonConfig), "account should be unlocked")
}

func Test_UnlockOneAccountAtStartup(t *testing.T) {
	defer setEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultSecretIDEnv),
	)()

	// comma-separated list of hex addresses to be unlocked at startup
	unlockOnStartup := ", 	bad , 4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"

	pluginConfig := hashicorp.HashicorpAccountStoreConfig{
		Vaults: []hashicorp.VaultConfig{{
			Addr: "", // this will be populated once the mock vault server is started
			TLS: hashicorp.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           unlockOnStartup,
			Auth: []hashicorp.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	require.Equal(t, "Locked", statusDelegate(t, &impl, vaultUrl, acct1JsonConfig), "account should be locked")

	require.Equal(t, "Unlocked", statusDelegate(t, &impl, vaultUrl, acct2JsonConfig), "account should be unlocked")
}

func Test_UnlockNoAccountsAtStartup(t *testing.T) {
	defer setEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultSecretIDEnv),
	)()

	// comma-separated list of hex addresses to be unlocked at startup
	unlockOnStartup := ""

	pluginConfig := hashicorp.HashicorpAccountStoreConfig{
		Vaults: []hashicorp.VaultConfig{{
			Addr: "", // this will be populated once the mock vault server is started
			TLS: hashicorp.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           unlockOnStartup,
			Auth: []hashicorp.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	require.Equal(t, "Locked", statusDelegate(t, &impl, vaultUrl, acct1JsonConfig), "account should be locked")

	require.Equal(t, "Locked", statusDelegate(t, &impl, vaultUrl, acct2JsonConfig), "account should be locked")
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
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []hashicorp.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	require.True(t, containsDelegate(t, &impl, vaultUrl, acct1JsonConfig))
	require.True(t, containsDelegate(t, &impl, vaultUrl, acct2JsonConfig))
}

func Test_Accounts(t *testing.T) {
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

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	accts := accountsDelegate(t, &impl, vaultUrl, acct1JsonConfig)
	require.Len(t, accts, 1)
	require.Equal(t, common.Bytes2Hex(accts[0].Address), "dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
}

func statusDelegate(t *testing.T, client *InitializerSignerClient, vaultUrl string, acctJsonConfig []byte) string {
	acctConfig := new(hashicorp.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(hashicorp.WalletScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	resp, err := client.Status(context.Background(), &proto.StatusRequest{
		WalletUrl: url.String(),
	})
	require.NoError(t, err)

	return resp.Status
}

func containsDelegate(t *testing.T, client *InitializerSignerClient, vaultUrl string, acctJsonConfig []byte) bool {
	acctConfig := new(hashicorp.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(hashicorp.WalletScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	resp, err := client.Contains(context.Background(), &proto.ContainsRequest{
		WalletUrl: url.String(),
		Account: &proto.Account{
			Address: common.HexToAddress(acctConfig.Address).Bytes(),
			Url:     "", // the account can be found with or without providing the account url
		},
	})
	require.NoError(t, err)

	return resp.IsContained
}

func accountsDelegate(t *testing.T, client *InitializerSignerClient, vaultUrl string, acctJsonConfig []byte) []*proto.Account {
	acctConfig := new(hashicorp.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(hashicorp.WalletScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	resp, err := client.Accounts(context.Background(), &proto.AccountsRequest{
		WalletUrl: url.String(),
	})
	require.NoError(t, err)

	return resp.Accounts
}
