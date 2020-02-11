package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/goquorum/quorum-account-manager-plugin-sdk-go/proto"
	"github.com/goquorum/quorum-plugin-hashicorp-vault-account-manager/internal/cache"
	"github.com/goquorum/quorum-plugin-hashicorp-vault-account-manager/internal/config"
	"github.com/goquorum/quorum-plugin-hashicorp-vault-account-manager/internal/manager"
	"github.com/goquorum/quorum-plugin-hashicorp-vault-account-manager/internal/test/utils"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

// global variables for use in account creation tests
var (
	createdAddr, createdKey string
	authToken               = "authToken"
)

func setup(t *testing.T, pluginConfig config.PluginAccountManagerConfig) (InitializerAccountManagerClient, string, string, func()) {

	authVaultHandler := utils.PathHandler{
		Path: "/v1/auth/approle/login",
		Handler: func(w http.ResponseWriter, r *http.Request) {
			vaultResponse := &api.Secret{Auth: &api.SecretAuth{ClientToken: authToken}}
			b, _ := json.Marshal(vaultResponse)
			_, _ = w.Write(b)
		},
	}

	acct1VaultHandler := utils.PathHandler{
		Path: "/v1/kv/data/kvacct",
		Handler: func(w http.ResponseWriter, r *http.Request) {
			err := utils.RequireRequestIsAuthenticated(r, authToken)
			require.NoError(t, err)
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

	acct2VaultHandler := utils.PathHandler{
		Path: "/v1/engine/data/engineacct",
		Handler: func(w http.ResponseWriter, r *http.Request) {
			err := utils.RequireRequestIsAuthenticated(r, authToken)
			require.NoError(t, err)
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

	acctCreationVaultHandler := utils.PathHandler{
		Path: "/v1/newengine/data/newpath",
		Handler: func(w http.ResponseWriter, r *http.Request) {
			err := utils.RequireRequestIsAuthenticated(r, authToken)
			require.NoError(t, err)
			switch r.Method {
			case http.MethodPut: // account creation

				bReq, err := ioutil.ReadAll(r.Body)
				require.NoError(t, err)
				body := make(map[string]interface{})
				err = json.Unmarshal(bReq, &body)
				require.NoError(t, err)
				require.NotZero(t, body)

				// if CAS value has been provided then client is using CAS protection.  Only accept the request if the CAS value they have provided equals 10.
				if options, ok := body["options"]; ok {
					opts := options.(map[string]interface{})
					if cas, ok := opts["cas"]; ok && cas != float64(10) {
						//return a 400 for simplicity
						http.Error(w, "invalid CAS value", http.StatusBadRequest)
						return
					}
				}

				// extract the acct data from the PUT request so that it can be returned to the caller if they GET the same path
				require.Contains(t, body, "data")
				data, _ := body["data"]
				d := data.(map[string]interface{})
				require.Len(t, d, 1)
				for addr, key := range d {
					createdAddr = addr
					createdKey = key.(string)
				}

				// create the response which contains the version of the created secret
				vaultResponse := &api.Secret{
					Data: map[string]interface{}{
						"version": 11,
					},
				}
				bResp, _ := json.Marshal(vaultResponse)
				_, _ = w.Write(bResp)

			default: // account retrieval
				vaultResponse := &api.Secret{
					Data: map[string]interface{}{
						"data": map[string]interface{}{
							createdAddr: createdKey,
						},
					},
				}
				b, _ := json.Marshal(vaultResponse)
				_, _ = w.Write(b)
			}
		},
	}

	vaultHandlers := []utils.PathHandler{
		authVaultHandler,
		acct1VaultHandler,
		acct2VaultHandler,
		acctCreationVaultHandler,
	}
	vault, err := utils.SetupMockTLSVaultServer(caCert, serverCert, serverKey, vaultHandlers...)
	require.NoError(t, err, "unable to set up mock Vault")

	client, server := plugin.TestPluginGRPCConn(t, map[string]plugin.Plugin{
		"HashicorpVaultAccountManagerDelegate": new(testableAccountManagerPluginImpl),
	})

	toClose := func() {
		client.Close()
		server.Stop()
		vault.Close()
	}

	raw, err := client.Dispense("HashicorpVaultAccountManagerDelegate")
	if err != nil {
		toClose()
		t.Fatal(err)
	}

	impl, ok := raw.(InitializerAccountManagerClient)
	if !ok {
		toClose()
		t.Fatalf("bad: %#v", raw)
	}

	// create temporary acctconfigdir
	dir, err := ioutil.TempDir("test/data", "acctconfig")
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
	if _, err := utils.AddTempFile(dir, utils.Acct1JsonConfig); err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}
	if _, err := utils.AddTempFile(dir, utils.Acct2JsonConfig); err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}

	// update provided config to use the url of the mocked vault server and the temp acctconfigdir
	pluginConfig.Vaults[0].URL = vault.URL
	pluginConfig.Vaults[0].AccountConfigDir = dir
	rawPluginConfig, err := json.Marshal(pluginConfig)
	if err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}

	_, err = impl.Init(context.Background(), &proto.PluginInitialization_Request{
		RawConfiguration: rawPluginConfig,
	})
	if err != nil {
		toCloseAndDelete()
		t.Fatal(err)
	}

	return impl, vault.URL, dir, toCloseAndDelete
}

func Test_GetEventStream_InformsCallerOfAddedRemovedOrEditedWallets(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
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
	filepath, err := utils.AddTempFile(dir, utils.Acct3JsonConfig)
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
	if err := ioutil.WriteFile(filepath, utils.Acct4JsonConfig, 0644); err != nil {
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
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	// comma-separated list of hex addresses to be unlocked at startup
	unlockOnStartup := "0xdc99ddec13457de6c0f6bb8e6cf3955c86f55526, 	bad , 4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           unlockOnStartup,
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	var (
		status string
		err    error
	)

	status, err = statusDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig)
	require.NoError(t, err)
	require.Equal(t, "Unlocked", status, "account should be unlocked")

	status, err = statusDelegate(t, &impl, vaultUrl, utils.Acct2JsonConfig)
	require.NoError(t, err)
	require.Equal(t, "Unlocked", status, "account should be unlocked")
}

func Test_UnlockOneAccountAtStartup(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	// comma-separated list of hex addresses to be unlocked at startup
	unlockOnStartup := ", 	bad , 4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           unlockOnStartup,
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	var (
		status string
		err    error
	)

	status, err = statusDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig)
	require.NoError(t, err)
	require.Equal(t, "Locked", status, "account should be locked")

	status, err = statusDelegate(t, &impl, vaultUrl, utils.Acct2JsonConfig)
	require.NoError(t, err)
	require.Equal(t, "Unlocked", status, "account should be unlocked")
}

func Test_UnlockNoAccountsAtStartup(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	// comma-separated list of hex addresses to be unlocked at startup
	unlockOnStartup := ""

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           unlockOnStartup,
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	var (
		status string
		err    error
	)

	status, err = statusDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig)
	require.NoError(t, err)
	require.Equal(t, "Locked", status, "account should be locked")

	status, err = statusDelegate(t, &impl, vaultUrl, utils.Acct2JsonConfig)
	require.NoError(t, err)
	require.Equal(t, "Locked", status, "account should be locked")
}

func Test_Contains(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	require.True(t, containsDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig))
	require.True(t, containsDelegate(t, &impl, vaultUrl, utils.Acct2JsonConfig))
}

func Test_Accounts(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	accts := accountsDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig)
	require.Len(t, accts, 1)
	require.Equal(t, common.Bytes2Hex(accts[0].Address), "dc99ddec13457de6c0f6bb8e6cf3955c86f55526")
}

func Test_SignHashAndUnlocking(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	toSign := crypto.Keccak256([]byte("to sign"))
	signingKey, err := crypto.HexToECDSA("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28")
	require.NoError(t, err)

	var (
		want []byte
		got  *proto.SignHashResponse
	)

	want, err = crypto.Sign(toSign, signingKey)
	require.NoError(t, err)

	// manually lock the account
	err = lockDelegate(&impl, utils.Acct1JsonConfig)
	require.NoError(t, err)

	// signHash fails as acct locked
	_, err = signHashDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), manager.ErrLocked.Error())

	// signHashWithPassphrase succeeds as it unlocks the acct
	got, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign, false)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// signHash fails as signHashWithPassphrase only unlocks the acct for the duration of the call
	_, err = signHashDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), manager.ErrLocked.Error())

	// unlock the account for a short period
	err = timedUnlockDelegate(&impl, vaultUrl, utils.Acct1JsonConfig, 100*time.Millisecond, false)
	require.NoError(t, err)

	// signHash succeeds as acct unlocked
	got, err = signHashDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// signHashWithPassphrase succeeds when acct is already unlocked
	got, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign, false)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// wait for the unlock to expire
	time.Sleep(250 * time.Millisecond)

	// signHash fails after unlock expires
	_, err = signHashDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), manager.ErrLocked.Error())

	// signHashWithPassphrase succeeds after acct is re-locked
	got, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign, false)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// unlock the account for a long period
	err = timedUnlockDelegate(&impl, vaultUrl, utils.Acct1JsonConfig, 100*time.Second, false)
	require.NoError(t, err)

	// override the unlock to be for a shorter duration
	err = timedUnlockDelegate(&impl, vaultUrl, utils.Acct1JsonConfig, 100*time.Millisecond, false)
	require.NoError(t, err)

	// signHash succeeds as acct unlocked
	got, err = signHashDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// wait for the unlock to expire
	time.Sleep(250 * time.Millisecond)

	// signHash fails after unlock expires
	_, err = signHashDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), manager.ErrLocked.Error())

	// unlock the account for a short period
	err = timedUnlockDelegate(&impl, vaultUrl, utils.Acct1JsonConfig, 100*time.Millisecond, false)
	require.NoError(t, err)

	// override the unlock to be indefinite
	err = timedUnlockDelegate(&impl, vaultUrl, utils.Acct1JsonConfig, 0, false)
	require.NoError(t, err)

	// signHash succeeds as acct unlocked
	got, err = signHashDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// wait to check that the unlock doesn't expire
	time.Sleep(250 * time.Millisecond)

	// signHash succeeds as acct unlocked
	got, err = signHashDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// manually lock the account
	err = lockDelegate(&impl, utils.Acct1JsonConfig)
	require.NoError(t, err)

	// signHash fails after manual lock
	_, err = signHashDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), manager.ErrLocked.Error())
}

func Test_SignTxAndUnlocking_PrivateTransactions(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})

	signingKey, err := crypto.HexToECDSA("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28")
	require.NoError(t, err)

	signer := types.QuorumPrivateTxSigner{}
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], signingKey)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.  When the caller decodes it back to a tx, the size field of the tx will be populated (see types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	// mark the tx as private so the plugin account manager knows to sign with the QuorumPrivateTxSigner
	toSign.SetPrivate()

	chainID := big.NewInt(42)
	signTxAndUnlockingTestCases(t, &impl, vaultUrl, chainID, toSign, want)
}

func Test_SignTxAndUnlocking_PublicTransactions_EIP155(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})

	signingKey, err := crypto.HexToECDSA("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28")
	require.NoError(t, err)

	chainID := big.NewInt(42)
	signer := types.NewEIP155Signer(chainID)
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], signingKey)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.  When the caller decodes it back to a tx, the size field of the tx will be populated (see types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	signTxAndUnlockingTestCases(t, &impl, vaultUrl, chainID, toSign, want)
}

func Test_SignTxAndUnlocking_PublicTransactions_Homestead(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})

	signingKey, err := crypto.HexToECDSA("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28")
	require.NoError(t, err)

	signer := types.HomesteadSigner{}
	txSignerHash := signer.Hash(toSign)
	txSignerSignature, err := crypto.Sign(txSignerHash[:], signingKey)
	require.NoError(t, err)

	want, err := toSign.WithSignature(signer, txSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.  When the caller decodes it back to a tx, the size field of the tx will be populated (see types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	var chainID *big.Int
	signTxAndUnlockingTestCases(t, &impl, vaultUrl, chainID, toSign, want)
}

func signTxAndUnlockingTestCases(t *testing.T, impl *InitializerAccountManagerClient, vaultUrl string, chainID *big.Int, toSign *types.Transaction, want *types.Transaction) {
	var (
		got *types.Transaction
		err error
	)

	// manually lock the account
	err = lockDelegate(impl, utils.Acct1JsonConfig)
	require.NoError(t, err)

	// signTx fails as acct locked
	_, err = signTxDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID)
	require.Error(t, err)
	require.Contains(t, err.Error(), manager.ErrLocked.Error())

	// signTxWithPassphrase succeeds as it unlocks the acct
	got, err = signTxWithPassphraseDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID, false)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// signTx fails as signTxWithPassphrase only unlocks the acct for the duration of the call
	_, err = signTxDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID)
	require.Error(t, err)
	require.Contains(t, err.Error(), manager.ErrLocked.Error())

	// unlock the account for a short period
	err = timedUnlockDelegate(impl, vaultUrl, utils.Acct1JsonConfig, 100*time.Millisecond, false)
	require.NoError(t, err)

	// signTx succeeds as acct unlocked
	got, err = signTxDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// signTxWithPassphrase succeeds when acct is already unlocked
	got, err = signTxWithPassphraseDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID, false)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// wait for the unlock to expire
	time.Sleep(250 * time.Millisecond)

	// signTx fails after unlock expires
	_, err = signTxDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID)
	require.Error(t, err)
	require.Contains(t, err.Error(), manager.ErrLocked.Error())

	// signTxWithPassphrase succeeds after acct is re-locked
	got, err = signTxWithPassphraseDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID, false)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// unlock the account for a long period
	err = timedUnlockDelegate(impl, vaultUrl, utils.Acct1JsonConfig, 100*time.Second, false)
	require.NoError(t, err)

	// override the unlock to be for a shorter duration
	err = timedUnlockDelegate(impl, vaultUrl, utils.Acct1JsonConfig, 100*time.Millisecond, false)
	require.NoError(t, err)

	// signTx succeeds as acct unlocked
	got, err = signTxDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// wait for the unlock to expire
	time.Sleep(250 * time.Millisecond)

	// signTx fails after unlock expires
	_, err = signTxDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID)
	require.Error(t, err)
	require.Contains(t, err.Error(), manager.ErrLocked.Error())

	// unlock the account for a short period
	err = timedUnlockDelegate(impl, vaultUrl, utils.Acct1JsonConfig, 100*time.Millisecond, false)
	require.NoError(t, err)

	// override the unlock to be indefinite
	err = timedUnlockDelegate(impl, vaultUrl, utils.Acct1JsonConfig, 0, false)
	require.NoError(t, err)

	// signTx succeeds as acct unlocked
	got, err = signTxDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// wait to check that the unlock doesn't expire
	time.Sleep(250 * time.Millisecond)

	// signTx succeeds as acct unlocked
	got, err = signTxDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// manually lock the account
	err = lockDelegate(impl, utils.Acct1JsonConfig)
	require.NoError(t, err)

	// signTx fails after manual lock
	_, err = signTxDelegate(t, impl, vaultUrl, utils.Acct1JsonConfig, toSign, chainID)
	require.Error(t, err)
	require.Contains(t, err.Error(), manager.ErrLocked.Error())
}

func Test_UnknownAccount(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	// status fails
	_, err := statusDelegate(t, &impl, vaultUrl, utils.Acct4JsonConfig)
	require.Error(t, err)
	require.Contains(t, err.Error(), accounts.ErrUnknownWallet.Error())

	// unlock fails
	err = timedUnlockDelegate(&impl, vaultUrl, utils.Acct4JsonConfig, 0, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), accounts.ErrUnknownWallet.Error())

	// lock fails
	err = lockDelegate(&impl, utils.Acct4JsonConfig)
	require.Error(t, err)
	require.Contains(t, err.Error(), accounts.ErrUnknownWallet.Error())

	// signHashWithPassphrase fails
	toSign := crypto.Keccak256([]byte("to sign"))
	_, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, utils.Acct4JsonConfig, toSign, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), accounts.ErrUnknownWallet.Error())

	// signTxWithPassphrase fails
	toSignTx := new(types.Transaction)
	_, err = signTxWithPassphraseDelegate(t, &impl, vaultUrl, utils.Acct4JsonConfig, toSignTx, nil, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), accounts.ErrUnknownWallet.Error())
}

func Test_AmbiguousAccount(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, dir, toClose := setup(t, pluginConfig)
	defer toClose()

	var err error

	// add another accountconfigfile that has the same address but different path params to give a different account/wallet url.  This will result in the plugin account manager having the same address loaded from two different locations
	_, err = utils.AddTempFile(dir, utils.Acct1JsonConfigDiffPathParams)
	require.NoError(t, err)

	// wait to give the account manager time to recognise the filesystem change
	time.Sleep(2500 * time.Millisecond)

	// unlock
	// fails if account URL not provided
	err = timedUnlockDelegate(&impl, vaultUrl, utils.Acct1JsonConfig, 0, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), cache.AmbiguousAddrMsg)
	// succeeds if account URL provided
	err = timedUnlockDelegate(&impl, vaultUrl, utils.Acct1JsonConfig, 0, true)
	require.NoError(t, err)

	// signHashWithPassphrase
	// fails if account URL not provided
	toSign := crypto.Keccak256([]byte("to sign"))
	_, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), cache.AmbiguousAddrMsg)
	// succeeds if account URL provided
	_, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSign, true)
	require.NoError(t, err)

	// signTxWithPassphrase
	// fails if account URL not provided
	toSignTx := new(types.Transaction)
	_, err = signTxWithPassphraseDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSignTx, nil, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), cache.AmbiguousAddrMsg)
	// succeeds if account URL provided
	_, err = signTxWithPassphraseDelegate(t, &impl, vaultUrl, utils.Acct1JsonConfig, toSignTx, nil, true)
	require.NoError(t, err)
}

func Test_NewAccount_CorrectCasValue(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, dir, toClose := setup(t, pluginConfig)
	defer toClose()

	newAccountCreationConfig := NewAccountHashicorpVaultConfig{
		VaultAddr:        vaultUrl,
		AuthID:           "FOO",
		SecretEnginePath: "newengine",
		SecretPath:       "newpath",
		InsecureSkipCas:  false,
		CasValue:         10,
	}

	// make note of the number of files in the acctconfigdir before acct creation
	beforeFiles, err := ioutil.ReadDir(dir)
	require.NoError(t, err)

	// request the plugin account manager to create a new account
	createdAddr = ""
	createdKey = ""
	resp, err := newAccountDelegate(&impl, newAccountCreationConfig)
	require.NoError(t, err)

	// check that the vault location of the new acct data is correct and valid
	wantUri := fmt.Sprintf(
		"%v/v1/%v/data/%v?version=%v",
		vaultUrl,
		newAccountCreationConfig.SecretEnginePath,
		newAccountCreationConfig.SecretPath,
		11, // this is the version number returned by the mock vault handler
	)
	require.Equal(t, wantUri, resp.KeyUri)

	addr := strings.TrimSpace(common.Bytes2Hex(resp.Account.Address))
	require.True(t, common.IsHexAddress(addr))

	// check that a new acctconfig file was created
	afterFiles, err := ioutil.ReadDir(dir)
	require.NoError(t, err)
	require.Equal(t, 1, len(afterFiles)-len(beforeFiles))

	// identify the new file and read the contents so we can use our helpers
	var newFile os.FileInfo
	for _, a := range afterFiles {
		var isOld bool
		for _, b := range beforeFiles {
			if a.Name() == b.Name() {
				isOld = true
				break
			}
		}
		if !isOld {
			newFile = a
		}
	}
	require.NotNil(t, newFile, "no new file found ")
	filepath := fmt.Sprintf("%v/%v", dir, newFile.Name())

	createdAcctJsonConfig, err := ioutil.ReadFile(filepath)
	require.False(t, os.IsNotExist(err), "file does not exist")
	require.NoError(t, err)

	// check that we can sign with the new acct
	toSign := crypto.Keccak256([]byte("to sign"))

	require.NotZero(t, createdKey)
	signingKey, err := crypto.HexToECDSA(createdKey)
	require.NoError(t, err)

	var (
		want []byte
		got  *proto.SignHashResponse
	)

	want, err = crypto.Sign(toSign, signingKey)
	require.NoError(t, err)

	got, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, createdAcctJsonConfig, toSign, false)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)
}

func Test_NewAccount_IncorrectCasValue(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	newAccountCreationConfig := NewAccountHashicorpVaultConfig{
		VaultAddr:        vaultUrl,
		AuthID:           "FOO",
		SecretEnginePath: "newengine",
		SecretPath:       "newpath",
		InsecureSkipCas:  false,
		CasValue:         1,
	}

	// request the plugin account manager to create a new account
	createdAddr = ""
	createdKey = ""
	_, err := newAccountDelegate(&impl, newAccountCreationConfig)
	require.Error(t, err)
}

func Test_NewAccount_SkipCasCheck(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, dir, toClose := setup(t, pluginConfig)
	defer toClose()

	newAccountCreationConfig := NewAccountHashicorpVaultConfig{
		VaultAddr:        vaultUrl,
		AuthID:           "FOO",
		SecretEnginePath: "newengine",
		SecretPath:       "newpath",
		InsecureSkipCas:  true,
		CasValue:         1,
	}

	// make note of the number of files in the acctconfigdir before acct creation
	beforeFiles, err := ioutil.ReadDir(dir)
	require.NoError(t, err)

	// request the plugin account manager to create a new account
	createdAddr = ""
	createdKey = ""
	resp, err := newAccountDelegate(&impl, newAccountCreationConfig)
	require.NoError(t, err)

	// check that the vault location of the new acct data is correct and valid
	wantUri := fmt.Sprintf(
		"%v/v1/%v/data/%v?version=%v",
		vaultUrl,
		newAccountCreationConfig.SecretEnginePath,
		newAccountCreationConfig.SecretPath,
		11, // this is the version number returned by the mock vault handler
	)
	require.Equal(t, wantUri, resp.KeyUri)

	addr := strings.TrimSpace(common.Bytes2Hex(resp.Account.Address))
	require.True(t, common.IsHexAddress(addr))

	// check that a new acctconfig file was created
	afterFiles, err := ioutil.ReadDir(dir)
	require.NoError(t, err)
	require.Equal(t, 1, len(afterFiles)-len(beforeFiles))

	// identify the new file and read the contents so we can use our helpers
	var newFile os.FileInfo
	for _, a := range afterFiles {
		var isOld bool
		for _, b := range beforeFiles {
			if a.Name() == b.Name() {
				isOld = true
				break
			}
		}
		if !isOld {
			newFile = a
		}
	}
	require.NotNil(t, newFile, "no new file found ")
	filepath := fmt.Sprintf("%v/%v", dir, newFile.Name())

	createdAcctJsonConfig, err := ioutil.ReadFile(filepath)
	require.False(t, os.IsNotExist(err), "file does not exist")
	require.NoError(t, err)

	// check that we can sign with the new acct
	toSign := crypto.Keccak256([]byte("to sign"))

	require.NotZero(t, createdKey)
	signingKey, err := crypto.HexToECDSA(createdKey)
	require.NoError(t, err)

	var (
		want []byte
		got  *proto.SignHashResponse
	)

	want, err = crypto.Sign(toSign, signingKey)
	require.NoError(t, err)

	got, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, createdAcctJsonConfig, toSign, false)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)
}

func Test_ImportRawKey_CorrectCasValue(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, dir, toClose := setup(t, pluginConfig)
	defer toClose()

	newAccountCreationConfig := NewAccountHashicorpVaultConfig{
		VaultAddr:        vaultUrl,
		AuthID:           "FOO",
		SecretEnginePath: "newengine",
		SecretPath:       "newpath",
		InsecureSkipCas:  false,
		CasValue:         10,
	}

	// make note of the number of files in the acctconfigdir before acct creation
	beforeFiles, err := ioutil.ReadDir(dir)
	require.NoError(t, err)

	// request the plugin account manager to create a new account
	createdAddr = ""
	createdKey = ""
	rawKey := "fb395a831f64105628206467a9e827ca13767abef9705d782295a62a118bbc41"
	resp, err := importRawKeyDelegate(&impl, newAccountCreationConfig, rawKey)
	require.NoError(t, err)

	// check that the vault location of the new acct data is correct and valid
	wantUri := fmt.Sprintf(
		"%v/v1/%v/data/%v?version=%v",
		vaultUrl,
		newAccountCreationConfig.SecretEnginePath,
		newAccountCreationConfig.SecretPath,
		11, // this is the version number returned by the mock vault handler
	)
	require.Equal(t, wantUri, resp.KeyUri)

	addr := strings.TrimSpace(common.Bytes2Hex(resp.Account.Address))
	require.True(t, common.IsHexAddress(addr))

	// check that a new acctconfig file was created
	afterFiles, err := ioutil.ReadDir(dir)
	require.NoError(t, err)
	require.Equal(t, 1, len(afterFiles)-len(beforeFiles))

	// identify the new file and read the contents so we can use our helpers
	var newFile os.FileInfo
	for _, a := range afterFiles {
		var isOld bool
		for _, b := range beforeFiles {
			if a.Name() == b.Name() {
				isOld = true
				break
			}
		}
		if !isOld {
			newFile = a
		}
	}
	require.NotNil(t, newFile, "no new file found ")
	filepath := fmt.Sprintf("%v/%v", dir, newFile.Name())

	createdAcctJsonConfig, err := ioutil.ReadFile(filepath)
	require.False(t, os.IsNotExist(err), "file does not exist")
	require.NoError(t, err)

	// check that we can sign with the new acct
	toSign := crypto.Keccak256([]byte("to sign"))

	require.Equal(t, rawKey, createdKey)
	signingKey, err := crypto.HexToECDSA(rawKey)
	require.NoError(t, err)

	var (
		want []byte
		got  *proto.SignHashResponse
	)

	want, err = crypto.Sign(toSign, signingKey)
	require.NoError(t, err)

	got, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, createdAcctJsonConfig, toSign, false)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)
}

func Test_ImportRawKey_IncorrectCasValue(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, _, toClose := setup(t, pluginConfig)
	defer toClose()

	newAccountCreationConfig := NewAccountHashicorpVaultConfig{
		VaultAddr:        vaultUrl,
		AuthID:           "FOO",
		SecretEnginePath: "newengine",
		SecretPath:       "newpath",
		InsecureSkipCas:  false,
		CasValue:         1,
	}

	// request the plugin account manager to create a new account
	createdAddr = ""
	createdKey = ""
	rawKey := "fb395a831f64105628206467a9e827ca13767abef9705d782295a62a118bbc41"
	_, err := importRawKeyDelegate(&impl, newAccountCreationConfig, rawKey)
	require.Error(t, err)
}

func Test_ImportRawKey_SkipCasCheck(t *testing.T) {
	defer utils.SetEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", manager.DefaultSecretIDEnv),
	)()

	pluginConfig := config.PluginAccountManagerConfig{
		Vaults: []config.VaultConfig{{
			URL: "", // this will be populated once the mock vault server is started
			TLS: config.TLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
			AccountConfigDir: "", // this will be populated once the mock vault server is started
			Unlock:           "",
			Auth: []config.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "", // defaults to approle
			}},
		}},
	}

	impl, vaultUrl, dir, toClose := setup(t, pluginConfig)
	defer toClose()

	newAccountCreationConfig := NewAccountHashicorpVaultConfig{
		VaultAddr:        vaultUrl,
		AuthID:           "FOO",
		SecretEnginePath: "newengine",
		SecretPath:       "newpath",
		InsecureSkipCas:  true,
		CasValue:         1,
	}

	// make note of the number of files in the acctconfigdir before acct creation
	beforeFiles, err := ioutil.ReadDir(dir)
	require.NoError(t, err)

	// request the plugin account manager to create a new account
	createdAddr = ""
	createdKey = ""
	rawKey := "fb395a831f64105628206467a9e827ca13767abef9705d782295a62a118bbc41"
	resp, err := importRawKeyDelegate(&impl, newAccountCreationConfig, rawKey)
	require.NoError(t, err)

	// check that the vault location of the new acct data is correct and valid
	wantUri := fmt.Sprintf(
		"%v/v1/%v/data/%v?version=%v",
		vaultUrl,
		newAccountCreationConfig.SecretEnginePath,
		newAccountCreationConfig.SecretPath,
		11, // this is the version number returned by the mock vault handler
	)
	require.Equal(t, wantUri, resp.KeyUri)

	addr := strings.TrimSpace(common.Bytes2Hex(resp.Account.Address))
	require.True(t, common.IsHexAddress(addr))

	// check that a new acctconfig file was created
	afterFiles, err := ioutil.ReadDir(dir)
	require.NoError(t, err)
	require.Equal(t, 1, len(afterFiles)-len(beforeFiles))

	// identify the new file and read the contents so we can use our helpers
	var newFile os.FileInfo
	for _, a := range afterFiles {
		var isOld bool
		for _, b := range beforeFiles {
			if a.Name() == b.Name() {
				isOld = true
				break
			}
		}
		if !isOld {
			newFile = a
		}
	}
	require.NotNil(t, newFile, "no new file found ")
	filepath := fmt.Sprintf("%v/%v", dir, newFile.Name())

	createdAcctJsonConfig, err := ioutil.ReadFile(filepath)
	require.False(t, os.IsNotExist(err), "file does not exist")
	require.NoError(t, err)

	// check that we can sign with the new acct
	toSign := crypto.Keccak256([]byte("to sign"))

	require.Equal(t, rawKey, createdKey)
	signingKey, err := crypto.HexToECDSA(rawKey)
	require.NoError(t, err)

	var (
		want []byte
		got  *proto.SignHashResponse
	)

	want, err = crypto.Sign(toSign, signingKey)
	require.NoError(t, err)

	got, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, createdAcctJsonConfig, toSign, false)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)
}

func statusDelegate(t *testing.T, client *InitializerAccountManagerClient, vaultUrl string, acctJsonConfig []byte) (string, error) {
	acctConfig := new(config.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(config.HashiScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	resp, err := client.Status(context.Background(), &proto.StatusRequest{
		WalletUrl: url.String(),
	})
	if err != nil {
		return "", err
	}

	return resp.Status, nil
}

func containsDelegate(t *testing.T, client *InitializerAccountManagerClient, vaultUrl string, acctJsonConfig []byte) bool {
	acctConfig := new(config.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(config.HashiScheme, vaultUrl, *acctConfig)
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

func accountsDelegate(t *testing.T, client *InitializerAccountManagerClient, vaultUrl string, acctJsonConfig []byte) []*proto.Account {
	acctConfig := new(config.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(config.HashiScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	resp, err := client.Accounts(context.Background(), &proto.AccountsRequest{
		WalletUrl: url.String(),
	})
	require.NoError(t, err)

	return resp.Accounts
}

func signHashDelegate(t *testing.T, client *InitializerAccountManagerClient, vaultUrl string, acctJsonConfig []byte, toSign []byte) (*proto.SignHashResponse, error) {
	acctConfig := new(config.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(config.HashiScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	acctAddr := common.HexToAddress(acctConfig.Address)

	return client.SignHash(context.Background(), &proto.SignHashRequest{
		WalletUrl: url.String(),
		Account: &proto.Account{
			Address: acctAddr.Bytes(),
			Url:     "",
		},
		Hash: toSign,
	})
}

func signHashWithPassphraseDelegate(t *testing.T, client *InitializerAccountManagerClient, vaultUrl string, acctJsonConfig []byte, toSign []byte, sendAcctUrl bool) (*proto.SignHashResponse, error) {
	acctConfig := new(config.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(config.HashiScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	acctAddr := common.HexToAddress(acctConfig.Address)

	var acctUrl string
	if sendAcctUrl {
		url, err := makeWalletUrl(config.HashiScheme, vaultUrl, *acctConfig)
		if err != nil {
			return nil, err
		}
		acctUrl = url.String()
	}

	return client.SignHashWithPassphrase(context.Background(), &proto.SignHashWithPassphraseRequest{
		WalletUrl: url.String(),
		Account: &proto.Account{
			Address: acctAddr.Bytes(),
			Url:     acctUrl,
		},
		Hash:       toSign,
		Passphrase: "pwd", // this value is arbitary as the hashicorp acct manager does not use the password for anything
	})
}

func signTxDelegate(t *testing.T, client *InitializerAccountManagerClient, vaultUrl string, acctJsonConfig []byte, toSign *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	acctConfig := new(config.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(config.HashiScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	acctAddr := common.HexToAddress(acctConfig.Address)

	rlpTx, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	var chainIDBytes []byte
	if chainID != nil {
		chainIDBytes = chainID.Bytes()
	}

	resp, err := client.SignTx(context.Background(), &proto.SignTxRequest{
		WalletUrl: url.String(),
		Account: &proto.Account{
			Address: acctAddr.Bytes(),
			Url:     "",
		},
		RlpTx:   rlpTx,
		ChainID: chainIDBytes,
	})

	if err != nil {
		return nil, err
	}

	// decode the signed tx in the response
	signedTx := new(types.Transaction)
	if err = rlp.DecodeBytes(resp.RlpTx, signedTx); err != nil {
		return nil, err
	}
	return signedTx, nil
}

func signTxWithPassphraseDelegate(t *testing.T, client *InitializerAccountManagerClient, vaultUrl string, acctJsonConfig []byte, toSign *types.Transaction, chainID *big.Int, sendAcctUrl bool) (*types.Transaction, error) {
	acctConfig := new(config.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(config.HashiScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	acctAddr := common.HexToAddress(acctConfig.Address)

	rlpTx, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	var chainIDBytes []byte
	if chainID != nil {
		chainIDBytes = chainID.Bytes()
	}

	var acctUrl string
	if sendAcctUrl {
		url, err := makeWalletUrl(config.HashiScheme, vaultUrl, *acctConfig)
		if err != nil {
			return nil, err
		}
		acctUrl = url.String()
	}

	resp, err := client.SignTxWithPassphrase(context.Background(), &proto.SignTxWithPassphraseRequest{
		WalletUrl: url.String(),
		Account: &proto.Account{
			Address: acctAddr.Bytes(),
			Url:     acctUrl,
		},
		Passphrase: "pwd", // this value is arbitary as the hashicorp acct manager does not use the password for anything
		RlpTx:      rlpTx,
		ChainID:    chainIDBytes,
	})

	if err != nil {
		return nil, err
	}

	// decode the signed tx in the response
	signedTx := new(types.Transaction)
	if err = rlp.DecodeBytes(resp.RlpTx, signedTx); err != nil {
		return nil, err
	}
	return signedTx, nil
}

func timedUnlockDelegate(client *InitializerAccountManagerClient, vaultUrl string, acctJsonConfig []byte, unlockDuration time.Duration, sendAcctUrl bool) error {
	acctConfig := new(config.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	acctAddr := common.HexToAddress(acctConfig.Address)
	var acctUrl string
	if sendAcctUrl {
		url, err := makeWalletUrl(config.HashiScheme, vaultUrl, *acctConfig)
		if err != nil {
			return err
		}
		acctUrl = url.String()
	}

	_, err := client.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account: &proto.Account{
			Address: acctAddr.Bytes(),
			Url:     acctUrl,
		},
		Password: "pwd", // this value is arbitary as the hashicorp acct manager does not use the password for anything
		Duration: unlockDuration.Nanoseconds(),
	})

	return err
}

func lockDelegate(client *InitializerAccountManagerClient, acctJsonConfig []byte) error {
	acctConfig := new(config.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	acctAddr := common.HexToAddress(acctConfig.Address)

	_, err := client.Lock(context.Background(), &proto.LockRequest{
		Account: &proto.Account{
			Address: acctAddr.Bytes(),
			Url:     "",
		},
	})

	return err
}

func newAccountDelegate(client *InitializerAccountManagerClient, newAccountConfig NewAccountHashicorpVaultConfig) (*proto.NewAccountResponse, error) {
	confBytes, err := json.Marshal(newAccountConfig)
	if err != nil {
		return nil, err
	}

	return client.NewAccount(context.Background(), &proto.NewAccountRequest{
		NewAccountConfig: confBytes,
	})
}

func importRawKeyDelegate(client *InitializerAccountManagerClient, newAccountConfig NewAccountHashicorpVaultConfig, rawKey string) (*proto.ImportRawKeyResponse, error) {
	confBytes, err := json.Marshal(newAccountConfig)
	if err != nil {
		return nil, err
	}

	return client.ImportRawKey(context.Background(), &proto.ImportRawKeyRequest{
		RawKey:           rawKey,
		NewAccountConfig: confBytes,
	})
}
