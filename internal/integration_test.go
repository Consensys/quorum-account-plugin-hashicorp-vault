package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"io/ioutil"
	"math/big"
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

func Test_SignHash_Unlocking(t *testing.T) {
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
	lockDelegate(t, &impl, acct1JsonConfig)

	// signHash fails as acct locked
	_, err = signHashDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), hashicorp.ErrLocked.Error())

	// signHashWithPassphrase succeeds as it unlocks the acct
	got, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// signHash fails as signHashWithPassphrase only unlocks the acct for the duration of the call
	_, err = signHashDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), hashicorp.ErrLocked.Error())

	// unlock the account for a short period
	timedUnlockDelegate(t, &impl, acct1JsonConfig, 100*time.Millisecond)

	// signHash succeeds as acct unlocked
	got, err = signHashDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// signHashWithPassphrase succeeds when acct is already unlocked
	got, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// wait for the unlock to expire
	time.Sleep(250 * time.Millisecond)

	// signHash fails after unlock expires
	_, err = signHashDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), hashicorp.ErrLocked.Error())

	// signHashWithPassphrase succeeds after acct is re-locked
	got, err = signHashWithPassphraseDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// unlock the account for a long period
	timedUnlockDelegate(t, &impl, acct1JsonConfig, 100*time.Second)

	// override the unlock to be for a shorter duration
	timedUnlockDelegate(t, &impl, acct1JsonConfig, 100*time.Millisecond)

	// signHash succeeds as acct unlocked
	got, err = signHashDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// wait for the unlock to expire
	time.Sleep(250 * time.Millisecond)

	// signHash fails after unlock expires
	_, err = signHashDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), hashicorp.ErrLocked.Error())

	// unlock the account for a short period
	timedUnlockDelegate(t, &impl, acct1JsonConfig, 100*time.Millisecond)

	// override the unlock to be indefinite
	timedUnlockDelegate(t, &impl, acct1JsonConfig, 0)

	// signHash succeeds as acct unlocked
	got, err = signHashDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// wait to check that the unlock doesn't expire
	time.Sleep(250 * time.Millisecond)

	// signHash succeeds as acct unlocked
	got, err = signHashDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got.Result)

	// manually lock the account
	lockDelegate(t, &impl, acct1JsonConfig)

	// signHash fails after manual lock
	_, err = signHashDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), hashicorp.ErrLocked.Error())
}

func Test_SignTx_Unlocking(t *testing.T) {
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

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, []byte{})

	signingKey, err := crypto.HexToECDSA("7af58d8bd863ce3fce9508a57dff50a2655663a1411b6634cea6246398380b28")
	require.NoError(t, err)

	privateTxSignerHash := types.QuorumPrivateTxSigner{}.Hash(toSign)
	privateTxSignerSignature, err := crypto.Sign(privateTxSignerHash[:], signingKey)
	require.NoError(t, err)

	var (
		want *types.Transaction
		got  *types.Transaction
	)

	want, err = toSign.WithSignature(types.QuorumPrivateTxSigner{}, privateTxSignerSignature)
	require.NoError(t, err)
	// The plugin account manager will send the signed tx to the caller in rlp-encoded form.  When the caller decodes it back to a tx, the size field of the tx will be populated (see types/transaction.go: *Transaction.DecodeRLP).  We must populate that field so that we can compare the returned tx with want.  This is achieved by calling Size().
	want.Size()

	// mark the tx as private so the plugin account manager knows to sign with the QuorumPrivateTxSigner
	toSign.SetPrivate()

	// manually lock the account
	lockDelegate(t, &impl, acct1JsonConfig)

	// signTx fails as acct locked
	_, err = signTxDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), hashicorp.ErrLocked.Error())

	// signTxWithPassphrase succeeds as it unlocks the acct
	got, err = signTxWithPassphraseDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// signTx fails as signTxWithPassphrase only unlocks the acct for the duration of the call
	_, err = signTxDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), hashicorp.ErrLocked.Error())

	// unlock the account for a short period
	timedUnlockDelegate(t, &impl, acct1JsonConfig, 100*time.Millisecond)

	// signTx succeeds as acct unlocked
	got, err = signTxDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// signTxWithPassphrase succeeds when acct is already unlocked
	got, err = signTxWithPassphraseDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// wait for the unlock to expire
	time.Sleep(250 * time.Millisecond)

	// signTx fails after unlock expires
	_, err = signTxDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), hashicorp.ErrLocked.Error())

	// signTxWithPassphrase succeeds after acct is re-locked
	got, err = signTxWithPassphraseDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// unlock the account for a long period
	timedUnlockDelegate(t, &impl, acct1JsonConfig, 100*time.Second)

	// override the unlock to be for a shorter duration
	timedUnlockDelegate(t, &impl, acct1JsonConfig, 100*time.Millisecond)

	// signTx succeeds as acct unlocked
	got, err = signTxDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// wait for the unlock to expire
	time.Sleep(250 * time.Millisecond)

	// signTx fails after unlock expires
	_, err = signTxDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), hashicorp.ErrLocked.Error())

	// unlock the account for a short period
	timedUnlockDelegate(t, &impl, acct1JsonConfig, 100*time.Millisecond)

	// override the unlock to be indefinite
	timedUnlockDelegate(t, &impl, acct1JsonConfig, 0)

	// signTx succeeds as acct unlocked
	got, err = signTxDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// wait to check that the unlock doesn't expire
	time.Sleep(250 * time.Millisecond)

	// signTx succeeds as acct unlocked
	got, err = signTxDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want, got)

	// manually lock the account
	lockDelegate(t, &impl, acct1JsonConfig)

	// signTx fails after manual lock
	_, err = signTxDelegate(t, &impl, vaultUrl, acct1JsonConfig, toSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), hashicorp.ErrLocked.Error())
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

func signHashDelegate(t *testing.T, client *InitializerSignerClient, vaultUrl string, acctJsonConfig []byte, toSign []byte) (*proto.SignHashResponse, error) {
	acctConfig := new(hashicorp.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(hashicorp.WalletScheme, vaultUrl, *acctConfig)
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

func signHashWithPassphraseDelegate(t *testing.T, client *InitializerSignerClient, vaultUrl string, acctJsonConfig []byte, toSign []byte) (*proto.SignHashResponse, error) {
	acctConfig := new(hashicorp.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(hashicorp.WalletScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	acctAddr := common.HexToAddress(acctConfig.Address)

	return client.SignHashWithPassphrase(context.Background(), &proto.SignHashWithPassphraseRequest{
		WalletUrl: url.String(),
		Account: &proto.Account{
			Address: acctAddr.Bytes(),
			Url:     "",
		},
		Hash:       toSign,
		Passphrase: "pwd", // this value is arbitary as the hashicorp acct manager does not use the password for anything
	})
}

func signTxDelegate(t *testing.T, client *InitializerSignerClient, vaultUrl string, acctJsonConfig []byte, toSign *types.Transaction) (*types.Transaction, error) {
	acctConfig := new(hashicorp.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(hashicorp.WalletScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	acctAddr := common.HexToAddress(acctConfig.Address)

	rlpTx, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	resp, err := client.SignTx(context.Background(), &proto.SignTxRequest{
		WalletUrl: url.String(),
		Account: &proto.Account{
			Address: acctAddr.Bytes(),
			Url:     "",
		},
		RlpTx:   rlpTx,
		ChainID: big.NewInt(42).Bytes(),
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

func signTxWithPassphraseDelegate(t *testing.T, client *InitializerSignerClient, vaultUrl string, acctJsonConfig []byte, toSign *types.Transaction) (*types.Transaction, error) {
	acctConfig := new(hashicorp.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	url, err := makeWalletUrl(hashicorp.WalletScheme, vaultUrl, *acctConfig)
	require.NoError(t, err)

	acctAddr := common.HexToAddress(acctConfig.Address)

	rlpTx, err := rlp.EncodeToBytes(toSign)
	require.NoError(t, err)

	resp, err := client.SignTxWithPassphrase(context.Background(), &proto.SignTxWithPassphraseRequest{
		WalletUrl: url.String(),
		Account: &proto.Account{
			Address: acctAddr.Bytes(),
			Url:     "",
		},
		Passphrase: "pwd", // this value is arbitary as the hashicorp acct manager does not use the password for anything
		RlpTx:      rlpTx,
		ChainID:    big.NewInt(42).Bytes(),
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

func timedUnlockDelegate(t *testing.T, client *InitializerSignerClient, acctJsonConfig []byte, unlockDuration time.Duration) {
	acctConfig := new(hashicorp.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	acctAddr := common.HexToAddress(acctConfig.Address)

	_, err := client.TimedUnlock(context.Background(), &proto.TimedUnlockRequest{
		Account: &proto.Account{
			Address: acctAddr.Bytes(),
			Url:     "",
		},
		Password: "pwd", // this value is arbitary as the hashicorp acct manager does not use the password for anything
		Duration: unlockDuration.Nanoseconds(),
	})

	require.NoError(t, err)
}

func lockDelegate(t *testing.T, client *InitializerSignerClient, acctJsonConfig []byte) {
	acctConfig := new(hashicorp.AccountConfig)
	_ = json.Unmarshal(acctJsonConfig, acctConfig)

	acctAddr := common.HexToAddress(acctConfig.Address)

	_, err := client.Lock(context.Background(), &proto.LockRequest{
		Account: &proto.Account{
			Address: acctAddr.Bytes(),
			Url:     "",
		},
	})

	require.NoError(t, err)
}
