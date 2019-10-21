package internal

import (
	"context"
	"encoding/json"
	"fmt"
	iproto "github.com/goquorum/quorum-plugin-definitions/initializer/go/proto"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/hashicorp"
	"github.com/hashicorp/go-plugin"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test(t *testing.T) {
	client, server := plugin.TestPluginGRPCConn(t, map[string]plugin.Plugin{
		"signer": new(testableSignerPluginImpl),
	})
	defer client.Close()
	defer server.Stop()

	defer setEnvironmentVariables(
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultRoleIDEnv),
		fmt.Sprintf("%v_%v", "FOO", hashicorp.DefaultSecretIDEnv),
	)()

	raw, err := client.Dispense("signer")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	//initImpl, ok := raw.(iproto.PluginInitializerClient)
	initImpl, ok := raw.(InitializerSignerClient)
	if !ok {
		t.Fatalf("bad: %#v", raw)
	}

	pluginConfig := hashicorp.HashicorpAccountStoreConfig{
		Vaults: []hashicorp.VaultConfig{{
			Addr:             "http://localhost:8200",
			TLS:              hashicorp.TLS{},
			AccountConfigDir: "/Users/chrishounom/quorum-plugin-hashicorp-account-store/internal/testdata",
			Unlock:           "",
			Auth: []hashicorp.VaultAuth{{
				AuthID:      "FOO",
				ApprolePath: "not-default",
			}},
		}},
	}
	rawPluginConfig, err := json.Marshal(pluginConfig)
	require.NoError(t, err)

	_, err = initImpl.Init(context.Background(), &iproto.PluginInitialization_Request{
		RawConfiguration: rawPluginConfig,
	})
	require.NoError(t, err)

	//signerImpl, ok := raw.(sproto.SignerClient)
	//if !ok {
	//	t.Fatalf("bad: %#v", raw)
	//}
	//
	//result, err := signerImpl.Contains(context.Background(), &sproto.ContainsRequest{
	//	WalletUrl: "http://localhost:8200",
	//	Account:   &sproto.Account{
	//		Address: common.HexToAddress("0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5").Bytes(),
	//	},
	//})
	//log.Printf("%#v", result)
	//if result == nil || !result.IsContained {
	//	t.Fatalf("bad: %#v", result)
	//}
}
