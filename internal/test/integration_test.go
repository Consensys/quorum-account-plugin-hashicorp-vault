package test

import (
	"context"
	"github.com/hashicorp/go-plugin"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto_common"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlugin_Init_InvalidPluginConfig(t *testing.T) {
	// create plugin server and load client impl
	client, server := plugin.TestPluginGRPCConn(t, map[string]plugin.Plugin{
		"impl": new(testableHashicorpPlugin),
	})

	defer client.Close()
	defer server.Stop()

	raw, err := client.Dispense("impl")
	require.NoError(t, err)

	acctman, ok := raw.(hashicorpPluginGRPCClient)
	require.True(t, ok)

	// create plugin config and init plugin
	pluginConfNoVaultUrl := `[
		{
			"accountDirectory": "/path/to/dir",
			"authentication": {
				"token": "env://TOKEN"
			}
		}
	]`

	_, err = acctman.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: []byte(pluginConfNoVaultUrl),
	})

	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = invalid config: array index 0: vault must be a valid HTTP/HTTPS url")
}
