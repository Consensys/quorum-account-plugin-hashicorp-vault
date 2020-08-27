package test

import (
	"context"
	"testing"

	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto_common"
	"github.com/stretchr/testify/require"
)

func TestPlugin_Init_InvalidPluginConfig(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	err := ctx.StartPlugin(t)
	require.NoError(t, err)

	noVaultUrlConf := `{
	"accountDirectory": "/path/to/dir",
	"authentication": {
		"token": "env://TOKEN"
	}
}`

	_, err = ctx.AccountManager.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: []byte(noVaultUrlConf),
	})

	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = vault must be a valid HTTP/HTTPS url")
}
