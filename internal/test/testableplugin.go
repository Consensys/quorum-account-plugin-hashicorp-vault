package test

import (
	"context"

	"github.com/ConsenSys/quorum-account-plugin-hashicorp-vault/internal/server"
	"github.com/hashicorp/go-plugin"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto_common"
	"google.golang.org/grpc"
)

// testableHashicorpPlugin embeds a server.HashicorpPlugin, overriding the unimplemented GRPCClient(...).  This is so that
// integration tests can create both a plugin server and client to mimic the behaviour of Quorum calling the plugin server.
type testableHashicorpPlugin struct {
	server.HashicorpPlugin
}

type hashicorpPluginGRPCClient struct {
	proto_common.PluginInitializerClient
	proto.AccountServiceClient
}

func (testableHashicorpPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, cc *grpc.ClientConn) (interface{}, error) {
	return hashicorpPluginGRPCClient{
		PluginInitializerClient: proto_common.NewPluginInitializerClient(cc),
		AccountServiceClient:    proto.NewAccountServiceClient(cc),
	}, nil
}
