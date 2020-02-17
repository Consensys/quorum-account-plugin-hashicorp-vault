package server

import (
	"context"
	"fmt"
	"github.com/hashicorp/go-plugin"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto_common"
	"google.golang.org/grpc"
	"log"
)

func (p *HashicorpPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	log.Println("[INFO] Register Initializer")
	proto_common.RegisterPluginInitializerServer(s, p)
	log.Println("[INFO] Register Hashicorp Vault AccountManager")
	proto.RegisterAccountManagerServer(s, p)
	return nil
}

func (*HashicorpPlugin) GRPCClient(context.Context, *plugin.GRPCBroker, *grpc.ClientConn) (interface{}, error) {
	return nil, fmt.Errorf("not supported")
}
