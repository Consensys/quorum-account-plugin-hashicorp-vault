package server

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/go-plugin"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto_common"
	"google.golang.org/grpc"
)

func (p *HashicorpPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	log.Println("[INFO] Register Initializer")
	proto_common.RegisterPluginInitializerServer(s, p)
	log.Println("[INFO] Register Hashicorp Vault AccountManager")
	proto.RegisterAccountServiceServer(s, p)
	return nil
}

func (*HashicorpPlugin) GRPCClient(context.Context, *plugin.GRPCBroker, *grpc.ClientConn) (interface{}, error) {
	return nil, fmt.Errorf("not supported")
}
