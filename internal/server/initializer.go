package server

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/hashicorp"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto_common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (p *HashicorpPlugin) Init(_ context.Context, req *proto_common.PluginInitialization_Request) (*proto_common.PluginInitialization_Response, error) {
	startTime := time.Now()
	defer func() {
		log.Println("[INFO] plugin initialization took", time.Now().Sub(startTime).Round(time.Microsecond))
	}()

	conf := new(config.VaultClient)

	if err := json.Unmarshal(req.GetRawConfiguration(), conf); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	if err := conf.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	am, err := hashicorp.NewAccountManager(*conf)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	p.acctManager = am

	return &proto_common.PluginInitialization_Response{}, nil
}
