package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	iproto "github.com/goquorum/quorum-plugin-definitions/initializer/go/proto"
	sproto "github.com/goquorum/quorum-plugin-definitions/signer/go/proto"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault/hashicorp"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SignerPluginImpl struct {
	plugin.Plugin
	signer
}

func (p *SignerPluginImpl) Init(ctx context.Context, req *iproto.PluginInitialization_Request) (*iproto.PluginInitialization_Response, error) {
	// read config and start signer
	startTime := time.Now()
	defer func() {
		log.Println("[INFO] plugin initialization took", time.Now().Sub(startTime).Round(time.Microsecond))
	}()
	conf, err := NewSignerConfiguration(req.GetRawConfiguration())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	if err := p.signer.init(conf); err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	return &iproto.PluginInitialization_Response{}, nil
}

func NewSignerConfiguration(rawJSON []byte) (hashicorp.HashicorpAccountStoreConfig, error) {
	var conf hashicorp.HashicorpAccountStoreConfig
	if err := json.Unmarshal(rawJSON, &conf); err != nil {
		return hashicorp.HashicorpAccountStoreConfig{}, fmt.Errorf("can't parse configuration")
	}
	if err := conf.Validate(); err != nil {
		return hashicorp.HashicorpAccountStoreConfig{}, fmt.Errorf("invalid configuration: %s", err)
	}
	//conf.SetDefaults()
	return conf, nil
}

func (p *SignerPluginImpl) GRPCServer(b *plugin.GRPCBroker, s *grpc.Server) error {
	iproto.RegisterPluginInitializerServer(s, p)
	sproto.RegisterSignerServer(s, p)
	return nil
}

func (p *SignerPluginImpl) GRPCClient(ctx context.Context, b *plugin.GRPCBroker, cc *grpc.ClientConn) (interface{}, error) {
	return nil, errors.New("not supported")
}
