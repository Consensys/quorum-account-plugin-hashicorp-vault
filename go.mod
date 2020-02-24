module github.com/jpmorganchase/quorum-plugin-account-store-hashicorp

go 1.13

replace github.com/ethereum/go-ethereum => github.com/jpmorganchase/quorum v2.4.0+incompatible

replace github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go => /Users/chrishounsom/quorum-account-manager-plugin-sdk-go

require (
	github.com/aristanetworks/goarista v0.0.0-20200214154357-2151774b0d85 // indirect
	github.com/btcsuite/btcd v0.20.1-beta // indirect
	github.com/ethereum/go-ethereum v0.0.0
	github.com/hashicorp/go-plugin v1.0.1
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go v0.0.0
	github.com/stretchr/testify v1.3.0
	github.com/syndtr/goleveldb v1.0.0 // indirect
	google.golang.org/grpc v1.23.1
)
