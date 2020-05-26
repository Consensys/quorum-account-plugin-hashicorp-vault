module github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault

go 1.13

// currently cannot replace with a non-module project so have to use the current quorum release instead of a local build
// of quorum with the account plugin changes
replace github.com/ethereum/go-ethereum => github.com/jpmorganchase/quorum v2.6.0+incompatible

replace github.com/jpmorganchase/quorum-account-plugin-sdk-go => /Users/chrishounsom/go/src/github.com/jpmorganchase/quorum-account-plugin-sdk-go

require (
	github.com/allegro/bigcache v1.2.1 // indirect
	github.com/aristanetworks/goarista v0.0.0-20200214154357-2151774b0d85 // indirect
	github.com/btcsuite/btcd v0.20.1-beta // indirect
	github.com/elastic/gosigar v0.10.5 // indirect
	github.com/ethereum/go-ethereum v0.0.0
	github.com/hashicorp/go-plugin v1.0.1
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/jpmorganchase/quorum-account-plugin-sdk-go v0.0.0
	github.com/steakknife/bloomfilter v0.0.0-20180922174646-6819c0d2a570 // indirect
	github.com/steakknife/hamming v0.0.0-20180906055917-c99c65617cd3 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/syndtr/goleveldb v1.0.0 // indirect
	google.golang.org/grpc v1.23.1
)
