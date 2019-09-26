module quorum-plugin-hashicorp-account-store

require (
	github.com/aristanetworks/goarista v0.0.0-20190924011532-60b7b74727fd // indirect
	github.com/btcsuite/btcd v0.0.0-20190824003749-130ea5bddde3 // indirect
	github.com/cespare/cp v1.1.1 // indirect
	github.com/deckarep/golang-set v1.7.1
	github.com/ethereum/go-ethereum v0.0.0
	github.com/golang/protobuf v1.3.2
	github.com/hashicorp/go-plugin v1.0.1
	github.com/hashicorp/vault v1.2.0 // indirect
	github.com/hashicorp/vault/api v1.0.5-0.20190730042357-746c0b111519
	github.com/hashicorp/vault/sdk v0.1.14-0.20190730042320-0dc007d98cc8
	github.com/pborman/uuid v1.2.0 // indirect
	github.com/rjeczalik/notify v0.9.2
	github.com/syndtr/goleveldb v1.0.0 // indirect
	google.golang.org/grpc v1.23.1
)

replace github.com/ethereum/go-ethereum => github.com/jpmorganchase/quorum v2.2.5+incompatible
