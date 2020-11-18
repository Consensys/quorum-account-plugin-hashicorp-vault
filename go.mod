module github.com/ConsenSys/quorum-account-plugin-hashicorp-vault

go 1.13

// Checkout QuorumEngineering/quorum-go-utils and update the RHS of the replace statement
//replace github.com/ConsenSys/quorum-go-utils => /Users/chrishounsom/quorum-go-utils

require (
	github.com/ConsenSys/quorum-go-utils v0.0.0
	github.com/ConsenSys/quorum/crypto/secp256k1 v0.0.0-20201109194625-1ecd42625e8e
	github.com/fatih/color v1.10.0 // indirect
	github.com/frankban/quicktest v1.7.2 // indirect
	github.com/hashicorp/go-plugin v1.0.1
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/jpmorganchase/quorum-account-plugin-sdk-go v0.0.0-20201013091638-8d6ab53641ae
	github.com/kr/pretty v0.2.0 // indirect
	github.com/pierrec/lz4 v2.4.1+incompatible // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.6.1
	golang.org/x/crypto v0.0.0-20201117144127-c1f2f97bffc9 // indirect
	golang.org/x/sys v0.0.0-20201117222635-ba5294a509c7 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	golang.org/x/tools v0.0.0-20201118030313-598b068a9102 // indirect
	google.golang.org/genproto v0.0.0-20200218151345-dad8c97a84f5 // indirect
	google.golang.org/grpc v1.27.1
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gotest.tools/gotestsum v0.6.0 // indirect
)
