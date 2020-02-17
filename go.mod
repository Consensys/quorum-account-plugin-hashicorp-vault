module github.com/jpmorganchase/quorum-plugin-account-store-hashicorp

go 1.13

replace github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go => /Users/chrishounsom/quorum-account-manager-plugin-sdk-go

require (
	github.com/hashicorp/go-plugin v1.0.1
	github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go v0.0.0
	github.com/stretchr/testify v1.3.0
	google.golang.org/grpc v1.18.0
)
