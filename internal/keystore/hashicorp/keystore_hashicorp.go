package hashicorp

import "github.com/ethereum/go-ethereum/common"

type keystoreHashicorp struct{}

func (ks keystoreHashicorp) GetKey(addr common.Address, filename string, auth string) (*Key, error) {
	panic("implement me")
}

func (ks keystoreHashicorp) StoreKey(filename string, k *Key, auth string) error {
	panic("implement me")
}

func (ks keystoreHashicorp) JoinPath(filename string) string {
	panic("implement me")
}
