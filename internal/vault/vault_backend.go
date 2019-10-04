package vault

import (
	"errors"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"sort"
	"strings"
	"sync"
)

//// BackendType is the reflect type of a vault backend.
//var BackendType = reflect.TypeOf(&VaultBackend{})

type PluginBackend interface {
	accounts.Backend
	FindWalletByUrl(url string) (accounts.Wallet, error)
}

// VaultBackend implements accounts.Backend to manage all wallets for a particular vendor's vault
type VaultBackend struct {
	updateScope event.SubscriptionScope
	updateFeed  event.Feed
	mutex       sync.RWMutex // TODO
	wallets     []accounts.Wallet
}

// NewHashicorpBackend creates a VaultBackend containing Hashicorp Vault compatible vaultWallets for each of the provided walletConfigs
func NewHashicorpBackend(walletConfigs []HashicorpWalletConfig) (*VaultBackend, error) {
	wallets := []accounts.Wallet{}

	backend := &VaultBackend{}

	for _, conf := range walletConfigs {
		w, err := newHashicorpWallet(conf, backend)
		if err != nil {
			log.Error("unable to create Hashicorp wallet from config", "err", err)
			continue
		}
		wallets = append(wallets, w)
	}

	sort.Sort(walletsByUrl(wallets))

	backend.wallets = wallets

	return backend, nil
}

// Wallets implements accounts.Backend returning a copy of the list of wallets managed by the VaultBackend
func (b *VaultBackend) Wallets() []accounts.Wallet {
	cpy := make([]accounts.Wallet, len(b.wallets))
	copy(cpy, b.wallets)
	return cpy
}

// Subscribe implements accounts.Backend, creating an async subscription to receive notifications on the additional of vaultWallets
func (b *VaultBackend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	return b.updateScope.Track(b.updateFeed.Subscribe(sink))
}

func (b *VaultBackend) FindWalletByUrl(url string) (accounts.Wallet, error) {
	u, err := parseURL(url)
	if err != nil {
		return nil, err
	}

	for _, wallet := range b.Wallets() {
		if wallet.URL() == u {
			return wallet, nil
		}
	}
	return nil, accounts.ErrUnknownWallet
}

// parseURL converts a user supplied URL into the accounts specific structure.
func parseURL(url string) (accounts.URL, error) {
	parts := strings.Split(url, "://")
	if len(parts) != 2 || parts[0] == "" {
		return accounts.URL{}, errors.New("protocol scheme missing")
	}
	return accounts.URL{
		Scheme: parts[0],
		Path:   parts[1],
	}, nil
}

//func (b *VaultBackend) TimedUnlock(account accounts.Account, duration time.Duration) error {
//	w, err := b.findWalletByAcct(account)
//
//	if err != nil {
//		return err
//	}
//
//	return w.TimedUnlock(account, duration)
//}
//
//func (b *VaultBackend) Lock(account accounts.Account) error {
//	w, err := b.findWalletByAcct(account)
//
//	if err != nil {
//		return err
//	}
//
//	return w.Lock(account)
//}
//
//func (b *VaultBackend) findWalletByAcct(account accounts.Account) (*vaultWallet, error) {
//	b.mutex.RLock()
//	defer b.mutex.RUnlock()
//
//	for _, wallet := range b.wallets {
//		if wallet.Contains(account) {
//			w, ok := wallet.(*vaultWallet)
//
//			if !ok {
//				continue
//			}
//
//			return w, nil
//		}
//	}
//	return nil, accounts.ErrUnknownAccount
//}
//
//
//func (b *VaultBackend) NewAccount(walletUrl string, config interface{}) (common.Address, error) {
//	url, err := parseURL(walletUrl)
//
//	if err != nil {
//		return common.Address{}, err
//	}
//
//	w, err := b.findWalletByUrl(url)
//
//	if err != nil {
//		return common.Address{}, err
//	}
//
//	return w.NewAccount(config)
//}
//
//func (b *VaultBackend) ImportECDSA(key *ecdsa.PrivateKey, walletUrl string, config interface{}) (common.Address, error) {
//	url, err := parseURL(walletUrl)
//
//	if err != nil {
//		return common.Address{}, err
//	}
//
//	w, err := b.findWalletByUrl(url)
//
//	if err != nil {
//		return common.Address{}, err
//	}
//
//	return w.Import(key, config)
//}

// walletsByUrl implements the sort interface to enable the sorting of a slice of wallets alphanumerically by their urls
type walletsByUrl []accounts.Wallet

func (w walletsByUrl) Len() int {
	return len(w)
}

func (w walletsByUrl) Less(i, j int) bool {
	return (w[i].URL()).Cmp(w[j].URL()) < 0
}

func (w walletsByUrl) Swap(i, j int) {
	w[i], w[j] = w[j], w[i]
}
