package hashicorp

import (
	"errors"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"sort"
	"strings"
	"sync"
)

type WalletFinderBackend interface {
	accounts.Backend
	WalletFinder
}

type WalletFinder interface {
	FindWalletByUrl(url string) (accounts.Wallet, error)
}

// Backend implements accounts.Backend to manage all wallets for a particular vendor's vault
type Backend struct {
	updateScope event.SubscriptionScope
	updateFeed  event.Feed
	mutex       sync.RWMutex // TODO
	wallets     []accounts.Wallet
}

// NewHashicorpBackend creates a Backend containing Hashicorp Vault compatible vaultWallets for each of the provided walletConfigs
func NewHashicorpBackend(walletConfigs []HashicorpWalletConfig) (*Backend, error) {
	wallets := []accounts.Wallet{}

	backend := &Backend{}

	for _, conf := range walletConfigs {
		w, err := newHashicorpWallet(conf, backend, false)
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

// Wallets implements accounts.Backend returning a copy of the list of wallets managed by the Backend
func (b *Backend) Wallets() []accounts.Wallet {
	cpy := make([]accounts.Wallet, len(b.wallets))
	copy(cpy, b.wallets)
	return cpy
}

// Subscribe implements accounts.Backend, creating an async subscription to receive notifications on the additional of vaultWallets
func (b *Backend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	return b.updateScope.Track(b.updateFeed.Subscribe(sink))
}

func (b *Backend) FindWalletByUrl(url string) (accounts.Wallet, error) {
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
