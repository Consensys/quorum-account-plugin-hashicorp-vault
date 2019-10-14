// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package hashicorp

import (
	"github.com/ethereum/go-ethereum/accounts"
	"log"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/event"
)

// Manager is an overarching account manager that can communicate with various
// backends for signing transactions.
type Manager struct {
	backends []accounts.Backend        // Index of backends currently registered
	updaters []event.Subscription      // Wallet update subscriptions for all backends
	updates  chan accounts.WalletEvent // Subscription sink for backend wallet changes
	wallets  []accounts.Wallet         // Cache of all wallets from all registered backends

	feed event.Feed // Wallet feed notifying of arrivals/departures

	quit chan chan error
	lock sync.RWMutex
}

// NewManager creates a generic account manager to sign transaction via various
// supported backends.
func NewManager(config []VaultConfig) (*Manager, error) {
	log.Println("[PLUGIN Manager] NewManager")

	backends := make([]accounts.Backend, len(config))
	updates := make(chan accounts.WalletEvent, 4*len(backends))
	subs := make([]event.Subscription, len(backends))
	var wallets []accounts.Wallet

	for i, conf := range config {
		backend, err := NewBackend(conf)
		if err != nil {
			return nil, err
		}
		backends[i] = backend

		// Retrieve the initial list of wallets from the backends and sort by URL
		wallets = merge(wallets, backend.Wallets()...)

		// Subscribe to wallet notifications from the backend
		subs[i] = backend.Subscribe(updates)
	}

	// Assemble the account manager and return
	am := &Manager{
		backends: backends,
		updaters: subs,
		updates:  updates,
		wallets:  wallets,
		quit:     make(chan chan error),
	}

	go am.update()

	return am, nil
}

// Close terminates the account manager's internal notification processes.
func (am *Manager) Close() error {
	errc := make(chan error)
	am.quit <- errc
	return <-errc
}

// update is the wallet event loop listening for notifications from the backends
// and updating the cache of wallets.
func (am *Manager) update() {
	// Close all subscriptions when the manager terminates
	defer func() {
		am.lock.Lock()
		for _, sub := range am.updaters {
			sub.Unsubscribe()
		}
		am.updaters = nil
		am.lock.Unlock()
	}()

	// Loop until termination
	for {
		select {
		case event := <-am.updates:
			// Wallet event arrived, update local cache
			log.Println("[MANAGER] wallet event arrived")
			am.lock.Lock()
			switch event.Kind {
			case accounts.WalletArrived:
				am.wallets = merge(am.wallets, event.Wallet)
			case accounts.WalletDropped:
				am.wallets = drop(am.wallets, event.Wallet)
			}
			am.lock.Unlock()

			// Notify any listeners of the event
			am.feed.Send(event)

		case errc := <-am.quit:
			// Manager terminating, return
			errc <- nil
			return
		}
	}
}

func (am *Manager) Backend(account accounts.Account) (accounts.Backend, error) {
	for _, b := range am.backends {
		for _, w := range b.Wallets() {
			if w.Contains(account) {
				return b, nil
			}
		}
	}
	return nil, accounts.ErrUnknownWallet
}

// Wallets returns all signer accounts registered under this account manager.
func (am *Manager) Wallets() []accounts.Wallet {
	am.lock.RLock()
	defer am.lock.RUnlock()

	cpy := make([]accounts.Wallet, len(am.wallets))
	copy(cpy, am.wallets)
	return cpy
}

// Wallet retrieves the wallet associated with a particular URL.
func (am *Manager) Wallet(url string) (accounts.Wallet, error) {
	am.lock.RLock()
	defer am.lock.RUnlock()

	parsed, err := parseURL(url)
	if err != nil {
		return nil, err
	}
	for _, wallet := range am.Wallets() {
		if wallet.URL() == parsed {
			return wallet, nil
		}
	}
	return nil, accounts.ErrUnknownWallet
}

// Find attempts to locate the wallet corresponding to a specific account. Since
// accounts can be dynamically added to and removed from wallets, this method has
// a linear runtime in the number of wallets.
func (am *Manager) Find(account accounts.Account) (accounts.Wallet, error) {
	am.lock.RLock()
	defer am.lock.RUnlock()

	for _, wallet := range am.wallets {
		if wallet.Contains(account) {
			return wallet, nil
		}
	}
	return nil, accounts.ErrUnknownAccount
}

// Subscribe creates an async subscription to receive notifications when the
// manager detects the arrival or departure of a wallet from any of its backends.
func (am *Manager) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	return am.feed.Subscribe(sink)
}

// merge is a sorted analogue of append for wallets, where the ordering of the
// origin list is preserved by inserting new wallets at the correct position.
//
// The original slice is assumed to be already sorted by URL.
func merge(slice []accounts.Wallet, wallets ...accounts.Wallet) []accounts.Wallet {
	for _, wallet := range wallets {
		n := sort.Search(len(slice), func(i int) bool { return slice[i].URL().Cmp(wallet.URL()) >= 0 })
		if n == len(slice) {
			slice = append(slice, wallet)
			continue
		}
		slice = append(slice[:n], append([]accounts.Wallet{wallet}, slice[n:]...)...)
	}
	return slice
}

// drop is the couterpart of merge, which looks up wallets from within the sorted
// cache and removes the ones specified.
func drop(slice []accounts.Wallet, wallets ...accounts.Wallet) []accounts.Wallet {
	for _, wallet := range wallets {
		n := sort.Search(len(slice), func(i int) bool { return slice[i].URL().Cmp(wallet.URL()) >= 0 })
		if n == len(slice) {
			// Wallet not found, may happen during startup
			continue
		}
		slice = append(slice[:n], slice[n+1:]...)
	}
	return slice
}
