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

package manager

import (
	"errors"
	"fmt"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/config"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
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
func NewManager(config []config.VaultConfig) (*Manager, error) {
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

		if err := unlockAccounts(backend, conf.Unlock); err != nil {
			log.Printf("[ERROR] Failed to unlock the following accounts:\n%v", err)
		}

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

func unlockAccounts(backend *Backend, unlock string) error {
	var failedMsgs []string

	addrs := strings.Split(unlock, ",")
	for _, addr := range addrs {
		trimmed := strings.TrimSpace(addr)

		if trimmed == "" {
			//do nothing
		} else if !common.IsHexAddress(trimmed) {
			failedMsgs = append(failedMsgs, fmt.Sprintf("unable to unlock %v: invalid hex-encoded ethereum address", trimmed))
		} else {
			err := backend.Unlock(accounts.Account{Address: common.HexToAddress(trimmed)}, "")
			if err != nil {
				failedMsgs = append(failedMsgs, fmt.Sprintf("unable to unlock %v: %v", trimmed, err))
			}
		}
	}

	if len(failedMsgs) > 0 {
		return errors.New(strings.Join(failedMsgs, "\n"))
	}
	return nil
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

func (am *Manager) GetAccountCreator(vaultAddr string) (AccountCreator, error) {
	for _, backend := range am.backends {
		switch b := backend.(type) {
		case *Backend:
			a := b.storage.(*vaultClientManager).vaultAddr
			if vaultAddr == a {
				return b, nil
			}
		}
	}
	return nil, fmt.Errorf("plugin signer not configured to use Vault %v", vaultAddr)
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

// Lock removes the private key with the given address from memory.
func (am *Manager) Lock(account accounts.Account) error {
	b, err := am.Backend(account)
	if err != nil {
		return err
	}
	pb := b.(*Backend)
	if err := pb.Lock(account.Address); err != nil {
		return err
	}
	return nil
}

// TimedUnlock unlocks the given account with the passphrase. The account
// stays unlocked for the duration of timeout. A timeout of 0 unlocks the account
// until the program exits. The account must match a unique key file.
//
// If the account address is already unlocked for a duration, TimedUnlock extends or
// shortens the active unlock timeout. If the address was previously unlocked
// indefinitely the timeout is not altered.
func (am *Manager) TimedUnlock(account accounts.Account, passphrase string, timeout time.Duration) error {
	b, err := am.Backend(account)
	if err != nil {
		return err
	}
	pb := b.(*Backend)
	if err := pb.TimedUnlock(account, passphrase, timeout); err != nil {
		return err
	}
	return nil
}
