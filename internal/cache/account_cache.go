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

package cache

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	//"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/config"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
)

// Minimum amount of time between cache reloads. This limit applies if the platform does
// not support change notifications. It also applies if the keystore directory does not
// exist yet, the code will attempt to create a watcher at most this often.
const minReloadInterval = 2 * time.Second

var ErrNoMatch = errors.New("no key for given address or file")

type accountsByURL []config.AccountAndWalletUrl

func (s accountsByURL) Len() int           { return len(s) }
func (s accountsByURL) Less(i, j int) bool { return s[i].Account.URL.Cmp(s[j].Account.URL) < 0 }
func (s accountsByURL) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// AmbiguousAddrError is returned when attempting to unlock
// an address for which more than one file exists.
type AmbiguousAddrError struct {
	Addr    common.Address
	Matches []config.AccountAndWalletUrl
}

func (err *AmbiguousAddrError) Error() string {
	files := ""
	for i, a := range err.Matches {
		files += a.Account.URL.Path
		if i < len(err.Matches)-1 {
			files += ", "
		}
	}
	return fmt.Sprintf("multiple keys match address (%s)", files)
}

// accountCache is a live index of all accounts in the keystore.
type AccountCache struct {
	keydir   string
	watcher  *watcher
	Mu       sync.Mutex // TODO has been exported due to moving into separate pkg, do we want to keep it this way?
	all      accountsByURL
	byAddr   map[common.Address][]config.AccountAndWalletUrl
	throttle *time.Timer
	notify   chan struct{}
	fileC    fileCache

	vaultAddr string
}

func NewAccountCache(keydir string, vaultAddr string) (*AccountCache, chan struct{}) {
	ac := &AccountCache{
		keydir:    keydir,
		byAddr:    make(map[common.Address][]config.AccountAndWalletUrl),
		notify:    make(chan struct{}, 1),
		fileC:     fileCache{all: mapset.NewThreadUnsafeSet()},
		vaultAddr: vaultAddr,
	}
	ac.watcher = newWatcher(ac)
	return ac, ac.notify
}

func (ac *AccountCache) Accounts() []config.AccountAndWalletUrl {
	ac.MaybeReload()
	ac.Mu.Lock()
	defer ac.Mu.Unlock()
	cpy := make([]config.AccountAndWalletUrl, len(ac.all))
	copy(cpy, ac.all)
	return cpy
}

func (ac *AccountCache) HasAddress(addr common.Address) bool {
	ac.MaybeReload()
	ac.Mu.Lock()
	defer ac.Mu.Unlock()
	return len(ac.byAddr[addr]) > 0
}

func (ac *AccountCache) Add(newAccount config.AccountAndWalletUrl) {
	ac.Mu.Lock()
	defer ac.Mu.Unlock()

	i := sort.Search(len(ac.all), func(i int) bool { return ac.all[i].Account.URL.Cmp(newAccount.Account.URL) >= 0 })
	if i < len(ac.all) && ac.all[i] == newAccount {
		return
	}
	// newAccount is not in the cache.
	ac.all = append(ac.all, config.AccountAndWalletUrl{})
	copy(ac.all[i+1:], ac.all[i:])
	ac.all[i] = newAccount
	ac.byAddr[newAccount.Account.Address] = append(ac.byAddr[newAccount.Account.Address], newAccount)
}

// deleteByFile removes an account referenced by the given path.
func (ac *AccountCache) deleteByFile(path string) {
	ac.Mu.Lock()
	defer ac.Mu.Unlock()
	i := sort.Search(len(ac.all), func(i int) bool { return ac.all[i].Account.URL.Path >= path })

	if i < len(ac.all) && ac.all[i].Account.URL.Path == path {
		removed := ac.all[i]
		ac.all = append(ac.all[:i], ac.all[i+1:]...)
		if ba := removeAccountAndWalletUrl(ac.byAddr[removed.Account.Address], removed); len(ba) == 0 {
			delete(ac.byAddr, removed.Account.Address)
		} else {
			ac.byAddr[removed.Account.Address] = ba
		}
	}
}

func removeAccountAndWalletUrl(slice []config.AccountAndWalletUrl, elem config.AccountAndWalletUrl) []config.AccountAndWalletUrl {
	for i := range slice {
		if slice[i].Account == elem.Account {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// find returns the cached account for address if there is a unique match.
// The exact matching rules are explained by the documentation of accounts.Account.
// Callers must hold ac.mu.
func (ac *AccountCache) Find(a accounts.Account) (accounts.Account, error) {
	// Limit search to address candidates if possible.
	matches := ac.all
	if (a.Address != common.Address{}) {
		matches = ac.byAddr[a.Address]
	}
	if a.URL.Path != "" {
		// If only the basename is specified, complete the path.
		if !strings.ContainsRune(a.URL.Path, filepath.Separator) {
			a.URL.Path = filepath.Join(ac.keydir, a.URL.Path)
		}
		for i := range matches {
			if matches[i].Account.URL == a.URL {
				return matches[i].Account, nil
			}
		}
		if (a.Address == common.Address{}) {
			return accounts.Account{}, ErrNoMatch
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].Account, nil
	case 0:
		return accounts.Account{}, ErrNoMatch
	default:
		err := &AmbiguousAddrError{Addr: a.Address, Matches: make([]config.AccountAndWalletUrl, len(matches))}
		copy(err.Matches, matches)
		sort.Sort(accountsByURL(err.Matches))
		return accounts.Account{}, err
	}
}

func (ac *AccountCache) MaybeReload() {
	ac.Mu.Lock()

	if ac.watcher.running {
		ac.Mu.Unlock()
		return // A watcher is running and will keep the cache up-to-date.
	}
	if ac.throttle == nil {
		ac.throttle = time.NewTimer(0)
	} else {
		select {
		case <-ac.throttle.C:
		default:
			ac.Mu.Unlock()
			return // The cache was reloaded recently.
		}
	}
	// No watcher running, start it.
	ac.watcher.start()
	ac.throttle.Reset(minReloadInterval)
	ac.Mu.Unlock()
	ac.scanAccounts()
}

func (ac *AccountCache) Close() {
	ac.Mu.Lock()
	ac.watcher.close()
	if ac.throttle != nil {
		ac.throttle.Stop()
	}
	if ac.notify != nil {
		close(ac.notify)
		ac.notify = nil
	}
	ac.Mu.Unlock()
}

// scanAccounts checks if any changes have occurred on the filesystem, and
// updates the account cache accordingly
func (ac *AccountCache) scanAccounts() error {
	// Scan the entire folder metadata for file changes
	creates, deletes, updates, err := ac.fileC.scan(ac.keydir)
	if err != nil {
		log.Println("[DEBUG] Failed to reload keystore contents", "err", err)
		return err
	}
	if creates.Cardinality() == 0 && deletes.Cardinality() == 0 && updates.Cardinality() == 0 {
		return nil
	}
	// Create a helper method to scan the contents of the key files
	var (
		buf        = new(bufio.Reader)
		acctConfig config.AccountConfig
	)
	readAccount := func(path string) *config.AccountAndWalletUrl {
		fd, err := os.Open(path)
		if err != nil {
			log.Println("[DEBUG] Failed to open acctconfig file", "path", path, "err", err)
			return nil
		}
		defer fd.Close()
		buf.Reset(fd)
		// Parse the address.
		if err := json.NewDecoder(buf).Decode(&acctConfig); err != nil {
			log.Println("[DEBUG] Failed to decode acctconfig key", "path", path, "err", err)
			return nil
		}

		if err := acctConfig.ValidateForAccountRetrieval(); err != nil {
			log.Println("[DEBUG] Invalid secret config", "path", path, "err", err)
			return nil
		}

		acct, err := config.ParseAccount(acctConfig, ac.vaultAddr, path)
		if err != nil {
			log.Println("[DEBUG] Failed to create account from secret config", "path", path, "err", err)
			return nil
		}
		return &acct
	}
	// Process all the file diffs
	start := time.Now()

	for _, p := range creates.ToSlice() {
		log.Printf("[DEBUG] %v added, updating cache", p.(string))
		if a := readAccount(p.(string)); a != nil {
			log.Println("[DEBUG] adding acct: ", a.Account.URL.String())
			ac.Add(*a)
		}
	}
	for _, p := range deletes.ToSlice() {
		log.Printf("[DEBUG] %v deleted, updating cache", p.(string))
		ac.deleteByFile(p.(string))
	}
	for _, p := range updates.ToSlice() {
		log.Printf("[DEBUG] %v updated, updating cache", p.(string))
		path := p.(string)
		ac.deleteByFile(path)
		if a := readAccount(path); a != nil {
			ac.Add(*a)
		}
	}
	end := time.Now()

	select {
	case ac.notify <- struct{}{}:
	default:
	}
	log.Println("[DEBUG] Handled keystore changes", "time", end.Sub(start))
	return nil
}
