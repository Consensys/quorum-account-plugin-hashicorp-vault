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
	"fmt"
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
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
)

// Minimum amount of time between cache reloads. This limit applies if the platform does
// not support change notifications. It also applies if the keystore directory does not
// exist yet, the code will attempt to create a watcher at most this often.
const minReloadInterval = 2 * time.Second

type accountsByURL []vault.AccountAndWalletUrl

func (s accountsByURL) Len() int           { return len(s) }
func (s accountsByURL) Less(i, j int) bool { return s[i].Account.URL.Cmp(s[j].Account.URL) < 0 }
func (s accountsByURL) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// AmbiguousAddrError is returned when attempting to unlock
// an address for which more than one file exists.
type AmbiguousAddrError struct {
	Addr    common.Address
	Matches []vault.AccountAndWalletUrl
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
	byAddr   map[common.Address][]vault.AccountAndWalletUrl
	throttle *time.Timer
	notify   chan struct{}
	fileC    fileCache

	vaultAddr                 string
	accountConfigUnmarshaller vault.AccountConfigUnmarshaller
}

func NewAccountCache(keydir string, vaultAddr string, unmarshaller vault.AccountConfigUnmarshaller) (*AccountCache, chan struct{}) {
	ac := &AccountCache{
		keydir:                    keydir,
		byAddr:                    make(map[common.Address][]vault.AccountAndWalletUrl),
		notify:                    make(chan struct{}, 1),
		fileC:                     fileCache{all: mapset.NewThreadUnsafeSet()},
		vaultAddr:                 vaultAddr,
		accountConfigUnmarshaller: unmarshaller,
	}
	ac.watcher = newWatcher(ac)
	return ac, ac.notify
}

func (ac *AccountCache) Accounts() []vault.AccountAndWalletUrl {
	ac.MaybeReload()
	ac.Mu.Lock()
	defer ac.Mu.Unlock()
	cpy := make([]vault.AccountAndWalletUrl, len(ac.all))
	copy(cpy, ac.all)
	return cpy
}

func (ac *AccountCache) HasAddress(addr common.Address) bool {
	ac.MaybeReload()
	ac.Mu.Lock()
	defer ac.Mu.Unlock()
	return len(ac.byAddr[addr]) > 0
}

func (ac *AccountCache) Add(newAccount vault.AccountAndWalletUrl) {
	log.Println("[DEBUG] Plugin AccountCache Add: ", newAccount.Account.URL)
	ac.Mu.Lock()
	defer ac.Mu.Unlock()

	i := sort.Search(len(ac.all), func(i int) bool { return ac.all[i].Account.URL.Cmp(newAccount.Account.URL) >= 0 })
	if i < len(ac.all) && ac.all[i] == newAccount {
		return
	}
	// newAccount is not in the cache.
	ac.all = append(ac.all, vault.AccountAndWalletUrl{})
	copy(ac.all[i+1:], ac.all[i:])
	ac.all[i] = newAccount
	ac.byAddr[newAccount.Account.Address] = append(ac.byAddr[newAccount.Account.Address], newAccount)
}

//// note: removed needs to be unique here (i.e. both File and Address must be set).
//func (ac *AccountCache) Delete(removed vault.AccountAndWalletUrl) {
//	ac.Mu.Lock()
//	defer ac.Mu.Unlock()
//
//	ac.all = removeAccountAndWalletUrl(ac.all, removed)
//	if ba := removeAccountAndWalletUrl(ac.byAddr[removed.Account.Address], removed); len(ba) == 0 {
//		delete(ac.byAddr, removed.Account.Address)
//	} else {
//		ac.byAddr[removed.Account.Address] = ba
//	}
//}

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

func removeAccountAndWalletUrl(slice []vault.AccountAndWalletUrl, elem vault.AccountAndWalletUrl) []vault.AccountAndWalletUrl {
	for i := range slice {
		if slice[i].Account == elem.Account {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

//func removeAccount(slice []accounts.Account, elem accounts.Account) []accounts.Account {
//	for i := range slice {
//		if slice[i] == elem {
//			return append(slice[:i], slice[i+1:]...)
//		}
//	}
//	return slice
//}

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
			return accounts.Account{}, vault.ErrNoMatch
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].Account, nil
	case 0:
		return accounts.Account{}, vault.ErrNoMatch
	default:
		err := &AmbiguousAddrError{Addr: a.Address, Matches: make([]vault.AccountAndWalletUrl, len(matches))}
		copy(err.Matches, matches)
		sort.Sort(accountsByURL(err.Matches))
		return accounts.Account{}, err
	}
}

func (ac *AccountCache) MaybeReload() {
	log.Println("[DEBUG] PLUGIN AccountCache MaybeReload")
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
		log.Println("[ERROR] Failed to reload keystore contents", "err", err)
		return err
	}
	if creates.Cardinality() == 0 && deletes.Cardinality() == 0 && updates.Cardinality() == 0 {
		return nil
	}
	// Create a helper method to scan the contents of the key files
	var (
		buf        = new(bufio.Reader)
		acctConfig vault.ValidatableAccountParsableConfig
	)
	readAccount := func(path string) *vault.AccountAndWalletUrl {
		log.Println("[DEBUG] PLUGIN AccountCache readAccount")
		fd, err := os.Open(path)
		if err != nil {
			log.Println("[DEBUG] PLUGIN AccountCache failed to open keystore file: ", err)
			log.Println("[INFO] Failed to open keystore file", "path", path, "err", err)
			return nil
		}
		defer fd.Close()
		buf.Reset(fd)
		// Parse the address.
		acctConfig, err = ac.accountConfigUnmarshaller.Unmarshal(buf)
		if err != nil {
			log.Println("[Debug] PLUGIN AccountCache failed to decode keystore key:", err)
			log.Println("[INFO] Failed to decode keystore key", "path", path, "err", err)
			return nil
		}

		if err := acctConfig.Validate(); err != nil {
			log.Println("[DEBUG] PLUGIN AccountCache invalid secret config:", err)
			log.Println("[INFO] Invalid secret config", "path", path, "err", err)
			return nil
		}

		acct, err := acctConfig.ParseAccount(ac.vaultAddr, path)
		if err != nil {
			log.Println("[INFO] Failed to create account from secret config", "path", path, "err", err)
			return nil
		}
		return &acct
	}
	// Process all the file diffs
	start := time.Now()

	for _, p := range creates.ToSlice() {
		if a := readAccount(p.(string)); a != nil {
			log.Println("[DEBUG] PLUGIN AccountCache Adding: ", a.Account.URL.String())
			ac.Add(*a)
		}
	}
	for _, p := range deletes.ToSlice() {
		log.Println("[DEBUG] PLUGIN AccountCache Deleting: ", p.(string))
		ac.deleteByFile(p.(string))
	}
	for _, p := range updates.ToSlice() {
		log.Println("[DEBUG] PLUGIN AccountCache Updating: ", p.(string))
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
