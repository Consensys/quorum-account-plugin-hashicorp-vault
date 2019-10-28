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
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/config"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/test/utils"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/require"
)

var (
	initialAccounts = []accounts.Account{
		{
			Address: common.HexToAddress("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"),
			URL: accounts.URL{
				Scheme: config.HashiScheme,
				Path:   fmt.Sprintf("FOO@url/v1/engine/data/engineacct?version=2#addr=4d6d744b6da435b5bbdde2526dc20e9a41cb72e5"),
			},
		},
		{
			Address: common.HexToAddress("dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
			URL: accounts.URL{
				Scheme: config.HashiScheme,
				Path:   fmt.Sprintf("FOO@url/v1/kv/data/kvacct?version=1#addr=dc99ddec13457de6c0f6bb8e6cf3955c86f55526"),
			},
		},
	}
)

func TestCache_InitialReload_OrderByUrl(t *testing.T) {
	// create temporary acctconfigdir
	dir, err := ioutil.TempDir("../test/data", "acctconfig")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// add 2 acctconfigs to acctconfigdir
	if _, err := utils.AddTempFile(dir, utils.Acct1JsonConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := utils.AddTempFile(dir, utils.Acct2JsonConfig); err != nil {
		t.Fatal(err)
	}

	vaulturl := "http://url"
	cache, _ := NewAccountCache(dir, vaulturl)
	accts := cache.Accounts()

	if !reflect.DeepEqual(accts, initialAccounts) {
		t.Fatalf("got initial accounts: %+v\nwant %+v", accts, initialAccounts)
	}
}

func TestCache_AddDeletePreserveOrder(t *testing.T) {
	// create temporary acctconfigdir
	dir, err := ioutil.TempDir("../test/data", "acctconfig")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	vaulturl := "http://url"
	cache, _ := NewAccountCache(dir, vaulturl)
	cacheImpl := cache.(*accountCache)

	cacheImpl.watcher.running = true // prevent unexpected reloads

	accs := []accounts.Account{
		{
			Address: common.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87"),
			URL:     accounts.URL{Scheme: config.HashiScheme, Path: "url:1/path"},
		},
		{
			Address: common.HexToAddress("2cac1adea150210703ba75ed097ddfe24e14f213"),
			URL:     accounts.URL{Scheme: config.HashiScheme, Path: "ggg:43/something"},
		},
		{
			Address: common.HexToAddress("8bda78331c916a08481428e4b07c96d3e916d165"),
			URL:     accounts.URL{Scheme: config.HashiScheme, Path: "BAR@aah:11/secret/path"},
		},
		{
			Address: common.HexToAddress("d49ff4eeb0b2686ed89c0fc0f2b6ea533ddbbd5e"),
			URL:     accounts.URL{Scheme: config.HashiScheme, Path: "AUTH@vaulturl:8080/v1/kv/data/secret?version=1#addr=something"},
		},
		{
			Address: common.HexToAddress("7ef5a6135f1fd6a02593eedc869c6d41d934aef8"),
			URL:     accounts.URL{Scheme: config.HashiScheme, Path: "url:2/path"},
		},
		{
			Address: common.HexToAddress("f466859ead1932d743d622cb74fc058882e8648a"),
			URL:     accounts.URL{Scheme: config.HashiScheme, Path: "ENV@addr/1"},
		},
		{
			Address: common.HexToAddress("289d485d9771714cce91d3393d764e1311907acc"),
			URL:     accounts.URL{Scheme: config.HashiScheme, Path: "zzz/secret/data"},
		},
	}

	files := make([]string, len(accs))
	for i := range accs {
		files[i] = fmt.Sprintf("filepath%v", i)
	}

	for i, a := range accs {
		cache.Add(a, files[i])
	}
	// Add some of them twice to check that they don't get reinserted.
	cache.Add(accs[0], files[0])
	cache.Add(accs[2], files[2])

	// Check that the account list is sorted by filename.
	wantAccounts := make([]accounts.Account, len(accs))
	copy(wantAccounts, accs)
	sort.Sort(accountsByURL(wantAccounts))
	list := cache.Accounts()
	if !reflect.DeepEqual(list, wantAccounts) {
		t.Fatalf("got accounts: %+v\nwant %+v", accs, wantAccounts)
	}

	// check existing accts show up with HasAddress
	for _, a := range accs {
		if !cache.HasAddress(a.Address) {
			t.Errorf("expected hasAccount(%x) to return true", a.Address)
		}
	}

	// check nonexistent accts do not show up with HasAddress
	if cache.HasAddress(common.HexToAddress("fd9bd350f08ee3c0c19b85a8e16114a11a60aa4e")) {
		t.Errorf("expected hasAccount(%x) to return false", common.HexToAddress("fd9bd350f08ee3c0c19b85a8e16114a11a60aa4e"))
	}

	// Delete a few keys from the cache.
	for i := 0; i < len(accs); i += 2 {
		cacheImpl.deleteByFile(files[i])
	}
	// delete a nonexistent acct
	cacheImpl.deleteByFile("notanacctfile")

	// Check content again after deletion.
	wantAccountsAfterDelete := []accounts.Account{
		accs[1],
		accs[3],
		accs[5],
	}

	sortedWantAccountsAfterDelete := make([]accounts.Account, len(wantAccountsAfterDelete))
	copy(sortedWantAccountsAfterDelete, wantAccountsAfterDelete)
	sort.Sort(accountsByURL(sortedWantAccountsAfterDelete))

	list = cache.Accounts()
	if !reflect.DeepEqual(list, sortedWantAccountsAfterDelete) {
		t.Fatalf("got accounts after delete: %+v\nwant %+v", list, sortedWantAccountsAfterDelete)
	}
	for _, a := range sortedWantAccountsAfterDelete {
		if !cache.HasAddress(a.Address) {
			t.Errorf("expected hasAccount(%x) to return true", a.Address)
		}
	}
	if cache.HasAddress(accs[0].Address) {
		t.Errorf("expected hasAccount(%x) to return false", wantAccounts[0].Address)
	}
}

func TestCache_Find(t *testing.T) {
	// create temporary acctconfigdir
	dir, err := ioutil.TempDir("../test/data", "acctconfig")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	vaulturl := "http://url"
	cache, _ := NewAccountCache(dir, vaulturl)
	cacheImpl := cache.(*accountCache)

	cacheImpl.watcher.running = true // prevent unexpected reloads

	accs := []accounts.Account{
		{
			Address: common.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87"),
			URL:     accounts.URL{Scheme: config.HashiScheme, Path: "url/1"},
		},
		{
			Address: common.HexToAddress("2cac1adea150210703ba75ed097ddfe24e14f213"),
			URL:     accounts.URL{Scheme: config.HashiScheme, Path: "url/2"},
		},
		{
			Address: common.HexToAddress("d49ff4eeb0b2686ed89c0fc0f2b6ea533ddbbd5e"),
			URL:     accounts.URL{Scheme: config.HashiScheme, Path: "url/3"},
		},
		{
			Address: common.HexToAddress("d49ff4eeb0b2686ed89c0fc0f2b6ea533ddbbd5e"),
			URL:     accounts.URL{Scheme: config.HashiScheme, Path: "url/4"},
		},
	}
	for i, a := range accs {
		cache.Add(a, fmt.Sprintf("filepath%v", i))
	}

	nomatchAccount := accounts.Account{
		Address: common.HexToAddress("f466859ead1932d743d622cb74fc058882e8648a"),
		URL:     accounts.URL{Scheme: config.HashiScheme, Path: "url/5"},
	}
	tests := []struct {
		Query      accounts.Account
		WantResult accounts.Account
		WantError  error
	}{
		// by address
		{Query: accounts.Account{Address: accs[0].Address}, WantResult: accs[0]},
		// by file
		{Query: accounts.Account{URL: accs[0].URL}, WantResult: accs[0]},
		// by file and address
		{Query: accs[0], WantResult: accs[0]},
		// ambiguous address, tie resolved by file
		{Query: accs[2], WantResult: accs[2]},
		// ambiguous address error
		{
			Query: accounts.Account{Address: accs[2].Address},
			WantError: &AmbiguousAddrError{
				Addr:    accs[2].Address,
				Matches: []accounts.Account{accs[2], accs[3]},
			},
		},
		// no match error
		{Query: nomatchAccount, WantError: ErrNoMatch},
		{Query: accounts.Account{URL: nomatchAccount.URL}, WantError: ErrNoMatch},
		{Query: accounts.Account{Address: nomatchAccount.Address}, WantError: ErrNoMatch},
	}
	for i, test := range tests {
		a, err := cache.Find(test.Query)
		if !reflect.DeepEqual(err, test.WantError) {
			t.Errorf("test %d: error mismatch for query %v\ngot %q\nwant %q", i, test.Query, err, test.WantError)
			continue
		}
		if a != test.WantResult {
			t.Errorf("test %d: result mismatch for query %v\ngot %v\nwant %v", i, test.Query, a, test.WantResult)
			continue
		}
	}
}

func TestCache_WatchForNewFiles(t *testing.T) {
	// create temporary acctconfigdir
	dir, err := ioutil.TempDir("../test/data", "acctconfig")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// start the cache with no files in the dir
	vaulturl := "http://url"
	cache, _ := NewAccountCache(dir, vaulturl)
	accts := cache.Accounts()
	require.Len(t, accts, 0)

	// add acctconfigs to acctconfigdir
	_, err = utils.AddTempFile(dir, utils.Acct1JsonConfig)
	require.NoError(t, err)
	_, err = utils.AddTempFile(dir, utils.Acct2JsonConfig)
	require.NoError(t, err)

	// add an invalid acctconfig (addr is not valid) - this should not be added to the cache
	invalidAcctJsonConfig := []byte(`{
  "address": "invalid",
  "vaultsecret": {
    "pathparams": {
      "secretenginepath": "engine",
      "secretpath": "engineacct",
      "secretversion": 2
    },
    "authid": "FOO"
  },
  "id": "d88bd481-4db4-4ee5-8ea6-84042d2fb0cf",
  "version": 1
}`)

	_, err = utils.AddTempFile(dir, invalidAcctJsonConfig)
	require.NoError(t, err)

	time.Sleep(2500 * time.Millisecond)

	accts = cache.Accounts()
	require.Len(t, accts, 2)

	if !reflect.DeepEqual(accts, initialAccounts) {
		t.Fatalf("got initial accounts: %+v\nwant %+v", accts, initialAccounts)
	}
}

func TestCache_WatchForFileDeletes(t *testing.T) {
	// create temporary acctconfigdir
	dir, err := ioutil.TempDir("../test/data", "acctconfig")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// add acctconfigs to acctconfigdir
	file, err := utils.AddTempFile(dir, utils.Acct1JsonConfig)
	require.NoError(t, err)

	// start the cache with no files in the dir
	vaulturl := "http://url"
	cache, _ := NewAccountCache(dir, vaulturl)
	accts := cache.Accounts()
	require.Len(t, accts, 1)
	require.Contains(t, accts, initialAccounts[1])

	// delete the file and check the account is removed from the cache
	err = os.Remove(file)
	require.NoError(t, err)
	time.Sleep(2500 * time.Millisecond)

	accts = cache.Accounts()
	require.Len(t, accts, 0)
}

// TestUpdatedKeyfileContents tests that updating the contents of a keystore file
// is noticed by the watcher, and the account cache is updated accordingly
func TestCache_WatchForFileUpdates(t *testing.T) {
	// create temporary acctconfigdir
	dir, err := ioutil.TempDir("../test/data", "acctconfig")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// add acctconfigs to acctconfigdir
	file, err := utils.AddTempFile(dir, utils.Acct1JsonConfig)
	require.NoError(t, err)

	vaulturl := "http://url"
	cache, _ := NewAccountCache(dir, vaulturl)
	accts := cache.Accounts()
	require.Contains(t, accts, initialAccounts[1])

	// update the file and check that the account in the cache is replaced
	err = ioutil.WriteFile(file, utils.Acct2JsonConfig, 0644)
	require.NoError(t, err)
	time.Sleep(2500 * time.Millisecond)
	accts = cache.Accounts()
	require.Contains(t, accts, initialAccounts[0])

	// update the file to contain invalid contents and check that there are no accts in the cache
	err = ioutil.WriteFile(file, []byte("invalid"), 0644)
	require.NoError(t, err)
	time.Sleep(2500 * time.Millisecond)
	accts = cache.Accounts()
	require.Len(t, accts, 0)
}

func TestCache_WatchNoDir(t *testing.T) {
	dir := fmt.Sprintf("../test/data/acctconfig%v", uuid.New())

	// start the cache with non-existent dir
	vaulturl := "http://url"
	cache, _ := NewAccountCache(dir, vaulturl)
	accts := cache.Accounts()
	require.Len(t, accts, 0)

	// create the dir and add acctconfig
	err := os.Mkdir(dir, 0744)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	_, err = utils.AddTempFile(dir, utils.Acct1JsonConfig)
	require.NoError(t, err)

	time.Sleep(2500 * time.Millisecond)

	accts = cache.Accounts()
	require.Len(t, accts, 1)
	require.Contains(t, accts, initialAccounts[1])
}

func TestCache_CloseStopsWatch(t *testing.T) {
	// create temporary acctconfigdir
	dir, err := ioutil.TempDir("../test/data", "acctconfig")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// start the cache with no files in the dir
	vaulturl := "http://url"
	cache, _ := NewAccountCache(dir, vaulturl)
	accts := cache.Accounts()
	require.Len(t, accts, 0)

	// close the cache
	cache.Close()

	// add acctconfigs to acctconfigdir
	_, err = utils.AddTempFile(dir, utils.Acct1JsonConfig)
	require.NoError(t, err)
	_, err = utils.AddTempFile(dir, utils.Acct2JsonConfig)
	require.NoError(t, err)

	time.Sleep(2500 * time.Millisecond)

	//check that the accounts are not added to the cache
	cacheImpl := cache.(*accountCache)
	cacheImpl.watcher.running = true // prevent unexpected reloads
	accts = cache.Accounts()
	require.Len(t, accts, 0)
}
