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
	"math/big"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
)

// wallet implements the accounts.Wallet interface for the original
// keystore.
type wallet struct {
	account accounts.Account // Single account contained in this wallet
	backend *Backend         // Keystore where the account originates from
}

// URL implements accounts.Wallet, returning the URL of the account within.
func (w *wallet) URL() accounts.URL {
	return w.account.URL
}

// Status implements accounts.Wallet, returning whether the account held by the
// keystore wallet is unlocked or not.
func (w *wallet) Status() (string, error) {
	w.backend.mu.RLock()
	defer w.backend.mu.RUnlock()

	if _, ok := w.backend.unlocked[w.account.Address]; ok {
		return "Unlocked", nil
	}
	return "Locked", nil
}

// Open implements accounts.Wallet, but is a noop for plain wallets since there
// is no connection or decryption step necessary to access the list of accounts.
func (w *wallet) Open(passphrase string) error { return nil }

// Close implements accounts.Wallet, but is a noop for plain wallets since is no
// meaningful open operation.
func (w *wallet) Close() error { return nil }

// Accounts implements accounts.Wallet, returning an account list consisting of
// a single account that the plain kestore wallet contains.
func (w *wallet) Accounts() []accounts.Account {
	return []accounts.Account{w.account}
}

// Contains implements accounts.Wallet, returning whether a particular account is
// or is not wrapped by this wallet instance.
func (w *wallet) Contains(account accounts.Account) bool {
	return account.Address == w.account.Address && (account.URL == (accounts.URL{}) || account.URL == w.account.URL)
}

// Derive implements accounts.Wallet, but is a noop for plain wallets since there
// is no notion of hierarchical account derivation for plain keystore accounts.
func (w *wallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	return accounts.Account{}, accounts.ErrNotSupported
}

// SelfDerive implements accounts.Wallet, but is a noop for plain wallets since
// there is no notion of hierarchical account derivation for plain keystore accounts.
func (w *wallet) SelfDerive(base accounts.DerivationPath, chain ethereum.ChainStateReader) {}

// SignHash implements accounts.Wallet, attempting to sign the given hash with
// the given account. If the wallet does not wrap this particular account, an
// error is returned to avoid account leakage (even though in theory we may be
// able to sign via our shared keystore backend).
func (w *wallet) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	if account.Address != w.account.Address {
		return nil, accounts.ErrUnknownAccount
	}
	if account.URL != (accounts.URL{}) && account.URL != w.account.URL {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the backend to sign
	return w.backend.SignHash(account, hash)
}

// SignTx implements accounts.Wallet, attempting to sign the given transaction
// with the given account. If the wallet does not wrap this particular account,
// an error is returned to avoid account leakage (even though in theory we may
// be able to sign via our shared keystore backend).
func (w *wallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	// Make sure the requested account is contained within
	if account.Address != w.account.Address {
		return nil, accounts.ErrUnknownAccount
	}
	if account.URL != (accounts.URL{}) && account.URL != w.account.URL {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the backend to sign
	return w.backend.SignTx(account, tx, chainID)
}

// SignHashWithPassphrase implements accounts.Wallet, attempting to sign the
// given hash with the given account using passphrase as extra authentication.
func (w *wallet) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	if account.Address != w.account.Address {
		return nil, accounts.ErrUnknownAccount
	}
	if account.URL != (accounts.URL{}) && account.URL != w.account.URL {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the backend to sign
	return w.backend.SignHashWithPassphrase(account, passphrase, hash)
}

// SignTxWithPassphrase implements accounts.Wallet, attempting to sign the given
// transaction with the given account using passphrase as extra authentication.
func (w *wallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	// Make sure the requested account is contained within
	if account.Address != w.account.Address {
		return nil, accounts.ErrUnknownAccount
	}
	if account.URL != (accounts.URL{}) && account.URL != w.account.URL {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the backend to sign
	return w.backend.SignTxWithPassphrase(account, passphrase, tx, chainID)
}