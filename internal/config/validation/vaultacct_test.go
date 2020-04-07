package validation

import (
	"net/url"
	"testing"

	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/stretchr/testify/require"
)

func toUrl(t *testing.T, raw string) *url.URL {
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func minimumValidNewAccountConfig(t *testing.T) config.NewAccount {
	return config.NewAccount{
		SecretEnginePath: "engine",
		SecretPath:       "secret",
		InsecureSkipCAS:  false,
		CASValue:         0,
	}
}

func TestNewAccount_Validate_MinimumValidConfig(t *testing.T) {
	err := minimumValidNewAccountConfig(t).Validate()
	require.NoError(t, err)
}

func TestNewAccount_Validate_SecretLocation_Invalid(t *testing.T) {
	var (
		conf    config.NewAccount
		err     error
		wantErr = config.InvalidSecretLocation
	)

	conf = minimumValidNewAccountConfig(t)
	conf.SecretPath = ""
	err = conf.Validate()
	require.EqualError(t, err, wantErr)

	conf = minimumValidNewAccountConfig(t)
	conf.SecretEnginePath = ""
	err = conf.Validate()
	require.EqualError(t, err, wantErr)

	conf = minimumValidNewAccountConfig(t)
	conf.SecretEnginePath = ""
	conf.SecretPath = ""
	err = conf.Validate()
	require.EqualError(t, err, wantErr)
}

func TestNewAccount_Validate_CAS_Valid(t *testing.T) {
	var (
		conf config.NewAccount
		err  error
	)

	conf = minimumValidNewAccountConfig(t)
	conf.InsecureSkipCAS = true
	conf.CASValue = 0
	err = conf.Validate()
	require.NoError(t, err)

	conf = minimumValidNewAccountConfig(t)
	conf.InsecureSkipCAS = false
	conf.CASValue = 1
	err = conf.Validate()
	require.NoError(t, err)

	conf = minimumValidNewAccountConfig(t)
	conf.InsecureSkipCAS = false
	conf.CASValue = 0
	err = conf.Validate()
	require.NoError(t, err)
}

func TestNewAccount_Validate_CAS_Invalid(t *testing.T) {
	var (
		conf    config.NewAccount
		err     error
		wantErr = config.InvalidCAS
	)

	conf = minimumValidNewAccountConfig(t)
	conf.InsecureSkipCAS = true
	conf.CASValue = 1
	err = conf.Validate()
	require.EqualError(t, err, wantErr)
}
