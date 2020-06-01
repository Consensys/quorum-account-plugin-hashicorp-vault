package validation

import (
	"testing"

	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/stretchr/testify/require"
)

func minimumValidNewAccountConfig() config.NewAccount {
	return config.NewAccount{
		SecretEnginePath: "engine",
		SecretPath:       "secret",
		InsecureSkipCAS:  false,
		CASValue:         0,
	}
}

func TestNewAccount_Validate_MinimumValidConfig(t *testing.T) {
	err := minimumValidNewAccountConfig().Validate()
	require.NoError(t, err)
}

func TestNewAccount_Validate_SecretLocation_Invalid(t *testing.T) {
	var (
		conf    config.NewAccount
		err     error
		wantErr = config.InvalidSecretLocation
	)

	conf = minimumValidNewAccountConfig()
	conf.SecretPath = ""
	err = conf.Validate()
	require.EqualError(t, err, wantErr)

	conf = minimumValidNewAccountConfig()
	conf.SecretEnginePath = ""
	err = conf.Validate()
	require.EqualError(t, err, wantErr)

	conf = minimumValidNewAccountConfig()
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

	conf = minimumValidNewAccountConfig()
	conf.InsecureSkipCAS = true
	conf.CASValue = 0
	err = conf.Validate()
	require.NoError(t, err)

	conf = minimumValidNewAccountConfig()
	conf.InsecureSkipCAS = false
	conf.CASValue = 1
	err = conf.Validate()
	require.NoError(t, err)

	conf = minimumValidNewAccountConfig()
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

	conf = minimumValidNewAccountConfig()
	conf.InsecureSkipCAS = true
	conf.CASValue = 1
	err = conf.Validate()
	require.EqualError(t, err, wantErr)
}
