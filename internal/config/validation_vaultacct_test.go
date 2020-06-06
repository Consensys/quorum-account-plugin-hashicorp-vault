package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func minimumValidNewAccountConfig() NewAccount {
	return NewAccount{
		SecretName: "secret",
		OverwriteProtection: OverwriteProtection{
			InsecureDisable: false,
			CurrentVersion:  0,
		},
	}
}

func TestNewAccount_Validate_MinimumValidConfig(t *testing.T) {
	err := minimumValidNewAccountConfig().Validate()
	require.NoError(t, err)
}

func TestNewAccount_Validate_SecretName_Invalid(t *testing.T) {
	var (
		conf    NewAccount
		err     error
		wantErr = InvalidSecretName
	)

	conf = minimumValidNewAccountConfig()
	conf.SecretName = ""
	err = conf.Validate()
	require.EqualError(t, err, wantErr)
}

func TestNewAccount_Validate_OverwriteProtection_Valid(t *testing.T) {
	var (
		conf NewAccount
		err  error
	)

	conf = minimumValidNewAccountConfig()
	conf.OverwriteProtection.InsecureDisable = true
	conf.OverwriteProtection.CurrentVersion = 0
	err = conf.Validate()
	require.NoError(t, err)

	conf = minimumValidNewAccountConfig()
	conf.OverwriteProtection.InsecureDisable = false
	conf.OverwriteProtection.CurrentVersion = 1
	err = conf.Validate()
	require.NoError(t, err)

	conf = minimumValidNewAccountConfig()
	conf.OverwriteProtection.InsecureDisable = false
	conf.OverwriteProtection.CurrentVersion = 0
	err = conf.Validate()
	require.NoError(t, err)
}

func TestNewAccount_Validate_OverwriteProtection_Invalid(t *testing.T) {
	var (
		conf    NewAccount
		err     error
		wantErr = InvalidOverwriteProtection
	)

	conf = minimumValidNewAccountConfig()
	conf.OverwriteProtection.InsecureDisable = true
	conf.OverwriteProtection.CurrentVersion = 1
	err = conf.Validate()
	require.EqualError(t, err, wantErr)
}
