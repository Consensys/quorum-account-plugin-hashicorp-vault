package utils

import (
	"os"
)

// SetEnvironmentVariables sets environment variables and returns a function to unset those variables.  The values of the toSet environment variables are equal to their names (i.e. toSet = {"FOO"} will set FOO=FOO)
func SetEnvironmentVariables(toSet ...string) func() {
	for _, s := range toSet {
		os.Setenv(s, s)
	}

	return func() {
		for _, s := range toSet {
			os.Unsetenv(s)
		}
	}
}
