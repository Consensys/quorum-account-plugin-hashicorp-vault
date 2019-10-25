package utils

import (
	"os"
)

// SetEnvironmentVariables sets environment variables and returns a function to unset those variables.  toSet is a variadic list of key/value pairs; therefore the number of args provided must be a multiple of 2.
func SetEnvironmentVariables(toSet ...string) func() {
	//if len(toSet) % 2 != 0 {
	//	return func(){}, errors.New("SetEnvironmentVariables test-helper error: env var key provided without value")
	//}
	//
	//for i := 0; i < len(toSet); i = i + 2 {
	//	os.Setenv(toSet[i], toSet[i+1])
	//}
	//
	//return func() {
	//	for i := 0; i < len(toSet); i = i + 2 {
	//		os.Unsetenv(toSet[i])
	//	}
	//}, nil

	for _, s := range toSet {
		os.Setenv(s, s)
	}

	return func() {
		for _, s := range toSet {
			os.Unsetenv(s)
		}
	}
}
