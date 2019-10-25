package utils

//
//// make sure the SetEnvironmentVariables test-helper works as intended
//func TestSetEnvironmentVariables(t *testing.T) {
//	var (
//		key1 = "ENV1"
//		key2 = "ENV2"
//		key3 = "ENV3"
//		val1 = "val1"
//		val2 = "val2"
//		val3 = "val3"
//	)
//
//	var (
//		isSet bool
//		got string
//	)
//
//	_, isSet = os.LookupEnv(key1)
//	require.False(t, isSet)
//	_, isSet = os.LookupEnv(key2)
//	require.False(t, isSet)
//	_, isSet = os.LookupEnv(key3)
//	require.False(t, isSet)
//
//	unsetFn, err := SetEnvironmentVariables(key1, val1, key2, val2, key3, val3)
//
//	require.NoError(t, err)
//	got, isSet = os.LookupEnv(key1)
//	require.True(t, isSet)
//	require.Equal(t, val1, got)
//	got, isSet = os.LookupEnv(key2)
//	require.True(t, isSet)
//	require.Equal(t, val2, got)
//	got, isSet = os.LookupEnv(key3)
//	require.True(t, isSet)
//	require.Equal(t, val3, got)
//
//	unsetFn()
//
//	_, isSet = os.LookupEnv(key1)
//	require.False(t, isSet)
//	_, isSet = os.LookupEnv(key2)
//	require.False(t, isSet)
//	_, isSet = os.LookupEnv(key3)
//	require.False(t, isSet)
//}
