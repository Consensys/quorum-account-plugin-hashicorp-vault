package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"math/rand"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type Request struct {
	JsonRPC string
	Method  string
	Params  []interface{}
	ID      int
}

func NewRPCRequest(t *testing.T, method string, paramsJSON string) Request {
	var params []interface{}
	byt := []byte(paramsJSON)
	err := json.Unmarshal(byt, &params)
	require.NoError(t, err)

	return Request{
		JsonRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      rand.Int(),
	}
}

func (r *Request) HTTPDo(url string) (*http.Response, error) {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(r); err != nil {
		return nil, err
	}
	return http.Post(url, "application/json", buf)
}

func (r *Request) UnixDo(t *testing.T, stdioui bool, clef clef, unixSocket string) map[string]interface{} {
	c, err := net.Dial("unix", unixSocket)
	require.NoError(t, err)
	defer c.Close()

	buf := new(bytes.Buffer)
	err = json.NewEncoder(buf).Encode(r)
	require.NoError(t, err)

	log.Print("sending request over unix socket")
	_, err = c.Write(buf.Bytes())
	require.NoError(t, err)

	if !stdioui {
		// approve request and wait for response
		<-time.After(1 * time.Second)
		clef.y(t)
		<-time.After(1 * time.Second)
	}

	log.Print("getting response from unix socket")
	d := json.NewDecoder(c)
	var resp map[string]interface{}

	err = d.Decode(&resp)
	require.NoError(t, err)

	result, ok := resp["result"]
	require.True(t, ok, "clef response does not contain result data")

	return result.(map[string]interface{})
}

func (r *Request) UnixDoExpectError(t *testing.T, clef clef, unixSocket string) string {
	c, err := net.Dial("unix", unixSocket)
	require.NoError(t, err)
	defer c.Close()

	buf := new(bytes.Buffer)
	err = json.NewEncoder(buf).Encode(r)
	require.NoError(t, err)

	log.Print("sending request over unix socket")
	_, err = c.Write(buf.Bytes())
	require.NoError(t, err)

	// approve request and wait for response
	<-time.After(1 * time.Second)
	clef.y(t)
	<-time.After(1 * time.Second)

	log.Print("getting response from unix socket")

	// TODO(cjh) need more robust solution here - multiple scans & timeout if deadlock ?
	scanner := bufio.NewScanner(c)
	scanner.Scan()
	clefOut := scanner.Text()

	return clefOut
}
