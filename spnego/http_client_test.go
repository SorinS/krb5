package spnego

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stepTransport redirects /step/i to /step/i+1 until i reaches limit, then 200.
// It keeps no state, so it is safe for concurrent requests.
type stepTransport struct{ limit int }

func (s stepTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	i := 0
	fmt.Sscanf(r.URL.Path, "/step/%d", &i)

	if i < s.limit {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": {fmt.Sprintf("http://h.test/step/%d", i+1)}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

func stepClient(limit int) *Client {
	return NewClient(nil, &http.Client{Transport: stepTransport{limit: limit}}, "")
}

func get(t *testing.T, c *Client, n int) (*http.Response, error) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://h.test/step/%d", n), nil)
	require.NoError(t, err)

	return c.Do(req)
}

func TestClient_Do_FollowsRedirects(t *testing.T) {
	resp, err := get(t, stepClient(5), 0)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestClient_Do_StopsAtDefaultLimit(t *testing.T) {
	_, err := get(t, stepClient(100), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("stopped after %d redirects", defaultMaxRedirects))
}

func TestClient_Do_MaxRedirectsConfigurable(t *testing.T) {
	c := stepClient(100)
	c.MaxRedirects = 3

	_, err := get(t, c, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stopped after 3 redirects")
}

// The redirect count is per call, not shared on the Client: concurrent Do calls
// do not race (run with -race) and each follows its own chain.
func TestClient_Do_Concurrent(t *testing.T) {
	c := stepClient(5)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			resp, err := get(t, c, 0)
			assert.NoError(t, err)

			if err == nil {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			}
		}()
	}

	wg.Wait()
}

// setRequestSPN derives the SPN from the URL host (canonicalized, port
// dropped) and leaves r.Host as the caller set it: a service behind a proxy or
// load balancer is dialed by one name but sends another in the Host header,
// and the earlier code overwrote that with the dialed name.
func TestSetRequestSPN_DoesNotRewriteHost(t *testing.T) {
	for _, u := range []string{"http://web.service.invalid:8443/path", "http://web.service.invalid/path"} {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		require.NoError(t, err)

		// A Host header distinct from the dialed URL host.
		req.Host = "vhost.public.example"

		spn, err := setRequestSPN(req)
		require.NoError(t, err, u)

		// The SPN is the URL host (.invalid never resolves, so as written),
		// not the Host header.
		assert.Equal(t, "HTTP/web.service.invalid", spn.PrincipalNameString(), u)
		assert.Equal(t, "vhost.public.example", req.Host, "Host must not be rewritten: %s", u)
	}
}
