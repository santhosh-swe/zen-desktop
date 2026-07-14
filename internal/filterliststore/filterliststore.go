package filterliststore

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"regexp"
	"syscall"
	"time"

	"github.com/irbis-sh/zen-desktop/internal/filterliststore/diskcache"
)

const (
	defaultExpiry = 24 * time.Hour
	// maxListSize bounds the size of a single downloaded filter list so that a
	// compromised list host cannot exhaust memory or disk.
	maxListSize = 20 << 20 // 20 MiB
	// maxRedirects bounds redirect chains followed while downloading lists.
	maxRedirects = 3
)

var (
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			// Proxy is intentionally nil: list downloads always connect
			// directly, so proxy env vars cannot reroute them.
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				// Control runs on every connection attempt with the resolved
				// address, so it also covers redirects and DNS rebinding.
				Control: func(_, address string, _ syscall.RawConn) error {
					host, _, err := net.SplitHostPort(address)
					if err != nil {
						return fmt.Errorf("split host/port: %w", err)
					}
					ip := net.ParseIP(host)
					if ip == nil {
						return fmt.Errorf("dial target %q is not an IP address", host)
					}
					if !isPublicIP(ip) {
						return fmt.Errorf("refusing to connect to non-public address %s", ip)
					}
					return nil
				},
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "https" {
				return errors.New("refusing to follow redirect to non-HTTPS URL")
			}
			return nil
		},
	}
	// headerRegex matches comments prefixed with a hash and [Adblock Plus 2.0]-style headers.
	headerRegex = regexp.MustCompile(`^(?:!|\[|#[^#%@$])`)
)

// isPublicIP reports whether ip is a globally routable unicast address.
// Loopback, RFC 1918/4193 private, link-local (including the cloud metadata
// range), multicast, and unspecified addresses are all rejected.
func isPublicIP(ip net.IP) bool {
	switch {
	case ip.IsLoopback(),
		ip.IsPrivate(),
		ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast(),
		ip.IsUnspecified():
		return false
	default:
		return true
	}
}

// maxSizeReader errors once more than limit bytes have been read.
type maxSizeReader struct {
	r         io.Reader
	remaining int64
}

func (m *maxSizeReader) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	m.remaining -= int64(n)
	if m.remaining < 0 {
		return n, fmt.Errorf("filter list exceeds the maximum allowed size of %d bytes", maxListSize)
	}
	return n, err
}

type FilterListStore struct {
	cache *diskcache.Cache
}

func New(cachePath string) (*FilterListStore, error) {
	cache, err := diskcache.New(cachePath)
	if err != nil {
		return nil, fmt.Errorf("create cache: %v", err)
	}

	return &FilterListStore{
		cache: cache,
	}, nil
}

func (st *FilterListStore) Get(url string) (io.ReadCloser, error) {
	// Hardened build: filter lists may only be fetched over HTTPS. Enforced
	// before the cache lookup so previously cached plaintext-HTTP lists are
	// also refused.
	if parsedURL, err := neturl.Parse(url); err != nil {
		return nil, fmt.Errorf("parse url: %v", err)
	} else if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("refusing to fetch filter list over %q: only HTTPS is allowed", parsedURL.Scheme)
	}

	if content, err := st.cache.Load(url); err != nil {
		log.Printf("failed to load from cache: %v", err)
	} else if content != nil {
		log.Printf("loading %q from cache", url)
		return content, nil
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %v", err)
	}

	resp, err := httpClient.Do(req) // #nosec G704 -- URL is validated as HTTPS above, and the transport refuses non-public dial targets.
	if err != nil {
		return nil, fmt.Errorf("do request: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("non-200 response: %q", resp.Status)
	}

	if resp.ContentLength > maxListSize {
		resp.Body.Close()
		return nil, fmt.Errorf("filter list size %d exceeds the maximum allowed size of %d bytes", resp.ContentLength, maxListSize)
	}

	var teeBuffer bytes.Buffer
	var notifyCh <-chan struct{}
	var errCh <-chan struct{}
	resp.Body, notifyCh, errCh = newNotifyReadCloser(struct {
		io.Reader
		io.Closer
	}{
		Reader: io.TeeReader(&maxSizeReader{r: resp.Body, remaining: maxListSize}, &teeBuffer),
		Closer: resp.Body,
	})

	go func() {
		// The goal here is to make caching non-blocking. Data from the response body is cloned into teeBuffer,
		// and the cache is saved in a separate goroutine.
		// This allows the consumer of Get to start reading the response body without waiting for the entire response to be fetched.
		select {
		case <-errCh:
			// An error occurred while reading the response body, so the response should not be cached.
			return
		case <-notifyCh:
			// The response body has been closed, and we can proceed to cache the content.
		}

		cacheContent, _ := io.ReadAll(&teeBuffer) // err is always nil with bytes.Buffer.

		var cacheTTL time.Duration
		scanner := bufio.NewScanner(bytes.NewReader(cacheContent))

	outer:
		for scanner.Scan() {
			line := scanner.Bytes()

			if len(line) != 0 && !headerRegex.Match(line) {
				// Stop scanning for "! Expires" if we encounter a non-comment line.
				break
			}

			cacheTTL, err = parseExpires(line)
			switch {
			case errors.Is(err, errNotExpires):
				continue
			case err != nil:
				log.Printf("failed to parse cache TTL from %q, assuming default: %v", line, err)
				break outer
			default:
				break outer
			}
		}

		if cacheTTL == 0 {
			// Default to 24 hours if no expiry is found.
			cacheTTL = defaultExpiry
		}
		expiresAt := time.Now().Add(cacheTTL) // time.Now() might deviate from the time the request was received, but it isn't critical.

		if err := st.cache.Save(url, cacheContent, expiresAt); err != nil {
			log.Printf("failed to store in cache: %v", err)
		}
	}()

	return resp.Body, nil
}
