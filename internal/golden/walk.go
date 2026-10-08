package golden

import (
	"crypto/tls"
	"fmt"
	"time"
)

// maxPages bounds a paged walk, so a server that never returns an
// empty cookie fails the test instead of hanging it.
const maxPages = 50

// WalkPages drives a paged search to its end and returns the DNs
// of each page in order.
//
// One connection for the whole walk: slapd keeps paged state per
// connection, so a cookie from one connection is not valid on
// another.
func WalkPages(
	addr string, size int32,
) ([][]string, error) {
	c, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := c.SetDeadline(
		time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	return walk(c, size)
}

// walk sends one request per page until the cookie comes back
// empty.
func walk(
	c *tls.Conn, size int32,
) ([][]string, error) {
	var pages [][]string
	var cookie []byte
	for i := 0; i < maxPages; i++ {
		dns, next, err := onePage(
			c, int32(i+1), size, cookie)
		if err != nil {
			return nil, err
		}
		pages = append(pages, dns)
		if len(next) == 0 {
			return pages, nil
		}
		cookie = next
	}
	return nil, fmt.Errorf(
		"paged search did not end within %d pages",
		maxPages)
}
