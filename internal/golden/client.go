package golden

import (
	"crypto/tls"
	"errors"
	"io"
	"time"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// Run drives script against the server at addr over TLS and
// returns the transcript.
//
// The same function drives both implementations: the oracle
// over TCP to the container, Olivine over TCP to an in-process
// listener. Identical bytes out, so a difference in the
// transcript is a difference in the server.
func Run(addr string, script Script) (*Transcript, error) {
	c, err := tls.Dial("tcp", addr, &tls.Config{
		// The oracle's certificate is generated per run and
		// is not the thing under test.
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
	return runSteps(c, script)
}

// runSteps sends each request and collects the replies.
func runSteps(
	c io.ReadWriter, script Script,
) (*Transcript, error) {
	t := &Transcript{}
	for i, req := range script.Requests {
		packet, err := req.Encode(int32(i + 1))
		if err != nil {
			return nil, err
		}
		if _, err := c.Write(packet); err != nil {
			return nil, err
		}
		if req.NoReply {
			t.Steps = append(t.Steps, Step{
				Op: req.Name, Result: "(no reply)",
			})
			continue
		}
		step, err := collect(c, req.Name)
		if err != nil {
			return nil, err
		}
		t.Steps = append(t.Steps, step)
	}
	t.Normalise()
	return t, nil
}

// collect reads replies until the operation's result arrives.
//
// A search sends zero or more entries before its result, so
// this cannot read exactly one message.
func collect(c io.Reader, name string) (Step, error) {
	step := Step{Op: name}
	for {
		packet, err := ber.ReadPacket(
			c, ber.MaxIncomingAuth)
		if err != nil {
			if errors.Is(err, io.EOF) {
				step.Result = "(connection closed)"
				return step, nil
			}
			return step, err
		}
		m, err := ldap.ParseMessage(packet)
		if err != nil {
			return step, err
		}
		done, err := absorb(&step, m)
		if err != nil {
			return step, err
		}
		if done {
			return step, nil
		}
	}
}
