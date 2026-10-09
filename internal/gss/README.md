# internal/gss

The acceptor side of Kerberos 5 GSS-API, as much as a SASL
GSSAPI bind needs. New code: `sasl.c` delegates the mechanism
to Cyrus SASL, which delegates it to MIT Kerberos, so there is
no C in the submodule to port.

What *is* ported is the observed exchange. It was captured by
putting a logging TCP proxy between upstream's own `ldapwhoami`
and slapd, which settled two things reading RFC 4752 would not
have:

- it is **three** LDAP bind round trips, and
- the client's **second request carries no credentials field at
  all** — not an empty one. A server that required
  present-but-empty would refuse every MIT client.

## The exchange

| Step | Client sends | Acceptor answers |
|---|---|---|
| 1 | initial context token wrapping an AP-REQ | one wrapping an AP-REP, `saslBindInProgress` |
| 2 | the mechanism name, no credentials | Wrap token: security-layer bitmask and maximum buffer |
| 3 | Wrap token: the layer it chose | success, no credentials |

## Only no-security-layer is offered

slapd offers integrity and confidentiality too, and MIT takes
confidentiality by default — over `ldaps://` that is a second
layer of encryption inside the first, which the oracle was
observed doing. Olivine is TLS-only, so there is nothing left
for a SASL security layer to protect. A client sees `SASL SSF:
0`.

## gokrb5 is a client library

Which shows twice on this side of the exchange: it can read an
AP-REP but not write one, and it ships `NewInitiatorWrapToken`
with no acceptor counterpart. So `aprep.go` writes the AP-REP
and `wrap.go` builds the acceptor's Wrap token, where both the
flags and the key usage change direction. Either one wrong fails
as a bad checksum rather than as a type error — hence the unit
tests here and `make golden-gssapi` for the rest.

One sharp edge: `WrapToken.SetCheckSum` computes the checksum
but leaves `EC` at zero, and `EC` is the checksum's length on an
unsealed token. Marshalling without setting it puts the payload
where the client looks for the checksum.

Another: the AP-REQ is verified through `service.VerifyAPREQ`,
not `APReq.Verify`. The second does every check *except* the
replay detection RFC 4120 §3.2.3 requires — the cache lives one
layer up. An AP-REQ is valid for the whole clock-skew window, so
without it a captured one could be presented twice.
