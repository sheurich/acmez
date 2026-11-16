// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package acme

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
)

// Challenge holds information about an ACME challenge.
//
// "An ACME challenge object represents a server's offer to validate a
// client's possession of an identifier in a specific way.  Unlike the
// other objects listed above, there is not a single standard structure
// for a challenge object.  The contents of a challenge object depend on
// the validation method being used.  The general structure of challenge
// objects and an initial set of validation methods are described in
// Section 8." §7.1.5
type Challenge struct {
	// "Challenge objects all contain the following basic fields..." §8

	// type (required, string):  The type of challenge encoded in the
	// object.
	Type string `json:"type"`

	// url (required, string):  The URL to which a response can be posted.
	URL string `json:"url"`

	// status (required, string):  The status of this challenge.  Possible
	// values are "pending", "processing", "valid", and "invalid" (see
	// Section 7.1.6).
	Status string `json:"status"`

	// validated (optional, string):  The time at which the server validated
	// this challenge, encoded in the format specified in [RFC3339].
	// This field is REQUIRED if the "status" field is "valid".
	Validated string `json:"validated,omitempty"`

	// error (optional, object):  Error that occurred while the server was
	// validating the challenge, if any, structured as a problem document
	// [RFC7807].  Multiple errors can be indicated by using subproblems
	// Section 6.7.1.  A challenge object with an error MUST have status
	// equal to "invalid".
	Error *Problem `json:"error,omitempty"`

	// "All additional fields are specified by the challenge type." §8
	// (We also add our own for convenience.)

	// "The token for a challenge is a string comprised entirely of
	// characters in the URL-safe base64 alphabet." §8.1
	//
	// Used by the http-01, tls-alpn-01, and dns-01 challenges.
	Token string `json:"token,omitempty"`

	// A key authorization is a string that concatenates the token for the
	// challenge with a key fingerprint, separated by a "." character (§8.1):
	//
	//     keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))
	//
	// This client package automatically assembles and sets this value for you.
	KeyAuthorization string `json:"keyAuthorization,omitempty"`

	// We attach the identifier that this challenge is associated with, which
	// may be useful information for solving a challenge. It is not part of the
	// structure as defined by the spec but is added by us to provide enough
	// information to solve the DNS-01 challenge.
	Identifier Identifier `json:"identifier,omitempty"`

	// Wildcard is copied from the parent Authorization when the authorization
	// is for a wildcard domain name (RFC 8555 §7.1.4).
	Wildcard bool `json:"wildcard,omitempty"`

	// From header of email must match with the "from" field of challenge object
	// as described in RFC8823 §3.1 - 2, added on 3-6.3.1
	From string `json:"from,omitempty"`

	// Payload contains a JSON-marshallable value that will be sent to the CA
	// when responding to challenges. If not set, an empty JSON body "{}" will
	// be included in the POST request. This field is applicable when responding
	// to "device-attest-01" challenges.
	Payload any `json:"-"`

	// TkAuthType is the Authority Token Subtype as described in RFC9447 §3
	// This field is only applicable when responding to "tkauth-01" challenges
	// and indicates the type of Authority token that will be used
	// to validate the challenge.
	TkAuthType string `json:"tkauth-type,omitempty"`

	// IssuerDomainNames is a list of Issuer Domain Names provided by the CA
	// in a dns-persist-01 challenge. The client selects one to use when
	// constructing the persistent TXT record value.
	// Each name is in A-label format, lowercase, without trailing dot.
	// draft-ietf-acme-dns-persist-03 §3.1
	IssuerDomainNames []string `json:"issuerDomainNames,omitempty"`
}

// HTTP01ResourcePath returns the URI path for solving the http-01 challenge.
//
// "The path at which the resource is provisioned is comprised of the
// fixed prefix '/.well-known/acme-challenge/', followed by the 'token'
// value in the challenge." §8.3
func (c Challenge) HTTP01ResourcePath() string {
	return "/.well-known/acme-challenge/" + c.Token
}

// DNS01TXTRecordName returns the name of the TXT record to create for
// solving the dns-01 challenge.
//
// "The client constructs the validation domain name by prepending the
// label '_acme-challenge' to the domain name being validated, then
// provisions a TXT record with the digest value under that name." §8.4
func (c Challenge) DNS01TXTRecordName() string {
	return "_acme-challenge." + c.Identifier.Value
}

// DNS01KeyAuthorization encodes a key authorization value to be used
// in a TXT record for the _acme-challenge DNS record.
//
// "A client fulfills this challenge by constructing a key authorization
// from the 'token' value provided in the challenge and the client's
// account key.  The client then computes the SHA-256 digest [FIPS180-4]
// of the key authorization.
//
// The record provisioned to the DNS contains the base64url encoding of
// this digest." §8.4
func (c Challenge) DNS01KeyAuthorization() string {
	h := sha256.Sum256([]byte(c.KeyAuthorization))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// DNSAccount01TXTRecordName returns the name of the TXT record to create
// for solving the dns-account-01 challenge. §3.2
//
// The base32 encoding uses the standard RFC 4648 alphabet (uppercase A-Z),
// but DNS labels are converted to lowercase for canonical form and
// interoperability. Some providers (e.g., CloudFront, GlobalSign) enforce
// lowercase labels, making lowercase conversion essential for reliable operation.
func (c Challenge) DNSAccount01TXTRecordName(a Account) string {
	acctURLhash := sha256.Sum256([]byte(a.Location))
	truncAcctURLHash := acctURLhash[:10]
	b32TruncAcctURLHash := base32.StdEncoding.EncodeToString(truncAcctURLHash)
	canonicalForm := strings.ToLower(b32TruncAcctURLHash)
	return fmt.Sprintf("_%s._acme-challenge.%s", canonicalForm, c.Identifier.Value)
}

// MailReply00KeyAuthorization encodes a key authorization value
// to be sent back to the reply-to address of the ACME challenge email.
// The subject of that mail contains token-part1, which must be combined
// with token-part2, which was received as part of the JSON challenge as
// described in RFC8823 §3.1.
func (c Challenge) MailReply00KeyAuthorization(mailSubject string) (string, error) {
	// if subject given has "ACME:" header, strip it before calculating the key authorization
	mailSubject = strings.TrimPrefix(mailSubject, "ACME: ")
	tokenPart1, err := base64.RawURLEncoding.DecodeString(mailSubject)
	if err != nil {
		return "", fmt.Errorf("failed decoding token-part1: %w", err)
	}
	tokenPart2, err := base64.RawURLEncoding.DecodeString(c.Token)
	if err != nil {
		return "", fmt.Errorf("failed decoding token-part2: %w", err)
	}
	fullToken := append(tokenPart1, tokenPart2...)
	encodedFullToken := base64.RawURLEncoding.EncodeToString(fullToken)
	mailKeyAuth := strings.Replace(c.KeyAuthorization, c.Token, encodedFullToken, 1)
	h := sha256.Sum256([]byte(mailKeyAuth))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// DNSPersist01TXTRecordName returns the name of the TXT record to create
// for the dns-persist-01 challenge. For "ip" identifiers, it returns
// "_ip-validation-persist.<reverse-name>" under in-addr.arpa or ip6.arpa.
// draft-ietf-acme-dns-persist-03 §§4, 7.1
func (c Challenge) DNSPersist01TXTRecordName() string {
	if c.Identifier.Type == "ip" {
		rev, err := ipReverseZoneName(c.Identifier.Value)
		if err != nil {
			return ""
		}
		return "_ip-validation-persist." + rev
	}
	return "_validation-persist." + c.Identifier.Value
}

// DNSPersist01HashedAccountURI computes the domain-scoped or wildcard
// ("*") hashed account URI for a dns-persist-01 TXT record:
//
//	<accountHashPrefix>sha-256/<base64url(SHA-256(len || domain || keyThumbprint || account.Location))>
//
// accountHashPrefix comes from the ACME server's directory meta.accountHashPrefix
// field (for example, "https://ca.example/account-hash/"). domain is the
// domain being validated (or "*" for a domain-wildcard record, or the reverse
// zone name for an IP identifier).
// draft-ietf-acme-dns-persist-03 §§4.1, 12.2
func DNSPersist01HashedAccountURI(a Account, accountHashPrefix, domain string) (string, error) {
	if !isValidAccountHashPrefix(accountHashPrefix) {
		return "", fmt.Errorf("invalid or missing accountHashPrefix %q", accountHashPrefix)
	}
	if a.Location == "" {
		return "", fmt.Errorf("missing account location")
	}
	if a.PrivateKey == nil {
		return "", fmt.Errorf("missing account private key")
	}
	thumbprint, err := jwkThumbprint(a.PrivateKey.Public())
	if err != nil {
		return "", fmt.Errorf("computing account JWK thumbprint: %w", err)
	}
	canonDomain := "*"
	if domain != "*" {
		canonDomain = strings.TrimSuffix(domain, ".")
		if canonDomain == "" || len(canonDomain) > 253 || canonDomain == "*" || strings.HasPrefix(canonDomain, "*.") {
			return "", fmt.Errorf("invalid domain %q", domain)
		}
		for i := 0; i < len(canonDomain); i++ {
			if canonDomain[i] <= 0x20 || canonDomain[i] >= 0x7f {
				return "", fmt.Errorf("invalid character in domain %q", domain)
			}
		}
		canonDomain = strings.ToLower(canonDomain)
	}

	h := sha256.New()
	h.Write([]byte{byte(len(canonDomain))})
	h.Write([]byte(canonDomain))
	h.Write([]byte(thumbprint))
	h.Write([]byte(a.Location))

	digest := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return accountHashPrefix + "sha-256/" + digest, nil
}

// DNSPersist01TXTRecordValue constructs the TXT record RDATA for the
// dns-persist-01 challenge using RFC 8659 issue-value syntax.
//
// accountHashPrefix comes from the ACME server's directory meta.accountHashPrefix
// field. issuerDomainName should be selected from the challenge's (or directory
// meta's) IssuerDomainNames field. When wildcard or c.Wildcard is true,
// "policy=wildcard" is appended, which authorizes issuance of wildcard
// certificates and certificates for subdomains.
// draft-ietf-acme-dns-persist-03 §§4.1, 12.2
func (c Challenge) DNSPersist01TXTRecordValue(a Account, accountHashPrefix, issuerDomainName string, wildcard bool) (string, error) {
	if issuerDomainName == "" || strings.ContainsAny(issuerDomainName, "; \t\r\n") {
		return "", fmt.Errorf("invalid or missing issuer domain name %q", issuerDomainName)
	}
	domain := c.Identifier.Value
	if c.Identifier.Type == "ip" {
		rev, err := ipReverseZoneName(c.Identifier.Value)
		if err != nil {
			return "", err
		}
		domain = rev
	}
	hashedURI, err := DNSPersist01HashedAccountURI(a, accountHashPrefix, domain)
	if err != nil {
		return "", err
	}
	value := issuerDomainName + "; accounturi=" + hashedURI
	if (wildcard || c.Wildcard) && c.Identifier.Type != "ip" {
		value += "; policy=wildcard"
	}
	return value, nil
}

// isValidAccountHashPrefix verifies that accountHashPrefix is non-empty and
// contains only characters permitted in both an RFC 8659 CAA parameter value
// (%x21-3A / %x3C-7E, excluding ';' and whitespace) and an RFC 3986 URI
// (reserved / unreserved / "%").
// draft-ietf-acme-dns-persist-03 §4.1
func isValidAccountHashPrefix(prefix string) bool {
	if prefix == "" {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		b := prefix[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') {
			continue
		}
		switch b {
		case '-', '.', '_', '~', '%', ':', '/', '?', '#', '[', ']', '@', '!', '$', '&', '\'', '(', ')', '*', '+', ',', '=':
			continue
		}
		return false
	}
	return true
}

func ipReverseZoneName(ipStr string) (string, error) {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("invalid IP identifier %q", ipStr)
	}
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0]), nil
	}
	b := addr.As16()
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", b[i]&0x0f, b[i]>>4)
	}
	sb.WriteString("ip6.arpa")
	return sb.String(), nil
}

// InitiateChallenge "indicates to the server that it is ready for the challenge
// validation by sending an empty JSON body ('{}') carried in a POST request to
// the challenge URL (not the authorization URL)." §7.5.1
func (c *Client) InitiateChallenge(ctx context.Context, account Account, challenge Challenge) (Challenge, error) {
	if err := c.provision(ctx); err != nil {
		return Challenge{}, err
	}
	if challenge.Payload == nil {
		challenge.Payload = struct{}{}
	}
	_, err := c.httpPostJWS(ctx, account.PrivateKey, account.Location, challenge.URL, challenge.Payload, &challenge)
	return challenge, err
}

// The standard or well-known ACME challenge types.
const (
	ChallengeTypeHTTP01         = "http-01"          // RFC 8555 §8.3
	ChallengeTypeDNS01          = "dns-01"           // RFC 8555 §8.4
	ChallengeTypeTLSALPN01      = "tls-alpn-01"      // RFC 8737 §3
	ChallengeTypeDeviceAttest01 = "device-attest-01" // draft-acme-device-attest-00 §5
	ChallengeTypeEmailReply00   = "email-reply-00"   // RFC 8823 §5.2
	ChallengeTypeAuthorityToken = "tkauth-01"        // RFC 9447 §3 - ACME Authority Token challenge type
	ChallengeTypeDNSAccount01   = "dns-account-01"   // draft-ietf-acme-dns-account-label-01 §5
	ChallengeTypeDNSPersist01   = "dns-persist-01"   // draft-ietf-acme-dns-persist-03
)
