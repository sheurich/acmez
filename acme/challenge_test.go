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
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestChallenge_DNSAccount01TXTRecordName(t *testing.T) {
	tests := []struct {
		name       string
		account    Account
		identifier Identifier
		expected   string
	}{
		{
			name:       "standard account location",
			account:    Account{Location: "https://acme-v02.api.letsencrypt.org/acme/acct/12345"},
			identifier: Identifier{Type: "dns", Value: "example.com"},
			expected:   "_lvrajhh53e27yh7f._acme-challenge.example.com",
		},
		{
			name:       "different account location",
			account:    Account{Location: "https://example.com/acme/account/67890"},
			identifier: Identifier{Type: "dns", Value: "test.example.org"},
			expected:   "_pbvtvcg2uxbmkni3._acme-challenge.test.example.org",
		},
		{
			name:       "empty account location",
			account:    Account{Location: ""},
			identifier: Identifier{Type: "dns", Value: "sub.domain.net"},
			expected:   "_4oymiquy7qobjgx3._acme-challenge.sub.domain.net",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := Challenge{
				Identifier: test.identifier,
			}
			got := c.DNSAccount01TXTRecordName(test.account)
			if got != test.expected {
				t.Errorf("DNSAccount01TXTRecordName() = %q, want %q", got, test.expected)
			}
		})
	}
}

func TestChallenge_DNSPersist01TXTRecordName(t *testing.T) {
	tests := []struct {
		name       string
		identifier Identifier
		expected   string
	}{
		{
			name:       "apex domain",
			identifier: Identifier{Type: "dns", Value: "example.com"},
			expected:   "_validation-persist.example.com",
		},
		{
			name:       "subdomain",
			identifier: Identifier{Type: "dns", Value: "sub.example.com"},
			expected:   "_validation-persist.sub.example.com",
		},
		{
			name:       "IPv4 identifier",
			identifier: Identifier{Type: "ip", Value: "192.0.2.1"},
			expected:   "_ip-validation-persist.1.2.0.192.in-addr.arpa",
		},
		{
			name:       "IPv6 identifier",
			identifier: Identifier{Type: "ip", Value: "2001:db8::1"},
			expected:   "_ip-validation-persist.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
		},
		{
			name:       "invalid IP identifier",
			identifier: Identifier{Type: "ip", Value: "not-an-ip"},
			expected:   "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := Challenge{Identifier: test.identifier}
			got := c.DNSPersist01TXTRecordName()
			if got != test.expected {
				t.Errorf("DNSPersist01TXTRecordName() = %q, want %q", got, test.expected)
			}
		})
	}
}

// rfc7638ExampleRSAKey constructs the RSA key from RFC 7638 §3.1 used by the
// draft-ietf-acme-dns-persist-03 §13 test vectors (thumbprint
// "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs").
func rfc7638ExampleRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	nBytes, err := base64.RawURLEncoding.DecodeString(
		"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt" +
			"VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6" +
			"4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD" +
			"W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9" +
			"1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksIN" +
			"HaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	)
	if err != nil {
		t.Fatalf("decoding modulus: %v", err)
	}
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: 65537,
		},
	}
}

func TestChallenge_DNSPersist01TXTRecordValue(t *testing.T) {
	account := Account{
		Location:   "https://ca.example/acct/123",
		PrivateKey: rfc7638ExampleRSAKey(t),
	}
	prefix := "https://ca.example/account-hash/"

	tests := []struct {
		name       string
		identifier Identifier
		issuer     string
		wildcard   bool
		expected   string
	}{
		{
			name:       "draft-03 section 13.1/13.2 example.com",
			identifier: Identifier{Type: "dns", Value: "example.com"},
			issuer:     "authority.example",
			wildcard:   false,
			expected:   "authority.example; accounturi=https://ca.example/account-hash/sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw",
		},
		{
			name:       "draft-03 section 13.4 with policy=wildcard",
			identifier: Identifier{Type: "dns", Value: "example.com"},
			issuer:     "authority.example",
			wildcard:   true,
			expected:   "authority.example; accounturi=https://ca.example/account-hash/sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw; policy=wildcard",
		},
		{
			name:       "draft-03 section 13.2 A-label uppercase and trailing dot",
			identifier: Identifier{Type: "dns", Value: "XN--FA-HIA.example."},
			issuer:     "authority.example",
			wildcard:   false,
			expected:   "authority.example; accounturi=https://ca.example/account-hash/sha-256/dc3zyKBvsc9_vyWQoZSyM4fgcN0d7jnr61730r7ekAw",
		},
		{
			name:       "draft-03 section 13.2 domain-wildcard (*)",
			identifier: Identifier{Type: "dns", Value: "*"},
			issuer:     "authority.example",
			wildcard:   false,
			expected:   "authority.example; accounturi=https://ca.example/account-hash/sha-256/NpDnSwUthQK8zCgFdefYxAdAVPnygMLbs9US6oO-5ug",
		},
		{
			name:       "draft-03 section 7.3 IPv4 192.0.2.1",
			identifier: Identifier{Type: "ip", Value: "192.0.2.1"},
			issuer:     "authority.example",
			wildcard:   false,
			expected:   "authority.example; accounturi=https://ca.example/account-hash/sha-256/CnwSwHOHJbE-X_FSkydPTw6dGMovluSdRsY3_tmA-0E",
		},
		{
			name:       "draft-03 section 7.3 IPv6 2001:db8::1",
			identifier: Identifier{Type: "ip", Value: "2001:db8::1"},
			issuer:     "authority.example",
			wildcard:   false,
			expected:   "authority.example; accounturi=https://ca.example/account-hash/sha-256/9RLd7iwi0v30KV01dsPwGvSBucGEYgsJhDNCxk8Nb9g",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := Challenge{Identifier: test.identifier}
			got, err := c.DNSPersist01TXTRecordValue(account, prefix, test.issuer, test.wildcard)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != test.expected {
				t.Errorf("DNSPersist01TXTRecordValue() = %q, want %q", got, test.expected)
			}
		})
	}

	// Verify invalid accountHashPrefix, issuer, or wildcard domain inputs are rejected.
	c := Challenge{Identifier: Identifier{Type: "dns", Value: "example.com"}}
	for _, badPrefix := range []string{"", "https://ca.example/account-hash/;x=", "https://ca.example/account hash/"} {
		if _, err := c.DNSPersist01TXTRecordValue(account, badPrefix, "ca.example", false); err == nil {
			t.Errorf("expected error for invalid accountHashPrefix %q, got nil", badPrefix)
		}
	}
	if _, err := c.DNSPersist01TXTRecordValue(account, prefix, "ca.example; policy=wildcard", false); err == nil {
		t.Error("expected error for issuerDomainName containing ';', got nil")
	}
	if _, err := DNSPersist01HashedAccountURI(account, prefix, "*.example.com"); err == nil {
		t.Error("expected error for unstripped wildcard domain '*.example.com', got nil")
	}
}
