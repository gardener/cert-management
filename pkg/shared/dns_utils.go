/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package shared

import (
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

const defaultPath = "/etc/resolv.conf"

var defaultNameservers = []string{
	// google-public-dns-a.google.com
	"8.8.8.8:53",
	// google-public-dns-b.google.com
	"8.8.4.4:53",
}

// PreparePrecheckNameservers collects the nameservers for checking DNS propagation.
// If no nameservers are provided, it tries to read them from `/etc/resolv.conf`, and
// last resort is to use Google public DNS servers (8.8.8.8 and 8.8.4.4)
func PreparePrecheckNameservers(nameservers []string) []string {
	if len(nameservers) == 0 || len(nameservers) == 1 && len(nameservers[0]) == 0 {
		return getNameservers(defaultPath, defaultNameservers)
	}
	return dns01.ParseNameservers(nameservers)
}

// getNameservers attempts to get systems nameservers before falling back to the defaults
func getNameservers(path string, defaults []string) []string {
	config, err := dns.ClientConfigFromFile(path)
	if err != nil || len(config.Servers) == 0 {
		return defaults
	}

	return dns01.ParseNameservers(config.Servers)
}

// CreateWrapPreCheckOption creates lego DNS ChallengeOption for custom Precheck function,
// checking the DNS propagation of the DNS challenge TXT record.
func CreateWrapPreCheckOption(nameservers []string) dns01.ChallengeOption {
	return dns01.WrapPreCheck(func(_, fqdn, value string, _ dns01.PreCheckFunc) (b bool, err error) {
		return CheckDNSPropagation(nameservers, fqdn, value)
	})
}

// NoPropagationCheckOption creates lego DNS ChallengeOption for custom Precheck function,
// performing no DNS propagation check of the DNS challenge TXT record at all.
func NoPropagationCheckOption() dns01.ChallengeOption {
	return dns01.WrapPreCheck(func(_, _, _ string, _ dns01.PreCheckFunc) (b bool, err error) {
		return true, nil
	})
}

// CheckDNSPropagation checks if the expected TXT record has been propagated to all authoritative nameservers.
func CheckDNSPropagation(nameservers []string, fqdn string, values ...string) (bool, error) {
	// Initial attempt to resolve at the recursive NS
	r, err := dnsQuery(fqdn, dns.TypeTXT, nameservers, true)
	if err != nil {
		return false, err
	}

	return checkTXTValue(r.Answer, values), nil
}

func checkTXTValue(answer []dns.RR, values []string) bool {
	found := make([]bool, len(values))
	for _, rr := range answer {
		if v, ok := rr.(*dns.TXT); ok {
			for _, txt := range v.Txt {
				for i, value := range values {
					if txt == value {
						found[i] = true
					}
				}
			}
		}
	}

	for _, b := range found {
		if !b {
			return false
		}
	}
	return true
}

// FollowCNAMEs follows the CNAME records and returns the last non-CNAME fully qualified domain name
// that it finds. Returns an error when a loop is found in the CNAME chain. The
// argument fqdnChain is used by the function itself to keep track of which fqdns it
// already encountered and detect loops.
// Method copied from https://github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util/wait.go
func FollowCNAMEs(fqdn string, nameservers []string, fqdnChain ...string) (string, error) {
	r, err := dnsQuery(fqdn, dns.TypeCNAME, nameservers, true)
	if err != nil {
		return "", err
	}
	if r.Rcode != dns.RcodeSuccess {
		return fqdn, err
	}
	for _, rr := range r.Answer {
		cn, ok := rr.(*dns.CNAME)
		if !ok || cn.Hdr.Name != fqdn {
			continue
		}
		// Check if we were here before to prevent loops in the chain of CNAME records.
		for _, fqdnInChain := range fqdnChain {
			if cn.Target != fqdnInChain {
				continue
			}
			return "", fmt.Errorf("found recursive CNAME record to %q when looking up %q", cn.Target, fqdn)
		}
		return FollowCNAMEs(cn.Target, nameservers, append(fqdnChain, fqdn)...)
	}
	return fqdn, nil
}

// The following methods are copied from github.com/go-acme/lego/v3/challenge/dns01/nameserver.go

// dnsTimeout is used to override the default DNS timeout of 10 seconds.
var dnsTimeout = 10 * time.Second

func dnsQuery(fqdn string, rtype uint16, nameservers []string, recursive bool) (*dns.Msg, error) {
	m := createDNSMsg(fqdn, rtype, recursive)

	var in *dns.Msg
	var err error

	for _, ns := range nameservers {
		in, err = sendDNSQuery(m, ns)
		if err == nil && len(in.Answer) > 0 {
			break
		}
	}
	return in, err
}

func createDNSMsg(fqdn string, rtype uint16, recursive bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, rtype)
	m.SetEdns0(4096, false)

	if !recursive {
		m.RecursionDesired = false
	}

	return m
}

func sendDNSQuery(m *dns.Msg, ns string) (*dns.Msg, error) {
	udp := &dns.Client{Net: "udp", Timeout: dnsTimeout}
	in, _, err := udp.Exchange(m, ns)

	// customization: try TCP if UDP fails
	if err != nil || in != nil && in.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: dnsTimeout}
		// If the TCP request succeeds, the err will reset to nil
		var err2 error
		in, _, err2 = tcp.Exchange(m, ns)
		if err == nil {
			err = err2
		} else if err2 != nil {
			err = fmt.Errorf("DNS lookup: udp failed with %s, tcp failed with %s", err, err2)
		} else {
			err = nil
		}
	}

	return in, err
}
