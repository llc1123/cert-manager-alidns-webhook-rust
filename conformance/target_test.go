package conformance

import (
	"context"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

const fakeZone = "example.com."

// target is a running webhook plus a way to observe the records it manages.
type target struct {
	process *webhookProcess
	client  keyPair // front-proxy client certificate used by the aggregator
	zone    string
	backend backend
	fake    *aliDNSFake // nil in external mode
}

type backend interface {
	waitPresent(t *testing.T, fqdn, value string)
	waitAbsent(t *testing.T, fqdn, value string)
	assertSingle(t *testing.T, fqdn, value string)
}

// newTarget uses an in-process AliDNS fake unless all CONFORMANCE_ALIDNS_*
// variables are set, in which case it talks to the real AliDNS API and
// verifies records through their authoritative nameservers.
func newTarget(t *testing.T) *target {
	t.Helper()
	id := os.Getenv("CONFORMANCE_ALIDNS_ACCESS_KEY_ID")
	secret := os.Getenv("CONFORMANCE_ALIDNS_ACCESS_KEY_SECRET")
	zone := os.Getenv("CONFORMANCE_ALIDNS_ZONE")
	if id == "" && secret == "" && zone == "" {
		fake := newAliDNSFake(t, strings.TrimSuffix(fakeZone, "."))
		process := startWebhook(t, fake.server.URL, fakeAccessKeyID, fakeAccessKeySecret)
		return &target{
			process: process,
			client:  newClientCert(t, process.frontProxy, frontProxyName),
			zone:    fakeZone,
			backend: fakeBackend{fake: fake, zone: fakeZone},
			fake:    fake,
		}
	}
	if id == "" || secret == "" || zone == "" {
		t.Fatal("CONFORMANCE_ALIDNS_ACCESS_KEY_ID, _ACCESS_KEY_SECRET, and _ZONE must all be set for external mode")
	}
	endpoint := os.Getenv("CONFORMANCE_ALIDNS_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://alidns.aliyuncs.com"
	}
	resolver := os.Getenv("CONFORMANCE_DNS_SERVER")
	if resolver == "" {
		resolver = "223.5.5.5:53"
	}
	process := startWebhook(t, endpoint, id, secret)
	return &target{
		process: process,
		client:  newClientCert(t, process.frontProxy, frontProxyName),
		zone:    util.ToFqdn(zone),
		backend: dnsBackend{resolver: util.NewCachingResolver(), nameservers: []string{resolver}},
	}
}

// requireFake skips the test unless the in-process fake is in use.
func (tg *target) requireFake(t *testing.T) *aliDNSFake {
	t.Helper()
	if tg.fake == nil {
		t.Skip("requires the in-process AliDNS fake")
	}
	return tg.fake
}

type fakeBackend struct {
	fake *aliDNSFake
	zone string
}

// rr splits fqdn into the fake domain and relative record name.
func (b fakeBackend) rr(t *testing.T, fqdn string) (string, string) {
	t.Helper()
	domain := util.UnFqdn(b.zone)
	rr, ok := strings.CutSuffix(util.UnFqdn(fqdn), "."+domain)
	if !ok {
		t.Fatalf("%s is outside %s", fqdn, b.zone)
	}
	return domain, rr
}

// waitPresent asserts the record exists; the fake is synchronous.
func (b fakeBackend) waitPresent(t *testing.T, fqdn, value string) {
	t.Helper()
	domain, rr := b.rr(t, fqdn)
	if len(b.fake.matching(domain, rr, value)) == 0 {
		t.Fatalf("TXT %s=%q is missing", fqdn, value)
	}
}

// waitAbsent asserts the record is gone.
func (b fakeBackend) waitAbsent(t *testing.T, fqdn, value string) {
	t.Helper()
	domain, rr := b.rr(t, fqdn)
	if records := b.fake.matching(domain, rr, value); len(records) != 0 {
		t.Fatalf("TXT %s=%q still exists: %#v", fqdn, value, records)
	}
}

// assertSingle asserts exactly one matching record exists.
func (b fakeBackend) assertSingle(t *testing.T, fqdn, value string) {
	t.Helper()
	domain, rr := b.rr(t, fqdn)
	if records := b.fake.matching(domain, rr, value); len(records) != 1 {
		t.Fatalf("expected exactly one TXT %s=%q, got %#v", fqdn, value, records)
	}
}

// dnsBackend uses cert-manager's own propagation check against the zone's
// authoritative nameservers, as the ACME self-check does.
type dnsBackend struct {
	resolver    *util.CachingResolver
	nameservers []string
}

const (
	pollInterval     = 5 * time.Second
	propagationLimit = 5 * time.Minute
)

// waitPresent polls the authoritative nameservers until the value appears.
func (b dnsBackend) waitPresent(t *testing.T, fqdn, value string) {
	t.Helper()
	err := wait.PollUntilContextTimeout(t.Context(), pollInterval, propagationLimit, true, func(ctx context.Context) (bool, error) {
		return b.resolver.CheckTXTRecordPropagation(ctx, fqdn, value, b.nameservers, util.UseAuthoritative(true))
	})
	if err != nil {
		t.Fatalf("TXT %s=%q did not propagate: %v", fqdn, value, err)
	}
}

// waitAbsent polls the authoritative nameservers until the value disappears.
func (b dnsBackend) waitAbsent(t *testing.T, fqdn, value string) {
	t.Helper()
	err := wait.PollUntilContextTimeout(t.Context(), pollInterval, propagationLimit, true, func(ctx context.Context) (bool, error) {
		authoritative, err := b.resolver.LookupAuthoritativeNameservers(ctx, fqdn, b.nameservers)
		if err != nil {
			return false, err
		}
		for _, nameserver := range authoritative {
			msg, err := util.DNSQuery(ctx, fqdn, dns.TypeTXT, []string{net.JoinHostPort(nameserver, "53")}, false)
			if err != nil {
				return false, err
			}
			for _, rr := range msg.Answer {
				if txt, ok := rr.(*dns.TXT); ok && slices.Contains(txt.Txt, value) {
					return false, nil
				}
			}
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("TXT %s=%q was not removed: %v", fqdn, value, err)
	}
}

// assertSingle is a no-op: DNS answers cannot reveal duplicate records.
func (dnsBackend) assertSingle(*testing.T, string, string) {}
