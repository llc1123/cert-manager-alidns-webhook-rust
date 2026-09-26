package conformance

import (
	"strconv"
	"strings"
	"testing"
)

// Fuzzy RRKeyWord matches spread over several 500-record pages must neither
// hide an existing record (duplicate Present) nor a record to delete.
func TestPaginatedRecordLookup(t *testing.T) {
	target := newTarget(t)
	fake := target.requireFake(t)
	domain := strings.TrimSuffix(target.zone, ".")
	for i := range 1100 {
		fake.seed(domain, "_acme-challenge.noise"+strconv.Itoa(i), "noise")
	}
	hook := solver(t, target.process, &target.client)
	ch := challenge(target.zone, "_acme-challenge."+target.zone, "paged-key")

	if err := hook.Present(ch); err != nil {
		t.Fatal(err)
	}
	writes := fake.writeCount()
	if err := hook.Present(ch); err != nil {
		t.Fatal(err)
	}
	if fake.writeCount() != writes {
		t.Fatal("repeated Present wrote to AliDNS although the record is on the last page")
	}
	target.backend.assertSingle(t, ch.ResolvedFQDN, ch.Key)
	if err := hook.CleanUp(ch); err != nil {
		t.Fatal(err)
	}
	target.backend.waitAbsent(t, ch.ResolvedFQDN, ch.Key)
	if fake.count() != 1100 {
		t.Fatalf("CleanUp touched unrelated records: %d remain", fake.count())
	}
}

func TestTransientFailureIsReportedAndRetryConverges(t *testing.T) {
	target := newTarget(t)
	fake := target.requireFake(t)
	hook := solver(t, target.process, &target.client)
	ch := challenge(target.zone, "_acme-challenge.retry."+target.zone, "retry-key")

	fake.failNextCall("AddDomainRecord", "ServiceUnavailable")
	if err := hook.Present(ch); err == nil || !strings.Contains(err.Error(), "ServiceUnavailable") {
		t.Fatalf("expected the injected failure to reach cert-manager, got %v", err)
	}
	if err := hook.Present(ch); err != nil {
		t.Fatalf("retry: %v", err)
	}
	target.backend.assertSingle(t, ch.ResolvedFQDN, ch.Key)

	fake.failNextCall("DeleteDomainRecord", "ServiceUnavailable")
	if err := hook.CleanUp(ch); err == nil {
		t.Fatal("expected the injected CleanUp failure to reach cert-manager")
	}
	if err := hook.CleanUp(ch); err != nil {
		t.Fatalf("retry: %v", err)
	}
	target.backend.waitAbsent(t, ch.ResolvedFQDN, ch.Key)
}

// AliDNS rejects duplicates; a concurrent Present that loses the race must
// still report success.
func TestDuplicateRecordRaceIsSuccess(t *testing.T) {
	target := newTarget(t)
	fake := target.requireFake(t)
	hook := solver(t, target.process, &target.client)
	ch := challenge(target.zone, "_acme-challenge.race."+target.zone, "race-key")

	// Simulate the other writer by failing the lookup-hidden add with the
	// provider's duplicate code.
	fake.failNextCall("AddDomainRecord", "DomainRecordDuplicate")
	if err := hook.Present(ch); err != nil {
		t.Fatalf("DomainRecordDuplicate must be treated as success: %v", err)
	}
}
