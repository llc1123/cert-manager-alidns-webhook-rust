package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alibabacloud-go/openapi-util/service"
	"github.com/alibabacloud-go/tea/tea"
)

const (
	fakeAccessKeyID     = "LTAIconformance"
	fakeAccessKeySecret = "conformance-secret"
)

type fakeRecord struct {
	ID     int
	Domain string
	RR     string
	Type   string
	Value  string
}

// aliDNSFake is a stateful AliDNS RPC endpoint. It verifies signature V3
// (ACS3-HMAC-SHA256) with Alibaba Cloud's official openapi-util and mirrors
// the documented error codes the webhook depends on.
type aliDNSFake struct {
	server  *httptest.Server
	domains map[string]bool

	mu       sync.Mutex
	nextID   int
	records  map[int]fakeRecord
	nonces   map[string]bool
	writes   int
	failNext map[string]string
}

func newAliDNSFake(t *testing.T, domains ...string) *aliDNSFake {
	t.Helper()
	fake := &aliDNSFake{
		domains:  map[string]bool{},
		nextID:   1000,
		records:  map[int]fakeRecord{},
		nonces:   map[string]bool{},
		failNext: map[string]string{},
	}
	for _, domain := range domains {
		fake.domains[domain] = true
	}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *aliDNSFake) seed(domain, rr, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.records[f.nextID] = fakeRecord{ID: f.nextID, Domain: domain, RR: rr, Type: "TXT", Value: value}
}

func (f *aliDNSFake) failNextCall(action, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[action] = code
}

func (f *aliDNSFake) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

func (f *aliDNSFake) matching(domain, rr, value string) []fakeRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeRecord
	for _, record := range f.records {
		if record.Domain == domain && record.RR == rr && record.Type == "TXT" && record.Value == value {
			out = append(out, record)
		}
	}
	return out
}

func (f *aliDNSFake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.records)
}

func (f *aliDNSFake) serve(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if r.Method != http.MethodPost || r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "InvalidAction.NotFound")
		return
	}
	if code := verifySignature(r); code != "" {
		writeError(w, http.StatusBadRequest, code)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	nonce := r.Header.Get("x-acs-signature-nonce")
	if f.nonces[nonce] {
		writeError(w, http.StatusBadRequest, "SignatureNonceUsed")
		return
	}
	f.nonces[nonce] = true
	action := r.Header.Get("x-acs-action")
	if code, ok := f.failNext[action]; ok {
		delete(f.failNext, action)
		writeError(w, http.StatusServiceUnavailable, code)
		return
	}
	switch action {
	case "DescribeDomainRecords":
		f.describe(w, query)
	case "AddDomainRecord":
		f.add(w, query)
	case "DeleteDomainRecord":
		f.delete(w, query)
	default:
		writeError(w, http.StatusBadRequest, "InvalidAction.NotFound")
	}
}

func (f *aliDNSFake) describe(w http.ResponseWriter, query url.Values) {
	domain := query.Get("DomainName")
	if !f.domains[domain] {
		writeError(w, http.StatusBadRequest, "InvalidDomainName.NoExist")
		return
	}
	page, pageErr := strconv.Atoi(query.Get("PageNumber"))
	size, sizeErr := strconv.Atoi(query.Get("PageSize"))
	if pageErr != nil || sizeErr != nil || page < 1 || size < 1 || size > 500 {
		writeError(w, http.StatusBadRequest, "InvalidParameter")
		return
	}
	// COMBINATION: exact RRKeyWord; otherwise fuzzy, case-insensitive.
	keyword := query.Get("RRKeyWord")
	rrMatches := func(rr string) bool { return strings.Contains(strings.ToLower(rr), strings.ToLower(keyword)) }
	if query.Get("SearchMode") == "COMBINATION" {
		rrMatches = func(rr string) bool { return keyword == "" || rr == keyword }
	}
	recordType := query.Get("TypeKeyWord")
	var hits []fakeRecord
	for _, record := range f.records {
		if record.Domain == domain && rrMatches(record.RR) && (recordType == "" || record.Type == recordType) {
			hits = append(hits, record)
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].ID < hits[j].ID })
	start := min((page-1)*size, len(hits))
	end := min(start+size, len(hits))
	records := make([]map[string]any, 0, end-start)
	for _, record := range hits[start:end] {
		records = append(records, map[string]any{
			"RecordId": strconv.Itoa(record.ID), "DomainName": record.Domain, "RR": record.RR,
			"Type": record.Type, "Value": record.Value, "TTL": 600, "Line": "default", "Status": "ENABLE",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"RequestId": "fake", "TotalCount": len(hits), "PageNumber": page, "PageSize": size,
		"DomainRecords": map[string]any{"Record": records},
	})
}

func (f *aliDNSFake) add(w http.ResponseWriter, query url.Values) {
	domain, rr, recordType, value := query.Get("DomainName"), query.Get("RR"), query.Get("Type"), query.Get("Value")
	if !f.domains[domain] {
		writeError(w, http.StatusBadRequest, "InvalidDomainName.NoExist")
		return
	}
	if rr == "" || recordType != "TXT" || value == "" {
		writeError(w, http.StatusBadRequest, "InvalidParameter")
		return
	}
	for _, record := range f.records {
		if record.Domain == domain && record.RR == rr && record.Type == recordType && record.Value == value {
			writeError(w, http.StatusBadRequest, "DomainRecordDuplicate")
			return
		}
	}
	f.nextID++
	f.writes++
	f.records[f.nextID] = fakeRecord{ID: f.nextID, Domain: domain, RR: rr, Type: recordType, Value: value}
	writeJSON(w, http.StatusOK, map[string]any{"RequestId": "fake", "RecordId": strconv.Itoa(f.nextID)})
}

func (f *aliDNSFake) delete(w http.ResponseWriter, query url.Values) {
	id, err := strconv.Atoi(query.Get("RecordId"))
	if _, ok := f.records[id]; err != nil || !ok {
		writeError(w, http.StatusBadRequest, "DomainRecordNotBelongToUser")
		return
	}
	delete(f.records, id)
	f.writes++
	writeJSON(w, http.StatusOK, map[string]any{"RequestId": "fake", "RecordId": strconv.Itoa(id)})
}

// verifySignature checks a signature V3 request against Alibaba Cloud's
// official GetAuthorization, independently of the Rust code under test.
func verifySignature(r *http.Request) string {
	if r.Header.Get("x-acs-version") != "2015-01-09" {
		return "MissingParameter.Version"
	}
	date, err := time.Parse("2006-01-02T15:04:05Z", r.Header.Get("x-acs-date"))
	if err != nil || time.Since(date).Abs() > 15*time.Minute {
		return "InvalidTimeStamp.Format"
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "InvalidParameter"
	}
	payload := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(payload[:])
	if r.Header.Get("x-acs-content-sha256") != payloadHash {
		return "ContentSHA256NotMatched"
	}
	headers := map[string]*string{"host": tea.String(r.Host)}
	for name, values := range r.Header {
		headers[strings.ToLower(name)] = tea.String(strings.Join(values, ","))
	}
	query := map[string]*string{}
	for key, values := range r.URL.Query() {
		query[key] = tea.String(values[0])
	}
	request := tea.NewRequest()
	request.Method = tea.String(r.Method)
	request.Pathname = tea.String(r.URL.Path)
	request.Headers = headers
	request.Query = query
	want := service.GetAuthorization(request, tea.String("ACS3-HMAC-SHA256"), tea.String(payloadHash),
		tea.String(fakeAccessKeyID), tea.String(fakeAccessKeySecret))
	// The official signer covers every host/x-acs-* header present, so an
	// unsigned or altered header also fails this comparison.
	got := r.Header.Get("Authorization")
	if got != *want {
		return "SignatureDoesNotMatch"
	}
	return ""
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{
		"RequestId": "fake", "Code": code, "Message": fmt.Sprintf("fake AliDNS error %s", code),
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Guards the guard: the fake must reject wrongly signed or altered requests.
func TestFakeRejectsInvalidSignatures(t *testing.T) {
	fake := newAliDNSFake(t, "example.com")
	send := func(secret string, tamper func(*http.Request)) string {
		t.Helper()
		query := url.Values{"DomainName": {"example.com"}, "SearchMode": {"COMBINATION"}, "PageNumber": {"1"}, "PageSize": {"10"}}
		request, err := http.NewRequest(http.MethodPost, fake.server.URL+"/?"+query.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		empty := sha256.Sum256(nil)
		for name, value := range map[string]string{
			"x-acs-action": "DescribeDomainRecords", "x-acs-version": "2015-01-09",
			"x-acs-date":            time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"x-acs-signature-nonce": fmt.Sprint(time.Now().UnixNano()), "x-acs-content-sha256": hex.EncodeToString(empty[:]),
		} {
			request.Header.Set(name, value)
		}
		headers := map[string]*string{"host": tea.String(request.URL.Host)}
		for name := range request.Header {
			headers[strings.ToLower(name)] = tea.String(request.Header.Get(name))
		}
		signing := tea.NewRequest()
		signing.Method, signing.Pathname, signing.Headers = tea.String("POST"), tea.String("/"), headers
		signing.Query = map[string]*string{}
		for key := range query {
			signing.Query[key] = tea.String(query.Get(key))
		}
		request.Header.Set("Authorization", *service.GetAuthorization(signing, tea.String("ACS3-HMAC-SHA256"),
			tea.String(hex.EncodeToString(empty[:])), tea.String(fakeAccessKeyID), tea.String(secret)))
		tamper(request)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var body struct{ Code string }
		_ = json.NewDecoder(response.Body).Decode(&body)
		return body.Code
	}
	untouched := func(*http.Request) {}
	if code := send(fakeAccessKeySecret, untouched); code != "" {
		t.Fatalf("correctly signed request rejected: %s", code)
	}
	if code := send("wrong-secret", untouched); code != "SignatureDoesNotMatch" {
		t.Fatalf("wrong secret: got %q", code)
	}
	tampered := func(r *http.Request) {
		r.URL.RawQuery = strings.Replace(r.URL.RawQuery, "PageSize=10", "PageSize=11", 1)
	}
	if code := send(fakeAccessKeySecret, tampered); code != "SignatureDoesNotMatch" {
		t.Fatalf("tampered query: got %q", code)
	}
}
