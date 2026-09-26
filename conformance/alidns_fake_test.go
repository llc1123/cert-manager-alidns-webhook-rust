package conformance

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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

// aliDNSFake is a stateful AliDNS RPC endpoint that independently verifies
// signature version 1.0 and mirrors the documented error codes the webhook
// depends on.
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
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "InvalidAction.NotFound")
		return
	}
	if code := verifySignature(query); code != "" {
		writeError(w, http.StatusBadRequest, code)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	nonce := query.Get("SignatureNonce")
	if f.nonces[nonce] {
		writeError(w, http.StatusBadRequest, "SignatureNonceUsed")
		return
	}
	f.nonces[nonce] = true
	action := query.Get("Action")
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
	keyword := strings.ToLower(query.Get("RRKeyWord"))
	recordType := query.Get("TypeKeyWord")
	var hits []fakeRecord
	for _, record := range f.records {
		if record.Domain == domain && strings.Contains(strings.ToLower(record.RR), keyword) &&
			(recordType == "" || record.Type == recordType) {
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

// verifySignature implements https://help.aliyun.com/document_detail/29747.html
// independently of the Rust code under test.
func verifySignature(query url.Values) string {
	for key, want := range map[string]string{
		"AccessKeyId": fakeAccessKeyID, "Format": "JSON", "SignatureMethod": "HMAC-SHA1",
		"SignatureVersion": "1.0", "Version": "2015-01-09",
	} {
		if query.Get(key) != want {
			return "MissingParameter." + key
		}
	}
	timestamp, err := time.Parse("2006-01-02T15:04:05Z", query.Get("Timestamp"))
	if err != nil || time.Since(timestamp).Abs() > 15*time.Minute {
		return "InvalidTimeStamp.Format"
	}
	signature := query.Get("Signature")
	keys := make([]string, 0, len(query))
	for key := range query {
		if key != "Signature" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, specialURLEncode(key)+"="+specialURLEncode(query.Get(key)))
	}
	stringToSign := "GET&%2F&" + specialURLEncode(strings.Join(pairs, "&"))
	mac := hmac.New(sha1.New, []byte(fakeAccessKeySecret+"&"))
	mac.Write([]byte(stringToSign))
	if !hmac.Equal([]byte(signature), []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))) {
		return "SignatureDoesNotMatch"
	}
	return ""
}

func specialURLEncode(value string) string {
	encoded := url.QueryEscape(value)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	return strings.ReplaceAll(encoded, "%7E", "~")
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
