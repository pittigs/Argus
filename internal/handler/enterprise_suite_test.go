package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnterprise40SuiteEndpoints(t *testing.T) {
	srv, token, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.Routes()

	doRequest := func(method, path string, body []byte) *httptest.ResponseRecorder {
		var req *http.Request
		if body != nil {
			req = httptest.NewRequest(method, path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req = httptest.NewRequest(method, path, nil)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Test GET endpoints
	getEndpoints := []string{
		"/api/enterprise/crypto/merkle-root",
		"/api/enterprise/crypto/worm-status",
		"/api/enterprise/security/webauthn/challenge",
		"/api/enterprise/security/totp/setup",
		"/api/enterprise/security/sso/providers",
		"/api/enterprise/ad/domains",
		"/api/enterprise/ad/pso",
		"/api/enterprise/ad/gmsa",
		"/api/enterprise/ad/recycle-bin",
		"/api/enterprise/ad/delta-sync",
		"/api/enterprise/governance/breakglass",
		"/api/enterprise/governance/sod-rules",
		"/api/enterprise/governance/sod-conflicts",
		"/api/enterprise/governance/certifications",
		"/api/enterprise/governance/session-audits",
		"/api/enterprise/policy/rules",
		"/api/enterprise/policy/role-mining",
		"/api/enterprise/policy/orphans",
		"/api/enterprise/policy/shadow-admins",
		"/api/enterprise/compliance/controls",
		"/api/enterprise/compliance/certificate",
		"/api/enterprise/cluster/nodes",
		"/api/enterprise/cluster/cache",
		"/api/enterprise/cluster/storage-tiering",
		"/api/enterprise/cluster/replicas",
		"/api/enterprise/terraform/export",
		"/scim/v2/Users",
		"/api/enterprise/webhooks",
		"/api/openapi.json",
	}

	for _, ep := range getEndpoints {
		rec := doRequest(http.MethodGet, ep, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s returned %d, want 200. Body: %s", ep, rec.Code, rec.Body.String())
		}
	}

	// Test POST endpoints with sample payloads
	// 1. Sign Block
	signReqBody, _ := json.Marshal(map[string]string{"block_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
	rec := doRequest(http.MethodPost, "/api/enterprise/crypto/sign-block", signReqBody)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /api/enterprise/crypto/sign-block failed: %d", rec.Code)
	}

	// 2. Envelope Demo
	envReqBody, _ := json.Marshal(map[string]string{"plaintext": "Confidential GDPR string"})
	rec = doRequest(http.MethodPost, "/api/enterprise/crypto/envelope-demo", envReqBody)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /api/enterprise/crypto/envelope-demo failed: %d", rec.Code)
	}

	// 3. Adaptive Risk Assess
	riskBody, _ := json.Marshal(map[string]any{
		"username":   "sarah.connor",
		"ip_address": "10.0.0.1",
		"latitude":   52.52,
		"longitude":  13.40,
		"city":       "Berlin",
		"country":    "Germany",
	})
	rec = doRequest(http.MethodPost, "/api/enterprise/security/risk-assess", riskBody)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /api/enterprise/security/risk-assess failed: %d", rec.Code)
	}

	// 4. Pwned Password Check
	pwnBody, _ := json.Marshal(map[string]string{"password": "admin123"})
	rec = doRequest(http.MethodPost, "/api/enterprise/security/pwned-check", pwnBody)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /api/enterprise/security/pwned-check failed: %d", rec.Code)
	}

	// 5. Policy Evaluate
	polBody, _ := json.Marshal(map[string]any{
		"username":         "sarah.connor",
		"department":       "IT",
		"device_compliant": true,
		"action":           "file:read",
		"resource":         "share/docs",
	})
	rec = doRequest(http.MethodPost, "/api/enterprise/policy/evaluate", polBody)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /api/enterprise/policy/evaluate failed: %d", rec.Code)
	}

	// 6. Time Travel
	ttBody, _ := json.Marshal(map[string]string{"target_date": "2026-03-01T12:00:00Z"})
	rec = doRequest(http.MethodPost, "/api/enterprise/compliance/time-travel", ttBody)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /api/enterprise/compliance/time-travel failed: %d", rec.Code)
	}

	// 7. SIEM Export
	rec = doRequest(http.MethodPost, "/api/enterprise/compliance/siem-export", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /api/enterprise/compliance/siem-export failed: %d", rec.Code)
	}

	// 8. GDPR Shred
	shredBody, _ := json.Marshal(map[string]string{"username": "ex.staff", "user_id": "u-999"})
	rec = doRequest(http.MethodPost, "/api/enterprise/compliance/gdpr-shred", shredBody)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /api/enterprise/compliance/gdpr-shred failed: %d", rec.Code)
	}
}
