package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pittigs/argus/internal/directory"
)

func TestEnterpriseAPIEndpoints(t *testing.T) {
	srv, token, cleanup := setupTestServer(t)
	defer cleanup()

	routes := srv.Routes()

	// Helper to send authenticated requests
	doReq := func(method, path string, body interface{}) *httptest.ResponseRecorder {
		var reqBody *bytes.Buffer
		if body != nil {
			b, _ := json.Marshal(body)
			reqBody = bytes.NewBuffer(b)
		} else {
			reqBody = bytes.NewBuffer(nil)
		}
		req := httptest.NewRequest(method, path, reqBody)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		routes.ServeHTTP(rr, req)
		return rr
	}

	// 1. Bulk Template & Bulk Import
	rr := doReq("GET", "/api/directory/users/bulk-template", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for bulk-template, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "sAMAccountName") {
		t.Errorf("expected CSV template to contain sAMAccountName")
	}

	bulkCSV := `sAMAccountName,GivenName,Surname,Email,Department,JobTitle,Password,GlobalGroups
api.bulk1,ApiOne,User,api.bulk1@corp.local,Finanzen,Analyst,Pass#12345,G_Finanzen_Mitarbeiter
api.bulk2,ApiTwo,User,api.bulk2@corp.local,IT,Engineer,Pass#12345,G_IT_Admin
`
	rr = doReq("POST", "/api/directory/users/bulk-import", map[string]string{
		"csv_content": bulkCSV,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for bulk-import, got %d: %s", rr.Code, rr.Body.String())
	}
	var bulkRes directory.BulkImportResult
	_ = json.Unmarshal(rr.Body.Bytes(), &bulkRes)
	if bulkRes.SuccessCount != 2 {
		t.Errorf("expected 2 successes, got %d", bulkRes.SuccessCount)
	}

	// 2. JIT Temporary Memberships
	jitReq := directory.CreateJITRequest{
		UserSAM:       "api.bulk1",
		GroupName:     "DL_FS_Projekte_Argus_RW",
		DurationHours: 4,
		Reason:        "Production deployment maintenance window",
	}
	rr = doReq("POST", "/api/directory/jit", jitReq)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 for JIT creation, got %d: %s", rr.Code, rr.Body.String())
	}
	var jitItem directory.TemporaryMembership
	_ = json.Unmarshal(rr.Body.Bytes(), &jitItem)
	if jitItem.ID == "" || jitItem.Status != "active" {
		t.Errorf("invalid JIT item created: %+v", jitItem)
	}

	// List JIT
	rr = doReq("GET", "/api/directory/jit", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for listing JIT, got %d", rr.Code)
	}

	// Revoke JIT
	rr = doReq("DELETE", "/api/directory/jit/"+jitItem.ID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for revoking JIT, got %d", rr.Code)
	}

	// 3. Dual-Control Approvals
	appReq := directory.CreateApprovalInput{
		ActionType:     "ad:membership:grant",
		TargetResource: "Domain Admins",
		PayloadJSON:    `{"group_name":"Domain Admins","member":"api.bulk2"}`,
		Reason:         "Need domain admin access for forest migration",
	}
	rr = doReq("POST", "/api/approvals", appReq)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 for approval request, got %d: %s", rr.Code, rr.Body.String())
	}
	var appItem directory.ApprovalRequest
	_ = json.Unmarshal(rr.Body.Bytes(), &appItem)

	// List approvals
	rr = doReq("GET", "/api/approvals?status=pending", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for list approvals, got %d", rr.Code)
	}

	// 4. Share Templates
	rr = doReq("GET", "/api/directory/agdlp/templates", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for share templates, got %d", rr.Code)
	}

	applyReq := directory.ApplyShareTemplateInput{
		TemplateID: "dept_standard",
		ShareName:  "Personal",
		Department: "Personal",
	}
	rr = doReq("POST", "/api/directory/agdlp/templates/apply", applyReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for applying template, got %d: %s", rr.Code, rr.Body.String())
	}

	// 5. Compliance Reports
	// JSON
	rr = doReq("GET", "/api/directory/agdlp/compliance-report", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for JSON compliance report, got %d", rr.Code)
	}
	var compRep directory.ComplianceReport
	_ = json.Unmarshal(rr.Body.Bytes(), &compRep)
	if compRep.TotalShares == 0 || compRep.AuditChainHead == "" {
		t.Errorf("invalid compliance report summary: %+v", compRep)
	}

	// CSV
	rr = doReq("GET", "/api/directory/agdlp/compliance-report?format=csv", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for CSV compliance report, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Audit Report") {
		t.Errorf("expected CSV report to contain header")
	}

	// HTML
	rr = doReq("GET", "/api/directory/agdlp/compliance-report?format=html", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for HTML compliance report, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "<html") || !strings.Contains(rr.Body.String(), "Audit Zertifikat") {
		t.Errorf("expected HTML report to contain certificate layout")
	}
}
