package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/pittigs/argus/internal/audit"
	"github.com/pittigs/argus/internal/auth"
	"github.com/pittigs/argus/internal/db"
	"github.com/pittigs/argus/internal/directory"
	"github.com/pittigs/argus/internal/lifecycle"
	"github.com/pittigs/argus/internal/service"
)

func setupTestServer(t *testing.T) (*Server, string, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "argus_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := filepath.Join(tmpDir, "test.db")

	database, err := db.Open(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open test db: %v", err)
	}

	auditSvc := audit.NewService(database)
	authSvc := auth.NewService(database)
	mgmtSvc := service.NewManagementService(database, auditSvc)

	dirMgr, err := directory.NewManager(database, auditSvc)
	if err != nil {
		database.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to create dir manager: %v", err)
	}

	lifecycleSvc := lifecycle.NewService(database, auditSvc, dirMgr, mgmtSvc)
	srv := NewServer(authSvc, mgmtSvc, auditSvc, dirMgr, lifecycleSvc, nil)

	// Login as admin to get token
	loginBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "admin123",
	})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %s", rec.Body.String())
	}

	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &loginResp)

	cleanup := func() {
		database.Close()
		os.RemoveAll(tmpDir)
	}

	return srv, loginResp.Token, cleanup
}

func TestDirectoryAPIEndpoints(t *testing.T) {
	srv, token, cleanup := setupTestServer(t)
	defer cleanup()

	handler := srv.Routes()

	// 1. Test GET /api/directory/config
	req := httptest.NewRequest("GET", "/api/directory/config", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /api/directory/config, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Test POST /api/directory/test-connection
	req = httptest.NewRequest("POST", "/api/directory/test-connection", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /api/directory/test-connection, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. Test GET /api/directory/users
	req = httptest.NewRequest("GET", "/api/directory/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /api/directory/users, got %d", rec.Code)
	}

	// 4. Test POST /api/directory/users (Create new AD identity)
	newUserData, _ := json.Marshal(directory.CreateADUserInput{
		SAMAccountName: "thomas.mueller",
		GivenName:      "Thomas",
		Surname:        "Mueller",
		Mail:           "t.mueller@corp.local",
		Department:     "Logistik",
		Password:       "Password123!",
		Enabled:        true,
	})
	req = httptest.NewRequest("POST", "/api/directory/users", bytes.NewReader(newUserData))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for creating AD user, got %d: %s", rec.Code, rec.Body.String())
	}

	// 5. Test POST /api/directory/groups/agdlp (Generate AGDLP File Share Groups)
	shareData, _ := json.Marshal(directory.AGDLPShareInput{
		ShareName:         "Produktion",
		FolderName:        "Plaene_2026",
		CreateReadOnly:    true,
		CreateReadWrite:   true,
		CreateFullControl: false,
	})
	req = httptest.NewRequest("POST", "/api/directory/groups/agdlp", bytes.NewReader(shareData))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for AGDLP generation, got %d: %s", rec.Code, rec.Body.String())
	}

	// 6. Test GET /api/directory/agdlp-matrix
	req = httptest.NewRequest("GET", "/api/directory/agdlp-matrix", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for AGDLP matrix, got %d", rec.Code)
	}

	var matrixResp struct {
		Matrix []directory.AGDLPMatrixFolder `json:"matrix"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &matrixResp)
	if len(matrixResp.Matrix) == 0 {
		t.Errorf("expected non-empty AGDLP matrix")
	}
}
