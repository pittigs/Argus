package service_test

import (
	"path/filepath"
	"testing"

	"github.com/pittigs/argus/internal/audit"
	"github.com/pittigs/argus/internal/auth"
	"github.com/pittigs/argus/internal/db"
	"github.com/pittigs/argus/internal/service"
)

func TestUserServiceAndRBAC(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_service.db")

	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer database.Close()

	auditSvc := audit.NewService(database)
	mgmtSvc := service.NewManagementService(database, auditSvc)
	authSvc := auth.NewService(database)

	actor := service.ActorInfo{
		ID:        "admin-id",
		Username:  "admin",
		IPAddress: "127.0.0.1",
		UserAgent: "TestAgent",
	}

	// 1. List Initial Seed Users
	users, err := mgmtSvc.ListUsers()
	if err != nil {
		t.Fatalf("Failed to list users: %v", err)
	}
	if len(users) < 4 {
		t.Fatalf("Expected at least 4 seeded users, got %d", len(users))
	}

	// 2. Create New User
	roles, err := mgmtSvc.ListRoles()
	if err != nil {
		t.Fatalf("Failed to list roles: %v", err)
	}
	var superAdminRoleID string
	for _, r := range roles {
		if r.Name == "UserManager" {
			superAdminRoleID = r.ID
			break
		}
	}

	newUser, err := mgmtSvc.CreateUser(service.CreateUserInput{
		Username: "bob.ross",
		Email:    "bob@art.local",
		FullName: "Bob Ross",
		Password: "password123",
		Status:   "active",
		RoleIDs:  []string{superAdminRoleID},
	}, actor)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	if newUser.Username != "bob.ross" {
		t.Fatalf("Expected username bob.ross, got %s", newUser.Username)
	}

	// 3. Authenticate with newly created user
	session, authUser, err := authSvc.Authenticate("bob.ross", "password123", "127.0.0.1", "TestBrowser")
	if err != nil {
		t.Fatalf("Failed to authenticate new user: %v", err)
	}
	if authUser.ID != newUser.ID {
		t.Fatalf("User ID mismatch on auth")
	}

	// Validate permissions
	if !auth.HasPermission(session, "users:create") {
		t.Fatalf("UserManager should have users:create permission")
	}
	if auth.HasPermission(session, "system:admin") {
		t.Fatalf("UserManager should not have system:admin permission")
	}

	// 4. Update User
	updated, err := mgmtSvc.UpdateUser(newUser.ID, service.UpdateUserInput{
		FullName: "Robert Norman Ross",
		Email:    "bob.ross.legend@art.local",
		Status:   "suspended",
		RoleIDs:  []string{superAdminRoleID},
	}, actor)
	if err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}
	if updated.FullName != "Robert Norman Ross" || updated.Status != "suspended" {
		t.Fatalf("Updated fields mismatch")
	}

	// Authenticating suspended user should fail
	_, _, err = authSvc.Authenticate("bob.ross", "password123", "127.0.0.1", "TestBrowser")
	if err != auth.ErrAccountSuspended {
		t.Fatalf("Expected ErrAccountSuspended, got %v", err)
	}

	// 5. Test System Stats
	stats, err := mgmtSvc.GetStats()
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}
	if stats.TotalUsers < 5 {
		t.Fatalf("Expected at least 5 users in stats, got %d", stats.TotalUsers)
	}
	if !stats.ChainIntegrityOk {
		t.Fatalf("Chain integrity should be OK")
	}
}
