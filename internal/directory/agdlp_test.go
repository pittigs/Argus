package directory

import (
	"testing"
)

func TestAGDLPNamingConventions(t *testing.T) {
	// Test Resource Group Name generation
	roName, err := BuildResourceGroupName("Projekte", "Argus", PermReadOnly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if roName != "DL_FS_Projekte_Argus_RO" {
		t.Errorf("expected DL_FS_Projekte_Argus_RO, got %s", roName)
	}

	rwName, err := BuildResourceGroupName("Finanzen", "Jahresabschluss 2026", PermReadWrite)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rwName != "DL_FS_Finanzen_Jahresabschluss_2026_RW" {
		t.Errorf("expected DL_FS_Finanzen_Jahresabschluss_2026_RW, got %s", rwName)
	}

	// Test Global Role Group Name generation
	globalName, err := BuildGlobalRoleGroupName("DEV", "Argus")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if globalName != "G_DEV_Argus" {
		t.Errorf("expected G_DEV_Argus, got %s", globalName)
	}

	// Test metadata parsing
	metaRO := ParseGroupMetadata("DL_FS_Projekte_Argus_RO")
	if !metaRO.IsAGDLP || metaRO.Category != "FileShare" || metaRO.Permission != "RO" {
		t.Errorf("invalid meta for DL_FS group: %+v", metaRO)
	}

	metaG := ParseGroupMetadata("G_DEV_Argus")
	if !metaG.IsAGDLP || metaG.Category != "Role" || metaG.Department != "DEV" || metaG.RoleName != "Argus" {
		t.Errorf("invalid meta for G group: %+v", metaG)
	}
}

func TestMockProviderAGDLPOperations(t *testing.T) {
	mock := NewMockProvider()

	// Verify pre-seeded users
	users, err := mock.ListUsers("")
	if err != nil {
		t.Fatalf("failed to list users: %v", err)
	}
	if len(users) < 4 {
		t.Fatalf("expected at least 4 seeded users, got %d", len(users))
	}

	// Test create new AD user
	newUser, err := mock.CreateUser(CreateADUserInput{
		SAMAccountName: "bernd.stromberg",
		GivenName:      "Bernd",
		Surname:        "Stromberg",
		Mail:           "b.stromberg@corp.local",
		Department:     "Schadensregulierung",
		Enabled:        true,
		RoleGroups:     []string{"G_HR_Mitarbeiter"},
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if newUser.SAMAccountName != "bernd.stromberg" {
		t.Errorf("unexpected samAccountName: %s", newUser.SAMAccountName)
	}

	// Test toggle status
	err = mock.SetUserStatus("bernd.stromberg", false)
	if err != nil {
		t.Fatalf("failed to disable user: %v", err)
	}
	u, _ := mock.GetUser("bernd.stromberg")
	if u.Enabled {
		t.Errorf("expected user to be disabled")
	}

	// Test AGDLP File Share Generation
	groups, err := mock.CreateAGDLPFileShare(AGDLPShareInput{
		ShareName:            "Marketing",
		FolderName:           "Kampagnen_Q3",
		CreateReadOnly:       true,
		CreateReadWrite:      true,
		CreateFullControl:    false,
		AssignedGlobalGroups: []string{"G_DEV_Argus"},
	})
	if err != nil {
		t.Fatalf("failed to generate AGDLP file share: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups (RO, RW), got %d", len(groups))
	}

	// Verify member assignment
	rwGroup, err := mock.GetGroup("DL_FS_Marketing_Kampagnen_Q3_RW")
	if err != nil {
		t.Fatalf("failed to fetch RW group: %v", err)
	}
	hasMember := false
	for _, m := range rwGroup.Members {
		if m == "G_DEV_Argus" {
			hasMember = true
			break
		}
	}
	if !hasMember {
		t.Errorf("expected G_DEV_Argus in members of RW group: %+v", rwGroup.Members)
	}
}
