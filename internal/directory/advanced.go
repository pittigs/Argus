package directory

import (
	"fmt"
	"strings"
	"time"
)

// EffectivePermission represents a resolved permission on a file share folder for a user
type EffectivePermission struct {
	ShareName       string    `json:"share_name"`
	FolderName      string    `json:"folder_name"`
	Permission      string    `json:"permission"`       // "RO", "RW", "FC"
	PermissionLabel string    `json:"permission_label"` // "Lesen", "Ändern", "Vollzugriff"
	InheritedVia    string    `json:"inherited_via"`    // The Global Group (e.g. "G_DEV_Argus") or "Direkt"
	ResourceGroup   string    `json:"resource_group"`   // The Domain Local Group (e.g. "DL_FS_Projekte_Argus_RW")
}

// PermissionConflict describes an anomaly in AGDLP group assignments
type PermissionConflict struct {
	Type        string `json:"type"`        // "DUAL_ACCESS", "ORPHANED_GROUP", "DIRECT_ASSIGNMENT"
	Severity    string `json:"severity"`    // "WARNING", "INFO", "CRITICAL"
	ShareName   string `json:"share_name,omitempty"`
	FolderName  string `json:"folder_name,omitempty"`
	Target      string `json:"target"`      // User or Group affected
	Description string `json:"description"`
	Suggestion  string `json:"suggestion"`
}

// UserComparison shows shared and differing permissions between two AD users
type UserComparison struct {
	UserA             string                `json:"user_a"`
	UserB             string                `json:"user_b"`
	SharedGroups      []string              `json:"shared_groups"`
	OnlyUserAGroups   []string              `json:"only_user_a_groups"`
	OnlyUserBGroups   []string              `json:"only_user_b_groups"`
	SharedPermissions []EffectivePermission `json:"shared_permissions"`
	OnlyUserAPerms    []EffectivePermission `json:"only_user_a_perms"`
	OnlyUserBPerms    []EffectivePermission `json:"only_user_b_perms"`
}

// ACLScriptOutput holds generated scripts for Windows and Linux fileservers
type ACLScriptOutput struct {
	ShareName       string `json:"share_name"`
	FolderName      string `json:"folder_name"`
	PowerShellScript string `json:"powershell_script"`
	BashScript      string `json:"bash_script"`
}

// GenerateACLACommands produces exact, production-ready icacls and setfacl commands
func GenerateACLACommands(share, folder string, groups map[string]ADGroup) ACLScriptOutput {
	cleanShare := CleanToken(share)
	cleanFolder := CleanToken(folder)

	var psLines []string
	var bashLines []string

	psLines = append(psLines, fmt.Sprintf("# ================================================================"))
	psLines = append(psLines, fmt.Sprintf("# Argus AGDLP NTFS ACL Provisionierung fuer \\\\fileserver\\%s\\%s", cleanShare, cleanFolder))
	psLines = append(psLines, fmt.Sprintf("# Erstellt am: %s (Automatisierte Konfiguration)", time.Now().Format("2006-01-02 15:04:05")))
	psLines = append(psLines, fmt.Sprintf("# ================================================================"))
	psLines = append(psLines, fmt.Sprintf("$FolderPath = \"D:\\Shares\\%s\\%s\"", cleanShare, cleanFolder))
	psLines = append(psLines, fmt.Sprintf("if (!(Test-Path -Path $FolderPath)) { New-Item -ItemType Directory -Path $FolderPath -Force }"))
	psLines = append(psLines, "")
	psLines = append(psLines, "# Vererbung aktivieren und bestehende Berechtigungen beibehalten:")
	psLines = append(psLines, "icacls $FolderPath /inheritance:e")

	bashLines = append(bashLines, fmt.Sprintf("# ================================================================"))
	bashLines = append(bashLines, fmt.Sprintf("# Argus Samba / Linux POSIX ACL Provisionierung: /srv/samba/%s/%s", strings.ToLower(cleanShare), strings.ToLower(cleanFolder)))
	bashLines = append(bashLines, fmt.Sprintf("# ================================================================"))
	bashLines = append(bashLines, fmt.Sprintf("FOLDER=\"/srv/samba/%s/%s\"", strings.ToLower(cleanShare), strings.ToLower(cleanFolder)))
	bashLines = append(bashLines, "mkdir -p \"$FOLDER\"")

	// Read-Only
	if grp, ok := groups[PermReadOnly]; ok {
		psLines = append(psLines, fmt.Sprintf("# Read-Only: %s", grp.SAMAccountName))
		psLines = append(psLines, fmt.Sprintf("icacls $FolderPath /grant:r \"%s:(OI)(CI)RX\" /T /C", grp.SAMAccountName))

		bashLines = append(bashLines, fmt.Sprintf("# Read-Only fuer %s", grp.SAMAccountName))
		bashLines = append(bashLines, fmt.Sprintf("setfacl -R -m g:\"%s\":r-x \"$FOLDER\"", grp.SAMAccountName))
		bashLines = append(bashLines, fmt.Sprintf("setfacl -R -d -m g:\"%s\":r-x \"$FOLDER\"", grp.SAMAccountName))
	}

	// Read-Write (Modify)
	if grp, ok := groups[PermReadWrite]; ok {
		psLines = append(psLines, fmt.Sprintf("# Read-Write (Modify): %s", grp.SAMAccountName))
		psLines = append(psLines, fmt.Sprintf("icacls $FolderPath /grant:r \"%s:(OI)(CI)M\" /T /C", grp.SAMAccountName))

		bashLines = append(bashLines, fmt.Sprintf("# Read-Write fuer %s", grp.SAMAccountName))
		bashLines = append(bashLines, fmt.Sprintf("setfacl -R -m g:\"%s\":rwx \"$FOLDER\"", grp.SAMAccountName))
		bashLines = append(bashLines, fmt.Sprintf("setfacl -R -d -m g:\"%s\":rwx \"$FOLDER\"", grp.SAMAccountName))
	}

	// Full Control
	if grp, ok := groups[PermFullControl]; ok {
		psLines = append(psLines, fmt.Sprintf("# Full Control: %s", grp.SAMAccountName))
		psLines = append(psLines, fmt.Sprintf("icacls $FolderPath /grant:r \"%s:(OI)(CI)F\" /T /C", grp.SAMAccountName))

		bashLines = append(bashLines, fmt.Sprintf("# Full Control fuer %s", grp.SAMAccountName))
		bashLines = append(bashLines, fmt.Sprintf("setfacl -R -m g:\"%s\":rwx \"$FOLDER\"", grp.SAMAccountName))
		bashLines = append(bashLines, fmt.Sprintf("setfacl -R -d -m g:\"%s\":rwx \"$FOLDER\"", grp.SAMAccountName))
	}

	psLines = append(psLines, "")
	psLines = append(psLines, "Write-Host \"[Argus] AGDLP NTFS-Berechtigungen fuer $FolderPath erfolgreich gesetzt!\" -ForegroundColor Green")

	bashLines = append(bashLines, "")
	bashLines = append(bashLines, "echo \"[Argus] Samba / POSIX ACLs fuer $FOLDER erfolgreich gesetzt!\"")

	return ACLScriptOutput{
		ShareName:        cleanShare,
		FolderName:       cleanFolder,
		PowerShellScript: strings.Join(psLines, "\n"),
		BashScript:       strings.Join(bashLines, "\n"),
	}
}
