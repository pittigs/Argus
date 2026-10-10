package directory

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// Regex for AGDLP Domain Local File Share groups: DL_FS_<SHARE>_<FOLDER>_<PERM>
	reResourceGroup = regexp.MustCompile(`^DL_FS_([A-Za-z0-9]+)_([A-Za-z0-9_-]+)_(RO|RW|FC|WO|LIST)$`)
	// Regex for Global Role groups: G_<DEPT>_<ROLE>
	reGlobalGroup   = regexp.MustCompile(`^G_([A-Za-z0-9]+)_([A-Za-z0-9_-]+)$`)
	// Valid SAMAccountName characters in Active Directory
	reValidSAM      = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// PermissionLevel constants
const (
	PermReadOnly    = "RO"
	PermReadWrite   = "RW"
	PermFullControl = "FC"
	PermWriteOnly   = "WO"
	PermList        = "LIST"
	MaxSAMLength    = 64
)

// CleanToken removes spaces, umlauts and illegal characters from a token for AD group names
func CleanToken(s string) string {
	s = strings.TrimSpace(s)
	replacer := strings.NewReplacer(
		"ä", "ae", "ö", "oe", "ü", "ue",
		"Ä", "Ae", "Ö", "Oe", "Ü", "Ue",
		"ß", "ss", " ", "_", "-", "_",
	)
	s = replacer.Replace(s)
	// Remove anything that is not alphanumeric or underscore
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// BuildResourceGroupName constructs the standardized DL_FS name
func BuildResourceGroupName(share, folder, perm string) (string, error) {
	cleanShare := CleanToken(share)
	cleanFolder := CleanToken(folder)
	perm = strings.ToUpper(strings.TrimSpace(perm))

	switch perm {
	case PermReadOnly, PermReadWrite, PermFullControl, PermWriteOnly, PermList:
	default:
		return "", fmt.Errorf("ungültige Berechtigungsstufe '%s'. Erlaubt sind: RO, RW, FC, WO, LIST", perm)
	}

	if cleanShare == "" || cleanFolder == "" {
		return "", fmt.Errorf("Freigabe und Ordnername dürfen nicht leer sein")
	}

	name := fmt.Sprintf("DL_FS_%s_%s_%s", cleanShare, cleanFolder, perm)
	if len(name) > 64 {
		return "", fmt.Errorf("Gruppenname überschreitet das AD-Limit von 64 Zeichen (Länge: %d)", len(name))
	}

	return name, nil
}

// BuildGlobalRoleGroupName constructs the standardized G_ group name
func BuildGlobalRoleGroupName(department, role string) (string, error) {
	cleanDept := CleanToken(department)
	cleanRole := CleanToken(role)

	if cleanDept == "" || cleanRole == "" {
		return "", fmt.Errorf("Abteilung und Rollenname dürfen nicht leer sein")
	}

	name := fmt.Sprintf("G_%s_%s", cleanDept, cleanRole)
	if len(name) > 64 {
		return "", fmt.Errorf("Gruppenname überschreitet das AD-Limit von 64 Zeichen (Länge: %d)", len(name))
	}

	return name, nil
}

// GroupMetadata parses an AD group name and extracts its AGDLP classification
type GroupMetadata struct {
	SAMAccountName string
	IsAGDLP        bool
	Category       string // "FileShare", "Role", "Standard"
	GroupScope     string // "DomainLocal", "Global"
	ShareName      string
	FolderName     string
	Permission     string
	Department     string
	RoleName       string
}

// ParseGroupMetadata analyzes the group name
func ParseGroupMetadata(name string) GroupMetadata {
	meta := GroupMetadata{
		SAMAccountName: name,
		GroupScope:     "Global",
		Category:       "Standard",
	}

	if matches := reResourceGroup.FindStringSubmatch(name); len(matches) == 4 {
		meta.IsAGDLP = true
		meta.Category = "FileShare"
		meta.GroupScope = "DomainLocal"
		meta.ShareName = matches[1]
		meta.FolderName = matches[2]
		meta.Permission = matches[3]
		return meta
	}

	if matches := reGlobalGroup.FindStringSubmatch(name); len(matches) == 3 {
		meta.IsAGDLP = true
		meta.Category = "Role"
		meta.GroupScope = "Global"
		meta.Department = matches[1]
		meta.RoleName = matches[2]
		return meta
	}

	if strings.HasPrefix(name, "DL_") {
		meta.GroupScope = "DomainLocal"
	}

	return meta
}

// ValidateSAMAccountName validates username / group name length and characters
func ValidateSAMAccountName(name string) error {
	name = strings.TrimSpace(name)
	if len(name) == 0 {
		return fmt.Errorf("Name darf nicht leer sein")
	}
	if len(name) > 64 {
		return fmt.Errorf("Name überschreitet 64 Zeichen")
	}
	if !reValidSAM.MatchString(name) {
		return fmt.Errorf("Name enthält unzulässige Zeichen (nur Buchstaben, Zahlen, '.', '-', '_' erlaubt)")
	}
	return nil
}
