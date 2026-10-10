package directory

import "errors"

var (
	ErrUserNotFound    = errors.New("AD-Benutzer nicht gefunden")
	ErrUserExists      = errors.New("AD-Benutzer existiert bereits")
	ErrGroupNotFound   = errors.New("AD-Gruppe nicht gefunden")
	ErrGroupExists     = errors.New("AD-Gruppe existiert bereits")
	ErrInvalidPassword = errors.New("Kennwort entspricht nicht den Komplexitätsanforderungen")
	ErrConnection      = errors.New("Verbindung zum Domain Controller fehlgeschlagen")
)

// Provider abstracts Active Directory / Samba-AD operations
type Provider interface {
	// Status & Config
	TestConnection() ConnectionTestResult

	// Users
	ListUsers(search string) ([]ADUser, error)
	GetUser(samAccountName string) (*ADUser, error)
	CreateUser(input CreateADUserInput) (*ADUser, error)
	UpdateUser(samAccountName string, input UpdateADUserInput) (*ADUser, error)
	SetUserStatus(samAccountName string, enabled bool) error
	ResetPassword(samAccountName, newPassword string) error
	DeleteUser(samAccountName string) error

	// Groups & AGDLP
	ListGroups(category string) ([]ADGroup, error)
	GetGroup(groupName string) (*ADGroup, error)
	CreateGroup(name, description, scope string) (*ADGroup, error)
	CreateAGDLPFileShare(input AGDLPShareInput) ([]ADGroup, error)
	AddMemberToGroup(groupName, member string) error
	RemoveMemberFromGroup(groupName, member string) error
	GetUserGroups(samAccountName string) ([]string, error)
}
