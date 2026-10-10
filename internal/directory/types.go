package directory

import "time"

// ADUser represents an identity in Active Directory or Samba-AD
type ADUser struct {
	SAMAccountName    string     `json:"sam_account_name"`
	UserPrincipalName string     `json:"user_principal_name"`
	DisplayName       string     `json:"display_name"`
	GivenName         string     `json:"given_name"`
	Surname           string     `json:"surname"`
	Mail              string     `json:"mail"`
	Department        string     `json:"department"`
	Title             string     `json:"title"`
	Enabled           bool       `json:"enabled"`
	DN                string     `json:"dn"`
	MemberOf          []string   `json:"member_of"` // List of group names or DNs
	CreatedAt         time.Time  `json:"created_at"`
	LastLogon         *time.Time `json:"last_logon,omitempty"`
}

// ADGroup represents a security group in Active Directory or Samba-AD
type ADGroup struct {
	SAMAccountName string   `json:"sam_account_name"`
	CN             string   `json:"cn"`
	DN             string   `json:"dn"`
	Description    string   `json:"description"`
	GroupScope     string   `json:"group_scope"` // "Global", "DomainLocal", "Universal"
	Category       string   `json:"category"`    // "Role", "FileShare", "Standard"
	Members        []string `json:"members"`     // User or group SAMAccountNames / DNs
	ShareName      string   `json:"share_name,omitempty"`
	FolderName     string   `json:"folder_name,omitempty"`
	Permission     string   `json:"permission,omitempty"` // "RO", "RW", "FC", "WO", "LIST"
}

// DirectoryConfig holds connection details for Windows AD or Samba 4 AD DC
type DirectoryConfig struct {
	Host               string    `json:"host"`
	Port               int       `json:"port"`
	UseTLS             bool      `json:"use_tls"`
	InsecureSkipVerify bool      `json:"insecure_skip_verify"`
	BaseDN             string    `json:"base_dn"`
	BindDN             string    `json:"bind_dn"`
	BindPassword       string    `json:"bind_password,omitempty"`
	UserContainer      string    `json:"user_container"`
	GroupContainer     string    `json:"group_container"`
	DemoMode           bool      `json:"demo_mode"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// CreateADUserInput represents input for creating a new AD identity
type CreateADUserInput struct {
	SAMAccountName string   `json:"sam_account_name"`
	GivenName      string   `json:"given_name"`
	Surname        string   `json:"surname"`
	DisplayName    string   `json:"display_name"`
	Mail           string   `json:"mail"`
	Password       string   `json:"password"`
	Department     string   `json:"department"`
	Title          string   `json:"title"`
	Enabled        bool     `json:"enabled"`
	RoleGroups     []string `json:"role_groups"` // Global Groups to assign
}

// UpdateADUserInput represents input for updating an AD user
type UpdateADUserInput struct {
	GivenName   string `json:"given_name"`
	Surname     string `json:"surname"`
	DisplayName string `json:"display_name"`
	Mail        string `json:"mail"`
	Department  string `json:"department"`
	Title       string `json:"title"`
}

// AGDLPShareInput specifies a file share structure to generate standard groups for
type AGDLPShareInput struct {
	ShareName            string   `json:"share_name"`            // e.g. "Projekte"
	FolderName           string   `json:"folder_name"`           // e.g. "Argus"
	Description          string   `json:"description"`
	CreateReadOnly       bool     `json:"create_read_only"`      // Generates DL_FS_<Share>_<Folder>_RO
	CreateReadWrite      bool     `json:"create_read_write"`     // Generates DL_FS_<Share>_<Folder>_RW
	CreateFullControl    bool     `json:"create_full_control"`   // Generates DL_FS_<Share>_<Folder>_FC
	AssignedGlobalGroups []string `json:"assigned_global_groups"` // Assigned to ReadWrite by default
}

// MembershipChangeInput defines adding or removing a member from a group
type MembershipChangeInput struct {
	GroupName string `json:"group_name"`
	Member    string `json:"member"` // Username or sub-group name
}

// ConnectionTestResult reports status of an AD/LDAP reachability check
type ConnectionTestResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Latency string `json:"latency"`
	Demo    bool   `json:"demo"`
}

// TemporaryMembership represents time-bound just-in-time access in AGDLP groups
type TemporaryMembership struct {
	ID            string     `json:"id"`
	UserSAM       string     `json:"user_sam"`
	GroupName     string     `json:"group_name"`
	RequestedBy   string     `json:"requested_by"`
	Reason        string     `json:"reason"`
	DurationHours int        `json:"duration_hours"`
	Status        string     `json:"status"` // "active", "expired", "revoked"
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedBy     string     `json:"revoked_by,omitempty"`
}

// CreateJITRequest defines request payload to grant temporary group membership
type CreateJITRequest struct {
	UserSAM       string `json:"user_sam"`
	GroupName     string `json:"group_name"`
	DurationHours int    `json:"duration_hours"`
	Reason        string `json:"reason"`
}

// ApprovalRequest represents a pending or completed dual-control action
type ApprovalRequest struct {
	ID              string     `json:"id"`
	ActionType      string     `json:"action_type"` // e.g. "ad:membership:grant", "ad:user:delete"
	TargetResource  string     `json:"target_resource"`
	PayloadJSON     string     `json:"payload_json"`
	RequestedBy     string     `json:"requested_by"`
	Reason          string     `json:"reason"`
	Status          string     `json:"status"` // "pending", "approved", "rejected"
	ApprovedBy      string     `json:"approved_by,omitempty"`
	ResolutionNotes string     `json:"resolution_notes,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
}

// CreateApprovalInput represents payload to create an approval request
type CreateApprovalInput struct {
	ActionType     string `json:"action_type"`
	TargetResource string `json:"target_resource"`
	PayloadJSON    string `json:"payload_json"`
	Reason         string `json:"reason"`
}

// ResolveApprovalInput represents payload to approve or reject a dual-control request
type ResolveApprovalInput struct {
	Decision string `json:"decision"` // "approved" or "rejected"
	Notes    string `json:"notes"`
}

// BulkImportRow represents one row in a CSV bulk import
type BulkImportRow struct {
	RowNumber      int      `json:"row_number"`
	SAMAccountName string   `json:"sam_account_name"`
	GivenName      string   `json:"given_name"`
	Surname        string   `json:"surname"`
	Email          string   `json:"email"`
	Department     string   `json:"department"`
	JobTitle       string   `json:"job_title"`
	Password       string   `json:"password,omitempty"`
	GlobalGroups   []string `json:"global_groups"`
	Success        bool     `json:"success"`
	ErrorMessage   string   `json:"error_message,omitempty"`
}

// BulkImportResult summarizes the outcome of a batch CSV import
type BulkImportResult struct {
	TotalProcessed int             `json:"total_processed"`
	SuccessCount   int             `json:"success_count"`
	FailureCount   int             `json:"failure_count"`
	Results        []BulkImportRow `json:"results"`
}

// ShareTemplateFolder defines a folder in a standardized share template
type ShareTemplateFolder struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Permissions     []string `json:"permissions"` // e.g. ["RO", "RW"]
	DefaultRoleTags []string `json:"default_role_tags"`
}

// ShareTemplate defines standard department or project share patterns
type ShareTemplate struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Category    string                `json:"category"`
	Folders     []ShareTemplateFolder `json:"folders"`
}

// ApplyShareTemplateInput specifies arguments for provisioning a template
type ApplyShareTemplateInput struct {
	TemplateID string `json:"template_id"`
	ShareName  string `json:"share_name"`
	Department string `json:"department"`
}

// TemplateApplyResult summarizes the outcome of applying a share template
type TemplateApplyResult struct {
	ShareName      string          `json:"share_name"`
	CreatedGroups  []ADGroup       `json:"created_groups"`
	Scripts        ACLScriptOutput `json:"scripts"`
	FoldersCreated int             `json:"folders_created"`
}

// ComplianceReport summarizes access governance for ISO 27001 / DSGVO audits
type ComplianceReport struct {
	GeneratedAt       time.Time            `json:"generated_at"`
	Domain            string               `json:"domain"`
	DCHost            string               `json:"dc_host"`
	AuditChainHead    string               `json:"audit_chain_head"`
	TotalUsers        int                  `json:"total_users"`
	TotalGroups       int                  `json:"total_groups"`
	TotalShares       int                  `json:"total_shares"`
	TotalConflicts    int                  `json:"total_conflicts"`
	Shares            []AGDLPMatrixFolder  `json:"shares"`
	Conflicts         []PermissionConflict `json:"conflicts"`
	UserAccessSummary []UserAccessItem     `json:"user_access_summary"`
}

// UserAccessItem contains summary permissions for an identity
type UserAccessItem struct {
	SAMAccountName string   `json:"sam_account_name"`
	DisplayName    string   `json:"display_name"`
	Department     string   `json:"department"`
	DirectRoles    []string `json:"direct_roles"`
	SharesCount    int      `json:"shares_count"`
}

