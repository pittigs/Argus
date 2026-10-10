package adextended

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// -------------------------------------------------------------
// 11. Multi-Domain & Multi-Forest Management
// -------------------------------------------------------------

type ForestDomain struct {
	DNSName       string   `json:"dns_name"`       // e.g. "corp.local", "emea.corp.local"
	NetBIOSName   string   `json:"netbios_name"`   // e.g. "CORP", "EMEA"
	ForestRoot    string   `json:"forest_root"`    // e.g. "corp.local"
	DomainSID     string   `json:"domain_sid"`
	LdapURL       string   `json:"ldap_url"`
	IsRoot        bool     `json:"is_root"`
	TrustType     string   `json:"trust_type"`     // "Parent-Child", "External", "Forest", "Realm"
	TrustDirect   string   `json:"trust_direction"` // "Bidirectional", "One-Way Inbound", "One-Way Outbound"
	Status        string   `json:"status"`         // "ONLINE", "DEGRADED", "OFFLINE"
}

type MultiForestManager struct {
	domains       map[string]ForestDomain
	activeDomain  string
	mu            sync.RWMutex
}

func NewMultiForestManager() *MultiForestManager {
	mf := &MultiForestManager{
		domains:      make(map[string]ForestDomain),
		activeDomain: "corp.local",
	}

	mf.domains["corp.local"] = ForestDomain{
		DNSName:       "corp.local",
		NetBIOSName:   "CORP",
		ForestRoot:    "corp.local",
		DomainSID:     "S-1-5-21-3623811015-3361044348-30300820",
		LdapURL:       "ldaps://dc01.corp.local:636",
		IsRoot:        true,
		TrustType:     "ForestRoot",
		TrustDirect:   "Bidirectional",
		Status:        "ONLINE",
	}

	mf.domains["emea.corp.local"] = ForestDomain{
		DNSName:       "emea.corp.local",
		NetBIOSName:   "EMEA",
		ForestRoot:    "corp.local",
		DomainSID:     "S-1-5-21-3623811015-3361044348-30300821",
		LdapURL:       "ldaps://dc-frankfurt.emea.corp.local:636",
		IsRoot:        false,
		TrustType:     "Parent-Child",
		TrustDirect:   "Bidirectional",
		Status:        "ONLINE",
	}

	mf.domains["partner-cloud.net"] = ForestDomain{
		DNSName:       "partner-cloud.net",
		NetBIOSName:   "PARTNER",
		ForestRoot:    "partner-cloud.net",
		DomainSID:     "S-1-5-21-1234567890-9876543210-11223344",
		LdapURL:       "ldaps://dc-ext.partner-cloud.net:636",
		IsRoot:        true,
		TrustType:     "External",
		TrustDirect:   "One-Way Inbound",
		Status:        "ONLINE",
	}

	return mf
}

func (mf *MultiForestManager) ListDomains() []ForestDomain {
	mf.mu.RLock()
	defer mf.mu.RUnlock()
	res := make([]ForestDomain, 0, len(mf.domains))
	for _, d := range mf.domains {
		res = append(res, d)
	}
	return res
}

func (mf *MultiForestManager) SwitchActiveDomain(dnsName string) error {
	mf.mu.Lock()
	defer mf.mu.Unlock()
	if _, ok := mf.domains[dnsName]; !ok {
		return fmt.Errorf("domain %s not registered in forest", dnsName)
	}
	mf.activeDomain = dnsName
	return nil
}

func (mf *MultiForestManager) GetActiveDomain() string {
	mf.mu.RLock()
	defer mf.mu.RUnlock()
	return mf.activeDomain
}

// -------------------------------------------------------------
// 12. Fine-Grained Password Policies (FGPP / PSO Management)
// -------------------------------------------------------------

type PasswordSettingsObject struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`                  // e.g. "PSO_Privileged_Admins"
	Precedence            int       `json:"precedence"`            // Lower value = higher precedence
	MinPasswordLength     int       `json:"min_password_length"`   // e.g. 16 or 24
	PasswordHistoryLength int       `json:"password_history_length"`
	ComplexityEnabled     bool      `json:"complexity_enabled"`
	MaxPasswordAgeDays    int       `json:"max_password_age_days"`
	MinPasswordAgeDays    int       `json:"min_password_age_days"`
	LockoutThreshold      int       `json:"lockout_threshold"`      // Invalid attempts before lock
	LockoutDurationMins   int       `json:"lockout_duration_mins"`
	LockoutWindowMins     int       `json:"lockout_window_mins"`
	AppliesToGroups       []string  `json:"applies_to_groups"`      // DNs or sAMAccountNames
	CreatedAt             time.Time `json:"created_at"`
}

type PSOManager struct {
	policies map[string]PasswordSettingsObject
	mu       sync.RWMutex
}

func NewPSOManager() *PSOManager {
	pso := &PSOManager{
		policies: make(map[string]PasswordSettingsObject),
	}
	pso.policies["pso-admins"] = PasswordSettingsObject{
		ID:                    "pso-admins",
		Name:                  "PSO_Privileged_Admins",
		Precedence:            10,
		MinPasswordLength:     20,
		PasswordHistoryLength: 24,
		ComplexityEnabled:     true,
		MaxPasswordAgeDays:    60,
		MinPasswordAgeDays:    1,
		LockoutThreshold:      3,
		LockoutDurationMins:   60,
		LockoutWindowMins:     30,
		AppliesToGroups:       []string{"Domain Admins", "Enterprise Admins", "G_Sec_Engineers"},
		CreatedAt:             time.Now().UTC(),
	}
	pso.policies["pso-standard"] = PasswordSettingsObject{
		ID:                    "pso-standard",
		Name:                  "PSO_Standard_Employees",
		Precedence:            100,
		MinPasswordLength:     14,
		PasswordHistoryLength: 10,
		ComplexityEnabled:     true,
		MaxPasswordAgeDays:    180,
		MinPasswordAgeDays:    0,
		LockoutThreshold:      5,
		LockoutDurationMins:   30,
		LockoutWindowMins:     15,
		AppliesToGroups:       []string{"Domain Users"},
		CreatedAt:             time.Now().UTC(),
	}
	return pso
}

func (pm *PSOManager) ListPSOs() []PasswordSettingsObject {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	res := make([]PasswordSettingsObject, 0, len(pm.policies))
	for _, p := range pm.policies {
		res = append(res, p)
	}
	return res
}

func (pm *PSOManager) UpsertPSO(p PasswordSettingsObject) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if p.ID == "" {
		p.ID = fmt.Sprintf("pso-%d", time.Now().UnixNano())
	}
	p.CreatedAt = time.Now().UTC()
	pm.policies[p.ID] = p
}

// -------------------------------------------------------------
// 13. Group Managed Service Accounts (gMSA) & SPN Inventory
// -------------------------------------------------------------

type GMSAccount struct {
	SAMAccountName string    `json:"sam_account_name"` // ends with $ e.g. "gmsa-argus-svc$"
	DNSHostName    string    `json:"dns_hostname"`
	PrincipalsAllowedToRetrieveManagedPassword []string `json:"allowed_hosts"`
	SPNs           []string  `json:"spns"`             // e.g. "HTTP/argus.corp.local"
	LastRolledAt   time.Time `json:"last_rolled_at"`
	NextRollDate   time.Time `json:"next_roll_date"`
	EncryptionTypes []string `json:"encryption_types"` // AES256-CTS-HMAC-SHA1-96, etc.
	Status         string    `json:"status"`           // "HEALTHY", "NEEDS_ROTATION"
}

type GMSAManager struct {
	accounts map[string]GMSAccount
	mu       sync.RWMutex
}

func NewGMSAManager() *GMSAManager {
	gm := &GMSAManager{
		accounts: make(map[string]GMSAccount),
	}
	now := time.Now().UTC()
	gm.accounts["gmsa-argus-svc$"] = GMSAccount{
		SAMAccountName: "gmsa-argus-svc$",
		DNSHostName:    "argus-cluster.corp.local",
		PrincipalsAllowedToRetrieveManagedPassword: []string{"SRV-ARGUS-01$", "SRV-ARGUS-02$"},
		SPNs:           []string{"HTTP/argus.corp.local", "HTTP/iam.corp.local"},
		LastRolledAt:   now.Add(-15 * 24 * time.Hour),
		NextRollDate:   now.Add(15 * 24 * time.Hour),
		EncryptionTypes: []string{"AES256", "AES128"},
		Status:         "HEALTHY",
	}
	gm.accounts["gmsa-sqldb-svc$"] = GMSAccount{
		SAMAccountName: "gmsa-sqldb-svc$",
		DNSHostName:    "sql-cluster.corp.local",
		PrincipalsAllowedToRetrieveManagedPassword: []string{"SRV-DB-01$"},
		SPNs:           []string{"MSSQLSvc/sql-cluster.corp.local:1433"},
		LastRolledAt:   now.Add(-28 * 24 * time.Hour),
		NextRollDate:   now.Add(2 * 24 * time.Hour),
		EncryptionTypes: []string{"AES256"},
		Status:         "HEALTHY",
	}
	return gm
}

func (gm *GMSAManager) ListGMSAs() []GMSAccount {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	res := make([]GMSAccount, 0, len(gm.accounts))
	for _, a := range gm.accounts {
		res = append(res, a)
	}
	return res
}

func (gm *GMSAManager) RotatePasswordNow(sam string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	acc, ok := gm.accounts[sam]
	if !ok {
		return errors.New("gMSA account not found")
	}
	now := time.Now().UTC()
	acc.LastRolledAt = now
	acc.NextRollDate = now.Add(30 * 24 * time.Hour)
	acc.Status = "HEALTHY"
	gm.accounts[sam] = acc
	return nil
}

// -------------------------------------------------------------
// 14. AD Recycle Bin & Tombstone Restoration
// -------------------------------------------------------------

type DeletedADObject struct {
	ObjectGUID    string    `json:"object_guid"`
	SAMAccountName string   `json:"sam_account_name"`
	DistinguishedName string `json:"distinguished_name"`
	LastKnownParent string  `json:"last_known_parent"`
	ObjectClass   string    `json:"object_class"` // "user", "group"
	DeletedAt     time.Time `json:"deleted_at"`
	FormerGroups  []string  `json:"former_groups"`
	IsRecycled    bool      `json:"is_recycled"`
}

type RecycleBinManager struct {
	deletedObjects map[string]DeletedADObject
	mu             sync.RWMutex
}

func NewRecycleBinManager() *RecycleBinManager {
	rb := &RecycleBinManager{
		deletedObjects: make(map[string]DeletedADObject),
	}
	// Seed sample deleted object for immediate testability
	rb.deletedObjects["guid-dev-01"] = DeletedADObject{
		ObjectGUID:        "guid-dev-01",
		SAMAccountName:    "florian.ex",
		DistinguishedName: "CN=florian.ex\\0ADEL:guid-dev-01,CN=Deleted Objects,DC=corp,DC=local",
		LastKnownParent:   "OU=Software Engineering,OU=Users,DC=corp,DC=local",
		ObjectClass:       "user",
		DeletedAt:         time.Now().UTC().Add(-4 * 24 * time.Hour),
		FormerGroups:      []string{"Domain Users", "G_Dev_Engineers", "DL_FS_Project_Docs_ReadWrite"},
		IsRecycled:        false,
	}
	return rb
}

func (rb *RecycleBinManager) ListDeletedObjects() []DeletedADObject {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	res := make([]DeletedADObject, 0, len(rb.deletedObjects))
	for _, o := range rb.deletedObjects {
		res = append(res, o)
	}
	return res
}

func (rb *RecycleBinManager) RestoreObject(guid string) (*DeletedADObject, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	obj, ok := rb.deletedObjects[guid]
	if !ok {
		return nil, errors.New("gelöschtes AD-Objekt nicht im Papierkorb gefunden")
	}
	delete(rb.deletedObjects, guid)
	return &obj, nil
}

// -------------------------------------------------------------
// 15. Delta Sync & USNChanged Directory Polling Engine
// -------------------------------------------------------------

type DeltaSyncStatus struct {
	LastSyncTime   time.Time `json:"last_sync_time"`
	HighestUSN     int64     `json:"highest_usn"`
	ChangesApplied int64     `json:"changes_applied"`
	SyncState      string    `json:"sync_state"` // "IN_SYNC", "POLLING", "DRIFT_DETECTED"
	DomainName     string    `json:"domain_name"`
}

type DeltaSyncEngine struct {
	status DeltaSyncStatus
	mu     sync.RWMutex
}

func NewDeltaSyncEngine(domain string) *DeltaSyncEngine {
	return &DeltaSyncEngine{
		status: DeltaSyncStatus{
			LastSyncTime:   time.Now().UTC(),
			HighestUSN:     1048576,
			ChangesApplied: 142,
			SyncState:      "IN_SYNC",
			DomainName:     domain,
		},
	}
}

func (de *DeltaSyncEngine) GetStatus() DeltaSyncStatus {
	de.mu.RLock()
	defer de.mu.RUnlock()
	return de.status
}

func (de *DeltaSyncEngine) RecordExternalChange(usn int64) {
	de.mu.Lock()
	defer de.mu.Unlock()
	if usn > de.status.HighestUSN {
		de.status.HighestUSN = usn
	}
	de.status.ChangesApplied++
	de.status.LastSyncTime = time.Now().UTC()
	de.status.SyncState = "IN_SYNC"
}
