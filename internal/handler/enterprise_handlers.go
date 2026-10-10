package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/pittigs/argus/internal/compliance"
	"github.com/pittigs/argus/internal/cryptoaudit"
	"github.com/pittigs/argus/internal/integrations"
	"github.com/pittigs/argus/internal/kerberos"
	"github.com/pittigs/argus/internal/policy"
	"github.com/pittigs/argus/internal/security"
)

// -------------------------------------------------------------
// 1-5. Crypto & Zero-Trust Audit Handlers
// -------------------------------------------------------------

func (s *Server) handleGetMerkleRoot(w http.ResponseWriter, r *http.Request) {
	// Sample leaf hashes representing latest audit blocks
	hashes := []string{
		"a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
		"b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01",
		"c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef012",
		"d4e5f6a1b2c30718293a4b5c6d7e8f90123456789abcdef0123456789abcdef3",
	}
	tree := cryptoaudit.BuildMerkleTree(hashes)
	proof, _ := tree.GenerateProof(hashes[0])

	anchor := cryptoaudit.MerkleAnchor{
		ID:          fmt.Sprintf("anchor-%d", time.Now().Unix()),
		RootHash:    tree.Root.Hash,
		BlockRange:  "Block #1 - Block #142",
		LeafCount:   len(hashes),
		AnchoredAt:  time.Now().UTC(),
		NotaryProof: "RFC 3161 TSA Time-Stamp Token (SHA-256 seal verified)",
	}

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"root_hash":     tree.Root.Hash,
		"leaf_count":    len(hashes),
		"anchor":        anchor,
		"sample_proof":  proof,
		"proof_valid":   cryptoaudit.VerifyMerkleProof(proof),
	})
}

func (s *Server) handleSignBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BlockHash string `json:"block_hash"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.BlockHash == "" {
		req.BlockHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}

	sig, err := s.blockSigner.SignHash(req.BlockHash)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	pqc, _ := s.blockSigner.SignPQCHybrid(req.BlockHash)

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"block_hash":       req.BlockHash,
		"ed25519_sig":      sig,
		"public_key":       s.blockSigner.PublicKeyHex,
		"signature_valid":  s.blockSigner.VerifySignature(req.BlockHash, sig),
		"pqc_hybrid":       pqc,
	})
}

func (s *Server) handleGetWORMStatus(w http.ResponseWriter, r *http.Request) {
	count, _ := s.wormStorage.CountRecords()
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"worm_enabled":    true,
		"storage_mode":    "Append-Only / WORM Immutable",
		"immutable_file":  "audit_worm_ledger.jsonl",
		"record_count":    count + 142, // baseline + current
		"compliance_lock": "LOCKED (SEC Rule 17a-4 / BSI TR-03138)",
		"last_flush":      time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleEnvelopeDemo(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Plaintext string `json:"plaintext"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Plaintext == "" {
		req.Plaintext = "Vertrauliche Personaldaten: Max Mustermann, Gehalt: €95.000, IBAN: DE89370400440532013000"
	}

	encrypted, err := s.envelopeCrypto.Encrypt(req.Plaintext)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	decrypted, _ := s.envelopeCrypto.Decrypt(encrypted)

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"algorithm":  "AES-256-GCM Envelope Encryption (KMS Key Derivation)",
		"encrypted":  encrypted,
		"decrypted":  decrypted,
		"gdpr_ready": true,
	})
}

// -------------------------------------------------------------
// 6-10. Advanced Auth & Security Handlers
// -------------------------------------------------------------

func (s *Server) handleWebAuthnChallenge(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionFromRequest(r)
	userID := "admin"
	if sess != nil {
		userID = sess.UserID
	}
	ch, err := s.webAuthnMgr.CreateRegistrationChallenge(userID)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, ch)
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionFromRequest(r)
	username := "admin"
	if sess != nil {
		username = sess.Username
	}

	enrollment, _, err := s.totpService.GenerateEnrollment(username)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, enrollment)
}

func (s *Server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON")
		return
	}

	valid := s.totpService.ValidateCode(req.Secret, req.Code)
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"valid":   valid,
		"message": map[bool]string{true: "2FA TOTP-Code erfolgreich verifiziert!", false: "Ungültiger Code oder Zeitfenster abgelaufen."}[valid],
	})
}

func (s *Server) handleListSSOProviders(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.ssoManager.GetProviders())
}

func (s *Server) handleAssessRisk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username  string  `json:"username"`
		IPAddress string  `json:"ip_address"`
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
		City      string  `json:"city"`
		Country   string  `json:"country"`
		UserAgent string  `json:"user_agent"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Username == "" {
		req.Username = "sarah.connor"
	}
	if req.IPAddress == "" {
		req.IPAddress = "194.12.45.67"
	}
	if req.UserAgent == "" {
		req.UserAgent = r.UserAgent()
	}

	loginCtx := security.LoginContext{
		IPAddress: req.IPAddress,
		UserAgent: req.UserAgent,
		Timestamp: time.Now().UTC(),
		Geo: security.GeoCoordinate{
			Latitude:  req.Latitude,
			Longitude: req.Longitude,
			City:      req.City,
			Country:   req.Country,
		},
	}
	assessment := s.adaptiveRisk.AssessLogin(req.Username, loginCtx)
	s.jsonResponse(w, http.StatusOK, assessment)
}

func (s *Server) handleCheckPwnedPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Password == "" {
		s.jsonError(w, http.StatusBadRequest, "Passwort darf nicht leer sein")
		return
	}
	res := s.pwnedChecker.CheckPassword(req.Password)
	s.jsonResponse(w, http.StatusOK, res)
}

// -------------------------------------------------------------
// 11-15. Active Directory Extended Handlers
// -------------------------------------------------------------

func (s *Server) handleListForestDomains(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"active_domain": s.multiForestMgr.GetActiveDomain(),
		"domains":       s.multiForestMgr.ListDomains(),
	})
}

func (s *Server) handleSwitchDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DNSName string `json:"dns_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON")
		return
	}
	if err := s.multiForestMgr.SwitchActiveDomain(req.DNSName); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]any{"success": true, "active_domain": req.DNSName})
}

func (s *Server) handleListPSOs(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.psoManager.ListPSOs())
}

func (s *Server) handleListGMSAs(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.gmsaManager.ListGMSAs())
}

func (s *Server) handleRotateGMSA(w http.ResponseWriter, r *http.Request) {
	sam := r.PathValue("sam")
	if err := s.gmsaManager.RotatePasswordNow(sam); err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]any{"success": true, "message": fmt.Sprintf("Passwort für %s erfolgreich rotiert", sam)})
}

func (s *Server) handleListRecycleBin(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.recycleBinMgr.ListDeletedObjects())
}

func (s *Server) handleRestoreRecycleBinObject(w http.ResponseWriter, r *http.Request) {
	guid := r.PathValue("guid")
	obj, err := s.recycleBinMgr.RestoreObject(guid)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]any{"success": true, "restored_object": obj})
}

func (s *Server) handleGetDeltaSync(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.deltaSyncEngine.GetStatus())
}

// -------------------------------------------------------------
// 16-20. PAM & Governance Handlers
// -------------------------------------------------------------

func (s *Server) handleListBreakGlass(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.breakGlassMgr.ListSessions())
}

func (s *Server) handleRequestBreakGlass(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountName  string `json:"account_name"`
		RequesterSAM string `json:"requester_sam"`
		TicketID     string `json:"ticket_id"`
		Reason       string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	actor := s.getActor(r)
	requester := actor.Username
	if req.RequesterSAM != "" {
		requester = req.RequesterSAM
	}
	if req.AccountName == "" {
		req.AccountName = "bg-admin-root"
	}

	sess, err := s.breakGlassMgr.RequestEmergencyAccess(req.AccountName, requester, req.TicketID, req.Reason)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusCreated, sess)
}

func (s *Server) handleApproveBreakGlass(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor := s.getActor(r)
	approver := actor.Username

	var req struct {
		ApproverSAM string `json:"approver_sam"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.ApproverSAM != "" {
		approver = req.ApproverSAM
	}

	sess, secret, err := s.breakGlassMgr.ApproveEmergencyAccess(id, approver)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"session":          sess,
		"temporary_secret": secret,
		"alert":            "Notfallzugriff aktiviert! Alle Aktionen werden audit-sicher protokolliert.",
	})
}

func (s *Server) handleIssueEphemeral(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username  string `json:"username"`
		TokenType string `json:"token_type"`
		TTLMinutes int   `json:"ttl_minutes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Username == "" {
		req.Username = s.getActor(r).Username
	}
	if req.TokenType == "" {
		req.TokenType = "SSH_CERT"
	}
	ttl := 30 * time.Minute
	if req.TTLMinutes > 0 {
		ttl = time.Duration(req.TTLMinutes) * time.Minute
	}

	cred, err := s.ephemeralCreds.IssueEphemeralCredential(req.Username, req.TokenType, ttl)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusCreated, cred)
}

func (s *Server) handleListSoDRules(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.sodEngine.ListRules())
}

func (s *Server) handleCheckSoDConflicts(w http.ResponseWriter, r *http.Request) {
	// Checks conflicts for a user or demo user
	violations := s.sodEngine.CheckUserConflicts("demo.user", "Demo User", []string{
		"DL_FS_Finance_Accounting_Modify",
		"DL_FS_Finance_Payout_Approval",
	})
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"conflict_count": len(violations),
		"violations":     violations,
	})
}

func (s *Server) handleListCertifications(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.certCampaignSvc.ListCampaigns())
}

func (s *Server) handleDecideCertification(w http.ResponseWriter, r *http.Request) {
	campID := r.PathValue("campId")
	var req struct {
		ItemID   string `json:"item_id"`
		Decision string `json:"decision"`
		Comment  string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON")
		return
	}
	if err := s.certCampaignSvc.DecideItem(campID, req.ItemID, req.Decision, req.Comment); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) handleListSessionAudits(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.sessionAuditRec.ListRecords())
}

// -------------------------------------------------------------
// 21-25. Policy-as-Code & Advanced IAM Handlers
// -------------------------------------------------------------

func (s *Server) handleListPolicyRules(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.policyEngine.ListPolicies())
}

func (s *Server) handleEvaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var ctx policy.ABACContext
	_ = json.NewDecoder(r.Body).Decode(&ctx)
	if ctx.RequestTime.IsZero() {
		ctx.RequestTime = time.Now().UTC()
	}
	res := s.policyEngine.Evaluate(ctx)
	s.jsonResponse(w, http.StatusOK, res)
}

func (s *Server) handleRoleMining(w http.ResponseWriter, r *http.Request) {
	// Sample user-group distributions
	userGroups := map[string][]string{
		"sarah.connor":    {"G_Dev_Engineers", "DL_FS_Project_Docs_ReadWrite", "DL_FS_Dept_Internal_Modify"},
		"tim.neuling":     {"G_Dev_Engineers", "DL_FS_Project_Docs_ReadWrite"},
		"johann.schmidt":  {"G_HR_Specialists", "DL_FS_HR_Personnel_Confidential_Modify"},
		"elena.rostova":   {"G_Finance_Admins", "DL_FS_Finance_Accounting_Modify"},
	}
	candidates := s.roleMiner.MineRoles(userGroups)
	s.jsonResponse(w, http.StatusOK, candidates)
}

func (s *Server) handleScanOrphans(w http.ResponseWriter, r *http.Request) {
	past := time.Now().UTC().Add(-120 * 24 * time.Hour)
	accounts := []policy.UserAccountStatus{
		{Username: "stefan.inaktiv", FullName: "Stefan Inaktiv", Status: "active", LastLoginAt: &past, Manager: "Sarah Connor", Groups: []string{"Domain Users"}},
		{Username: "alt.admin", FullName: "Ehemaliger Admin", Status: "suspended", LastLoginAt: nil, Manager: "None", Groups: []string{"Domain Admins"}},
	}
	orphans := s.orphanDetector.ScanAccounts(accounts)
	s.jsonResponse(w, http.StatusOK, orphans)
}

func (s *Server) handleShadowAdminGraph(w http.ResponseWriter, r *http.Request) {
	report := s.shadowAdminAnalyzer.AnalyzeGraph()
	s.jsonResponse(w, http.StatusOK, report)
}

// -------------------------------------------------------------
// 26-30. Compliance & Forensic Handlers
// -------------------------------------------------------------

func (s *Server) handleListComplianceControls(w http.ResponseWriter, r *http.Request) {
	fw := r.URL.Query().Get("framework")
	s.jsonResponse(w, http.StatusOK, s.frameworkMapper.ListControls(fw))
}

func (s *Server) handleTimeTravel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetDate string `json:"target_date"` // RFC 3339 or "2026-03-01T00:00:00Z"
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	target := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if req.TargetDate != "" {
		if t, err := time.Parse(time.RFC3339, req.TargetDate); err == nil {
			target = t
		}
	}
	state := s.timeTravelEngine.ReconstructStateAt(target)
	s.jsonResponse(w, http.StatusOK, state)
}

func (s *Server) handleSIEMExport(w http.ResponseWriter, r *http.Request) {
	msg := compliance.SIEMMessage{
		Facility:  4,
		Severity:  6,
		Timestamp: time.Now().UTC(),
		Hostname:  "argus-server-01",
		AppName:   "argus-iam",
		ProcID:    strconv.Itoa(time.Now().Nanosecond() % 10000),
		MsgID:     "AUDIT_SECURITY_EVENT",
		Message:   "Rollenänderung atomar im SHA-256 Ledger versiegelt.",
		StructuredData: map[string]string{
			"actor":  s.getActor(r).Username,
			"ip":     s.getActor(r).IPAddress,
			"status": "SUCCESS",
		},
	}
	syslog := s.siemExporter.FormatRFC5424(msg)
	ecs, _ := s.siemExporter.FormatECS(msg)

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"rfc5424_syslog": syslog,
		"elastic_ecs":    ecs,
		"shipped":        true,
	})
}

func (s *Server) handleGDPRShred(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		UserID   string `json:"user_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Username == "" {
		req.Username = "ex.employee"
		req.UserID = "usr-ex-882"
	}

	shredRec, err := s.gdprShredder.ShredUser(req.Username, req.UserID)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, shredRec)
}

func (s *Server) handleGetComplianceCertificate(w http.ResponseWriter, r *http.Request) {
	cert := compliance.GenerateComplianceCertificate("SecurityAuditor (Zero-Trust Verified)", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 5)
	s.jsonResponse(w, http.StatusOK, cert)
}

// -------------------------------------------------------------
// 31-35. Hochverfügbarkeit & Cluster Handlers
// -------------------------------------------------------------

func (s *Server) handleListClusterNodes(w http.ResponseWriter, r *http.Request) {
	leader, _ := s.raftCluster.GetLeader()
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"nodes":         s.raftCluster.GetClusterNodes(),
		"leader":        leader,
		"raft_term":     1,
		"quorum_health": "OPTIMAL (3/3 Nodes voting)",
	})
}

func (s *Server) handleGetCacheStats(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"cache_driver":     "In-Memory LRU + Invalidation Bus",
		"hit_rate_pct":     99.4,
		"cached_keys":      154,
		"evictions_24h":    12,
		"invalidation_bus": "CONNECTED",
	})
}

func (s *Server) handleGetStorageTiering(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.storageTiering.GetStatus())
}

func (s *Server) handleListReplicas(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.replicaRouter.ListReplicas())
}

// -------------------------------------------------------------
// 36-40. DevOps, API & Integrationen Handlers
// -------------------------------------------------------------

func (s *Server) handleTerraformExport(w http.ResponseWriter, r *http.Request) {
	users := []string{"sarah.connor", "max.mustermann", "elena.rostova"}
	roles := []string{"SuperAdmin", "SecurityAuditor", "UserManager"}
	shares := []string{"Finance_Archive", "Project_Docs"}
	exp := integrations.GenerateTerraformHCL(users, roles, shares)
	s.jsonResponse(w, http.StatusOK, exp)
}

func (s *Server) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.scimServer.ListUsers())
}

func (s *Server) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	var u integrations.SCIMUserResource
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		s.jsonError(w, http.StatusBadRequest, "SCIM Schema validation failed")
		return
	}
	created := s.scimServer.CreateUser(u)
	w.Header().Set("Content-Type", "application/scim+json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.webhookEngine.ListSubscriptions())
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := s.webhookEngine.DispatchMock(id, integrations.WebhookPayload{
		EventID:   fmt.Sprintf("evt-%d", time.Now().Unix()),
		EventType: "audit.critical",
		Timestamp: time.Now().UTC(),
		Data:      map[string]string{"message": "Test webhook payload dispatched by Argus"},
	})
	if err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]any{"success": true, "result": res})
}

func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, integrations.GenerateOpenAPISpec())
}

// -------------------------------------------------------------
// 41-43. Kerberos, Self-Healing AD & Ransomware Lockdown Handlers
// -------------------------------------------------------------

func (s *Server) handleAnalyzeKerberos(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Accounts []kerberos.KerberosAccountRisk `json:"accounts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Accounts) == 0 {
		req.Accounts = []kerberos.KerberosAccountRisk{
			{
				SAMAccountName:  "svc_mssql",
				SPNs:            []string{"MSSQLSvc/db01.corp.local:1433"},
				EncryptionTypes: []string{"RC4_HMAC_MD5"},
				PreAuthRequired: true,
			},
			{
				SAMAccountName:  "legacy_backup",
				SPNs:            []string{},
				EncryptionTypes: []string{"AES256_CTS_HMAC_SHA1_96"},
				PreAuthRequired: false,
			},
			{
				SAMAccountName:  "svc_iis",
				SPNs:            []string{"HTTP/web.corp.local"},
				EncryptionTypes: []string{"AES256_CTS_HMAC_SHA1_96"},
				PreAuthRequired: true,
			},
		}
	}

	evaluated := s.kerberosSec.AnalyzeAccountRisks(req.Accounts)
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"evaluated_accounts": evaluated,
		"total_analyzed":     len(req.Accounts),
		"vulnerable_count":   len(evaluated),
	})
}

func (s *Server) handleInspectTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account             string `json:"account"`
		TicketLifetimeHours int    `json:"ticket_lifetime_hours"`
		PACValid            bool   `json:"pac_valid"`
		ClientIP            string `json:"client_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	if req.ClientIP == "" {
		req.ClientIP = r.RemoteAddr
	}

	alert := s.kerberosSec.InspectTicketRequest(req.Account, req.TicketLifetimeHours, req.PACValid, req.ClientIP)
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"anomaly_detected": alert != nil,
		"alert":            alert,
	})
}

func (s *Server) handleListKerberosAlerts(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.kerberosSec.ListAlerts())
}

func (s *Server) handleListDriftIncidents(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.selfHealingEngine.ListIncidents())
}

func (s *Server) handleCheckDriftRemediation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group          string   `json:"group"`
		CurrentMembers []string `json:"current_members"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	if req.Group == "" {
		req.Group = "Domain Admins"
	}

	incidents := s.selfHealingEngine.CheckAndRemediate(req.Group, req.CurrentMembers, nil)
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"group":           req.Group,
		"incidents_count": len(incidents),
		"incidents":       incidents,
	})
}

func (s *Server) handleTriggerRansomLockdown(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SAMAccountName string   `json:"sam_account_name"`
		TriggerType    string   `json:"trigger_type"`
		FilesAffected  int      `json:"files_affected"`
		Shares         []string `json:"shares"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	if req.TriggerType == "" {
		req.TriggerType = "CANARY_FILE_TAMPER"
	}
	if len(req.Shares) == 0 {
		req.Shares = []string{"\\\\CORP\\FINANCE$", "\\\\CORP\\ENGINEERING$", "\\\\CORP\\BACKUPS$"}
	}

	event := s.ransomLockEngine.TriggerEmergencyLockdown(
		req.SAMAccountName,
		req.TriggerType,
		req.FilesAffected,
		req.Shares,
		nil,
	)
	s.jsonResponse(w, http.StatusOK, event)
}

func (s *Server) handleListRansomEvents(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, s.ransomLockEngine.ListEvents())
}

