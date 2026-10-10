package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pittigs/argus/internal/adextended"
	"github.com/pittigs/argus/internal/audit"
	"github.com/pittigs/argus/internal/auth"
	"github.com/pittigs/argus/internal/cluster"
	"github.com/pittigs/argus/internal/compliance"
	"github.com/pittigs/argus/internal/cryptoaudit"
	"github.com/pittigs/argus/internal/directory"
	"github.com/pittigs/argus/internal/governance"
	"github.com/pittigs/argus/internal/integrations"
	"github.com/pittigs/argus/internal/kerberos"
	"github.com/pittigs/argus/internal/lifecycle"
	"github.com/pittigs/argus/internal/model"
	"github.com/pittigs/argus/internal/policy"
	"github.com/pittigs/argus/internal/ransomlock"
	"github.com/pittigs/argus/internal/security"
	"github.com/pittigs/argus/internal/selfhealing"
	"github.com/pittigs/argus/internal/service"
)

type Server struct {
	authService      *auth.Service
	mgmtService      *service.ManagementService
	auditService     *audit.Service
	dirManager       *directory.Manager
	lifecycleService *lifecycle.Service
	staticFS         fs.FS

	// Enterprise Suite Components (40 Capabilities)
	blockSigner         *cryptoaudit.BlockSigner
	wormStorage         *cryptoaudit.WORMStorage
	envelopeCrypto      *cryptoaudit.EnvelopeEncryption
	webAuthnMgr         *security.WebAuthnManager
	totpService         *security.TOTPService
	ssoManager          *security.SSOManager
	adaptiveRisk        *security.AdaptiveRiskEngine
	pwnedChecker        *security.PwnedPasswordChecker
	multiForestMgr      *adextended.MultiForestManager
	psoManager          *adextended.PSOManager
	gmsaManager         *adextended.GMSAManager
	recycleBinMgr       *adextended.RecycleBinManager
	deltaSyncEngine     *adextended.DeltaSyncEngine
	breakGlassMgr       *governance.BreakGlassManager
	ephemeralCreds      *governance.EphemeralCredentialService
	sodEngine           *governance.SoDEngine
	certCampaignSvc     *governance.CertificationCampaignService
	sessionAuditRec     *governance.SessionAuditRecorder
	policyEngine        *policy.PolicyEngine
	roleMiner           *policy.RoleMiningEngine
	orphanDetector      *policy.OrphanDetector
	shadowAdminAnalyzer *policy.ShadowAdminAnalyzer
	frameworkMapper     *compliance.FrameworkMapper
	timeTravelEngine    *compliance.TimeTravelEngine
	siemExporter        *compliance.SIEMExporter
	gdprShredder        *compliance.GDPRShredder
	raftCluster         *cluster.RaftClusterManager
	distCache           *cluster.DistributedCache
	storageTiering      *cluster.StorageTieringManager
	replicaRouter       *cluster.ReplicaRouter
	scimServer          *integrations.SCIMServer
	webhookEngine       *integrations.WebhookEngine
	kerberosSec         *kerberos.KerberosSecurityEngine
	selfHealingEngine   *selfhealing.SelfHealingEngine
	ransomLockEngine    *ransomlock.RansomwareLockdownEngine
}

func NewServer(
	authSvc *auth.Service,
	mgmtSvc *service.ManagementService,
	auditSvc *audit.Service,
	dirMgr *directory.Manager,
	lifecycleSvc *lifecycle.Service,
	staticFiles fs.FS,
) *Server {
	bs, _ := cryptoaudit.NewBlockSigner()
	worm, _ := cryptoaudit.NewWORMStorage("./data/worm")
	envelope, _ := cryptoaudit.NewEnvelopeEncryption()

	return &Server{
		authService:         authSvc,
		mgmtService:         mgmtSvc,
		auditService:        auditSvc,
		dirManager:          dirMgr,
		lifecycleService:    lifecycleSvc,
		staticFS:            staticFiles,
		blockSigner:         bs,
		wormStorage:         worm,
		envelopeCrypto:      envelope,
		webAuthnMgr:         security.NewWebAuthnManager(),
		totpService:         security.NewTOTPService("Argus Enterprise"),
		ssoManager:          security.NewSSOManager(),
		adaptiveRisk:        security.NewAdaptiveRiskEngine(),
		pwnedChecker:        security.NewPwnedPasswordChecker(),
		multiForestMgr:      adextended.NewMultiForestManager(),
		psoManager:          adextended.NewPSOManager(),
		gmsaManager:         adextended.NewGMSAManager(),
		recycleBinMgr:       adextended.NewRecycleBinManager(),
		deltaSyncEngine:     adextended.NewDeltaSyncEngine("corp.local"),
		breakGlassMgr:       governance.NewBreakGlassManager(),
		ephemeralCreds:      governance.NewEphemeralCredentialService(),
		sodEngine:           governance.NewSoDEngine(),
		certCampaignSvc:     governance.NewCertificationCampaignService(),
		sessionAuditRec:     governance.NewSessionAuditRecorder(),
		policyEngine:        policy.NewPolicyEngine(),
		roleMiner:           policy.NewRoleMiningEngine(),
		orphanDetector:      policy.NewOrphanDetector(),
		shadowAdminAnalyzer: policy.NewShadowAdminAnalyzer(),
		frameworkMapper:     compliance.NewFrameworkMapper(),
		timeTravelEngine:    compliance.NewTimeTravelEngine(),
		siemExporter:        compliance.NewSIEMExporter("https://siem.corp.local:8088"),
		gdprShredder:        compliance.NewGDPRShredder(),
		raftCluster:         cluster.NewRaftClusterManager("argus-node-1", "127.0.0.1:8080"),
		distCache:           cluster.NewDistributedCache(),
		storageTiering:      cluster.NewStorageTieringManager(),
		replicaRouter:       cluster.NewReplicaRouter(),
		scimServer:          integrations.NewSCIMServer(),
		webhookEngine:       integrations.NewWebhookEngine(),
		kerberosSec:         kerberos.NewKerberosSecurityEngine(),
		selfHealingEngine:   selfhealing.NewSelfHealingEngine(),
		ransomLockEngine:    ransomlock.NewRansomwareLockdownEngine(),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Auth routes (public)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("POST /api/auth/change-password", s.requireAuth(s.handleChangePassword, ""))

	// Protected routes
	mux.HandleFunc("GET /api/auth/me", s.requireAuth(s.handleMe, ""))
	mux.HandleFunc("GET /api/stats", s.requireAuth(s.handleStats, "system:view"))

	// Users routes
	mux.HandleFunc("GET /api/users", s.requireAuth(s.handleListUsers, "users:read"))
	mux.HandleFunc("GET /api/users/{id}", s.requireAuth(s.handleGetUser, "users:read"))
	mux.HandleFunc("POST /api/users", s.requireAuth(s.handleCreateUser, "users:create"))
	mux.HandleFunc("PUT /api/users/{id}", s.requireAuth(s.handleUpdateUser, "users:update"))
	mux.HandleFunc("DELETE /api/users/{id}", s.requireAuth(s.handleDeleteUser, "users:delete"))

	// Roles & Permissions routes
	mux.HandleFunc("GET /api/roles", s.requireAuth(s.handleListRoles, "roles:read"))
	mux.HandleFunc("GET /api/roles/{id}", s.requireAuth(s.handleGetRole, "roles:read"))
	mux.HandleFunc("POST /api/roles", s.requireAuth(s.handleCreateRole, "roles:manage"))
	mux.HandleFunc("PUT /api/roles/{id}", s.requireAuth(s.handleUpdateRole, "roles:manage"))
	mux.HandleFunc("DELETE /api/roles/{id}", s.requireAuth(s.handleDeleteRole, "roles:manage"))
	mux.HandleFunc("GET /api/permissions", s.requireAuth(s.handleListPermissions, "roles:read"))

	// Audit routes
	mux.HandleFunc("GET /api/audit", s.requireAuth(s.handleListAudit, "audit:read"))
	mux.HandleFunc("GET /api/audit/verify", s.requireAuth(s.handleVerifyAuditChain, "audit:verify"))
	mux.HandleFunc("GET /api/audit/export", s.requireAuth(s.handleExportAudit, "audit:export"))

	// Directory & AGDLP routes (Active Directory & Samba-AD)
	mux.HandleFunc("GET /api/directory/config", s.requireAuth(s.handleGetDirectoryConfig, "ad:read"))
	mux.HandleFunc("POST /api/directory/config", s.requireAuth(s.handleUpdateDirectoryConfig, "ad:config"))
	mux.HandleFunc("POST /api/directory/test-connection", s.requireAuth(s.handleTestDirectoryConnection, "ad:read"))
	mux.HandleFunc("GET /api/directory/users", s.requireAuth(s.handleListDirectoryUsers, "ad:read"))
	mux.HandleFunc("GET /api/directory/users/{sam}", s.requireAuth(s.handleGetDirectoryUser, "ad:read"))
	mux.HandleFunc("POST /api/directory/users", s.requireAuth(s.handleCreateDirectoryUser, "ad:users:manage"))
	mux.HandleFunc("PUT /api/directory/users/{sam}", s.requireAuth(s.handleUpdateDirectoryUser, "ad:users:manage"))
	mux.HandleFunc("DELETE /api/directory/users/{sam}", s.requireAuth(s.handleDeleteDirectoryUser, "ad:users:manage"))
	mux.HandleFunc("POST /api/directory/users/{sam}/status", s.requireAuth(s.handleSetDirectoryUserStatus, "ad:users:manage"))
	mux.HandleFunc("POST /api/directory/users/{sam}/password", s.requireAuth(s.handleResetDirectoryUserPassword, "ad:users:password"))
	mux.HandleFunc("GET /api/directory/groups", s.requireAuth(s.handleListDirectoryGroups, "ad:read"))
	mux.HandleFunc("POST /api/directory/groups", s.requireAuth(s.handleCreateDirectoryGroup, "ad:groups:manage"))
	mux.HandleFunc("POST /api/directory/groups/agdlp", s.requireAuth(s.handleCreateAGDLPFileShare, "ad:groups:manage"))
	mux.HandleFunc("POST /api/directory/memberships", s.requireAuth(s.handleAddDirectoryMembership, "ad:groups:manage"))
	mux.HandleFunc("DELETE /api/directory/memberships", s.requireAuth(s.handleRemoveDirectoryMembership, "ad:groups:manage"))
	mux.HandleFunc("GET /api/directory/agdlp-matrix", s.requireAuth(s.handleGetAGDLPMatrix, "ad:read"))
	mux.HandleFunc("GET /api/directory/users/{sam}/effective-permissions", s.requireAuth(s.handleGetEffectivePermissions, "ad:read"))
	mux.HandleFunc("GET /api/directory/agdlp/conflicts", s.requireAuth(s.handleGetAGDLPConflicts, "ad:read"))
	mux.HandleFunc("GET /api/directory/users/compare", s.requireAuth(s.handleCompareUsers, "ad:read"))
	mux.HandleFunc("GET /api/directory/agdlp/scripts", s.requireAuth(s.handleGenerateACLScripts, "ad:read"))

	// Realtime Audit SSE Stream
	mux.HandleFunc("GET /api/audit/stream", s.handleAuditStream)

	// CSV Bulk Onboarding
	mux.HandleFunc("POST /api/directory/users/bulk-import", s.requireAuth(s.handleBulkImportDirectoryUsers, "ad:bulk:manage"))
	mux.HandleFunc("GET /api/directory/users/bulk-template", s.requireAuth(s.handleGetBulkTemplate, "ad:read"))

	// Just-In-Time (JIT) Temporary Memberships
	mux.HandleFunc("GET /api/directory/jit", s.requireAuth(s.handleListJITMemberships, "ad:read"))
	mux.HandleFunc("POST /api/directory/jit", s.requireAuth(s.handleCreateJITMembership, "ad:jit:manage"))
	mux.HandleFunc("DELETE /api/directory/jit/{id}", s.requireAuth(s.handleRevokeJITMembership, "ad:jit:manage"))

	// Vier-Augen-Prinzip / Approvals
	mux.HandleFunc("GET /api/approvals", s.requireAuth(s.handleListApprovals, "ad:read"))
	mux.HandleFunc("POST /api/approvals", s.requireAuth(s.handleCreateApproval, "ad:read"))
	mux.HandleFunc("POST /api/approvals/{id}/resolve", s.requireAuth(s.handleResolveApproval, "ad:approvals:manage"))

	// File Share Templates & Compliance Reports
	mux.HandleFunc("GET /api/directory/agdlp/templates", s.requireAuth(s.handleListShareTemplates, "ad:read"))
	mux.HandleFunc("POST /api/directory/agdlp/templates/apply", s.requireAuth(s.handleApplyShareTemplate, "ad:groups:manage"))
	mux.HandleFunc("GET /api/directory/agdlp/compliance-report", s.requireAuth(s.handleGetComplianceReport, "ad:read"))

	// User Lifecycle & HR Automation routes
	mux.HandleFunc("GET /api/lifecycle/employees", s.requireAuth(s.handleListLifecycleEmployees, "lifecycle:read"))
	mux.HandleFunc("GET /api/lifecycle/employees/{id}", s.requireAuth(s.handleGetLifecycleEmployee, "lifecycle:read"))
	mux.HandleFunc("POST /api/lifecycle/onboard", s.requireAuth(s.handleOnboardEmployee, "lifecycle:manage"))
	mux.HandleFunc("POST /api/lifecycle/offboard", s.requireAuth(s.handleOffboardEmployee, "lifecycle:manage"))
	mux.HandleFunc("POST /api/lifecycle/transfer", s.requireAuth(s.handleTransferEmployee, "lifecycle:manage"))
	mux.HandleFunc("POST /api/lifecycle/checklist", s.requireAuth(s.handleUpdateLifecycleChecklist, "lifecycle:manage"))
	mux.HandleFunc("GET /api/lifecycle/stats", s.requireAuth(s.handleGetLifecycleStats, "lifecycle:read"))

	// Enterprise Suite (40 Capabilities)
	// 1-5. Crypto & Zero-Trust Audit
	mux.HandleFunc("GET /api/enterprise/crypto/merkle-root", s.requireAuth(s.handleGetMerkleRoot, ""))
	mux.HandleFunc("POST /api/enterprise/crypto/sign-block", s.requireAuth(s.handleSignBlock, ""))
	mux.HandleFunc("GET /api/enterprise/crypto/worm-status", s.requireAuth(s.handleGetWORMStatus, ""))
	mux.HandleFunc("POST /api/enterprise/crypto/envelope-demo", s.requireAuth(s.handleEnvelopeDemo, ""))

	// 6-10. Advanced Auth & Security
	mux.HandleFunc("GET /api/enterprise/security/webauthn/challenge", s.requireAuth(s.handleWebAuthnChallenge, ""))
	mux.HandleFunc("GET /api/enterprise/security/totp/setup", s.requireAuth(s.handleTOTPSetup, ""))
	mux.HandleFunc("POST /api/enterprise/security/totp/verify", s.requireAuth(s.handleTOTPVerify, ""))
	mux.HandleFunc("GET /api/enterprise/security/sso/providers", s.requireAuth(s.handleListSSOProviders, ""))
	mux.HandleFunc("POST /api/enterprise/security/risk-assess", s.requireAuth(s.handleAssessRisk, ""))
	mux.HandleFunc("POST /api/enterprise/security/pwned-check", s.requireAuth(s.handleCheckPwnedPassword, ""))

	// 11-15. Active Directory Extended
	mux.HandleFunc("GET /api/enterprise/ad/domains", s.requireAuth(s.handleListForestDomains, "ad:read"))
	mux.HandleFunc("POST /api/enterprise/ad/domains/switch", s.requireAuth(s.handleSwitchDomain, "ad:config"))
	mux.HandleFunc("GET /api/enterprise/ad/pso", s.requireAuth(s.handleListPSOs, "ad:read"))
	mux.HandleFunc("GET /api/enterprise/ad/gmsa", s.requireAuth(s.handleListGMSAs, "ad:read"))
	mux.HandleFunc("POST /api/enterprise/ad/gmsa/{sam}/rotate", s.requireAuth(s.handleRotateGMSA, "ad:users:manage"))
	mux.HandleFunc("GET /api/enterprise/ad/recycle-bin", s.requireAuth(s.handleListRecycleBin, "ad:read"))
	mux.HandleFunc("POST /api/enterprise/ad/recycle-bin/{guid}/restore", s.requireAuth(s.handleRestoreRecycleBinObject, "ad:users:manage"))
	mux.HandleFunc("GET /api/enterprise/ad/delta-sync", s.requireAuth(s.handleGetDeltaSync, "ad:read"))

	// 16-20. PAM & Governance
	mux.HandleFunc("GET /api/enterprise/governance/breakglass", s.requireAuth(s.handleListBreakGlass, ""))
	mux.HandleFunc("POST /api/enterprise/governance/breakglass", s.requireAuth(s.handleRequestBreakGlass, ""))
	mux.HandleFunc("POST /api/enterprise/governance/breakglass/{id}/approve", s.requireAuth(s.handleApproveBreakGlass, ""))
	mux.HandleFunc("POST /api/enterprise/governance/ephemeral-credentials", s.requireAuth(s.handleIssueEphemeral, ""))
	mux.HandleFunc("GET /api/enterprise/governance/sod-rules", s.requireAuth(s.handleListSoDRules, ""))
	mux.HandleFunc("GET /api/enterprise/governance/sod-conflicts", s.requireAuth(s.handleCheckSoDConflicts, ""))
	mux.HandleFunc("GET /api/enterprise/governance/certifications", s.requireAuth(s.handleListCertifications, ""))
	mux.HandleFunc("POST /api/enterprise/governance/certifications/{campId}/decide", s.requireAuth(s.handleDecideCertification, ""))
	mux.HandleFunc("GET /api/enterprise/governance/session-audits", s.requireAuth(s.handleListSessionAudits, "audit:read"))

	// 21-25. Policy-as-Code & Advanced IAM
	mux.HandleFunc("GET /api/enterprise/policy/rules", s.requireAuth(s.handleListPolicyRules, ""))
	mux.HandleFunc("POST /api/enterprise/policy/evaluate", s.requireAuth(s.handleEvaluatePolicy, ""))
	mux.HandleFunc("GET /api/enterprise/policy/role-mining", s.requireAuth(s.handleRoleMining, ""))
	mux.HandleFunc("GET /api/enterprise/policy/orphans", s.requireAuth(s.handleScanOrphans, ""))
	mux.HandleFunc("GET /api/enterprise/policy/shadow-admins", s.requireAuth(s.handleShadowAdminGraph, ""))

	// 26-30. Compliance & Forensics
	mux.HandleFunc("GET /api/enterprise/compliance/controls", s.requireAuth(s.handleListComplianceControls, "audit:read"))
	mux.HandleFunc("POST /api/enterprise/compliance/time-travel", s.requireAuth(s.handleTimeTravel, "audit:read"))
	mux.HandleFunc("POST /api/enterprise/compliance/siem-export", s.requireAuth(s.handleSIEMExport, "audit:export"))
	mux.HandleFunc("POST /api/enterprise/compliance/gdpr-shred", s.requireAuth(s.handleGDPRShred, "system:admin"))
	mux.HandleFunc("GET /api/enterprise/compliance/certificate", s.requireAuth(s.handleGetComplianceCertificate, "audit:read"))

	// 31-35. Hochverfügbarkeit & Cluster
	mux.HandleFunc("GET /api/enterprise/cluster/nodes", s.requireAuth(s.handleListClusterNodes, "system:view"))
	mux.HandleFunc("GET /api/enterprise/cluster/cache", s.requireAuth(s.handleGetCacheStats, "system:view"))
	mux.HandleFunc("GET /api/enterprise/cluster/storage-tiering", s.requireAuth(s.handleGetStorageTiering, "system:view"))
	mux.HandleFunc("GET /api/enterprise/cluster/replicas", s.requireAuth(s.handleListReplicas, "system:view"))

	// 36-40. DevOps, API & Integrations
	mux.HandleFunc("GET /api/enterprise/terraform/export", s.requireAuth(s.handleTerraformExport, "system:admin"))
	mux.HandleFunc("GET /scim/v2/Users", s.requireAuth(s.handleSCIMListUsers, "users:read"))
	mux.HandleFunc("POST /scim/v2/Users", s.requireAuth(s.handleSCIMCreateUser, "users:create"))
	mux.HandleFunc("GET /api/enterprise/webhooks", s.requireAuth(s.handleListWebhooks, "system:admin"))
	mux.HandleFunc("POST /api/enterprise/webhooks/{id}/test", s.requireAuth(s.handleTestWebhook, "system:admin"))
	mux.HandleFunc("GET /api/openapi.json", s.handleOpenAPISpec)

	// 41-43. Kerberos, Self-Healing AD & Ransomware Lockdown
	mux.HandleFunc("POST /api/enterprise/security/kerberos/analyze", s.requireAuth(s.handleAnalyzeKerberos, "ad:read"))
	mux.HandleFunc("POST /api/enterprise/security/kerberos/inspect-ticket", s.requireAuth(s.handleInspectTicket, "ad:read"))
	mux.HandleFunc("GET /api/enterprise/security/kerberos/alerts", s.requireAuth(s.handleListKerberosAlerts, "audit:read"))
	mux.HandleFunc("GET /api/enterprise/ad/self-healing/incidents", s.requireAuth(s.handleListDriftIncidents, "audit:read"))
	mux.HandleFunc("POST /api/enterprise/ad/self-healing/check", s.requireAuth(s.handleCheckDriftRemediation, "ad:groups:manage"))
	mux.HandleFunc("POST /api/enterprise/security/ransomlock/trigger", s.requireAuth(s.handleTriggerRansomLockdown, "system:admin"))
	mux.HandleFunc("GET /api/enterprise/security/ransomlock/events", s.requireAuth(s.handleListRansomEvents, "audit:read"))

	// DevOps, Monitoring & Health Probes (Public)
	mux.HandleFunc("GET /metrics", s.handlePrometheusMetrics)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleHealthz)

	// Static UI routing
	if s.staticFS != nil {
		fileServer := http.FileServer(http.FS(s.staticFS))
		mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}
			fileServer.ServeHTTP(w, r)
		})
	}

	return s.corsMiddleware(mux)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowedOrigin := ""
		if origin != "" {
			if strings.HasPrefix(origin, "http://localhost") ||
				strings.HasPrefix(origin, "https://localhost") ||
				strings.HasPrefix(origin, "http://127.0.0.1") ||
				strings.HasPrefix(origin, "https://127.0.0.1") ||
				strings.Contains(origin, r.Host) {
				allowedOrigin = origin
			}
		} else {
			allowedOrigin = "*"
		}

		if allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			if allowedOrigin != "*" {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Enterprise Defensive Security Headers (OWASP Top 10 A05)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Context keys and middleware
type authContextKey string

const sessionContextKey authContextKey = "session"

func (s *Server) requireAuth(next http.HandlerFunc, requiredPerm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := auth.ExtractToken(r)
		session, err := s.authService.ValidateSession(token)
		if err != nil {
			s.jsonError(w, http.StatusUnauthorized, "Sitzung abgelaufen oder nicht authentifiziert")
			return
		}

		if requiredPerm != "" && !auth.HasPermission(session, requiredPerm) {
			s.jsonError(w, http.StatusForbidden, "Fehlende Berechtigung: "+requiredPerm)
			return
		}

		next(w, r)
	}
}

func (s *Server) getSessionFromRequest(r *http.Request) *model.Session {
	token := auth.ExtractToken(r)
	sess, _ := s.authService.ValidateSession(token)
	return sess
}

func (s *Server) getActor(r *http.Request) service.ActorInfo {
	sess := s.getSessionFromRequest(r)
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}

	if sess != nil {
		return service.ActorInfo{
			ID:        sess.UserID,
			Username:  sess.Username,
			IPAddress: ip,
			UserAgent: r.UserAgent(),
		}
	}

	return service.ActorInfo{
		ID:        "anonymous",
		Username:  "anonymous",
		IPAddress: ip,
		UserAgent: r.UserAgent(),
	}
}

func (s *Server) jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, message string) {
	s.jsonResponse(w, status, map[string]string{"error": message})
}

// ----------------- HANDLERS -----------------

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON Format")
		return
	}

	actor := s.getActor(r)
	session, user, err := s.authService.Authenticate(body.Username, body.Password, actor.IPAddress, actor.UserAgent)
	if err != nil {
		// Log failed authentication in audit log
		_, _ = s.auditService.Record(audit.LogEntryInput{
			ActorID:       "anonymous",
			ActorUsername: body.Username,
			ActorIP:       actor.IPAddress,
			UserAgent:     actor.UserAgent,
			Action:        "auth.login_failed",
			ResourceType:  "auth",
			ResourceID:    body.Username,
			Status:        "FAILURE",
			Reason:        err.Error(),
		})

		s.jsonError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Log successful login
	_, _ = s.auditService.Record(audit.LogEntryInput{
		ActorID:       user.ID,
		ActorUsername: user.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "auth.login",
		ResourceType:  "session",
		ResourceID:    session.Token[:8] + "...",
		Status:        "SUCCESS",
		Reason:        "Benutzeranmeldung erfolgreich",
	})

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "argus_session",
		Value:    session.Token,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	mustChange := auth.IsDefaultPassword(body.Password)
	notice := ""
	if mustChange {
		notice = "Sicherheitshinweis: Sie verwenden ein Standard-Initialpasswort. Bitte ändern Sie dieses umgehend via /api/auth/change-password."
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"token":                session.Token,
		"session":              session,
		"user":                 user,
		"must_change_password": mustChange,
		"security_notice":      notice,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	actor := s.getActor(r)
	token := auth.ExtractToken(r)

	if token != "" {
		_ = s.authService.RevokeSession(token)

		_, _ = s.auditService.Record(audit.LogEntryInput{
			ActorID:       actor.ID,
			ActorUsername: actor.Username,
			ActorIP:       actor.IPAddress,
			UserAgent:     actor.UserAgent,
			Action:        "auth.logout",
			ResourceType:  "session",
			ResourceID:    actor.Username,
			Status:        "SUCCESS",
			Reason:        "Benutzer hat sich abgemeldet",
		})
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "argus_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	s.jsonResponse(w, http.StatusOK, map[string]string{"message": "Erfolgreich abgemeldet"})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON Format")
		return
	}
	actor := s.getActor(r)
	if err := s.authService.ChangePassword(actor.Username, body.OldPassword, body.NewPassword); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	_, _ = s.auditService.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "user.password_change",
		ResourceType:  "user",
		ResourceID:    actor.Username,
		Status:        "SUCCESS",
		Reason:        "Passwort erfolgreich geändert",
	})

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "Kennwort erfolgreich aktualisiert. Alle Richtlinienanforderungen erfüllt.",
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionFromRequest(r)
	user, err := s.mgmtService.GetUser(sess.UserID)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "Benutzer nicht gefunden")
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"session": sess,
		"user":    user,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.mgmtService.GetStats()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, stats)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.mgmtService.ListUsers()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, users)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := s.mgmtService.GetUser(id)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, user)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var in service.CreateUserInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON Format")
		return
	}

	actor := s.getActor(r)
	user, err := s.mgmtService.CreateUser(in, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusCreated, user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in service.UpdateUserInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON Format")
		return
	}

	actor := s.getActor(r)
	user, err := s.mgmtService.UpdateUser(id, in, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, user)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor := s.getActor(r)
	if err := s.mgmtService.DeleteUser(id, actor); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]string{"message": "Benutzer erfolgreich gelöscht"})
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.mgmtService.ListRoles()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, roles)
}

func (s *Server) handleGetRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	role, err := s.mgmtService.GetRole(id)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, role)
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var in service.CreateRoleInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON")
		return
	}

	actor := s.getActor(r)
	role, err := s.mgmtService.CreateRole(in, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusCreated, role)
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in service.UpdateRoleInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON")
		return
	}

	actor := s.getActor(r)
	role, err := s.mgmtService.UpdateRole(id, in, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, role)
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor := s.getActor(r)
	if err := s.mgmtService.DeleteRole(id, actor); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]string{"message": "Rolle erfolgreich gelöscht"})
}

func (s *Server) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := s.mgmtService.ListPermissions()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, perms)
}

// ----------------- AUDIT HANDLERS -----------------

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	params := audit.FilterParams{
		Search:       q.Get("search"),
		Actor:        q.Get("actor"),
		Action:       q.Get("action"),
		ResourceType: q.Get("resource_type"),
		Status:       q.Get("status"),
		Limit:        limit,
		Offset:       offset,
	}

	if fromStr := q.Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			params.From = &t
		}
	}
	if toStr := q.Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			params.To = &t
		}
	}

	logs, total, err := s.auditService.Query(params)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"total":  total,
		"limit":  params.Limit,
		"offset": params.Offset,
		"items":  logs,
	})
}

func (s *Server) handleVerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	result, err := s.auditService.VerifyChain()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, result)
}

func (s *Server) handleExportAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := strings.ToLower(q.Get("format"))
	if format == "" {
		format = "json"
	}

	params := audit.FilterParams{
		Search:       q.Get("search"),
		Actor:        q.Get("actor"),
		Action:       q.Get("action"),
		ResourceType: q.Get("resource_type"),
		Status:       q.Get("status"),
	}

	actor := s.getActor(r)
	nowStr := time.Now().UTC().Format("20060102_150405")

	// Audit the export action
	_, _ = s.auditService.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "audit.export",
		ResourceType:  "audit",
		ResourceID:    format,
		Status:        "SUCCESS",
		Reason:        "Audit-Logdaten für Compliance-Revision exportiert (" + format + ")",
	})

	if format == "csv" {
		data, err := s.auditService.ExportCSV(params)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=\"argus_audit_log_"+nowStr+".csv\"")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}

	data, err := s.auditService.ExportJSON(params)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"argus_audit_log_"+nowStr+".json\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ================= DIRECTORY & AGDLP HANDLERS =================

func (s *Server) getDirectoryActor(r *http.Request) directory.ActorInfo {
	act := s.getActor(r)
	return directory.ActorInfo{
		ID:        act.ID,
		Username:  act.Username,
		IPAddress: act.IPAddress,
		UserAgent: act.UserAgent,
	}
}

func (s *Server) handleGetDirectoryConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.dirManager.GetConfig()
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{"config": cfg})
}

func (s *Server) handleUpdateDirectoryConfig(w http.ResponseWriter, r *http.Request) {
	var cfg directory.DirectoryConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON-Format")
		return
	}

	actor := s.getDirectoryActor(r)
	if err := s.dirManager.UpdateConfig(cfg, actor); err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Domain Controller Konfiguration erfolgreich aktualisiert",
		"config":  s.dirManager.GetConfig(),
	})
}

func (s *Server) handleTestDirectoryConnection(w http.ResponseWriter, r *http.Request) {
	result := s.dirManager.TestConnection()
	s.jsonResponse(w, http.StatusOK, result)
}

func (s *Server) handleListDirectoryUsers(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	users, err := s.dirManager.ListUsers(search)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{"users": users})
}

func (s *Server) handleGetDirectoryUser(w http.ResponseWriter, r *http.Request) {
	sam := r.PathValue("sam")
	user, err := s.dirManager.GetUser(sam)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "AD-Benutzer nicht gefunden")
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{"user": user})
}

func (s *Server) handleCreateDirectoryUser(w http.ResponseWriter, r *http.Request) {
	var in directory.CreateADUserInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON-Format")
		return
	}

	actor := s.getDirectoryActor(r)
	user, err := s.dirManager.CreateUser(in, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"message": fmt.Sprintf("AD-Benutzerkonto '%s' erfolgreich erstellt", user.SAMAccountName),
		"user":    user,
	})
}

func (s *Server) handleUpdateDirectoryUser(w http.ResponseWriter, r *http.Request) {
	sam := r.PathValue("sam")
	var in directory.UpdateADUserInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON-Format")
		return
	}

	actor := s.getDirectoryActor(r)
	user, err := s.dirManager.UpdateUser(sam, in, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("AD-Benutzerkonto '%s' erfolgreich aktualisiert", sam),
		"user":    user,
	})
}

func (s *Server) handleDeleteDirectoryUser(w http.ResponseWriter, r *http.Request) {
	sam := r.PathValue("sam")
	actor := s.getDirectoryActor(r)

	if err := s.dirManager.DeleteUser(sam, actor); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("AD-Benutzerkonto '%s' erfolgreich gelöscht", sam),
	})
}

func (s *Server) handleSetDirectoryUserStatus(w http.ResponseWriter, r *http.Request) {
	sam := r.PathValue("sam")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON-Format")
		return
	}

	actor := s.getDirectoryActor(r)
	if err := s.dirManager.SetUserStatus(sam, req.Enabled, actor); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	statusText := "aktiviert"
	if !req.Enabled {
		statusText = "deaktiviert"
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("AD-Benutzerkonto '%s' wurde %s", sam, statusText),
		"enabled": req.Enabled,
	})
}

func (s *Server) handleResetDirectoryUserPassword(w http.ResponseWriter, r *http.Request) {
	sam := r.PathValue("sam")
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON-Format")
		return
	}

	if len(req.Password) < 8 {
		s.jsonError(w, http.StatusBadRequest, "Kennwort muss mindestens 8 Zeichen lang sein")
		return
	}

	actor := s.getDirectoryActor(r)
	if err := s.dirManager.ResetPassword(sam, req.Password, actor); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Kennwort für AD-Benutzer '%s' erfolgreich zurückgesetzt & entsperrt", sam),
	})
}

func (s *Server) handleListDirectoryGroups(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	groups, err := s.dirManager.ListGroups(category)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{"groups": groups})
}

func (s *Server) handleCreateDirectoryGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON-Format")
		return
	}

	actor := s.getDirectoryActor(r)
	grp, err := s.dirManager.CreateGroup(in.Name, in.Description, in.Scope, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"message": fmt.Sprintf("AD-Gruppe '%s' erfolgreich erstellt", grp.SAMAccountName),
		"group":   grp,
	})
}

func (s *Server) handleCreateAGDLPFileShare(w http.ResponseWriter, r *http.Request) {
	var in directory.AGDLPShareInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON-Format")
		return
	}

	actor := s.getDirectoryActor(r)
	groups, err := s.dirManager.CreateAGDLPFileShare(in, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"message": fmt.Sprintf("AGDLP Ressourcengruppen für '%s/%s' erfolgreich generiert", in.ShareName, in.FolderName),
		"groups":  groups,
	})
}

func (s *Server) handleAddDirectoryMembership(w http.ResponseWriter, r *http.Request) {
	var in directory.MembershipChangeInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON-Format")
		return
	}

	actor := s.getDirectoryActor(r)
	if err := s.dirManager.AddMemberToGroup(in.GroupName, in.Member, actor); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("'%s' erfolgreich zur Gruppe '%s' hinzugefügt", in.Member, in.GroupName),
	})
}

func (s *Server) handleRemoveDirectoryMembership(w http.ResponseWriter, r *http.Request) {
	var in directory.MembershipChangeInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON-Format")
		return
	}

	actor := s.getDirectoryActor(r)
	if err := s.dirManager.RemoveMemberFromGroup(in.GroupName, in.Member, actor); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("'%s' erfolgreich aus Gruppe '%s' entfernt", in.Member, in.GroupName),
	})
}

func (s *Server) handleGetAGDLPMatrix(w http.ResponseWriter, r *http.Request) {
	matrix, err := s.dirManager.GetAGDLPMatrix()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{"matrix": matrix})
}

func (s *Server) handleGetEffectivePermissions(w http.ResponseWriter, r *http.Request) {
	sam := r.PathValue("sam")
	perms, err := s.dirManager.CalculateEffectivePermissions(sam)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"sam_account_name":      sam,
		"effective_permissions": perms,
	})
}

func (s *Server) handleGetAGDLPConflicts(w http.ResponseWriter, r *http.Request) {
	conflicts, err := s.dirManager.DetectConflicts()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"conflicts": conflicts,
		"count":     len(conflicts),
	})
}

func (s *Server) handleCompareUsers(w http.ResponseWriter, r *http.Request) {
	userA := r.URL.Query().Get("userA")
	userB := r.URL.Query().Get("userB")
	if userA == "" || userB == "" {
		s.jsonError(w, http.StatusBadRequest, "Parameter 'userA' und 'userB' erforderlich")
		return
	}

	cmp, err := s.dirManager.CompareUsers(userA, userB)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, cmp)
}

func (s *Server) handleGenerateACLScripts(w http.ResponseWriter, r *http.Request) {
	share := r.URL.Query().Get("share")
	folder := r.URL.Query().Get("folder")
	if share == "" || folder == "" {
		s.jsonError(w, http.StatusBadRequest, "Parameter 'share' und 'folder' erforderlich")
		return
	}

	scripts, err := s.dirManager.GenerateACLScript(share, folder)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, scripts)
}

func (s *Server) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.mgmtService.GetStats()
	var auditCount int64 = 0
	var integrityOk float64 = 1.0
	if stats != nil {
		auditCount = stats.TotalAuditEntries
		if !stats.ChainIntegrityOk {
			integrityOk = 0.0
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "# HELP argus_audit_entries_total Total number of tamper-evident SHA-256 audit records\n")
	fmt.Fprintf(w, "# TYPE argus_audit_entries_total counter\n")
	fmt.Fprintf(w, "argus_audit_entries_total %d\n\n", auditCount)

	fmt.Fprintf(w, "# HELP argus_chain_integrity_status Cryptographic hash chain validation status (1=OK, 0=Broken)\n")
	fmt.Fprintf(w, "# TYPE argus_chain_integrity_status gauge\n")
	fmt.Fprintf(w, "argus_chain_integrity_status %f\n\n", integrityOk)

	cfg := s.dirManager.GetConfig()
	demoVal := 0.0
	if cfg.DemoMode {
		demoVal = 1.0
	}
	fmt.Fprintf(w, "# HELP argus_directory_demo_mode Whether directory provider is operating in simulated mock mode\n")
	fmt.Fprintf(w, "# TYPE argus_directory_demo_mode gauge\n")
	fmt.Fprintf(w, "argus_directory_demo_mode %f\n", demoVal)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP","engine":"Argus IAM & Audit Matrix"}`))
}

// ----------------- ENTERPRISE AUDIT SSE & DIRECTORY HANDLERS -----------------

func (s *Server) handleAuditStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := s.auditService.Subscribe()
	defer s.auditService.Unsubscribe(ch)

	// Initial connection message
	fmt.Fprintf(w, "data: {\"type\":\"connected\",\"timestamp\":\"%s\"}\n\n", time.Now().UTC().Format(time.RFC3339))
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case entry, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(entry)
			if err == nil {
				fmt.Fprintf(w, "data: %s\n\n", string(b))
				flusher.Flush()
			}
		}
	}
}

func (s *Server) handleBulkImportDirectoryUsers(w http.ResponseWriter, r *http.Request) {
	actor := s.getDirectoryActor(r)
	var csvData string

	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			s.jsonError(w, http.StatusBadRequest, "Multipart Form konnte nicht gelesen werden: "+err.Error())
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			s.jsonError(w, http.StatusBadRequest, "Dateifeld 'file' fehlt")
			return
		}
		defer file.Close()
		b, err := io.ReadAll(file)
		if err != nil {
			s.jsonError(w, http.StatusBadRequest, "Dateiinhalt konnte nicht gelesen werden: "+err.Error())
			return
		}
		csvData = string(b)
	} else {
		var body struct {
			CSVContent string `json:"csv_content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON Format")
			return
		}
		csvData = body.CSVContent
	}

	if strings.TrimSpace(csvData) == "" {
		s.jsonError(w, http.StatusBadRequest, "CSV-Inhalt darf nicht leer sein")
		return
	}

	result, err := s.dirManager.BulkImportUsers(csvData, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, result)
}

func (s *Server) handleGetBulkTemplate(w http.ResponseWriter, r *http.Request) {
	template := directory.GetSampleCSV()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"argus_users_template.csv\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(template))
}

func (s *Server) handleListJITMemberships(w http.ResponseWriter, r *http.Request) {
	list, err := s.dirManager.ListActiveTemporaryMemberships()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, list)
}

func (s *Server) handleCreateJITMembership(w http.ResponseWriter, r *http.Request) {
	var req directory.CreateJITRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON Format")
		return
	}
	actor := s.getDirectoryActor(r)
	item, err := s.dirManager.CreateTemporaryMembership(req, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusCreated, item)
}

func (s *Server) handleRevokeJITMembership(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		s.jsonError(w, http.StatusBadRequest, "ID erforderlich")
		return
	}
	actor := s.getDirectoryActor(r)
	if err := s.dirManager.RevokeTemporaryMembership(id, actor); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]string{"message": "Befristeter Zugriff erfolgreich widerrufen"})
}

func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	list, err := s.dirManager.ListApprovalRequests(status)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, list)
}

func (s *Server) handleCreateApproval(w http.ResponseWriter, r *http.Request) {
	var input directory.CreateApprovalInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON Format")
		return
	}
	actor := s.getDirectoryActor(r)
	app, err := s.dirManager.CreateApprovalRequest(input, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusCreated, app)
}

func (s *Server) handleResolveApproval(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		s.jsonError(w, http.StatusBadRequest, "ID erforderlich")
		return
	}
	var input directory.ResolveApprovalInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON Format")
		return
	}
	actor := s.getDirectoryActor(r)
	app, err := s.dirManager.ResolveApprovalRequest(id, input, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, app)
}

func (s *Server) handleListShareTemplates(w http.ResponseWriter, r *http.Request) {
	templates := s.dirManager.GetShareTemplates()
	s.jsonResponse(w, http.StatusOK, templates)
}

func (s *Server) handleApplyShareTemplate(w http.ResponseWriter, r *http.Request) {
	var input directory.ApplyShareTemplateInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON Format")
		return
	}
	actor := s.getDirectoryActor(r)
	res, err := s.dirManager.ApplyShareTemplate(input, actor)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, res)
}

func (s *Server) handleGetComplianceReport(w http.ResponseWriter, r *http.Request) {
	rep, err := s.dirManager.GenerateComplianceReport()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	switch format {
	case "csv":
		csvBytes := directory.ExportComplianceCSV(rep)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=\"argus_compliance_report.csv\"")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(csvBytes)
	case "html":
		htmlContent := directory.GenerateComplianceHTML(rep)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(htmlContent))
	default:
		s.jsonResponse(w, http.StatusOK, rep)
	}
}

// ----------------- USER LIFECYCLE & HR AUTOMATION HANDLERS -----------------

func (s *Server) handleListLifecycleEmployees(w http.ResponseWriter, r *http.Request) {
	if s.lifecycleService == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Lifecycle service unavailable")
		return
	}
	stage := r.URL.Query().Get("stage")
	search := r.URL.Query().Get("search")
	employees, err := s.lifecycleService.ListEmployees(stage, search)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if employees == nil {
		employees = []lifecycle.EmployeeRecord{}
	}
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"employees": employees,
		"total":     len(employees),
	})
}

func (s *Server) handleGetLifecycleEmployee(w http.ResponseWriter, r *http.Request) {
	if s.lifecycleService == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Lifecycle service unavailable")
		return
	}
	id := r.PathValue("id")
	emp, err := s.lifecycleService.GetEmployee(id)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, emp)
}

func (s *Server) handleOnboardEmployee(w http.ResponseWriter, r *http.Request) {
	if s.lifecycleService == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Lifecycle service unavailable")
		return
	}
	var input lifecycle.OnboardInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON: "+err.Error())
		return
	}

	actor := s.getActor(r)
	emp, err := s.lifecycleService.Onboard(input, lifecycle.ActorInfo{
		ID:        actor.ID,
		Username:  actor.Username,
		IPAddress: actor.IPAddress,
		UserAgent: actor.UserAgent,
	})
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusCreated, emp)
}

func (s *Server) handleOffboardEmployee(w http.ResponseWriter, r *http.Request) {
	if s.lifecycleService == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Lifecycle service unavailable")
		return
	}
	var input lifecycle.OffboardInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON: "+err.Error())
		return
	}

	actor := s.getActor(r)
	emp, err := s.lifecycleService.Offboard(input, lifecycle.ActorInfo{
		ID:        actor.ID,
		Username:  actor.Username,
		IPAddress: actor.IPAddress,
		UserAgent: actor.UserAgent,
	})
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, emp)
}

func (s *Server) handleTransferEmployee(w http.ResponseWriter, r *http.Request) {
	if s.lifecycleService == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Lifecycle service unavailable")
		return
	}
	var input lifecycle.TransferInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON: "+err.Error())
		return
	}

	actor := s.getActor(r)
	emp, err := s.lifecycleService.Transfer(input, lifecycle.ActorInfo{
		ID:        actor.ID,
		Username:  actor.Username,
		IPAddress: actor.IPAddress,
		UserAgent: actor.UserAgent,
	})
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, emp)
}

func (s *Server) handleUpdateLifecycleChecklist(w http.ResponseWriter, r *http.Request) {
	if s.lifecycleService == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Lifecycle service unavailable")
		return
	}
	var input lifecycle.ChecklistUpdateInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Ungültiges JSON: "+err.Error())
		return
	}

	actor := s.getActor(r)
	emp, err := s.lifecycleService.UpdateChecklist(input, lifecycle.ActorInfo{
		ID:        actor.ID,
		Username:  actor.Username,
		IPAddress: actor.IPAddress,
		UserAgent: actor.UserAgent,
	})
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, emp)
}

func (s *Server) handleGetLifecycleStats(w http.ResponseWriter, r *http.Request) {
	if s.lifecycleService == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Lifecycle service unavailable")
		return
	}
	stats, err := s.lifecycleService.GetLifecycleStats()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, stats)
}

