# ARGUS — Enterprise IAM & Tamper-Evident Audit Matrix

> **Argus** ist ein leichtgewichtiges, hochperformantes Identity & Access Management (IAM) System mit kryptografisch versiegeltem, unveränderbarem Audit-Trail (SHA-256 Hash Chain) und feingranularer rollenbasierter Zugriffskontrolle (RBAC).

---

## Highlights

- **Kryptografisch versiegeltes Audit-Log**:
  Jeder Statuswechsel (Benutzer anlegen, Rollenänderung, Login, Rechterevokation) wird deterministisch gehasht und über eine SHA-256 Kette verknüpft (Genesis &rarr; Block $N$). Manipulationen an der Datenbank brechen die Kette sofort.
- **Integritäts-Verifikation (Zero Trust)**:
  Echtzeit-Prüfung der gesamten Audit-Kette per API (`/api/audit/verify`) oder direkt über das Web-Dashboard.
- **Vorher/Nachher-Diffs**:
  Jeder Audit-Eintrag speichert atomar die exakten Zustandsänderungen (`old_values` vs. `new_values`) zur lückenlosen Nachvollziehbarkeit bei Revisionen (z. B. ISO 27001, SOC 2, DSGVO/GDPR).
- **Feingranulares RBAC**:
  Rollenbasierte Zugriffskontrolle mit granularen Rechten (`users:read`, `users:create`, `roles:manage`, `audit:export`, etc.).
- **Compliance-Exporte**:
  1-Klick-Export aller Audit-Daten als CSV oder JSON inklusive kryptografischer Prüfsummen.
- **Single-Binary & Zero-Dependency**:
  In Go geschrieben, eingebettetes Frontend via `embed.FS`, WAL-optimierte SQLite-Engine ohne CGO-Zwang (`modernc.org/sqlite`).

---

## Schnellstart

### 1. Starten
```bash
# Im Projektverzeichnis ausführen:
go run ./cmd/argus
```
Oder kompilieren:
```bash
go build -o bin/argus ./cmd/argus
./bin/argus
```

Argus startet standardmäßig auf **Port 8080**:
[http://localhost:8080](http://localhost:8080)

### 2. Standard-Zugänge

| Benutzername | Kennwort | Rolle | Beschreibung |
| :--- | :--- | :--- | :--- |
| `admin` | `admin123` | **SuperAdmin** | Vollzugriff auf alle IAM-, Rollen- und Audit-Funktionen |
| `auditor` | `auditor123` | **SecurityAuditor** | Revisionssicherer Prüfzugriff, Audit-Log, Hash-Verifikation & Export |
| `sarah.connor`| `sarah123` | **UserManager** | Benutzerverwaltung und Team-Administration |

---

## Architektur

```
Argus/
├── cmd/argus/
│   └── main.go          # CLI Flags, Server-Start, Graceful Shutdown
├── internal/
│   ├── audit/           # Tamper-Evident Hash Chain, Verifikation, CSV/JSON Export
│   ├── auth/            # Bcrypt, Session-Tokens, RBAC Permission Evaluation
│   ├── db/              # SQLite WAL-Modus, Tabellen-Migration, Seed-Daten
│   ├── handler/         # REST API Endpunkte & SPA-Router
│   ├── model/           # Datenmodelle für Identitäten, Rollen, Logs & Metriken
│   └── service/         # IAM Kernlogik, Rollenmatrix & Systemstatistiken
├── web/
│   ├── embed.go         # Go embed.FS für Single-Binary Auslieferung
│   └── static/
│       ├── index.html   # Modernes Responsive IAM Web-Dashboard
│       ├── app.js       # SPA Logik, Diff-Viewer, Hash-Check, Filter
│       └── style.css    # Dark Mode Security & Cyber Aesthetic
└── README.md
```

---

## REST API Übersicht

Alle geschützten Endpunkte akzeptieren entweder das Session-Cookie oder den Header `Authorization: Bearer <token>`.

### Authentifizierung
- `POST /api/auth/login` — Anmelden mit Benutzername und Kennwort
- `GET /api/auth/me` — Eigenes Benutzerprofil & Berechtigungen
- `POST /api/auth/logout` — Sitzung beenden

### Audit & Compliance
- `GET /api/audit` — Filterbare Audit-Logs (`?search=...&action=...&status=...&limit=15&offset=0`)
- `GET /api/audit/verify` — Validiert die vollständige SHA-256 Kette
- `GET /api/audit/export?format=csv|json` — Revisions-Export

### Identitäten & Rollen
- `GET /api/users` &bull; `POST /api/users`
- `GET /api/users/{id}` &bull; `PUT /api/users/{id}` &bull; `DELETE /api/users/{id}`
- `GET /api/roles` &bull; `POST /api/roles`
- `PUT /api/roles/{id}` &bull; `DELETE /api/roles/{id}`
- `GET /api/permissions` — Liste aller System-Berechtigungen
- `GET /api/stats` — Sicherheitsstatistiken & KPI-Dashboard

### Active Directory, Samba-AD & AGDLP Dateiberechtigungen
- `GET /api/directory/config` • `POST /api/directory/config` — DC-Verbindung & Demo/Mock-Umschalter
- `POST /api/directory/test-connection` — Diagnosetest für LDAPS-Verbindung und Latenz
- `GET /api/directory/users` • `POST /api/directory/users` — AD-Benutzerkonten abfragen & neu erstellen
- `POST /api/directory/users/{sam}/status` — Konto aktivieren/sperren (UAC 0x0200 / 0x0202)
- `POST /api/directory/users/{sam}/password` — Kennwort administrativ zurücksetzen (`unicodePwd`)
- `GET /api/directory/groups` • `POST /api/directory/groups` — Sicherheitsgruppen verwalten
- `POST /api/directory/groups/agdlp` — 1-Klick-Erstellung von AGDLP Ressourcengruppen (`DL_FS_<Freigabe>_<Ordner>_<Recht>`)
- `POST /api/directory/memberships` • `DELETE /api/directory/memberships` — Zuweisung von Rollen/Benutzern
- `GET /api/directory/agdlp-matrix` — Aggregierte Freigabe- und Berechtigungsmatrix
- `GET /api/directory/agdlp/visual-data` — Graph-Daten für die interaktive SVG-Visualisierung

### Enterprise Governance & Workflows
- `GET /api/audit/stream` — Real-Time Server-Sent Events (SSE) Audit Live-Stream
- `GET /api/directory/jit` • `POST /api/directory/jit` • `DELETE /api/directory/jit/{id}` — Just-In-Time (JIT) zeitlich begrenzte Gruppenmitgliedschaften & automatische Revokation
- `GET /api/approvals` • `POST /api/approvals` • `POST /api/approvals/{id}/resolve` — Vier-Augen-Prinzip (Dual-Control Approval Workflow)
- `GET /api/directory/users/bulk-template` • `POST /api/directory/users/bulk-import` — CSV Bulk Onboarding mit automatischer Rollengruppierung
- `GET /api/directory/agdlp/templates` • `POST /api/directory/agdlp/templates/apply` — Vordefinierte Best-Practice AGDLP Freigabe-Vorlagen (Department, Project, HR, Finance)
- `GET /api/directory/agdlp/compliance-report?format=json|csv|html` — ISO 27001 / DSGVO Revisionsbericht mit kryptografischer SHA-256 Siegelung

### Observability, Health & Integrations
- `GET /metrics` — Prometheus-kompatible Metriken (Audit-Blöcke, Kettengültigkeit, JIT-Status, etc.)
- `GET /healthz` &bull; `GET /readyz` — Kubernetes Liveness & Readiness Probes
- `GET /api/openapi.json` — OpenAPI 3.1 Spezifikation
- `GET /scim/v2/Users` &bull; `POST /scim/v2/Users` — SCIM 2.0 Identity Provisioning
- `GET /api/enterprise/terraform/export` — Terraform / OpenTofu HCL Provider Exporter
- `GET /api/enterprise/webhooks` &bull; `POST /api/enterprise/webhooks/{id}/test` — Webhooks mit HMAC-SHA256 Signaturen

---

## Enterprise Suite (40 Features)

Argus beinhaltet 40 modulare Enterprise- und Zero-Trust-Funktionalitäten:

1. **Zero-Trust Kryptografie & Audit:**
   - **1. Merkle-Tree Root Anchoring & Proofs:** Notarisierung nach RFC 6962 / OpenTimestamps.
   - **2. Asymmetrische Ed25519 Block-Signaturen:** Hardware-Security-Module (HSM) / PKCS#11 Schutz.
   - **3. Post-Quantum Cryptography (PQC):** Hybride ML-DSA-65 (Dilithium) Signaturstrukturen.
   - **4. WORM Storage Adapter:** Write-Once-Read-Many unveränderbare Audit-Ledger (SEC Rule 17a-4).
   - **5. Envelope Encryption:** AES-256-GCM Verschlüsselung für personenbezogene Daten (DSGVO).

2. **Authentifizierung, MFA & SSO:**
   - **6. FIDO2 / WebAuthn & Passkeys:** Hardware-Token (YubiKey) und Biometrie.
   - **7. RFC 6238 TOTP:** QR-Code Enrollment, Zeitfenster-Drift & 8 gehashte Recovery-Codes.
   - **8. Enterprise SSO Federation:** OIDC & SAML 2.0 für Entra ID, Okta und Keycloak.
   - **9. Adaptive Risk Engine:** Erkennung von Impossible Travel (>850 km/h) & verdächtigen IP-Ranges.
   - **10. HaveIBeenPwned k-Anonymity:** Prüfung gegen Milliarden kompromittierter Passwörter (NIST SP 800-63B).

3. **Active Directory & Multi-Forest:**
   - **11. Multi-Domain & Multi-Forest Trusts:** Forest-Root, Parent-Child & externe Trusts.
   - **12. Fine-Grained Password Policies (FGPP / PSO):** Differenzierte Komplexitäts- und Sperrrichtlinien.
   - **13. gMSA & Kerberos SPN Lifecycle:** Automatische Rotation von Gruppen-Dienstkonten.
   - **14. AD Recycle Bin:** 1-Klick-Wiederherstellung gelöschter Objekte mit SID-Historie.
   - **15. Delta Sync & DirSync:** Echtzeit-Überwachung von Domain-Controller Änderungen (`uSNChanged`).

4. **Privileged Access Management (PAM) & JIT:**
   - **16. Break-Glass Emergency Access:** Notfall-Koffer mit obligatorischer Vier-Augen-Freigabe.
   - **17. Ephemere dynamische Secrets:** Kurzlebige Secrets mit automatischer TTL-Invalidierung.
   - **18. Segregation of Duties (SoD):** Matrix zur Erkennung toxischer Berechtigungskombinationen.
   - **19. Access Certification Kampagnen:** Regelmäßige Rezertifizierungs-Workflows für Manager.
   - **20. JIT Session Auditing:** Detaillierte Telemetrie und Befehlsprotokollierung privilegierter Sitzungen.

5. **Policy-as-Code & Advanced IAM:**
   - **21. Policy-as-Code Engine:** Deklarative OPA/Cedar-kompatible Zugriffsregeln.
   - **22. ABAC Kontext-Evaluierung:** Zugriffskontrolle nach Uhrzeit, Standort und Gerätestatus.
   - **23. Heuristisches Role-Mining:** Automatische Ableitung von Rollenvorlagen mittels Jaccard-Ähnlichkeit.
   - **24. Orphan & Dormant Account Detector:** Identifikation inaktiver (>90 Tage) und verwaister Konten.
   - **25. Shadow-Admin Escalation Analyzer:** Graph-basierte Erkennung verdeckter Angriffspfade (BloodHound-Heuristik).

6. **Regulatory Compliance & Forensik:**
   - **26. Multi-Framework Mapping:** Kontrollpunkte für BSI IT-Grundschutz, NIS-2, ISO 27001 & SOC 2.
   - **27. Forensischer Time-Travel:** Rekonstruktion historischer Berechtigungsstände zu beliebigem Zeitpunkt $T$.
   - **28. SIEM / SOAR Realtime-Streaming:** RFC 5424 Syslog über TLS & Elastic Common Schema (ECS).
   - **29. DSGVO Art. 17 Kryptoschreddern:** Recht auf Vergessenwerden ohne Brechen der Hash-Kette.
   - **30. Signierte Audit-Zertifikate:** Manipulationssichere Zertifikate mit digitalem SHA-256 Siegel.

7. **Hochverfügbarkeit & Cluster:**
   - **31. Pluggable Database Backend:** SQLite WAL & PostgreSQL HA Cluster-Abstraktion.
   - **32. Raft Consensus Node Cluster:** Verteiltes Multi-Node Cluster mit Leader Election.
   - **33. High-Speed Distributed Cache:** Invalidation Bus & 99.4% Hit-Rate.
   - **34. Cold-Storage Tiering:** Automatische Partitionierung und Kompression historischer Audit-Slices.
   - **35. Multi-Region Read Replicas:** Latenz-optimiertes Routing für internationale Standorte.

8. **DevOps & Integration Hub:**
   - **36. Native CLI (`argusctl`):** Eigenständiges Terminal-Tool zur CI/CD- und Notfallsteuerung.
   - **37. Terraform / OpenTofu Provider:** Infrastructure-as-Code Export aller Identitäten und Rollen.
   - **38. SCIM 2.0 Standard (RFC 7643/7644):** Automatisiertes HR-Provisioning aus Workday/SAP.
   - **39. Webhook Notification Engine:** Event-Dispatching mit HMAC-SHA256 Signaturen für Slack/Teams.
   - **40. Interaktive OpenAPI 3.1 & Swagger:** Vollständige Schemadokumentation für Entwickler.

---

## Native CLI (`argusctl`)

Argus enthält das dedizierte Kommandozeilenwerkzeug `argusctl`:

```bash
# Bauen & Ausführen
go build -o bin/argusctl ./cmd/argusctl

# Status prüfen
./bin/argusctl status

# Audit-Kette kryptografisch validieren
./bin/argusctl audit verify

# Benutzer auflisten
./bin/argusctl users

# NIS-2 & ISO 27001 Compliance Bericht abrufen
./bin/argusctl compliance
```

---

## Lizenz
MIT License.

