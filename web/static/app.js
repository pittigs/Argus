// Argus IAM & Tamper-Evident Audit Matrix
// Client-side Application Logic

(function() {
  'use strict';

  // State Management
  const state = {
    currentUser: null,
    token: localStorage.getItem('argus_token') || '',
    activeTab: 'dashboard',
    allRoles: [],
    allPermissions: [],
    audit: {
      items: [],
      total: 0,
      limit: 15,
      offset: 0,
      search: '',
      action: '',
      status: ''
    }
  };

  // DOM Elements
  const el = {
    loginModal: document.getElementById('loginModal'),
    loginForm: document.getElementById('loginForm'),
    loginUsername: document.getElementById('loginUsername'),
    loginPassword: document.getElementById('loginPassword'),
    loginErrorMsg: document.getElementById('loginErrorMsg'),
    demoAdminBtn: document.getElementById('demoAdminBtn'),
    demoAuditorBtn: document.getElementById('demoAuditorBtn'),
    demoManagerBtn: document.getElementById('demoManagerBtn'),
    logoutBtn: document.getElementById('logoutBtn'),
    headerAvatar: document.getElementById('headerAvatar'),
    headerUsername: document.getElementById('headerUsername'),
    headerRoleBadge: document.getElementById('headerRoleBadge'),
    headerChainStatus: document.getElementById('headerChainStatus'),
    navTabs: document.querySelectorAll('.nav-tab'),
    tabPanes: document.querySelectorAll('.tab-pane'),

    // Dashboard
    statTotalUsers: document.getElementById('statTotalUsers'),
    statActiveUsers: document.getElementById('statActiveUsers'),
    statTotalRoles: document.getElementById('statTotalRoles'),
    statTotalPerms: document.getElementById('statTotalPerms'),
    statTotalAudit: document.getElementById('statTotalAudit'),
    statRecentLogins: document.getElementById('statRecentLogins'),
    statSecurityAlerts: document.getElementById('statSecurityAlerts'),
    recentEventsList: document.getElementById('recentEventsList'),
    btnQuickCreateUser: document.getElementById('btnQuickCreateUser'),
    btnQuickVerify: document.getElementById('btnQuickVerify'),
    btnGoToAudit: document.getElementById('btnGoToAudit'),
    btnVerifyChainModal: document.getElementById('btnVerifyChainModal'),

    // Audit
    auditSearchInput: document.getElementById('auditSearchInput'),
    auditActionFilter: document.getElementById('auditActionFilter'),
    auditStatusFilter: document.getElementById('auditStatusFilter'),
    btnResetAuditFilter: document.getElementById('btnResetAuditFilter'),
    auditTableBody: document.getElementById('auditTableBody'),
    auditCountInfo: document.getElementById('auditCountInfo'),
    auditPrevBtn: document.getElementById('auditPrevBtn'),
    auditNextBtn: document.getElementById('auditNextBtn'),
    auditPageIndicator: document.getElementById('auditPageIndicator'),
    btnExportCSV: document.getElementById('btnExportCSV'),
    btnExportJSON: document.getElementById('btnExportJSON'),
    btnVerifyChainMain: document.getElementById('btnVerifyChainMain'),

    // Diff Modal
    diffModal: document.getElementById('diffModal'),
    closeDiffModalBtn: document.getElementById('closeDiffModalBtn'),
    closeDiffModalBottomBtn: document.getElementById('closeDiffModalBottomBtn'),
    diffModalActionBadge: document.getElementById('diffModalActionBadge'),
    diffMetaGrid: document.getElementById('diffMetaGrid'),
    diffPrevHash: document.getElementById('diffPrevHash'),
    diffEntryHash: document.getElementById('diffEntryHash'),
    diffOldValues: document.getElementById('diffOldValues'),
    diffNewValues: document.getElementById('diffNewValues'),

    // Verify Modal
    verifyModal: document.getElementById('verifyModal'),
    closeVerifyModalBtn: document.getElementById('closeVerifyModalBtn'),
    closeVerifyModalBottomBtn: document.getElementById('closeVerifyModalBottomBtn'),
    verifyModalBody: document.getElementById('verifyModalBody'),

    // Users
    usersTableBody: document.getElementById('usersTableBody'),
    btnCreateUser: document.getElementById('btnCreateUser'),
    userFormModal: document.getElementById('userFormModal'),
    userForm: document.getElementById('userForm'),
    userFormTitle: document.getElementById('userFormTitle'),
    userFormId: document.getElementById('userFormId'),
    userFormUsernameGroup: document.getElementById('userFormUsernameGroup'),
    formUsername: document.getElementById('formUsername'),
    formFullName: document.getElementById('formFullName'),
    formEmail: document.getElementById('formEmail'),
    formPassword: document.getElementById('formPassword'),
    formPasswordHint: document.getElementById('formPasswordHint'),
    formStatus: document.getElementById('formStatus'),
    formRolesCheckboxes: document.getElementById('formRolesCheckboxes'),
    userFormError: document.getElementById('userFormError'),
    closeUserModalBtn: document.getElementById('closeUserModalBtn'),
    cancelUserModalBtn: document.getElementById('cancelUserModalBtn'),

    // Roles
    rolesGrid: document.getElementById('rolesGrid'),
    permissionsReferenceList: document.getElementById('permissionsReferenceList'),
    btnCreateRole: document.getElementById('btnCreateRole'),
    roleFormModal: document.getElementById('roleFormModal'),
    roleForm: document.getElementById('roleForm'),
    roleFormTitle: document.getElementById('roleFormTitle'),
    roleFormId: document.getElementById('roleFormId'),
    formRoleName: document.getElementById('formRoleName'),
    formRoleDesc: document.getElementById('formRoleDesc'),
    formRolePermissionsChecklist: document.getElementById('formRolePermissionsChecklist'),
    roleFormError: document.getElementById('roleFormError'),
    closeRoleModalBtn: document.getElementById('closeRoleModalBtn'),
    cancelRoleModalBtn: document.getElementById('cancelRoleModalBtn'),

    // Toast
    toastContainer: document.getElementById('toastContainer')
  };

  // API Client Helper
  async function api(path, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    if (state.token) {
      headers['Authorization'] = `Bearer ${state.token}`;
    }

    const response = await fetch(path, { ...options, headers });
    if (response.status === 401) {
      // Unauthorized: show login modal
      showLoginModal();
      throw new Error('Sitzung abgelaufen. Bitte neu anmelden.');
    }

    if (!response.ok) {
      let errText = 'Netzwerkfehler aufgetreten';
      try {
        const data = await response.json();
        if (data && data.error) errText = data.error;
      } catch (e) {
        errText = await response.text();
      }
      throw new Error(errText);
    }

    // Check if JSON or blob
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      return response.json();
    }
    return response;
  }

  // Toast Notification
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    let icon = '&bull;';
    if (type === 'success') icon = '&#10003;';
    if (type === 'error') icon = '&times;';

    toast.innerHTML = `<span style="font-weight:700;">${icon}</span><span>${message}</span>`;
    el.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  // Auth Handling
  function showLoginModal() {
    el.loginModal.classList.add('open');
  }

  function hideLoginModal() {
    el.loginModal.classList.remove('open');
    el.loginErrorMsg.style.display = 'none';
  }

  async function checkCurrentUser() {
    try {
      const data = await api('/api/auth/me');
      state.currentUser = data.user;
      renderCurrentUser();
      hideLoginModal();
      loadAllData();
    } catch (err) {
      showLoginModal();
    }
  }

  function renderCurrentUser() {
    if (!state.currentUser) return;
    const u = state.currentUser;
    el.headerUsername.textContent = u.full_name || u.username;
    const initials = (u.full_name || u.username).substring(0, 2).toUpperCase();
    el.headerAvatar.textContent = initials;
    const roleNames = (u.roles || []).map(r => r.name).join(', ') || 'Benutzer';
    el.headerRoleBadge.textContent = roleNames;
  }

  // Event Listeners: Auth
  el.loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    el.loginErrorMsg.style.display = 'none';
    const username = el.loginUsername.value.trim();
    const password = el.loginPassword.value;

    try {
      const res = await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });
      state.token = res.token;
      localStorage.setItem('argus_token', res.token);
      state.currentUser = res.user;
      renderCurrentUser();
      hideLoginModal();
      showToast(`Willkommen, ${res.user.full_name || res.user.username}!`, 'success');
      loadAllData();
    } catch (err) {
      el.loginErrorMsg.textContent = err.message;
      el.loginErrorMsg.style.display = 'block';
    }
  });

  el.logoutBtn.addEventListener('click', async () => {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } catch (e) {}
    state.token = '';
    state.currentUser = null;
    localStorage.removeItem('argus_token');
    showLoginModal();
    showToast('Erfolgreich abgemeldet', 'info');
  });

  // Demo account quick buttons
  el.demoAdminBtn.addEventListener('click', () => {
    el.loginUsername.value = 'admin';
    el.loginPassword.value = 'admin123';
  });
  el.demoAuditorBtn.addEventListener('click', () => {
    el.loginUsername.value = 'auditor';
    el.loginPassword.value = 'auditor123';
  });
  el.demoManagerBtn.addEventListener('click', () => {
    el.loginUsername.value = 'sarah.connor';
    el.loginPassword.value = 'sarah123';
  });

  // Navigation Tabs
  el.navTabs.forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.getAttribute('data-tab');
      switchTab(tab);
    });
  });

  function switchTab(tabName) {
    state.activeTab = tabName;
    el.navTabs.forEach(b => {
      if (b.getAttribute('data-tab') === tabName) b.classList.add('active');
      else b.classList.remove('active');
    });

    el.tabPanes.forEach(pane => {
      if (pane.id === `section${capitalize(tabName)}`) pane.classList.add('active');
      else pane.classList.remove('active');
    });

    if (tabName === 'dashboard') loadStats();
    if (tabName === 'audit') loadAuditLogs();
    if (tabName === 'users') loadUsers();
    if (tabName === 'roles') loadRoles();
    if (tabName === 'directory') loadDirectoryData();
    if (tabName === 'lifecycle') loadLifecycleData();
    if (tabName === 'enterprise') loadEnterpriseData();
  }

  function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  // Load All Primary Data
  async function loadAllData() {
    await loadMetadata();
    loadStats();
    loadAuditLogs();
    loadUsers();
    loadRoles();
    loadLifecycleData();
    initSSE();
    checkPendingApprovalsCount();
  }

  async function loadMetadata() {
    try {
      const [roles, perms] = await Promise.all([
        api('/api/roles'),
        api('/api/permissions')
      ]);
      state.allRoles = roles;
      state.allPermissions = perms;
      renderPermissionsReference(perms);
    } catch (e) {
      console.error(e);
    }
  }

  // Dashboard & Stats
  async function loadStats() {
    try {
      const stats = await api('/api/stats');
      el.statTotalUsers.textContent = stats.total_users;
      el.statActiveUsers.textContent = `${stats.active_users} aktiv`;
      el.statTotalRoles.textContent = stats.total_roles;
      el.statTotalPerms.textContent = `${stats.total_permissions} Berechtigungen`;
      el.statTotalAudit.textContent = stats.total_audit_entries;
      el.statRecentLogins.textContent = stats.recent_logins_24h;
      el.statSecurityAlerts.textContent = `${stats.security_alerts_24h} Alerts`;

      if (stats.chain_integrity_ok) {
        el.headerChainStatus.className = 'chain-badge';
        el.headerChainStatus.querySelector('.chain-badge-text').textContent = 'CHAIN VERIFIED';
      } else {
        el.headerChainStatus.className = 'chain-badge compromised';
        el.headerChainStatus.querySelector('.chain-badge-text').textContent = 'CHAIN COMPROMISED';
      }

      loadRecentEvents();
    } catch (e) {
      console.error('Stats load error', e);
    }
  }

  async function loadRecentEvents() {
    try {
      const res = await api('/api/audit?limit=6&offset=0');
      el.recentEventsList.innerHTML = '';
      if (!res.items || res.items.length === 0) {
        el.recentEventsList.innerHTML = '<p class="form-hint">Keine aktuellen Ereignisse.</p>';
        return;
      }

      res.items.forEach(item => {
        const div = document.createElement('div');
        div.className = 'recent-event-item';
        div.innerHTML = `
          <div class="event-left">
            <span class="badge ${getActionBadgeClass(item.action)}">${item.action}</span>
            <div>
              <span class="event-actor">${escapeHtml(item.actor_username)}</span>
              <span class="event-resource">auf ${escapeHtml(item.resource_type)}:${escapeHtml(item.resource_id)}</span>
            </div>
          </div>
          <div class="event-right">
            <span class="event-time">${formatDate(item.timestamp)}</span>
            <span class="hash-snippet">${item.entry_hash.substring(0, 8)}...</span>
          </div>
        `;
        div.addEventListener('click', () => openDiffModal(item));
        el.recentEventsList.appendChild(div);
      });
    } catch (e) {
      console.error(e);
    }
  }

  el.btnGoToAudit.addEventListener('click', () => switchTab('audit'));
  el.btnQuickCreateUser.addEventListener('click', () => openCreateUserModal());
  el.btnQuickVerify.addEventListener('click', () => runVerification());
  el.btnVerifyChainModal.addEventListener('click', () => runVerification());
  el.btnVerifyChainMain.addEventListener('click', () => runVerification());

  // ================= AUDIT LOGS =================

  async function loadAuditLogs() {
    try {
      const params = new URLSearchParams({
        limit: state.audit.limit,
        offset: state.audit.offset,
        search: state.audit.search,
        action: state.audit.action,
        status: state.audit.status
      });

      const res = await api(`/api/audit?${params.toString()}`);
      state.audit.items = res.items || [];
      state.audit.total = res.total;
      renderAuditTable();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  function renderAuditTable() {
    el.auditTableBody.innerHTML = '';
    if (state.audit.items.length === 0) {
      el.auditTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 2rem; color: var(--text-dim);">Keine Audit-Einträge gefunden.</td></tr>`;
      el.auditCountInfo.textContent = '0 Einträge';
      return;
    }

    state.audit.items.forEach(item => {
      const tr = document.createElement('tr');
      const shortHash = item.entry_hash ? `${item.entry_hash.substring(0, 8)}...` : '';
      const statusIcon = item.status === 'SUCCESS' ? '<span style="color:var(--accent-emerald); font-weight:700;">&#10003;</span>' : '<span style="color:var(--accent-rose); font-weight:700;">&times;</span>';

      tr.innerHTML = `
        <td style="font-family:var(--font-mono); color:var(--text-dim);">#${String(item.sequence_number).padStart(4, '0')}</td>
        <td style="font-family:var(--font-mono); font-size:0.75rem;">${formatDateFull(item.timestamp)}</td>
        <td>
          <div style="font-weight:600;">${escapeHtml(item.actor_username)}</div>
          <div style="font-size:0.7rem; color:var(--text-dim); font-family:var(--font-mono);">${escapeHtml(item.actor_ip)}</div>
        </td>
        <td><span class="badge ${getActionBadgeClass(item.action)}">${item.action}</span></td>
        <td>
          <span style="font-size:0.75rem; color:var(--accent-cyan); text-transform:uppercase;">${escapeHtml(item.resource_type)}:</span>
          <span style="font-family:var(--font-mono); font-size:0.8rem;">${escapeHtml(item.resource_id)}</span>
        </td>
        <td>${statusIcon} <span style="font-size:0.75rem;">${item.status}</span></td>
        <td>
          <span class="hash-snippet" title="SHA-256: ${item.entry_hash}">${shortHash}</span>
        </td>
        <td style="text-align:right;">
          <button class="btn btn-secondary btn-xs btn-inspect-diff">Diff Details</button>
        </td>
      `;

      tr.querySelector('.btn-inspect-diff').addEventListener('click', () => openDiffModal(item));
      el.auditTableBody.appendChild(tr);
    });

    const currentPage = Math.floor(state.audit.offset / state.audit.limit) + 1;
    const totalPages = Math.ceil(state.audit.total / state.audit.limit) || 1;
    el.auditCountInfo.textContent = `${state.audit.total} Einträge gesamt (Zeige ${state.audit.offset + 1} - ${Math.min(state.audit.offset + state.audit.limit, state.audit.total)})`;
    el.auditPageIndicator.textContent = `Seite ${currentPage} von ${totalPages}`;
    el.auditPrevBtn.disabled = state.audit.offset <= 0;
    el.auditNextBtn.disabled = state.audit.offset + state.audit.limit >= state.audit.total;
  }

  // Audit Filters
  let searchTimer;
  el.auditSearchInput.addEventListener('input', (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.audit.search = e.target.value.trim();
      state.audit.offset = 0;
      loadAuditLogs();
    }, 250);
  });

  el.auditActionFilter.addEventListener('change', (e) => {
    state.audit.action = e.target.value;
    state.audit.offset = 0;
    loadAuditLogs();
  });

  el.auditStatusFilter.addEventListener('change', (e) => {
    state.audit.status = e.target.value;
    state.audit.offset = 0;
    loadAuditLogs();
  });

  el.btnResetAuditFilter.addEventListener('click', () => {
    el.auditSearchInput.value = '';
    el.auditActionFilter.value = '';
    el.auditStatusFilter.value = '';
    state.audit.search = '';
    state.audit.action = '';
    state.audit.status = '';
    state.audit.offset = 0;
    loadAuditLogs();
  });

  el.auditPrevBtn.addEventListener('click', () => {
    if (state.audit.offset > 0) {
      state.audit.offset -= state.audit.limit;
      loadAuditLogs();
    }
  });

  el.auditNextBtn.addEventListener('click', () => {
    if (state.audit.offset + state.audit.limit < state.audit.total) {
      state.audit.offset += state.audit.limit;
      loadAuditLogs();
    }
  });

  // Export handlers
  el.btnExportCSV.addEventListener('click', () => {
    window.open(`/api/audit/export?format=csv&search=${encodeURIComponent(state.audit.search)}`, '_blank');
    showToast('CSV Export gestartet', 'info');
  });

  el.btnExportJSON.addEventListener('click', () => {
    window.open(`/api/audit/export?format=json&search=${encodeURIComponent(state.audit.search)}`, '_blank');
    showToast('JSON Export gestartet', 'info');
  });

  // Diff Modal
  function openDiffModal(item) {
    el.diffModalActionBadge.className = `badge ${getActionBadgeClass(item.action)}`;
    el.diffModalActionBadge.textContent = item.action;

    el.diffMetaGrid.innerHTML = `
      <div class="meta-item">
        <span class="meta-label">Sequenznummer</span>
        <span class="meta-value">#${String(item.sequence_number).padStart(5, '0')}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Akteur</span>
        <span class="meta-value">${escapeHtml(item.actor_username)} (${escapeHtml(item.actor_ip)})</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Zeitstempel</span>
        <span class="meta-value">${formatDateFull(item.timestamp)}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Ressource</span>
        <span class="meta-value">${escapeHtml(item.resource_type)}:${escapeHtml(item.resource_id)}</span>
      </div>
      <div class="meta-item" style="grid-column: 1 / -1;">
        <span class="meta-label">Audit-Grund / Kontext</span>
        <span class="meta-value">${escapeHtml(item.reason || 'Keine zusätzliche Begründung hinterlegt')}</span>
      </div>
    `;

    el.diffPrevHash.textContent = item.prev_hash || '0000000000000000000000000000000000000000000000000000000000000000 (Genesis)';
    el.diffEntryHash.textContent = item.entry_hash;

    // Format Old and New values
    el.diffOldValues.textContent = formatDiffContent(item.old_values);
    el.diffNewValues.textContent = formatDiffContent(item.new_values);

    el.diffModal.classList.add('open');
  }

  function formatDiffContent(val) {
    if (!val || val === '""' || val === '{}') {
      return 'Keine Datensätze vorhanden (Initial oder unverändert)';
    }
    try {
      const parsed = JSON.parse(val);
      return JSON.stringify(parsed, null, 2);
    } catch (e) {
      return val;
    }
  }

  function closeDiffModal() {
    el.diffModal.classList.remove('open');
  }
  el.closeDiffModalBtn.addEventListener('click', closeDiffModal);
  el.closeDiffModalBottomBtn.addEventListener('click', closeDiffModal);

  // Cryptographic Chain Verification Modal
  async function runVerification() {
    el.verifyModal.classList.add('open');
    el.verifyModalBody.innerHTML = `
      <div style="text-align:center; padding: 2rem;">
        <div class="status-pulse-dot" style="margin: 0 auto 1rem; width:16px; height:16px;"></div>
        <p>Kryptografische Hash-Kette wird mathematisch verifiziert (SHA-256)...</p>
      </div>
    `;

    try {
      const res = await api('/api/audit/verify');
      const isValid = !res.is_compromised;

      el.verifyModalBody.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:1.25rem;">
          <div class="compliance-banner" style="background:${isValid ? 'rgba(16,185,129,0.1)' : 'rgba(244,63,94,0.1)'}; border-color:${isValid ? 'rgba(16,185,129,0.3)' : 'rgba(244,63,94,0.3)'};">
            <div style="color:${isValid ? 'var(--accent-emerald)' : 'var(--accent-rose)'}; font-size:1.8rem; font-weight:bold;">
              ${isValid ? '&#10003;' : '&times;'}
            </div>
            <div>
              <h4 style="font-size:1.1rem; font-weight:700; color:#fff;">${isValid ? 'Integrität 100% Gültig & Revisionssicher' : 'Manipulation Erkannt!'}</h4>
              <p style="font-size:0.85rem; color:var(--text-muted); margin-top:0.25rem;">${escapeHtml(res.message)}</p>
            </div>
          </div>

          <div class="audit-meta-grid">
            <div class="meta-item">
              <span class="meta-label">Verifizierte Kettenglieder</span>
              <span class="meta-value">${res.verified_count} von ${res.total_entries}</span>
            </div>
            <div class="meta-item">
              <span class="meta-label">Prüfzeitpunkt</span>
              <span class="meta-value">${formatDateFull(res.last_verified_at)}</span>
            </div>
            <div class="meta-item">
              <span class="meta-label">Kryptoverfahren</span>
              <span class="meta-value">SHA-256 Merkle Linkage</span>
            </div>
          </div>
        </div>
      `;

      if (isValid) {
        showToast('Kryptografische Hash-Kette erfolgreich validiert', 'success');
      } else {
        showToast('Achtung: Manipulationsverdacht in Audit-Kette!', 'error');
      }
      loadStats();
    } catch (e) {
      el.verifyModalBody.innerHTML = `<div class="form-error">${escapeHtml(e.message)}</div>`;
    }
  }

  function closeVerifyModal() {
    el.verifyModal.classList.remove('open');
  }
  el.closeVerifyModalBtn.addEventListener('click', closeVerifyModal);
  el.closeVerifyModalBottomBtn.addEventListener('click', closeVerifyModal);

  // ================= USERS MANAGEMENT =================

  async function loadUsers() {
    try {
      const users = await api('/api/users');
      renderUsersTable(users);
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  function renderUsersTable(users) {
    el.usersTableBody.innerHTML = '';
    if (!users || users.length === 0) {
      el.usersTableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 2rem;">Keine Benutzer vorhanden.</td></tr>`;
      return;
    }

    users.forEach(u => {
      const tr = document.createElement('tr');
      const initials = (u.full_name || u.username).substring(0, 2).toUpperCase();
      const roleBadges = (u.roles || []).map(r => {
        const cls = r.name === 'SuperAdmin' ? 'badge-role-tag badge-role-superadmin' : 'badge-role-tag';
        return `<span class="${cls}">${escapeHtml(r.name)}</span>`;
      }).join('') || '<span style="color:var(--text-dim);">-</span>';

      const statusBadge = u.status === 'active'
        ? `<span class="badge badge-status-active">Aktiv</span>`
        : `<span class="badge badge-status-suspended">Gesperrt</span>`;

      tr.innerHTML = `
        <td>
          <div style="display:flex; align-items:center; gap:0.75rem;">
            <div class="user-avatar" style="width:32px; height:32px; font-size:0.75rem;">${initials}</div>
            <div>
              <div style="font-weight:600;">${escapeHtml(u.full_name)}</div>
              <div style="font-size:0.75rem; color:var(--text-dim); font-family:var(--font-mono);">@${escapeHtml(u.username)}</div>
            </div>
          </div>
        </td>
        <td>${escapeHtml(u.email)}</td>
        <td>${statusBadge}</td>
        <td><div style="display:flex; flex-wrap:wrap; gap:0.25rem;">${roleBadges}</div></td>
        <td style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">${u.last_login_at ? formatDate(u.last_login_at) : 'Nie'}</td>
        <td style="font-size:0.75rem; color:var(--text-dim); font-family:var(--font-mono);">${formatDate(u.created_at)}</td>
        <td style="text-align:right;">
          <div style="display:flex; gap:0.5rem; justify-content:flex-end;">
            <button class="btn btn-secondary btn-xs btn-edit-user">Bearbeiten</button>
            <button class="btn btn-ghost btn-xs btn-audit-user" title="Audit filtern">Audit</button>
            <button class="btn btn-ghost btn-xs btn-del-user" style="color:var(--accent-rose);" title="Löschen">&times;</button>
          </div>
        </td>
      `;

      tr.querySelector('.btn-edit-user').addEventListener('click', () => openEditUserModal(u));
      tr.querySelector('.btn-audit-user').addEventListener('click', () => {
        state.audit.search = u.username;
        el.auditSearchInput.value = u.username;
        switchTab('audit');
      });
      tr.querySelector('.btn-del-user').addEventListener('click', () => deleteUser(u));

      el.usersTableBody.appendChild(tr);
    });
  }

  function openCreateUserModal() {
    el.userFormTitle.textContent = 'Neuen Benutzer anlegen';
    el.userFormId.value = '';
    el.userFormUsernameGroup.style.display = 'block';
    el.formUsername.value = '';
    el.formUsername.required = true;
    el.formFullName.value = '';
    el.formEmail.value = '';
    el.formPassword.value = '';
    el.formPassword.required = true;
    el.formPasswordHint.textContent = 'Mindestens 6 Zeichen';
    el.formStatus.value = 'active';
    el.userFormError.style.display = 'none';

    renderRoleCheckboxes([]);
    el.userFormModal.classList.add('open');
  }

  function openEditUserModal(u) {
    el.userFormTitle.textContent = `Benutzer bearbeiten: @${u.username}`;
    el.userFormId.value = u.id;
    el.userFormUsernameGroup.style.display = 'none'; // username cannot be changed
    el.formUsername.required = false;
    el.formFullName.value = u.full_name;
    el.formEmail.value = u.email;
    el.formPassword.value = '';
    el.formPassword.required = false;
    el.formPasswordHint.textContent = 'Leer lassen, um aktuelles Kennwort beizubehalten.';
    el.formStatus.value = u.status;
    el.userFormError.style.display = 'none';

    const userRoleIds = (u.roles || []).map(r => r.id);
    renderRoleCheckboxes(userRoleIds);
    el.userFormModal.classList.add('open');
  }

  function renderRoleCheckboxes(selectedRoleIds) {
    el.formRolesCheckboxes.innerHTML = '';
    state.allRoles.forEach(r => {
      const isChecked = selectedRoleIds.includes(r.id);
      const label = document.createElement('label');
      label.style.display = 'flex';
      label.style.alignItems = 'center';
      label.style.gap = '0.5rem';
      label.style.fontSize = '0.85rem';
      label.style.cursor = 'pointer';
      label.innerHTML = `
        <input type="checkbox" name="role_checkbox" value="${r.id}" ${isChecked ? 'checked' : ''} />
        <span><strong>${escapeHtml(r.name)}</strong> - <small style="color:var(--text-muted);">${escapeHtml(r.description)}</small></span>
      `;
      el.formRolesCheckboxes.appendChild(label);
    });
  }

  function closeUserModal() {
    el.userFormModal.classList.remove('open');
  }
  el.closeUserModalBtn.addEventListener('click', closeUserModal);
  el.cancelUserModalBtn.addEventListener('click', closeUserModal);
  el.btnCreateUser.addEventListener('click', openCreateUserModal);

  el.userForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    el.userFormError.style.display = 'none';

    const id = el.userFormId.value;
    const selectedRoles = Array.from(document.querySelectorAll('input[name="role_checkbox"]:checked')).map(cb => cb.value);

    try {
      if (!id) {
        // Create
        await api('/api/users', {
          method: 'POST',
          body: JSON.stringify({
            username: el.formUsername.value.trim(),
            full_name: el.formFullName.value.trim(),
            email: el.formEmail.value.trim(),
            password: el.formPassword.value,
            status: el.formStatus.value,
            role_ids: selectedRoles
          })
        });
        showToast('Benutzer erfolgreich angelegt', 'success');
      } else {
        // Update
        const payload = {
          full_name: el.formFullName.value.trim(),
          email: el.formEmail.value.trim(),
          status: el.formStatus.value,
          role_ids: selectedRoles
        };
        if (el.formPassword.value) {
          payload.password = el.formPassword.value;
        }
        await api(`/api/users/${id}`, {
          method: 'PUT',
          body: JSON.stringify(payload)
        });
        showToast('Benutzerdaten aktualisiert', 'success');
      }

      closeUserModal();
      loadUsers();
      loadStats();
    } catch (err) {
      el.userFormError.textContent = err.message;
      el.userFormError.style.display = 'block';
    }
  });

  async function deleteUser(u) {
    if (!confirm(`Soll der Benutzer "${u.full_name || u.username}" wirklich permanent gelöscht werden? Diese Aktion wird im Audit-Log dokumentiert.`)) {
      return;
    }
    try {
      await api(`/api/users/${u.id}`, { method: 'DELETE' });
      showToast('Benutzer erfolgreich gelöscht', 'info');
      loadUsers();
      loadStats();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  // ================= ROLES & RBAC =================

  async function loadRoles() {
    try {
      const roles = await api('/api/roles');
      state.allRoles = roles;
      renderRolesGrid(roles);
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  function renderRolesGrid(roles) {
    el.rolesGrid.innerHTML = '';
    roles.forEach(r => {
      const card = document.createElement('div');
      card.className = 'role-card';

      const permPills = (r.permissions || []).map(p => {
        return `<span class="perm-pill" title="${escapeHtml(p.description)}">${escapeHtml(p.code)}</span>`;
      }).join('') || '<span style="color:var(--text-dim); font-size:0.8rem;">Keine Berechtigungen zugewiesen</span>';

      const systemBadge = r.is_system
        ? `<span class="badge" style="background:rgba(255,255,255,0.08); color:var(--text-muted);">System</span>`
        : `<span class="badge" style="background:rgba(6,182,212,0.1); color:var(--accent-cyan);">Benutzerdefiniert</span>`;

      card.innerHTML = `
        <div>
          <div class="role-card-header">
            <div>
              <h3 class="role-card-title">${escapeHtml(r.name)}</h3>
              <p class="role-card-desc">${escapeHtml(r.description)}</p>
            </div>
            ${systemBadge}
          </div>
          <div style="margin-top: 1.25rem;">
            <div style="font-size:0.75rem; font-weight:600; color:var(--text-dim); text-transform:uppercase; margin-bottom:0.5rem;">Zugewiesene Berechtigungen (${(r.permissions || []).length})</div>
            <div class="role-perms-tag-group">${permPills}</div>
          </div>
        </div>
        <div style="display:flex; justify-content:flex-end; gap:0.5rem; padding-top:1rem; border-top:1px solid var(--border-color);">
          <button class="btn btn-secondary btn-xs btn-edit-role">Berechtigungen anpassen</button>
          ${!r.is_system ? `<button class="btn btn-ghost btn-xs btn-del-role" style="color:var(--accent-rose);">&times; Löschen</button>` : ''}
        </div>
      `;

      card.querySelector('.btn-edit-role').addEventListener('click', () => openEditRoleModal(r));
      const delBtn = card.querySelector('.btn-del-role');
      if (delBtn) {
        delBtn.addEventListener('click', () => deleteRole(r));
      }

      el.rolesGrid.appendChild(card);
    });
  }

  function renderPermissionsReference(perms) {
    el.permissionsReferenceList.innerHTML = '';
    const grouped = {};
    perms.forEach(p => {
      if (!grouped[p.category]) grouped[p.category] = [];
      grouped[p.category].push(p);
    });

    for (const [cat, list] of Object.entries(grouped)) {
      const catBox = document.createElement('div');
      catBox.style.marginBottom = '1.25rem';
      catBox.innerHTML = `
        <h4 style="font-size:0.85rem; font-weight:700; color:var(--accent-cyan); text-transform:uppercase; letter-spacing:0.05em; margin-bottom:0.5rem;">${escapeHtml(cat)}</h4>
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:0.5rem;">
          ${list.map(p => `
            <div style="background:rgba(0,0,0,0.3); padding:0.6rem 0.8rem; border-radius:var(--radius-sm); border:1px solid var(--border-color);">
              <div style="font-family:var(--font-mono); font-size:0.8rem; font-weight:600; color:#fff;">${escapeHtml(p.code)}</div>
              <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.15rem;">${escapeHtml(p.description)}</div>
            </div>
          `).join('')}
        </div>
      `;
      el.permissionsReferenceList.appendChild(catBox);
    }
  }

  function openCreateRoleModal() {
    el.roleFormTitle.textContent = 'Neue Rolle erstellen';
    el.roleFormId.value = '';
    el.formRoleName.value = '';
    el.formRoleName.disabled = false;
    el.formRoleDesc.value = '';
    el.roleFormError.style.display = 'none';

    renderRolePermissionsChecklist([]);
    el.roleFormModal.classList.add('open');
  }

  function openEditRoleModal(r) {
    el.roleFormTitle.textContent = `Rolle bearbeiten: ${r.name}`;
    el.roleFormId.value = r.id;
    el.formRoleName.value = r.name;
    el.formRoleName.disabled = r.is_system;
    el.formRoleDesc.value = r.description;
    el.roleFormError.style.display = 'none';

    const rolePermIds = (r.permissions || []).map(p => p.id);
    renderRolePermissionsChecklist(rolePermIds);
    el.roleFormModal.classList.add('open');
  }

  function renderRolePermissionsChecklist(selectedPermIds) {
    el.formRolePermissionsChecklist.innerHTML = '';
    state.allPermissions.forEach(p => {
      const isChecked = selectedPermIds.includes(p.id);
      const div = document.createElement('div');
      div.className = 'perm-check-item';
      div.innerHTML = `
        <input type="checkbox" name="role_perm_check" value="${p.id}" ${isChecked ? 'checked' : ''} id="perm_chk_${p.id}" />
        <label for="perm_chk_${p.id}" class="perm-info" style="cursor:pointer;">
          <span class="perm-code">${escapeHtml(p.code)}</span>
          <span class="perm-name">${escapeHtml(p.name)}</span>
        </label>
      `;
      el.formRolePermissionsChecklist.appendChild(div);
    });
  }

  function closeRoleModal() {
    el.roleFormModal.classList.remove('open');
  }
  el.closeRoleModalBtn.addEventListener('click', closeRoleModal);
  el.cancelRoleModalBtn.addEventListener('click', closeRoleModal);
  el.btnCreateRole.addEventListener('click', openCreateRoleModal);

  el.roleForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    el.roleFormError.style.display = 'none';

    const id = el.roleFormId.value;
    const selectedPerms = Array.from(document.querySelectorAll('input[name="role_perm_check"]:checked')).map(cb => cb.value);

    try {
      if (!id) {
        await api('/api/roles', {
          method: 'POST',
          body: JSON.stringify({
            name: el.formRoleName.value.trim(),
            description: el.formRoleDesc.value.trim(),
            permission_ids: selectedPerms
          })
        });
        showToast('Rolle erfolgreich erstellt', 'success');
      } else {
        await api(`/api/roles/${id}`, {
          method: 'PUT',
          body: JSON.stringify({
            description: el.formRoleDesc.value.trim(),
            permission_ids: selectedPerms
          })
        });
        showToast('Rollen-Berechtigungen aktualisiert', 'success');
      }

      closeRoleModal();
      loadRoles();
      loadStats();
    } catch (err) {
      el.roleFormError.textContent = err.message;
      el.roleFormError.style.display = 'block';
    }
  });

  async function deleteRole(r) {
    if (!confirm(`Soll die Rolle "${r.name}" gelöscht werden? Dies wird revisionssicher auditiert.`)) {
      return;
    }
    try {
      await api(`/api/roles/${r.id}`, { method: 'DELETE' });
      showToast('Rolle gelöscht', 'info');
      loadRoles();
      loadStats();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  // ================= ACTIVE DIRECTORY & AGDLP CONTROLLER =================

  let adUsersCache = [];
  let adGroupsCache = [];
  let agdlpMatrixCache = [];

  // Elements
  const btnDirViewUsers = document.getElementById('btnDirViewUsers');
  const btnDirViewAGDLP = document.getElementById('btnDirViewAGDLP');
  const btnDirViewConfig = document.getElementById('btnDirViewConfig');
  const dirSubViewUsers = document.getElementById('dirSubViewUsers');
  const dirSubViewAGDLP = document.getElementById('dirSubViewAGDLP');
  const dirSubViewConfig = document.getElementById('dirSubViewConfig');

  const dirStatusTitle = document.getElementById('dirStatusTitle');
  const dirStatusSubtitle = document.getElementById('dirStatusSubtitle');
  const dirStatusPulse = document.getElementById('dirStatusPulse');
  const btnTestConnQuick = document.getElementById('btnTestConnQuick');

  const adUserSearchInput = document.getElementById('adUserSearchInput');
  const btnOpenCreateADUserModal = document.getElementById('btnOpenCreateADUserModal');
  const adUsersTableBody = document.getElementById('adUsersTableBody');

  const btnOpenCreateAGDLPModal = document.getElementById('btnOpenCreateAGDLPModal');
  const agdlpMatrixGrid = document.getElementById('agdlpMatrixGrid');

  const adConfigForm = document.getElementById('adConfigForm');
  const btnTestConfigConn = document.getElementById('btnTestConfigConn');
  const cfgHost = document.getElementById('cfgHost');
  const cfgPort = document.getElementById('cfgPort');
  const cfgBaseDN = document.getElementById('cfgBaseDN');
  const cfgBindDN = document.getElementById('cfgBindDN');
  const cfgBindPassword = document.getElementById('cfgBindPassword');
  const cfgUserContainer = document.getElementById('cfgUserContainer');
  const cfgGroupContainer = document.getElementById('cfgGroupContainer');
  const cfgUseTLS = document.getElementById('cfgUseTLS');
  const cfgSkipVerify = document.getElementById('cfgSkipVerify');
  const cfgDemoMode = document.getElementById('cfgDemoMode');

  // Modals
  const adUserModal = document.getElementById('adUserModal');
  const closeADUserModalBtn = document.getElementById('closeADUserModalBtn');
  const cancelADUserModalBtn = document.getElementById('cancelADUserModalBtn');
  const adUserForm = document.getElementById('adUserForm');
  const adFormRoleGroupsChecklist = document.getElementById('adFormRoleGroupsChecklist');
  const adUserFormError = document.getElementById('adUserFormError');

  const adPasswordModal = document.getElementById('adPasswordModal');
  const closeADPasswordModalBtn = document.getElementById('closeADPasswordModalBtn');
  const cancelADPasswordModalBtn = document.getElementById('cancelADPasswordModalBtn');
  const adPasswordForm = document.getElementById('adPasswordForm');
  const adPasswordSam = document.getElementById('adPasswordSam');
  const adNewPassword = document.getElementById('adNewPassword');
  const adPasswordModalDesc = document.getElementById('adPasswordModalDesc');
  const adPasswordError = document.getElementById('adPasswordError');

  const adShareModal = document.getElementById('adShareModal');
  const closeADShareModalBtn = document.getElementById('closeADShareModalBtn');
  const cancelADShareModalBtn = document.getElementById('cancelADShareModalBtn');
  const adShareForm = document.getElementById('adShareForm');
  const adShareName = document.getElementById('adShareName');
  const adFolderName = document.getElementById('adFolderName');
  const adShareDesc = document.getElementById('adShareDesc');
  const adShareRO = document.getElementById('adShareRO');
  const adShareRW = document.getElementById('adShareRW');
  const adShareFC = document.getElementById('adShareFC');
  const adShareAssignRoleChecklist = document.getElementById('adShareAssignRoleChecklist');
  const adSharePreviewName = document.getElementById('adSharePreviewName');
  const adShareFormError = document.getElementById('adShareFormError');

  const adMemberModal = document.getElementById('adMemberModal');
  const closeADMemberModalBtn = document.getElementById('closeADMemberModalBtn');
  const cancelADMemberModalBtn = document.getElementById('cancelADMemberModalBtn');
  const adMemberForm = document.getElementById('adMemberForm');
  const adMemberGroupName = document.getElementById('adMemberGroupName');
  const adMemberModalDesc = document.getElementById('adMemberModalDesc');
  const adMemberSelect = document.getElementById('adMemberSelect');
  const adMemberFormError = document.getElementById('adMemberFormError');

  // Subview Navigation
  function switchDirSubView(view) {
    [btnDirViewUsers, btnDirViewAGDLP, btnDirViewConfig].forEach(b => b.classList.remove('active'));
    [dirSubViewUsers, dirSubViewAGDLP, dirSubViewConfig].forEach(v => v.style.display = 'none');

    if (view === 'users') {
      btnDirViewUsers.classList.add('active');
      dirSubViewUsers.style.display = 'block';
      loadADUsers();
    } else if (view === 'agdlp') {
      btnDirViewAGDLP.classList.add('active');
      dirSubViewAGDLP.style.display = 'block';
      loadAGDLPMatrix();
    } else if (view === 'config') {
      btnDirViewConfig.classList.add('active');
      dirSubViewConfig.style.display = 'block';
      loadADConfig();
    }
  }

  btnDirViewUsers.addEventListener('click', () => switchDirSubView('users'));
  btnDirViewAGDLP.addEventListener('click', () => switchDirSubView('agdlp'));
  btnDirViewConfig.addEventListener('click', () => switchDirSubView('config'));

  // Main Directory Data Loader
  async function loadDirectoryData() {
    loadADConfigStatus();
    loadADGroupsCache();
    switchDirSubView('users');
  }

  async function loadADConfigStatus() {
    try {
      const data = await api('/api/directory/config');
      const cfg = data.config;
      if (cfg.demo_mode) {
        dirStatusTitle.textContent = 'Demo / Mock-Modus aktiv (Samba-AD & Windows AD)';
        dirStatusSubtitle.textContent = 'In-Memory Domain Controller aktiv • Vollständige AGDLP-Matrix • SHA-256 Hash Chain versiegelt';
        dirStatusPulse.style.background = 'var(--accent-cyan)';
      } else {
        dirStatusTitle.textContent = `LDAPS Live-Verbindung: ${cfg.host}:${cfg.port}`;
        dirStatusSubtitle.textContent = `Base DN: ${cfg.base_dn} • Revisionssichere Verwaltung aktiv`;
        dirStatusPulse.style.background = 'var(--accent-emerald)';
      }
    } catch (err) {
      dirStatusTitle.textContent = 'Verbindungsstatus unbekannt';
      dirStatusSubtitle.textContent = err.message;
    }
  }

  async function loadADGroupsCache() {
    try {
      const data = await api('/api/directory/groups');
      adGroupsCache = data.groups || [];
    } catch (e) {
      console.warn('Could not load AD groups:', e);
    }
  }

  // --- 1. AD Users ---
  async function loadADUsers() {
    try {
      const search = adUserSearchInput.value.trim();
      const query = search ? `?search=${encodeURIComponent(search)}` : '';
      const data = await api(`/api/directory/users${query}`);
      adUsersCache = data.users || [];
      renderADUsers(adUsersCache);
    } catch (err) {
      adUsersTableBody.innerHTML = `<tr><td colspan="7" class="text-muted text-center py-4">Fehler beim Laden der AD-Benutzer: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  let adSearchTimeout = null;
  adUserSearchInput.addEventListener('input', () => {
    clearTimeout(adSearchTimeout);
    adSearchTimeout = setTimeout(loadADUsers, 300);
  });

  function renderADUsers(users) {
    if (!users || users.length === 0) {
      adUsersTableBody.innerHTML = `<tr><td colspan="7" class="text-muted text-center py-4">Keine AD-Benutzer gefunden.</td></tr>`;
      return;
    }

    adUsersTableBody.innerHTML = users.map(u => {
      const statusBadge = u.enabled
        ? '<span class="badge badge-active">Aktiv</span>'
        : '<span class="badge badge-suspended">Gesperrt</span>';

      const roleChips = (u.member_of || []).map(g => {
        const isGlobal = g.startsWith('G_');
        return `<span class="agdlp-member-chip ${isGlobal ? 'is-global-group' : ''}">${escapeHtml(g)}</span>`;
      }).join(' ') || '<span class="text-dim text-xs">Keine Rollengruppen</span>';

      const toggleActionTitle = u.enabled ? 'Konto sperren (UAC)' : 'Konto aktivieren (UAC)';
      const toggleActionIcon = u.enabled
        ? '<svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" stroke-width="2" fill="none"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>'
        : '<svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" stroke-width="2" fill="none"><polyline points="20 6 9 17 4 12"></polyline></svg>';

      return `
        <tr>
          <td>
            <div style="font-weight:600; font-family:var(--font-mono); color:#fff;">${escapeHtml(u.sam_account_name)}</div>
            <div class="text-dim text-xs">${escapeHtml(u.user_principal_name || '')}</div>
          </td>
          <td>
            <div style="font-weight:500;">${escapeHtml(u.display_name)}</div>
          </td>
          <td>
            <div>${escapeHtml(u.department || '-')}</div>
            <div class="text-dim text-xs">${escapeHtml(u.title || '')}</div>
          </td>
          <td>${escapeHtml(u.mail || '-')}</td>
          <td>${statusBadge}</td>
          <td><div class="agdlp-members-wrap">${roleChips}</div></td>
          <td class="text-right">
            <div class="action-btn-group">
              <button class="icon-btn btn-sm" onclick="window.argusDir.openEffectivePerms('${escapeHtml(u.sam_account_name)}')" title="Effektive Berechtigungen berechnen (A -> G -> DL -> P)">
                <svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" stroke-width="2" fill="none"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
              </button>
              <button class="icon-btn btn-sm" onclick="window.argusDir.toggleUserStatus('${escapeHtml(u.sam_account_name)}', ${!u.enabled})" title="${toggleActionTitle}">
                ${toggleActionIcon}
              </button>
              <button class="icon-btn btn-sm" onclick="window.argusDir.openPasswordReset('${escapeHtml(u.sam_account_name)}')" title="Kennwort zurücksetzen">
                <svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" stroke-width="2" fill="none"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
              </button>
              <button class="icon-btn btn-sm text-danger" onclick="window.argusDir.deleteUser('${escapeHtml(u.sam_account_name)}')" title="AD-Benutzer löschen">
                <svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" stroke-width="2" fill="none"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  // --- Create AD User Modal ---
  btnOpenCreateADUserModal.addEventListener('click', async () => {
    adUserForm.reset();
    adUserFormError.style.display = 'none';

    // Populate global groups
    await loadADGroupsCache();
    const globalGroups = adGroupsCache.filter(g => g.group_scope === 'Global' || g.sam_account_name.startsWith('G_'));

    if (globalGroups.length === 0) {
      adFormRoleGroupsChecklist.innerHTML = '<span class="text-dim text-xs">Keine globalen Gruppen vorhanden</span>';
    } else {
      adFormRoleGroupsChecklist.innerHTML = globalGroups.map(g => `
        <label class="checkbox-label" style="font-size:0.8rem;">
          <input type="checkbox" name="adRoleGroup" value="${escapeHtml(g.sam_account_name)}" />
          <span><strong>${escapeHtml(g.sam_account_name)}</strong> <small class="text-dim">(${escapeHtml(g.description || '')})</small></span>
        </label>
      `).join('');
    }

    adUserModal.classList.add('open');
  });

  closeADUserModalBtn.addEventListener('click', () => adUserModal.classList.remove('open'));
  cancelADUserModalBtn.addEventListener('click', () => adUserModal.classList.remove('open'));

  adUserForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    adUserFormError.style.display = 'none';

    const selectedGroups = Array.from(adFormRoleGroupsChecklist.querySelectorAll('input[type="checkbox"]:checked'))
      .map(cb => cb.value);

    const payload = {
      sam_account_name: document.getElementById('adFormSam').value.trim(),
      given_name: document.getElementById('adFormGiven').value.trim(),
      surname: document.getElementById('adFormSurname').value.trim(),
      mail: document.getElementById('adFormMail').value.trim(),
      department: document.getElementById('adFormDept').value.trim(),
      title: document.getElementById('adFormTitle').value.trim(),
      password: document.getElementById('adFormPassword').value,
      enabled: document.getElementById('adFormEnabled').checked,
      role_groups: selectedGroups
    };

    try {
      await api('/api/directory/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      showToast(`AD-Benutzer ${payload.sam_account_name} erfolgreich erstellt & versiegelt`, 'success');
      adUserModal.classList.remove('open');
      loadADUsers();
      loadStats();
    } catch (err) {
      adUserFormError.textContent = err.message;
      adUserFormError.style.display = 'block';
    }
  });

  // --- Password Reset Modal ---
  closeADPasswordModalBtn.addEventListener('click', () => adPasswordModal.classList.remove('open'));
  cancelADPasswordModalBtn.addEventListener('click', () => adPasswordModal.classList.remove('open'));

  adPasswordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    adPasswordError.style.display = 'none';
    const sam = adPasswordSam.value;
    const pwd = adNewPassword.value;

    try {
      await api(`/api/directory/users/${encodeURIComponent(sam)}/password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pwd })
      });
      showToast(`Kennwort für ${sam} zurückgesetzt & im Audit-Log versiegelt`, 'success');
      adPasswordModal.classList.remove('open');
      loadStats();
    } catch (err) {
      adPasswordError.textContent = err.message;
      adPasswordError.style.display = 'block';
    }
  });

  // --- 2. AGDLP Matrix ---
  async function loadAGDLPMatrix() {
    try {
      const [matrixData, conflictData] = await Promise.all([
        api('/api/directory/agdlp-matrix'),
        api('/api/directory/agdlp/conflicts')
      ]);
      const matrix = matrixData.matrix || [];
      agdlpMatrixCache = matrix;
      renderAGDLPMatrix(matrix);
      renderAGDLPConflicts(conflictData.conflicts || []);
    } catch (err) {
      agdlpMatrixGrid.innerHTML = `<div class="glass-card text-center py-4 text-muted">Fehler beim Laden der AGDLP Matrix: ${escapeHtml(err.message)}</div>`;
    }
  }

  function renderAGDLPConflicts(conflicts) {
    const alertBox = document.getElementById('agdlpConflictAlert');
    if (!alertBox) return;
    if (!conflicts || conflicts.length === 0) {
      alertBox.style.display = 'none';
      return;
    }
    alertBox.style.display = 'block';
    alertBox.innerHTML = `
      <div class="conflict-title">
        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
        <span>${conflicts.length} AGDLP-Abweichung(en) / Rechte-Konflikte erkannt</span>
      </div>
      <div class="conflict-list">
        ${conflicts.map(c => `
          <div class="conflict-item">
            <span class="conflict-badge">${escapeHtml(c.type)}</span>
            <div>
              <strong>${escapeHtml(c.target)}:</strong> ${escapeHtml(c.description)}
              <div class="text-dim text-xs" style="margin-top:2px;">Empfehlung: ${escapeHtml(c.suggestion)}</div>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  }

  function renderAGDLPMatrix(matrix) {
    if (!matrix || matrix.length === 0) {
      agdlpMatrixGrid.innerHTML = `
        <div class="glass-card text-center py-4" style="grid-column: 1 / -1;">
          <p class="text-muted mb-2">Noch keine AGDLP Dateifreigaben definiert.</p>
          <button class="btn btn-primary btn-sm" onclick="document.getElementById('btnOpenCreateAGDLPModal').click()">
            Erste Dateifreigabe anlegen
          </button>
        </div>`;
      return;
    }

    agdlpMatrixGrid.innerHTML = matrix.map(folder => {
      const permRows = ['RO', 'RW', 'FC'].map(perm => {
        const grp = folder.groups ? folder.groups[perm] : null;
        if (!grp) return '';

        const badgeClass = perm === 'RO' ? 'perm-ro' : (perm === 'RW' ? 'perm-rw' : 'perm-fc');
        const badgeLabel = perm === 'RO' ? 'LESEN (RO)' : (perm === 'RW' ? 'ÄNDERN (RW)' : 'VOLLZUGRIFF (FC)');

        const memberChips = (grp.members || []).map(m => {
          const isGlobal = m.startsWith('G_');
          return `
            <span class="agdlp-member-chip ${isGlobal ? 'is-global-group' : ''}">
              <span>${escapeHtml(m)}</span>
              <span class="chip-del" onclick="window.argusDir.removeMember('${escapeHtml(grp.sam_account_name)}', '${escapeHtml(m)}')" title="Entfernen">&times;</span>
            </span>`;
        }).join('') || '<span class="agdlp-empty-members">Keine Mitglieder zugewiesen</span>';

        return `
          <div class="agdlp-perm-row">
            <div class="agdlp-perm-header">
              <span class="agdlp-perm-badge ${badgeClass}">${badgeLabel}</span>
              <button class="btn btn-ghost btn-xs" onclick="window.argusDir.openAssignMemberModal('${escapeHtml(grp.sam_account_name)}')">
                + Zuweisen
              </button>
            </div>
            <div class="agdlp-group-name"><code>${escapeHtml(grp.sam_account_name)}</code></div>
            <div class="agdlp-members-wrap">${memberChips}</div>
          </div>
        `;
      }).filter(Boolean).join('');

      return `
        <div class="glass-card agdlp-folder-card">
          <div class="agdlp-folder-header">
            <div class="agdlp-folder-title">
              <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
              <span>${escapeHtml(folder.folder_name)}</span>
            </div>
            <div style="display:flex; align-items:center; gap:0.5rem;">
              <span class="agdlp-share-tag">\\\\${escapeHtml(folder.share_name)}</span>
              <button class="btn btn-ghost btn-xs" onclick="window.argusDir.openScriptModal('${escapeHtml(folder.share_name)}', '${escapeHtml(folder.folder_name)}')" title="icacls / setfacl Skript abrufen">
                <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="2" fill="none"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
                ACL Skript
              </button>
            </div>
          </div>
          <div class="agdlp-perm-strip">
            ${permRows}
          </div>
        </div>
      `;
    }).join('');
  }

  // --- Create AGDLP Share Wizard ---
  function updateShareNamePreview() {
    const s = adShareName.value.trim().replace(/[^a-zA-Z0-9_]/g, '') || 'Freigabe';
    const f = adFolderName.value.trim().replace(/[^a-zA-Z0-9_]/g, '') || 'Ordner';
    const parts = [];
    if (adShareRO.checked) parts.push(`DL_FS_${s}_${f}_RO`);
    if (adShareRW.checked) parts.push(`DL_FS_${s}_${f}_RW`);
    if (adShareFC.checked) parts.push(`DL_FS_${s}_${f}_FC`);
    adSharePreviewName.textContent = parts.join(' • ') || 'Keine Stufe ausgewählt';
  }

  adShareName.addEventListener('input', updateShareNamePreview);
  adFolderName.addEventListener('input', updateShareNamePreview);
  adShareRO.addEventListener('change', updateShareNamePreview);
  adShareRW.addEventListener('change', updateShareNamePreview);
  adShareFC.addEventListener('change', updateShareNamePreview);

  btnOpenCreateAGDLPModal.addEventListener('click', async () => {
    adShareForm.reset();
    adShareFormError.style.display = 'none';
    adShareRO.checked = true;
    adShareRW.checked = true;
    updateShareNamePreview();

    await loadADGroupsCache();
    const globalGroups = adGroupsCache.filter(g => g.group_scope === 'Global' || g.sam_account_name.startsWith('G_'));

    if (globalGroups.length === 0) {
      adShareAssignRoleChecklist.innerHTML = '<span class="text-dim text-xs">Keine globalen Rollengruppen verfügbar</span>';
    } else {
      adShareAssignRoleChecklist.innerHTML = globalGroups.map(g => `
        <label class="checkbox-label" style="font-size:0.8rem;">
          <input type="checkbox" name="adShareRole" value="${escapeHtml(g.sam_account_name)}" />
          <span><strong>${escapeHtml(g.sam_account_name)}</strong></span>
        </label>
      `).join('');
    }

    adShareModal.classList.add('open');
  });

  closeADShareModalBtn.addEventListener('click', () => adShareModal.classList.remove('open'));
  cancelADShareModalBtn.addEventListener('click', () => adShareModal.classList.remove('open'));

  adShareForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    adShareFormError.style.display = 'none';

    const selectedRoles = Array.from(adShareAssignRoleChecklist.querySelectorAll('input[type="checkbox"]:checked'))
      .map(cb => cb.value);

    const payload = {
      share_name: adShareName.value.trim(),
      folder_name: adFolderName.value.trim(),
      description: adShareDesc.value.trim(),
      create_read_only: adShareRO.checked,
      create_read_write: adShareRW.checked,
      create_full_control: adShareFC.checked,
      assigned_global_groups: selectedRoles
    };

    try {
      await api('/api/directory/groups/agdlp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      showToast(`AGDLP Freigabegruppen für ${payload.share_name}/${payload.folder_name} generiert`, 'success');
      adShareModal.classList.remove('open');
      loadAGDLPMatrix();
      loadStats();
    } catch (err) {
      adShareFormError.textContent = err.message;
      adShareFormError.style.display = 'block';
    }
  });

  // --- Assign Member Modal ---
  closeADMemberModalBtn.addEventListener('click', () => adMemberModal.classList.remove('open'));
  cancelADMemberModalBtn.addEventListener('click', () => adMemberModal.classList.remove('open'));

  adMemberForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    adMemberFormError.style.display = 'none';

    const groupName = adMemberGroupName.value;
    const member = adMemberSelect.value;

    try {
      await api('/api/directory/memberships', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_name: groupName, member: member })
      });
      showToast(`'${member}' erfolgreich zu '${groupName}' zugewiesen`, 'success');
      adMemberModal.classList.remove('open');
      loadAGDLPMatrix();
      loadStats();
    } catch (err) {
      adMemberFormError.textContent = err.message;
      adMemberFormError.style.display = 'block';
    }
  });

  // --- 3. DC Config ---
  async function loadADConfig() {
    try {
      const data = await api('/api/directory/config');
      const cfg = data.config;
      cfgHost.value = cfg.host || '';
      cfgPort.value = cfg.port || 636;
      cfgBaseDN.value = cfg.base_dn || '';
      cfgBindDN.value = cfg.bind_dn || '';
      cfgBindPassword.value = cfg.bind_password || '';
      cfgUserContainer.value = cfg.user_container || '';
      cfgGroupContainer.value = cfg.group_container || '';
      cfgUseTLS.checked = cfg.use_tls;
      cfgSkipVerify.checked = cfg.insecure_skip_verify;
      cfgDemoMode.checked = cfg.demo_mode;
    } catch (err) {
      showToast('Konfiguration konnte nicht geladen werden: ' + err.message, 'error');
    }
  }

  adConfigForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      host: cfgHost.value.trim(),
      port: parseInt(cfgPort.value, 10),
      base_dn: cfgBaseDN.value.trim(),
      bind_dn: cfgBindDN.value.trim(),
      bind_password: cfgBindPassword.value,
      user_container: cfgUserContainer.value.trim(),
      group_container: cfgGroupContainer.value.trim(),
      use_tls: cfgUseTLS.checked,
      insecure_skip_verify: cfgSkipVerify.checked,
      demo_mode: cfgDemoMode.checked
    };

    try {
      await api('/api/directory/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      showToast('Domain Controller Einstellungen erfolgreich gespeichert & auditiert', 'success');
      loadADConfigStatus();
    } catch (err) {
      showToast('Fehler beim Speichern: ' + err.message, 'error');
    }
  });

  async function testADConnection() {
    showToast('Prüfe Verbindung zum Domain Controller...', 'info');
    try {
      const res = await api('/api/directory/test-connection', { method: 'POST' });
      if (res.success) {
        showToast(`${res.message} (Latenz: ${res.latency})`, 'success');
      } else {
        showToast(`${res.message}`, 'error');
      }
    } catch (err) {
      showToast('Verbindungstest fehlgeschlagen: ' + err.message, 'error');
    }
  }

  btnTestConnQuick.addEventListener('click', testADConnection);
  btnTestConfigConn.addEventListener('click', testADConnection);

  // Expose global helpers for inline event handlers
  window.argusDir = {
    toggleUserStatus: async (sam, newStatus) => {
      const action = newStatus ? 'aktivieren' : 'sperren';
      if (!confirm(`Soll das Active Directory Konto "${sam}" wirklich ${action} werden?`)) return;
      try {
        await api(`/api/directory/users/${encodeURIComponent(sam)}/status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: newStatus })
        });
        showToast(`AD-Konto ${sam} wurde ${newStatus ? 'aktiviert' : 'gesperrt'}`, 'success');
        loadADUsers();
        loadStats();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },
    openPasswordReset: (sam) => {
      adPasswordSam.value = sam;
      adNewPassword.value = '';
      adPasswordModalDesc.textContent = `Neues Kennwort für AD-Benutzer "${sam}" festlegen und Sperre (lockout) aufheben.`;
      adPasswordError.style.display = 'none';
      adPasswordModal.classList.add('open');
    },
    deleteUser: async (sam) => {
      if (!confirm(`Soll das AD-Benutzerkonto "${sam}" unwiderruflich gelöscht werden?`)) return;
      try {
        await api(`/api/directory/users/${encodeURIComponent(sam)}`, { method: 'DELETE' });
        showToast(`AD-Benutzerkonto ${sam} gelöscht`, 'info');
        loadADUsers();
        loadStats();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },
    openAssignMemberModal: async (groupName) => {
      adMemberGroupName.value = groupName;
      adMemberModalDesc.innerHTML = `Zielgruppe: <code>${escapeHtml(groupName)}</code>`;
      adMemberFormError.style.display = 'none';

      // Load users & global groups
      await Promise.all([loadADUsers(), loadADGroupsCache()]);
      const globalGroups = adGroupsCache.filter(g => g.group_scope === 'Global' || g.sam_account_name.startsWith('G_'));

      let optHtml = '<optgroup label="Globale Rollengruppen (AGDLP Empfohlen)">';
      globalGroups.forEach(g => {
        optHtml += `<option value="${escapeHtml(g.sam_account_name)}">${escapeHtml(g.sam_account_name)}</option>`;
      });
      optHtml += '</optgroup><optgroup label="Einzelne AD-Benutzerkonten">';
      adUsersCache.forEach(u => {
        optHtml += `<option value="${escapeHtml(u.sam_account_name)}">${escapeHtml(u.display_name)} (${escapeHtml(u.sam_account_name)})</option>`;
      });
      optHtml += '</optgroup>';

      adMemberSelect.innerHTML = optHtml;
      adMemberModal.classList.add('open');
    },
    removeMember: async (groupName, member) => {
      if (!confirm(`Soll "${member}" aus der Ressourcengruppe "${groupName}" entfernt werden?`)) return;
      try {
        await api('/api/directory/memberships', {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ group_name: groupName, member: member })
        });
        showToast(`'${member}' aus '${groupName}' entfernt`, 'info');
        loadAGDLPMatrix();
        loadStats();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },
    openScriptModal: async (share, folder) => {
      const modal = document.getElementById('aclScriptModal');
      const title = document.getElementById('aclScriptTitle');
      const box = document.getElementById('scriptContentBox');
      const btnPS = document.getElementById('btnTabScriptPS');
      const btnBash = document.getElementById('btnTabScriptBash');
      const btnCopy = document.getElementById('btnCopyScript');

      title.textContent = `ACL Bereitstellung: \\\\${share}\\${folder}`;
      let currentPS = '';
      let currentBash = '';
      let activeOS = 'ps';

      box.textContent = '# Lade ACL-Skripte...';
      modal.classList.add('open');

      try {
        const data = await api(`/api/directory/agdlp/scripts?share=${encodeURIComponent(share)}&folder=${encodeURIComponent(folder)}`);
        currentPS = data.powershell_script;
        currentBash = data.bash_script;
        box.textContent = activeOS === 'ps' ? currentPS : currentBash;

        btnPS.onclick = () => {
          activeOS = 'ps';
          btnPS.classList.add('active');
          btnBash.classList.remove('active');
          box.textContent = currentPS;
        };
        btnBash.onclick = () => {
          activeOS = 'bash';
          btnBash.classList.add('active');
          btnPS.classList.remove('active');
          box.textContent = currentBash;
        };
        btnCopy.onclick = () => {
          navigator.clipboard.writeText(box.textContent);
          showToast('ACL-Skript in die Zwischenablage kopiert', 'success');
        };
      } catch (err) {
        box.textContent = `# Fehler: ${err.message}`;
      }
    },
    openEffectivePerms: async (sam) => {
      const modal = document.getElementById('effectivePermsModal');
      const title = document.getElementById('effectivePermsTitle');
      const tableBody = document.getElementById('effectivePermsTableBody');
      title.textContent = `Effektive Berechtigungen für "${sam}"`;
      tableBody.innerHTML = '<tr><td colspan="4" class="text-center py-4">Berechne effektive Vererbung (A -> G -> DL -> P)...</td></tr>';
      modal.classList.add('open');

      try {
        const data = await api(`/api/directory/users/${encodeURIComponent(sam)}/effective-permissions`);
        const perms = data.effective_permissions || [];
        if (perms.length === 0) {
          tableBody.innerHTML = '<tr><td colspan="4" class="text-muted text-center py-4">Keine Dateiberechtigungen für diesen Benutzer gefunden.</td></tr>';
          return;
        }

        tableBody.innerHTML = perms.map(p => {
          const badgeClass = p.permission === 'RO' ? 'perm-ro' : (p.permission === 'RW' ? 'perm-rw' : 'perm-fc');
          return `
            <tr>
              <td>
                <div style="font-weight:600; color:#fff;">\\\\${escapeHtml(p.share_name)}\\${escapeHtml(p.folder_name)}</div>
              </td>
              <td>
                <span class="agdlp-perm-badge ${badgeClass}">${escapeHtml(p.permission)}</span>
                <small class="text-dim ml-1">${escapeHtml(p.permission_label)}</small>
              </td>
              <td>
                <span class="agdlp-member-chip is-global-group">${escapeHtml(p.inherited_via)}</span>
              </td>
              <td>
                <code>${escapeHtml(p.resource_group)}</code>
              </td>
            </tr>
          `;
        }).join('');
      } catch (err) {
        tableBody.innerHTML = `<tr><td colspan="4" class="text-danger text-center py-4">Fehler: ${escapeHtml(err.message)}</td></tr>`;
      }
    }
  };

  // Close handlers for Script & Effective Perms Modals
  const closeACLScriptBtn = document.getElementById('closeACLScriptBtn');
  const closeACLScriptBottomBtn = document.getElementById('closeACLScriptBottomBtn');
  if (closeACLScriptBtn) closeACLScriptBtn.onclick = () => document.getElementById('aclScriptModal').classList.remove('open');
  if (closeACLScriptBottomBtn) closeACLScriptBottomBtn.onclick = () => document.getElementById('aclScriptModal').classList.remove('open');

  const closeEffectivePermsBtn = document.getElementById('closeEffectivePermsBtn');
  const closeEffectivePermsBottomBtn = document.getElementById('closeEffectivePermsBottomBtn');
  if (closeEffectivePermsBtn) closeEffectivePermsBtn.onclick = () => document.getElementById('effectivePermsModal').classList.remove('open');
  if (closeEffectivePermsBottomBtn) closeEffectivePermsBottomBtn.onclick = () => document.getElementById('effectivePermsModal').classList.remove('open');

  // --- User Comparison (Diff) Modal ---
  const btnOpenUserCompareModal = document.getElementById('btnOpenUserCompareModal');
  const userCompareModal = document.getElementById('userCompareModal');
  const closeUserCompareBtn = document.getElementById('closeUserCompareBtn');
  const closeUserCompareBottomBtn = document.getElementById('closeUserCompareBottomBtn');
  const compareSelectA = document.getElementById('compareSelectA');
  const compareSelectB = document.getElementById('compareSelectB');
  const compareResultContainer = document.getElementById('compareResultContainer');

  if (closeUserCompareBtn) closeUserCompareBtn.onclick = () => userCompareModal.classList.remove('open');
  if (closeUserCompareBottomBtn) closeUserCompareBottomBtn.onclick = () => userCompareModal.classList.remove('open');

  if (btnOpenUserCompareModal) {
    btnOpenUserCompareModal.onclick = async () => {
      await loadADUsers();
      if (adUsersCache.length < 2) {
        showToast('Es werden mindestens 2 AD-Benutzer für einen Vergleich benötigt', 'info');
        return;
      }
      compareSelectA.innerHTML = adUsersCache.map(u => `<option value="${escapeHtml(u.sam_account_name)}">${escapeHtml(u.display_name)} (${escapeHtml(u.sam_account_name)})</option>`).join('');
      compareSelectB.innerHTML = adUsersCache.map(u => `<option value="${escapeHtml(u.sam_account_name)}">${escapeHtml(u.display_name)} (${escapeHtml(u.sam_account_name)})</option>`).join('');
      if (adUsersCache.length > 1) {
        compareSelectB.selectedIndex = 1;
      }
      runUserComparison();
      userCompareModal.classList.add('open');
    };
  }

  if (compareSelectA && compareSelectB) {
    compareSelectA.onchange = runUserComparison;
    compareSelectB.onchange = runUserComparison;
  }

  async function runUserComparison() {
    const userA = compareSelectA.value;
    const userB = compareSelectB.value;
    if (!userA || !userB) return;

    compareResultContainer.innerHTML = '<div class="text-center py-4 text-muted">Berechne Berechtigungs-Vergleich...</div>';
    try {
      const data = await api(`/api/directory/users/compare?userA=${encodeURIComponent(userA)}&userB=${encodeURIComponent(userB)}`);
      
      const sharedGroupsHtml = (data.shared_groups || []).map(g => `<span class="agdlp-member-chip is-global-group">${escapeHtml(g)}</span>`).join(' ') || '<span class="text-dim text-xs">Keine gemeinsamen Gruppen</span>';
      const onlyAHtml = (data.only_user_a_groups || []).map(g => `<span class="agdlp-member-chip">${escapeHtml(g)}</span>`).join(' ') || '<span class="text-dim text-xs">Keine</span>';
      const onlyBHtml = (data.only_user_b_groups || []).map(g => `<span class="agdlp-member-chip">${escapeHtml(g)}</span>`).join(' ') || '<span class="text-dim text-xs">Keine</span>';

      compareResultContainer.innerHTML = `
        <div class="compare-grid">
          <div class="compare-box">
            <div class="compare-box-title">Exklusiv für ${escapeHtml(userA)}</div>
            <div><strong>Rollen:</strong> <div class="agdlp-members-wrap mt-1">${onlyAHtml}</div></div>
            <div class="mt-2"><strong>Dateiberechtigungen:</strong>
              ${(data.only_user_a_perms || []).map(p => `
                <div class="text-xs text-muted mt-1">&bull; \\\\${escapeHtml(p.share_name)}\\${escapeHtml(p.folder_name)} [${escapeHtml(p.permission)}]</div>
              `).join('') || '<div class="text-dim text-xs mt-1">Keine exklusiven Dateirechte</div>'}
            </div>
          </div>
          <div class="compare-box">
            <div class="compare-box-title">Exklusiv für ${escapeHtml(userB)}</div>
            <div><strong>Rollen:</strong> <div class="agdlp-members-wrap mt-1">${onlyBHtml}</div></div>
            <div class="mt-2"><strong>Dateiberechtigungen:</strong>
              ${(data.only_user_b_perms || []).map(p => `
                <div class="text-xs text-muted mt-1">&bull; \\\\${escapeHtml(p.share_name)}\\${escapeHtml(p.folder_name)} [${escapeHtml(p.permission)}]</div>
              `).join('') || '<div class="text-dim text-xs mt-1">Keine exklusiven Dateirechte</div>'}
            </div>
          </div>
        </div>
        <div class="compare-box mt-3">
          <div class="compare-box-title">Gemeinsame Berechtigungen & Gruppen</div>
          <div class="agdlp-members-wrap">${sharedGroupsHtml}</div>
        </div>
      `;
    } catch (e) {
      compareResultContainer.innerHTML = `<div class="text-danger py-2">Fehler beim Vergleich: ${escapeHtml(e.message)}</div>`;
    }
  }

  // --- Command Palette (Ctrl + K) ---
  const btnOpenCmdPalette = document.getElementById('btnOpenCmdPalette');
  const cmdPaletteModal = document.getElementById('cmdPaletteModal');
  const cmdPaletteInput = document.getElementById('cmdPaletteInput');
  const cmdPaletteResults = document.getElementById('cmdPaletteResults');

  function openCmdPalette() {
    cmdPaletteInput.value = '';
    renderCmdPaletteResults('');
    cmdPaletteModal.classList.add('open');
    setTimeout(() => cmdPaletteInput.focus(), 50);
  }

  if (btnOpenCmdPalette) btnOpenCmdPalette.onclick = openCmdPalette;

  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      openCmdPalette();
    }
    if (e.key === 'Escape' && cmdPaletteModal.classList.contains('open')) {
      cmdPaletteModal.classList.remove('open');
    }
  });

  cmdPaletteInput.addEventListener('input', () => {
    renderCmdPaletteResults(cmdPaletteInput.value.trim());
  });

  function renderCmdPaletteResults(query) {
    const q = query.toLowerCase();
    const items = [
      { type: 'Navigation', title: 'Dashboard', desc: 'Sicherheits- & IAM Übersicht', action: () => switchTab('dashboard') },
      { type: 'Navigation', title: 'AD & Samba (AGDLP)', desc: 'Identitäten & Dateiberechtigungen', action: () => switchTab('directory') },
      { type: 'Navigation', title: 'Audit-Log & Compliance', desc: 'SHA-256 Kette & Export', action: () => switchTab('audit') },
      { type: 'Navigation', title: 'Benutzer & Identitäten', desc: 'Lokale IAM Accounts', action: () => switchTab('users') },
      { type: 'Navigation', title: 'Rollen & RBAC', desc: 'Rechtematrix verwalten', action: () => switchTab('roles') },
      { type: 'Aktion', title: 'Neue AGDLP-Freigabe', desc: 'DL_FS Gruppen generieren', action: () => { switchTab('directory'); document.getElementById('btnOpenCreateAGDLPModal').click(); } },
      { type: 'Aktion', title: 'Neuer AD-Benutzer', desc: 'Domänenkonto erstellen', action: () => { switchTab('directory'); document.getElementById('btnOpenCreateADUserModal').click(); } },
      { type: 'Aktion', title: 'Hash-Kette prüfen', desc: 'Audit Zero-Trust Verifikation', action: () => verifyAuditChain() },
      { type: 'Aktion', title: 'Benutzer vergleichen', desc: 'Berechtigungs-Diff zwischen Konten', action: () => { switchTab('directory'); document.getElementById('btnOpenUserCompareModal').click(); } }
    ];

    // Add cached AD users
    adUsersCache.forEach(u => {
      items.push({
        type: 'AD-Benutzer',
        title: u.display_name,
        desc: `${u.sam_account_name} (${u.department || 'Keine Abt.'})`,
        action: () => { switchTab('directory'); window.argusDir.openEffectivePerms(u.sam_account_name); }
      });
    });

    const filtered = items.filter(it => !q || it.title.toLowerCase().includes(q) || it.desc.toLowerCase().includes(q));

    if (filtered.length === 0) {
      cmdPaletteResults.innerHTML = '<div class="text-center py-4 text-muted text-xs">Keine Treffer gefunden</div>';
      return;
    }

    cmdPaletteResults.innerHTML = filtered.slice(0, 8).map(it => `
      <div class="palette-item" onclick="window.argusExecuteCmd(${items.indexOf(it)})">
        <div class="palette-item-left">
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          <div>
            <div class="palette-item-title">${escapeHtml(it.title)}</div>
            <div class="palette-item-desc">${escapeHtml(it.desc)}</div>
          </div>
        </div>
        <span class="palette-item-badge">${escapeHtml(it.type)}</span>
      </div>
    `).join('');

    window._cmdItems = items;
  }

  window.argusExecuteCmd = (index) => {
    cmdPaletteModal.classList.remove('open');
    if (window._cmdItems && window._cmdItems[index]) {
      window._cmdItems[index].action();
    }
  };

  // ================= ENTERPRISE ROADMAP ENHANCEMENTS =================

  // --- 1. Theme Switcher ---
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  let currentTheme = localStorage.getItem('argus_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', currentTheme);

  function updateThemeIcon() {
    const icon = document.getElementById('themeIcon');
    if (!icon) return;
    if (currentTheme === 'light') {
      icon.innerHTML = `<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>`;
      if (themeToggleBtn) themeToggleBtn.setAttribute('title', 'Auf Cyber Dark umschalten');
    } else {
      icon.innerHTML = `<circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>`;
      if (themeToggleBtn) themeToggleBtn.setAttribute('title', 'Auf Enterprise Light umschalten');
    }
  }
  updateThemeIcon();

  if (themeToggleBtn) {
    themeToggleBtn.onclick = () => {
      currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', currentTheme);
      localStorage.setItem('argus_theme', currentTheme);
      updateThemeIcon();
      showToast(`Theme gewechselt: ${currentTheme === 'dark' ? 'Cyber Dark' : 'Enterprise Light'}`, 'info');
    };
  }

  // --- 2. Realtime Audit SSE Stream ---
  const liveStreamStatus = document.getElementById('liveStreamStatus');
  let eventSource = null;

  function initSSE() {
    if (eventSource) eventSource.close();
    eventSource = new EventSource('/api/audit/stream');

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'connected') {
          if (liveStreamStatus) liveStreamStatus.style.opacity = '1';
          return;
        }

        if (data.action) {
          if (state.activeTab === 'dashboard') {
            loadStats();
          } else if (state.activeTab === 'audit') {
            loadAuditLogs();
          }

          if (data.action.includes('grant') || data.action.includes('approved') || data.action.includes('create') || data.action.includes('delete')) {
            showToast(`Echtzeit-Audit: ${data.action}`, 'info');
          }
        }
      } catch (_) {}
    };

    eventSource.onerror = () => {
      if (liveStreamStatus) liveStreamStatus.style.opacity = '0.4';
    };
  }

  // --- 3. Password Generator & Entropy Meter ---
  function generateStrongPassword(len = 16) {
    const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*()_+';
    let pwd = '';
    const array = new Uint32Array(len);
    window.crypto.getRandomValues(array);
    for (let i = 0; i < len; i++) {
      pwd += chars[array[i] % chars.length];
    }
    return pwd;
  }

  function updatePasswordMeter(pwd, fillEl, ratingEl) {
    if (!fillEl || !ratingEl) return;
    if (!pwd) {
      fillEl.style.width = '0%';
      ratingEl.innerText = 'Mindestens 12 Zeichen (BSI TR-02102-1)';
      return;
    }
    const len = pwd.length;
    let score = 0;
    if (len >= 8) score += 25;
    if (len >= 12) score += 25;
    if (len >= 16) score += 20;
    if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score += 15;
    if (/[0-9]/.test(pwd)) score += 7;
    if (/[^A-Za-z0-9]/.test(pwd)) score += 8;

    score = Math.min(score, 100);
    fillEl.style.width = `${score}%`;

    if (score < 50) {
      fillEl.style.backgroundColor = 'var(--accent-rose)';
      ratingEl.innerText = `Schwach (${score}% Entropie) - Unsicher`;
    } else if (score < 80) {
      fillEl.style.backgroundColor = 'var(--accent-amber)';
      ratingEl.innerText = `Mittel (${score}% Entropie) - BSI Mindestanforderung`;
    } else {
      fillEl.style.backgroundColor = 'var(--accent-emerald)';
      ratingEl.innerText = `Stark (${score}% Entropie) - NIST SP 800-63B Konform`;
    }
  }

  const btnGenCreateUserPwd = document.getElementById('btnGenCreateUserPwd');
  const btnCopyCreateUserPwd = document.getElementById('btnCopyCreateUserPwd');
  const adFormPassword = document.getElementById('adFormPassword');
  const pwdMeterFillCreateUser = document.getElementById('pwdMeterFillCreateUser');
  const pwdRatingCreateUser = document.getElementById('pwdRatingCreateUser');

  if (btnGenCreateUserPwd) {
    btnGenCreateUserPwd.onclick = () => {
      const pwd = generateStrongPassword(16);
      adFormPassword.value = pwd;
      updatePasswordMeter(pwd, pwdMeterFillCreateUser, pwdRatingCreateUser);
    };
  }
  if (adFormPassword) {
    adFormPassword.oninput = () => updatePasswordMeter(adFormPassword.value, pwdMeterFillCreateUser, pwdRatingCreateUser);
  }
  if (btnCopyCreateUserPwd) {
    btnCopyCreateUserPwd.onclick = () => {
      if (!adFormPassword.value) return;
      navigator.clipboard.writeText(adFormPassword.value);
      showToast('Kennwort in Zwischenablage kopiert', 'info');
    };
  }

  const btnGenResetPwd = document.getElementById('btnGenResetPwd');
  const btnCopyResetPwd = document.getElementById('btnCopyResetPwd');
  const pwdMeterFillReset = document.getElementById('pwdMeterFillReset');
  const pwdRatingReset = document.getElementById('pwdRatingReset');

  if (btnGenResetPwd) {
    btnGenResetPwd.onclick = () => {
      const pwd = generateStrongPassword(16);
      if (adNewPassword) adNewPassword.value = pwd;
      updatePasswordMeter(pwd, pwdMeterFillReset, pwdRatingReset);
    };
  }
  if (adNewPassword) {
    adNewPassword.oninput = () => updatePasswordMeter(adNewPassword.value, pwdMeterFillReset, pwdRatingReset);
  }
  if (btnCopyResetPwd) {
    btnCopyResetPwd.onclick = () => {
      if (!adNewPassword || !adNewPassword.value) return;
      navigator.clipboard.writeText(adNewPassword.value);
      showToast('Kennwort in Zwischenablage kopiert', 'info');
    };
  }

  // --- 4. CSV Bulk Import ---
  const modalBulkImport = document.getElementById('modalBulkImport');
  const btnOpenBulkImportModal = document.getElementById('btnOpenBulkImportModal');
  const closeBulkImportBtn = document.getElementById('closeBulkImportBtn');
  const closeBulkImportBottomBtn = document.getElementById('closeBulkImportBottomBtn');
  const btnDownloadSampleCSV = document.getElementById('btnDownloadSampleCSV');
  const btnBrowseCSV = document.getElementById('btnBrowseCSV');
  const bulkFileInput = document.getElementById('bulkFileInput');
  const bulkDropzone = document.getElementById('bulkDropzone');
  const bulkCSVTextarea = document.getElementById('bulkCSVTextarea');
  const btnExecuteBulkImport = document.getElementById('btnExecuteBulkImport');
  const bulkResultContainer = document.getElementById('bulkResultContainer');
  const bulkResultTitle = document.getElementById('bulkResultTitle');
  const bulkResultTableBody = document.getElementById('bulkResultTableBody');

  if (btnOpenBulkImportModal) {
    btnOpenBulkImportModal.onclick = () => {
      modalBulkImport.classList.add('open');
      bulkResultContainer.style.display = 'none';
    };
  }
  if (closeBulkImportBtn) closeBulkImportBtn.onclick = () => modalBulkImport.classList.remove('open');
  if (closeBulkImportBottomBtn) closeBulkImportBottomBtn.onclick = () => modalBulkImport.classList.remove('open');

  if (btnDownloadSampleCSV) {
    btnDownloadSampleCSV.onclick = () => {
      window.location.href = '/api/directory/users/bulk-template';
    };
  }

  if (btnBrowseCSV && bulkFileInput) {
    btnBrowseCSV.onclick = () => bulkFileInput.click();
    bulkFileInput.onchange = (e) => {
      const file = e.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (evt) => {
          bulkCSVTextarea.value = evt.target.result;
        };
        reader.readAsText(file);
      }
    };
  }

  if (bulkDropzone) {
    bulkDropzone.ondragover = (e) => { e.preventDefault(); bulkDropzone.classList.add('dragover'); };
    bulkDropzone.ondragleave = () => bulkDropzone.classList.remove('dragover');
    bulkDropzone.ondrop = (e) => {
      e.preventDefault();
      bulkDropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length) {
        const file = e.dataTransfer.files[0];
        const reader = new FileReader();
        reader.onload = (evt) => {
          bulkCSVTextarea.value = evt.target.result;
        };
        reader.readAsText(file);
      }
    };
  }

  if (btnExecuteBulkImport) {
    btnExecuteBulkImport.onclick = async () => {
      const csvText = bulkCSVTextarea.value.trim();
      if (!csvText) {
        showToast('Bitte gib CSV-Daten ein oder wähle eine Datei', 'error');
        return;
      }

      btnExecuteBulkImport.disabled = true;
      btnExecuteBulkImport.innerText = 'Importiere...';

      try {
        const res = await api('/api/directory/users/bulk-import', {
          method: 'POST',
          body: JSON.stringify({ csv_content: csvText })
        });

        bulkResultContainer.style.display = 'block';
        bulkResultTitle.innerHTML = `Ergebnis: <span style="color:var(--accent-emerald); font-weight:bold;">${res.success_count} erfolgreich</span> / <span style="color:var(--accent-rose);">${res.failure_count} fehlgeschlagen</span>`;

        bulkResultTableBody.innerHTML = (res.results || []).map(r => `
          <tr>
            <td>${r.row_number}</td>
            <td><code>${escapeHtml(r.sam_account_name)}</code></td>
            <td>${escapeHtml(r.given_name)} ${escapeHtml(r.surname)}</td>
            <td>${escapeHtml(r.department || '-')}</td>
            <td>${(r.global_groups || []).map(g => `<span class="badge badge-accent">${escapeHtml(g)}</span>`).join(' ') || '-'}</td>
            <td>${r.success ? '<span style="color:var(--accent-emerald); font-weight:600;">Erfolgreich</span>' : `<span style="color:var(--accent-rose);">${escapeHtml(r.error_message)}</span>`}</td>
          </tr>
        `).join('');

        showToast(`Bulk-Import: ${res.success_count} AD-Benutzer angelegt`, 'success');
        loadADUsers();
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        btnExecuteBulkImport.disabled = false;
        btnExecuteBulkImport.innerText = 'Massenimport ausführen';
      }
    };
  }

  // --- 5. JIT Temporary Memberships ---
  const modalJIT = document.getElementById('modalJIT');
  const btnOpenJITModal = document.getElementById('btnOpenJITModal');
  const closeJITBtn = document.getElementById('closeJITBtn');
  const closeJITBottomBtn = document.getElementById('closeJITBottomBtn');
  const jitUserSelect = document.getElementById('jitUserSelect');
  const jitGroupSelect = document.getElementById('jitGroupSelect');
  const jitForm = document.getElementById('jitForm');
  const jitTableBody = document.getElementById('jitTableBody');

  async function loadJITMemberships() {
    try {
      const items = await api('/api/directory/jit');
      if (!items || items.length === 0) {
        jitTableBody.innerHTML = '<tr><td colspan="7" class="text-center py-4 text-muted">Keine aktiven JIT-Berechtigungen vorhanden</td></tr>';
        return;
      }

      jitTableBody.innerHTML = items.map(it => {
        const expDate = new Date(it.expires_at);
        const now = new Date();
        const diffMs = expDate - now;
        let countdown = 'Abgelaufen';
        let isExpired = true;

        if (it.status === 'active' && diffMs > 0) {
          isExpired = false;
          const hours = Math.floor(diffMs / 3600000);
          const mins = Math.floor((diffMs % 3600000) / 60000);
          countdown = `${hours}h ${mins}m verbleibend`;
        }

        return `
          <tr>
            <td><strong>${escapeHtml(it.user_sam)}</strong></td>
            <td><code>${escapeHtml(it.group_name)}</code></td>
            <td>${escapeHtml(it.requested_by)}</td>
            <td class="text-xs">${escapeHtml(it.reason || '-')}</td>
            <td class="text-xs">${formatDate(it.expires_at)} <span class="badge ${isExpired ? 'badge-warn' : 'badge-emerald'} ml-1">${countdown}</span></td>
            <td><span class="badge ${it.status === 'active' ? 'badge-emerald' : 'badge-role-create'}">${escapeHtml(it.status)}</span></td>
            <td class="text-right">
              ${it.status === 'active' ? `
                <button class="btn btn-secondary btn-xs text-rose" onclick="window.argusRevokeJIT('${it.id}')">
                  Widerrufen
                </button>
              ` : '-'}
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      jitTableBody.innerHTML = `<tr><td colspan="7" class="text-danger py-2">Fehler: ${escapeHtml(e.message)}</td></tr>`;
    }
  }

  window.argusRevokeJIT = async (id) => {
    if (!confirm('Möchtest du diesen befristeten Zugriff sofort vorzeitig widerrufen?')) return;
    try {
      await api(`/api/directory/jit/${id}`, { method: 'DELETE' });
      showToast('Befristete Berechtigung entzogen', 'success');
      loadJITMemberships();
      loadADGroups();
      loadAGDLPMatrix();
    } catch (e) {
      showToast(e.message, 'error');
    }
  };

  if (btnOpenJITModal) {
    btnOpenJITModal.onclick = () => {
      modalJIT.classList.add('open');
      jitUserSelect.innerHTML = adUsersCache.map(u => `<option value="${escapeHtml(u.sam_account_name)}">${escapeHtml(u.display_name)} (${u.sam_account_name})</option>`).join('');
      jitGroupSelect.innerHTML = adGroupsCache.map(g => `<option value="${escapeHtml(g.sam_account_name)}">${escapeHtml(g.sam_account_name)} [${g.group_scope}]</option>`).join('');
      loadJITMemberships();
    };
  }
  if (closeJITBtn) closeJITBtn.onclick = () => modalJIT.classList.remove('open');
  if (closeJITBottomBtn) closeJITBottomBtn.onclick = () => modalJIT.classList.remove('open');

  if (jitForm) {
    jitForm.onsubmit = async (e) => {
      e.preventDefault();
      const userSAM = jitUserSelect.value;
      const groupName = jitGroupSelect.value;
      const durationHours = parseInt(document.getElementById('jitDurationSelect').value, 10);
      const reason = document.getElementById('jitReasonInput').value.trim();

      try {
        await api('/api/directory/jit', {
          method: 'POST',
          body: JSON.stringify({
            user_sam: userSAM,
            group_name: groupName,
            duration_hours: durationHours,
            reason: reason
          })
        });

        showToast(`JIT-Zugriff für ${userSAM} aktiviert (${durationHours}h)`, 'success');
        document.getElementById('jitReasonInput').value = '';
        loadJITMemberships();
        loadADGroups();
        loadAGDLPMatrix();
      } catch (err) {
        showToast(err.message, 'error');
      }
    };
  }

  // --- 6. Dual-Control Approvals (Vier-Augen-Prinzip) ---
  const modalApprovals = document.getElementById('modalApprovals');
  const btnOpenApprovalsModal = document.getElementById('btnOpenApprovalsModal');
  const closeApprovalsBtn = document.getElementById('closeApprovalsBtn');
  const closeApprovalsBottomBtn = document.getElementById('closeApprovalsBottomBtn');
  const approvalsCountBadge = document.getElementById('approvalsCountBadge');
  const approvalsTableBody = document.getElementById('approvalsTableBody');
  const btnFilterApprovalsPending = document.getElementById('btnFilterApprovalsPending');
  const btnFilterApprovalsAll = document.getElementById('btnFilterApprovalsAll');
  let approvalsFilterStatus = 'pending';

  async function checkPendingApprovalsCount() {
    try {
      const list = await api('/api/approvals?status=pending');
      const count = list ? list.length : 0;
      if (approvalsCountBadge) {
        if (count > 0) {
          approvalsCountBadge.innerText = count;
          approvalsCountBadge.style.display = 'inline-block';
        } else {
          approvalsCountBadge.style.display = 'none';
        }
      }
    } catch (_) {}
  }

  async function loadApprovals() {
    try {
      const list = await api(`/api/approvals?status=${approvalsFilterStatus}`);
      if (!list || list.length === 0) {
        approvalsTableBody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted">Keine Anträge (${approvalsFilterStatus}) vorhanden</td></tr>`;
        return;
      }

      approvalsTableBody.innerHTML = list.map(it => `
        <tr>
          <td>
            <strong>${escapeHtml(it.action_type)}</strong><br>
            <code class="text-xs">${escapeHtml(it.target_resource)}</code>
          </td>
          <td>${escapeHtml(it.requested_by)}</td>
          <td class="text-xs">${escapeHtml(it.reason || '-')}</td>
          <td class="text-xs">${formatDate(it.created_at)}</td>
          <td>
            <span class="badge ${it.status === 'pending' ? 'badge-amber' : it.status === 'approved' ? 'badge-emerald' : 'badge-rose'}">
              ${escapeHtml(it.status.toUpperCase())}
            </span>
          </td>
          <td class="text-right">
            ${it.status === 'pending' ? `
              <button class="btn btn-primary btn-xs mr-1" onclick="window.argusResolveApproval('${it.id}', 'approved')">Freigeben</button>
              <button class="btn btn-secondary btn-xs text-rose" onclick="window.argusResolveApproval('${it.id}', 'rejected')">Ablehnen</button>
            ` : `
              <span class="text-dim text-xs">${escapeHtml(it.approved_by || '-')}: ${escapeHtml(it.resolution_notes || '-')}</span>
            `}
          </td>
        </tr>
      `).join('');
    } catch (e) {
      approvalsTableBody.innerHTML = `<tr><td colspan="6" class="text-danger py-2">Fehler: ${escapeHtml(e.message)}</td></tr>`;
    }
  }

  window.argusResolveApproval = async (id, decision) => {
    const notes = prompt(`Grund / Freigabe-Notiz für '${decision}':`, decision === 'approved' ? 'Vier-Augen-Freigabe erteilt' : 'Abgelehnt');
    if (notes === null) return;

    try {
      await api(`/api/approvals/${id}/resolve`, {
        method: 'POST',
        body: JSON.stringify({ decision, notes })
      });
      showToast(`Antrag als '${decision}' abgeschlossen`, 'success');
      loadApprovals();
      checkPendingApprovalsCount();
      loadADGroups();
      loadAGDLPMatrix();
    } catch (e) {
      showToast(e.message, 'error');
    }
  };

  if (btnOpenApprovalsModal) {
    btnOpenApprovalsModal.onclick = () => {
      modalApprovals.classList.add('open');
      loadApprovals();
    };
  }
  if (closeApprovalsBtn) closeApprovalsBtn.onclick = () => modalApprovals.classList.remove('open');
  if (closeApprovalsBottomBtn) closeApprovalsBottomBtn.onclick = () => modalApprovals.classList.remove('open');

  if (btnFilterApprovalsPending) {
    btnFilterApprovalsPending.onclick = () => {
      approvalsFilterStatus = 'pending';
      btnFilterApprovalsPending.classList.add('active');
      btnFilterApprovalsAll.classList.remove('active');
      loadApprovals();
    };
  }
  if (btnFilterApprovalsAll) {
    btnFilterApprovalsAll.onclick = () => {
      approvalsFilterStatus = 'all';
      btnFilterApprovalsAll.classList.add('active');
      btnFilterApprovalsPending.classList.remove('active');
      loadApprovals();
    };
  }

  // --- 7. Templates Wizard ---
  const modalTemplates = document.getElementById('modalTemplates');
  const btnOpenTemplatesModal = document.getElementById('btnOpenTemplatesModal');
  const closeTemplatesBtn = document.getElementById('closeTemplatesBtn');
  const closeTemplatesBottomBtn = document.getElementById('closeTemplatesBottomBtn');
  const templateCardsContainer = document.getElementById('templateCardsContainer');
  const templateShareNameInput = document.getElementById('templateShareNameInput');
  const templateDeptInput = document.getElementById('templateDeptInput');
  const btnApplySelectedTemplate = document.getElementById('btnApplySelectedTemplate');
  let selectedTemplateId = '';

  async function loadShareTemplates() {
    try {
      const templates = await api('/api/directory/agdlp/templates');
      if (!templates) return;

      templateCardsContainer.innerHTML = templates.map(t => `
        <div class="template-card ${selectedTemplateId === t.id ? 'selected' : ''}" onclick="window.argusSelectTemplate('${t.id}')">
          <div class="template-card-title">${escapeHtml(t.name)}</div>
          <div class="template-card-desc">${escapeHtml(t.description)}</div>
          <div class="text-xs text-muted mb-2">Ordner: <strong>${(t.folders || []).map(f => f.name).join(', ')}</strong></div>
          <span class="template-card-badge">${escapeHtml(t.category)}</span>
        </div>
      `).join('');

      if (!selectedTemplateId && templates.length > 0) {
        window.argusSelectTemplate(templates[0].id);
      }
    } catch (e) {
      templateCardsContainer.innerHTML = `<div class="text-danger py-2">Fehler: ${escapeHtml(e.message)}</div>`;
    }
  }

  window.argusSelectTemplate = (id) => {
    selectedTemplateId = id;
    document.querySelectorAll('.template-card').forEach(c => c.classList.remove('selected'));
    loadShareTemplates();
  };

  if (btnOpenTemplatesModal) {
    btnOpenTemplatesModal.onclick = () => {
      modalTemplates.classList.add('open');
      loadShareTemplates();
    };
  }
  if (closeTemplatesBtn) closeTemplatesBtn.onclick = () => modalTemplates.classList.remove('open');
  if (closeTemplatesBottomBtn) closeTemplatesBottomBtn.onclick = () => modalTemplates.classList.remove('open');

  if (btnApplySelectedTemplate) {
    btnApplySelectedTemplate.onclick = async () => {
      const shareName = templateShareNameInput.value.trim();
      const dept = templateDeptInput.value.trim();

      if (!shareName) {
        showToast('Bitte gib einen Freigabenamen ein', 'error');
        return;
      }

      btnApplySelectedTemplate.disabled = true;
      btnApplySelectedTemplate.innerText = 'Rolle Vorlage aus...';

      try {
        const res = await api('/api/directory/agdlp/templates/apply', {
          method: 'POST',
          body: JSON.stringify({
            template_id: selectedTemplateId,
            share_name: shareName,
            department: dept
          })
        });

        modalTemplates.classList.remove('open');
        showToast(`Vorlage '${selectedTemplateId}' erfolgreich ausgerollt`, 'success');
        loadAGDLPMatrix();
        loadADGroups();

        if (res.scripts) {
          window.argusOpenACLScript(res.share_name, 'TemplateRoot');
        }
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        btnApplySelectedTemplate.disabled = false;
        btnApplySelectedTemplate.innerText = 'Vorlage anwenden & AGDLP erzeugen';
      }
    };
  }

  // --- 8. Compliance Report ---
  const modalCompliance = document.getElementById('modalCompliance');
  const btnOpenComplianceModal = document.getElementById('btnOpenComplianceModal');
  const closeComplianceBtn = document.getElementById('closeComplianceBtn');
  const closeComplianceBottomBtn = document.getElementById('closeComplianceBottomBtn');
  const complianceHeadHash = document.getElementById('complianceHeadHash');
  const complianceKpiGrid = document.getElementById('complianceKpiGrid');
  const complianceSharesTableBody = document.getElementById('complianceSharesTableBody');
  const complianceConflictsTableBody = document.getElementById('complianceConflictsTableBody');
  const btnDownloadComplianceCSV = document.getElementById('btnDownloadComplianceCSV');
  const btnPrintComplianceCert = document.getElementById('btnPrintComplianceCert');

  async function loadComplianceReport() {
    try {
      const rep = await api('/api/directory/agdlp/compliance-report');
      if (!rep) return;

      complianceHeadHash.innerText = rep.audit_chain_head;

      complianceKpiGrid.innerHTML = `
        <div class="stat-card glass-card">
          <div class="stat-value">${rep.total_users}</div>
          <div class="stat-label">Identitäten</div>
        </div>
        <div class="stat-card glass-card">
          <div class="stat-value">${rep.total_groups}</div>
          <div class="stat-label">Sicherheitsgruppen</div>
        </div>
        <div class="stat-card glass-card">
          <div class="stat-value">${rep.total_shares}</div>
          <div class="stat-label">Dateifreigaben</div>
        </div>
        <div class="stat-card glass-card">
          <div class="stat-value" style="color: ${rep.total_conflicts > 0 ? 'var(--accent-rose)' : 'var(--accent-emerald)'};">${rep.total_conflicts}</div>
          <div class="stat-label">Anomalien / Konflikte</div>
        </div>
      `;

      let sharesRows = '';
      (rep.shares || []).forEach(f => {
        Object.keys(f.groups || {}).forEach(perm => {
          const g = f.groups[perm];
          sharesRows += `
            <tr>
              <td><strong>${escapeHtml(f.share_name)}</strong></td>
              <td>${escapeHtml(f.folder_name)}</td>
              <td><span class="badge badge-accent">${escapeHtml(perm)}</span></td>
              <td><code>${escapeHtml(g.sam_account_name || g.group_name)}</code></td>
              <td>${(g.members || []).map(r => `<span class="badge badge-role-create">${escapeHtml(r)}</span>`).join(' ') || '-'}</td>
              <td>${(g.members || []).length} Mitglieder</td>
            </tr>
          `;
        });
      });
      complianceSharesTableBody.innerHTML = sharesRows || '<tr><td colspan="6" class="text-center py-4 text-muted">Keine Freigaben vorhanden</td></tr>';

      if (!rep.conflicts || rep.conflicts.length === 0) {
        complianceConflictsTableBody.innerHTML = '<tr><td colspan="4" class="text-emerald font-semibold py-3 text-center">Keine AGDLP-Konflikte festgestellt (100% Konformität)</td></tr>';
      } else {
        complianceConflictsTableBody.innerHTML = rep.conflicts.map(c => `
          <tr>
            <td><span class="badge ${c.severity === 'CRITICAL' ? 'badge-rose' : 'badge-amber'}">${escapeHtml(c.severity)}</span></td>
            <td><strong>${escapeHtml(c.target)}</strong></td>
            <td>${escapeHtml(c.description)}</td>
            <td>${escapeHtml(c.suggestion)}</td>
          </tr>
        `).join('');
      }
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  if (btnOpenComplianceModal) {
    btnOpenComplianceModal.onclick = () => {
      modalCompliance.classList.add('open');
      loadComplianceReport();
    };
  }
  if (closeComplianceBtn) closeComplianceBtn.onclick = () => modalCompliance.classList.remove('open');
  if (closeComplianceBottomBtn) closeComplianceBottomBtn.onclick = () => modalCompliance.classList.remove('open');

  if (btnDownloadComplianceCSV) {
    btnDownloadComplianceCSV.onclick = () => {
      window.location.href = '/api/directory/agdlp/compliance-report?format=csv';
    };
  }
  if (btnPrintComplianceCert) {
    btnPrintComplianceCert.onclick = () => {
      window.open('/api/directory/agdlp/compliance-report?format=html', '_blank');
    };
  }

  // --- 9. Interactive AGDLP Visual Graph ---
  const modalAGDLPGraph = document.getElementById('modalAGDLPGraph');
  const btnOpenAGDLPGraphModal = document.getElementById('btnOpenAGDLPGraphModal');
  const closeAGDLPGraphBtn = document.getElementById('closeAGDLPGraphBtn');
  const closeAGDLPGraphBottomBtn = document.getElementById('closeAGDLPGraphBottomBtn');
  const agdlpGraphContainer = document.getElementById('agdlpGraphContainer');

  function renderAGDLPGraph() {
    if (!agdlpGraphContainer) return;

    const users = adUsersCache.slice(0, 10);
    const globalGroups = adGroupsCache.filter(g => g.category === 'Role' || g.sam_account_name.startsWith('G_')).slice(0, 8);
    const dlGroups = [];
    const sharesMap = {};

    agdlpMatrixCache.forEach(f => {
      Object.keys(f.groups || {}).forEach(p => {
        const g = f.groups[p];
        if (g && !dlGroups.find(d => d.name === g.sam_account_name)) {
          dlGroups.push({ name: g.sam_account_name, perm: p, share: f.share_name, folder: f.folder_name, members: g.members || [] });
        }
        sharesMap[`${f.share_name}/${f.folder_name}`] = true;
      });
    });

    const shares = Object.keys(sharesMap).slice(0, 8);

    const svgWidth = 960;
    const svgHeight = Math.max(users.length, globalGroups.length, dlGroups.length, shares.length) * 48 + 80;

    let svg = `<svg width="${svgWidth}" height="${svgHeight}" style="min-width: 960px;" id="graphSVG" xmlns="http://www.w3.org/2000/svg">`;

    const colX = [60, 280, 530, 780];
    const nodeCoords = {};

    const getY = (index) => 40 + index * 46;

    // Layer 0: Users (A)
    users.forEach((u, i) => {
      const id = `user_${u.sam_account_name}`;
      nodeCoords[id] = { x: colX[0], y: getY(i), type: 'user', name: u.sam_account_name };
    });

    // Layer 1: Global Groups (G)
    globalGroups.forEach((g, i) => {
      const id = `g_${g.sam_account_name}`;
      nodeCoords[id] = { x: colX[1], y: getY(i), type: 'global', name: g.sam_account_name };
    });

    // Layer 2: DL Groups (DL)
    dlGroups.forEach((dl, i) => {
      const id = `dl_${dl.name}`;
      nodeCoords[id] = { x: colX[2], y: getY(i), type: 'dl', name: dl.name, members: dl.members, share: `${dl.share}/${dl.folder}` };
    });

    // Layer 3: Shares (P)
    shares.forEach((sh, i) => {
      const id = `share_${sh.replace('/', '_')}`;
      nodeCoords[id] = { x: colX[3], y: getY(i), type: 'share', name: sh };
    });

    // Links Layer
    let linksSvg = '<g class="graph-links-layer">';

    // A -> G
    users.forEach(u => {
      const uId = `user_${u.sam_account_name}`;
      (u.member_of || []).forEach(grpName => {
        const gId = `g_${grpName}`;
        if (nodeCoords[uId] && nodeCoords[gId]) {
          const from = nodeCoords[uId];
          const to = nodeCoords[gId];
          const d = `M ${from.x + 120} ${from.y + 14} C ${from.x + 180} ${from.y + 14}, ${to.x - 40} ${to.y + 14}, ${to.x} ${to.y + 14}`;
          linksSvg += `<path d="${d}" class="graph-link link_${uId} link_${gId}" />`;
        }
      });
    });

    // G -> DL
    dlGroups.forEach(dl => {
      const dlId = `dl_${dl.name}`;
      (dl.members || []).forEach(rName => {
        const gId = `g_${rName}`;
        if (nodeCoords[gId] && nodeCoords[dlId]) {
          const from = nodeCoords[gId];
          const to = nodeCoords[dlId];
          const d = `M ${from.x + 140} ${from.y + 14} C ${from.x + 200} ${from.y + 14}, ${to.x - 40} ${to.y + 14}, ${to.x} ${to.y + 14}`;
          linksSvg += `<path d="${d}" class="graph-link link_${gId} link_${dlId}" />`;
        }
      });
    });

    // DL -> Share
    dlGroups.forEach(dl => {
      const dlId = `dl_${dl.name}`;
      const shId = `share_${dl.share.replace('/', '_')}`;
      if (nodeCoords[dlId] && nodeCoords[shId]) {
        const from = nodeCoords[dlId];
        const to = nodeCoords[shId];
        const d = `M ${from.x + 160} ${from.y + 14} C ${from.x + 210} ${from.y + 14}, ${to.x - 40} ${to.y + 14}, ${to.x} ${to.y + 14}`;
        linksSvg += `<path d="${d}" class="graph-link link_${dlId} link_${shId}" />`;
      }
    });

    linksSvg += '</g>';
    svg += linksSvg;

    // Nodes Layer
    svg += '<g class="graph-nodes-layer">';
    Object.keys(nodeCoords).forEach(id => {
      const n = nodeCoords[id];
      let color = '#38bdf8';
      let stroke = '#0284c7';
      let width = 130;
      let label = n.name;

      if (n.type === 'global') { color = '#818cf8'; stroke = '#4f46e5'; width = 150; }
      else if (n.type === 'dl') { color = '#34d399'; stroke = '#059669'; width = 170; }
      else if (n.type === 'share') { color = '#f59e0b'; stroke = '#d97706'; width = 140; }

      svg += `
        <g class="graph-node node_${id}" onclick="window.argusHighlightGraphNode('${id}')" id="node_${id}">
          <rect x="${n.x}" y="${n.y}" width="${width}" height="28" rx="6" fill="rgba(15, 23, 42, 0.85)" stroke="${stroke}" stroke-width="1.2" />
          <text x="${n.x + 10}" y="${n.y + 18}" fill="${color}" font-size="11" font-family="JetBrains Mono, monospace" font-weight="500">${escapeHtml(label.length > 20 ? label.substring(0, 18) + '...' : label)}</text>
        </g>
      `;
    });

    svg += '</g></svg>';
    agdlpGraphContainer.innerHTML = svg;
  }

  window.argusHighlightGraphNode = (id) => {
    const activeNode = document.getElementById(`node_${id}`);
    if (!activeNode) return;
    const isAlready = activeNode.classList.contains('active');
    document.querySelectorAll('.graph-node').forEach(n => n.classList.remove('active', 'dimmed'));
    document.querySelectorAll('.graph-link').forEach(l => l.classList.remove('active', 'dimmed'));

    if (isAlready) return;

    document.querySelectorAll('.graph-node').forEach(n => n.classList.add('dimmed'));
    document.querySelectorAll('.graph-link').forEach(l => l.classList.add('dimmed'));

    activeNode.classList.remove('dimmed');
    activeNode.classList.add('active');

    const links = document.querySelectorAll(`.link_${id}`);
    links.forEach(l => {
      l.classList.remove('dimmed');
      l.classList.add('active');
      const classes = l.className.baseVal.split(' ');
      classes.forEach(c => {
        if (c.startsWith('link_') && c !== `link_${id}`) {
          const neighborId = c.replace('link_', '');
          const neighborNode = document.getElementById(`node_${neighborId}`);
          if (neighborNode) {
            neighborNode.classList.remove('dimmed');
            neighborNode.classList.add('active');
          }
        }
      });
    });
  };

  if (btnOpenAGDLPGraphModal) {
    btnOpenAGDLPGraphModal.onclick = () => {
      modalAGDLPGraph.classList.add('open');
      renderAGDLPGraph();
    };
  }
  if (closeAGDLPGraphBtn) closeAGDLPGraphBtn.onclick = () => modalAGDLPGraph.classList.remove('open');
  if (closeAGDLPGraphBottomBtn) closeAGDLPGraphBottomBtn.onclick = () => modalAGDLPGraph.classList.remove('open');

  // ================= HR & USER LIFECYCLE CONTROLLER =================
  let lifecycleEmployees = [];
  let currentDetailEmp = null;

  const lcEl = {
    statLcPreBoarding: document.getElementById('statLcPreBoarding'),
    statLcActive: document.getElementById('statLcActive'),
    statLcTransferred: document.getElementById('statLcTransferred'),
    statLcOffboarded: document.getElementById('statLcOffboarded'),
    statLcOpenTasks: document.getElementById('statLcOpenTasks'),
    tableBody: document.getElementById('lifecycleTableBody'),
    countBadge: document.getElementById('lifecycleCountBadge'),
    searchInput: document.getElementById('searchLifecycleInput'),
    stageFilter: document.getElementById('filterLifecycleStage'),
    deptFilter: document.getElementById('filterLifecycleDept'),
    btnRefresh: document.getElementById('btnRefreshLifecycle'),

    // Onboard Modal
    btnOpenOnboard: document.getElementById('btnOpenOnboardModal'),
    modalOnboard: document.getElementById('modalOnboard'),
    closeOnboardBtn: document.getElementById('closeOnboardBtn'),
    cancelOnboardBtn: document.getElementById('cancelOnboardBtn'),
    formOnboard: document.getElementById('formOnboardEmployee'),
    onboardSuccessCard: document.getElementById('onboardSuccessCard'),
    btnCloseOnboardSuccess: document.getElementById('btnCloseOnboardSuccess'),
    btnCopyTempPwd: document.getElementById('btnCopyTempPwd'),

    // Offboard Modal
    btnOpenOffboard: document.getElementById('btnOpenOffboardModal'),
    modalOffboard: document.getElementById('modalOffboard'),
    closeOffboardBtn: document.getElementById('closeOffboardBtn'),
    cancelOffboardBtn: document.getElementById('cancelOffboardBtn'),
    formOffboard: document.getElementById('formOffboardEmployee'),
    offboardSelectEmployee: document.getElementById('offboardSelectEmployee'),

    // Details Modal
    modalDetails: document.getElementById('modalLifecycleDetails'),
    closeDetailsBtn: document.getElementById('closeLifecycleDetailsBtn'),
    closeDetailsBottomBtn: document.getElementById('closeLifecycleDetailsBottomBtn'),
    btnTransferFromDetails: document.getElementById('btnTransferFromDetails'),
    btnOffboardFromDetails: document.getElementById('btnOffboardFromDetails'),

    // Transfer Modal
    modalTransfer: document.getElementById('modalTransfer'),
    closeTransferBtn: document.getElementById('closeTransferBtn'),
    cancelTransferBtn: document.getElementById('cancelTransferBtn'),
    formTransfer: document.getElementById('formTransferEmployee'),
  };

  async function loadLifecycleData() {
    try {
      const stage = lcEl.stageFilter ? lcEl.stageFilter.value : 'all';
      const search = lcEl.searchInput ? lcEl.searchInput.value.trim() : '';

      const [stats, empData] = await Promise.all([
        api('/api/lifecycle/stats').catch(() => null),
        api(`/api/lifecycle/employees?stage=${stage}&search=${encodeURIComponent(search)}`).catch(() => ({ employees: [] }))
      ]);

      if (stats) {
        if (lcEl.statLcPreBoarding) lcEl.statLcPreBoarding.textContent = stats.pre_boarding || 0;
        if (lcEl.statLcActive) lcEl.statLcActive.textContent = stats.active_onboard || 0;
        if (lcEl.statLcTransferred) lcEl.statLcTransferred.textContent = stats.transferred || 0;
        if (lcEl.statLcOffboarded) lcEl.statLcOffboarded.textContent = stats.offboarded || 0;
        if (lcEl.statLcOpenTasks) lcEl.statLcOpenTasks.textContent = stats.open_tasks || 0;
      }

      lifecycleEmployees = empData.employees || [];
      renderLifecycleTable(lifecycleEmployees);
      updateOffboardSelectOptions();
    } catch (err) {
      console.error('Error loading lifecycle data:', err);
    }
  }

  function renderLifecycleTable(employees) {
    if (!lcEl.tableBody) return;

    const dept = lcEl.deptFilter ? lcEl.deptFilter.value : 'all';
    let filtered = employees;
    if (dept !== 'all') {
      filtered = filtered.filter(e => e.department === dept);
    }

    if (lcEl.countBadge) {
      lcEl.countBadge.textContent = `${filtered.length} Mitarbeiter`;
    }

    if (filtered.length === 0) {
      lcEl.tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-dim py-4">Keine Mitarbeiter für diesen Filter gefunden.</td></tr>`;
      return;
    }

    lcEl.tableBody.innerHTML = filtered.map(emp => {
      let stageBadge = '';
      if (emp.stage === 'pre_boarding') stageBadge = '<span class="badge badge-stage-pre">Pre-Boarding</span>';
      else if (emp.stage === 'onboarded') stageBadge = '<span class="badge badge-stage-onboarded">Aktiv Onboarded</span>';
      else if (emp.stage === 'transferred') stageBadge = '<span class="badge badge-stage-transferred">Rollenwechsel</span>';
      else if (emp.stage === 'offboarded') stageBadge = '<span class="badge badge-stage-offboarded">Offboarded</span>';

      let totalTasks = 0;
      let doneTasks = 0;
      if (emp.checklist) {
        const keys = Object.keys(emp.checklist);
        totalTasks = keys.length;
        doneTasks = keys.filter(k => emp.checklist[k].completed).length;
      }
      const isComplete = totalTasks > 0 && doneTasks === totalTasks;

      const groups = (emp.assigned_groups || []).map(g => `<span class="badge badge-role-tag">${escapeHtml(g)}</span>`).join('');
      const roles = (emp.assigned_roles || []).map(r => `<span class="badge badge-role-tag" style="border-color: #38bdf8;">${escapeHtml(r)}</span>`).join('');

      const initials = (emp.given_name ? emp.given_name[0] : '') + (emp.surname ? emp.surname[0] : '');

      return `
        <tr data-emp-id="${escapeHtml(emp.id)}">
          <td>
            <div class="flex items-center gap-2">
              <div class="user-avatar" style="width: 32px; height: 32px; font-size: 0.75rem;">${escapeHtml(initials.toUpperCase())}</div>
              <div class="flex flex-col">
                <span class="font-semibold text-main">${escapeHtml(emp.full_name)}</span>
                <span class="text-xs text-dim">${escapeHtml(emp.email)}</span>
              </div>
            </div>
          </td>
          <td>
            <code class="crypto-hash" style="padding: 2px 6px;">${escapeHtml(emp.sam_account_name)}</code>
          </td>
          <td>
            <div class="flex flex-col">
              <span class="font-medium text-main">${escapeHtml(emp.department)}</span>
              <span class="text-xs text-dim">${escapeHtml(emp.job_title)}</span>
            </div>
          </td>
          <td>${stageBadge}</td>
          <td>
            <div class="flex flex-col text-xs">
              <span>Eintritt: ${escapeHtml(emp.start_date || '-')}</span>
              ${emp.end_date ? `<span class="text-rose">Austritt: ${escapeHtml(emp.end_date)}</span>` : ''}
            </div>
          </td>
          <td>
            <div class="flex items-center gap-2">
              <span class="text-xs font-mono font-semibold ${isComplete ? 'text-emerald' : 'text-warning'}">${doneTasks} / ${totalTasks}</span>
              <span class="text-xs text-dim">${isComplete ? '✓ Erledigt' : 'In Bearbeitung'}</span>
            </div>
          </td>
          <td>
            <div class="flex flex-wrap gap-1 max-w-xs">
              ${roles || '<span class="text-xs text-dim">-</span>'}
              ${groups}
            </div>
          </td>
          <td style="text-align: right;">
            <div class="flex items-center justify-end gap-1">
              <button class="btn btn-secondary btn-xs" onclick="window.argusLifecycle.openDetails('${escapeHtml(emp.id)}')" title="Checkliste &amp; Akte">
                Checkliste
              </button>
              ${emp.stage !== 'offboarded' ? `
                <button class="btn btn-ghost btn-xs" onclick="window.argusLifecycle.openTransfer('${escapeHtml(emp.sam_account_name)}', '${escapeHtml(emp.full_name)}', '${escapeHtml(emp.department)}', '${escapeHtml(emp.job_title)}')" title="Abteilung wechseln">
                  Transfer
                </button>
                <button class="btn btn-ghost btn-xs text-rose" onclick="window.argusLifecycle.quickOffboard('${escapeHtml(emp.sam_account_name)}')" title="Offboarding starten">
                  Offboard
                </button>
              ` : `
                <span class="text-xs text-dim mr-2">Versiegelt</span>
              `}
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  function updateOffboardSelectOptions() {
    if (!lcEl.offboardSelectEmployee) return;
    const activeEmployees = lifecycleEmployees.filter(e => e.stage !== 'offboarded');
    lcEl.offboardSelectEmployee.innerHTML = '<option value="">-- Mitarbeiter auswählen --</option>' +
      activeEmployees.map(e => `<option value="${escapeHtml(e.sam_account_name)}">${escapeHtml(e.full_name)} (${escapeHtml(e.sam_account_name)} - ${escapeHtml(e.department)})</option>`).join('');
  }

  // --- Modal: Onboard ---
  if (lcEl.btnOpenOnboard) {
    lcEl.btnOpenOnboard.onclick = () => {
      if (lcEl.formOnboard) {
        lcEl.formOnboard.reset();
        lcEl.formOnboard.style.display = 'block';
      }
      if (lcEl.onboardSuccessCard) lcEl.onboardSuccessCard.style.display = 'none';
      const startDateInput = document.getElementById('onboardStartDate');
      if (startDateInput) {
        startDateInput.value = new Date().toISOString().split('T')[0];
      }
      lcEl.modalOnboard.classList.add('open');
    };
  }
  if (lcEl.closeOnboardBtn) lcEl.closeOnboardBtn.onclick = () => lcEl.modalOnboard.classList.remove('open');
  if (lcEl.cancelOnboardBtn) lcEl.cancelOnboardBtn.onclick = () => lcEl.modalOnboard.classList.remove('open');
  if (lcEl.btnCloseOnboardSuccess) lcEl.btnCloseOnboardSuccess.onclick = () => lcEl.modalOnboard.classList.remove('open');

  if (lcEl.formOnboard) {
    lcEl.formOnboard.onsubmit = async (e) => {
      e.preventDefault();
      const payload = {
        given_name: document.getElementById('onboardGivenName').value.trim(),
        surname: document.getElementById('onboardSurname').value.trim(),
        department: document.getElementById('onboardDept').value,
        job_title: document.getElementById('onboardJobTitle').value.trim(),
        start_date: document.getElementById('onboardStartDate').value,
        manager: document.getElementById('onboardManager').value.trim(),
        profile_preset: document.getElementById('onboardPreset').value,
        auto_create_iam: document.getElementById('onboardAutoIAM').checked,
        auto_create_ad: document.getElementById('onboardAutoAD').checked,
        auto_assign_agdlp: document.getElementById('onboardAutoAGDLP').checked,
        notes: document.getElementById('onboardNotes').value.trim()
      };

      try {
        const emp = await api('/api/lifecycle/onboard', {
          method: 'POST',
          body: JSON.stringify(payload)
        });

        // Show Credential Package Card
        if (lcEl.onboardSuccessCard) {
          document.getElementById('succEmpName').textContent = emp.full_name;
          document.getElementById('succEmpSAM').textContent = emp.sam_account_name;
          document.getElementById('succEmpMail').textContent = emp.email;
          document.getElementById('succEmpPwd').textContent = emp.temp_password || '********';
          document.getElementById('succEmpPerms').textContent = (emp.assigned_groups || []).join(', ') || 'Standard-Berechtigungen';

          lcEl.formOnboard.style.display = 'none';
          lcEl.onboardSuccessCard.style.display = 'block';
        }

        showToast(`Mitarbeiter '${emp.full_name}' erfolgreich automatisiert onboarded!`, 'success');
        loadLifecycleData();
        loadStats();
      } catch (err) {
        showToast(`Fehler beim Onboarding: ${err.message}`, 'error');
      }
    };
  }

  if (lcEl.btnCopyTempPwd) {
    lcEl.btnCopyTempPwd.onclick = () => {
      const pwd = document.getElementById('succEmpPwd').textContent;
      if (pwd && pwd !== '********') {
        navigator.clipboard.writeText(pwd).then(() => {
          showToast('Initial-Kennwort in die Zwischenablage kopiert!', 'info');
        });
      }
    };
  }

  // --- Modal: Offboard ---
  if (lcEl.btnOpenOffboard) {
    lcEl.btnOpenOffboard.onclick = () => {
      updateOffboardSelectOptions();
      const effDate = document.getElementById('offboardEffectiveDate');
      if (effDate) effDate.value = new Date().toISOString().split('T')[0];
      lcEl.modalOffboard.classList.add('open');
    };
  }
  if (lcEl.closeOffboardBtn) lcEl.closeOffboardBtn.onclick = () => lcEl.modalOffboard.classList.remove('open');
  if (lcEl.cancelOffboardBtn) lcEl.cancelOffboardBtn.onclick = () => lcEl.modalOffboard.classList.remove('open');

  if (lcEl.formOffboard) {
    lcEl.formOffboard.onsubmit = async (e) => {
      e.preventDefault();
      const sam = lcEl.offboardSelectEmployee.value;
      if (!sam) {
        showToast('Bitte wähle einen Mitarbeiter aus.', 'error');
        return;
      }

      const payload = {
        sam_account_name: sam,
        reason: document.getElementById('offboardReason').value,
        effective_date: document.getElementById('offboardEffectiveDate').value,
        revoke_access: document.getElementById('offboardRevokeGroups').checked,
        archive_data: document.getElementById('offboardArchiveData').checked,
        notes: document.getElementById('offboardNotes').value.trim()
      };

      try {
        const res = await api('/api/lifecycle/offboard', {
          method: 'POST',
          body: JSON.stringify(payload)
        });

        lcEl.modalOffboard.classList.remove('open');
        showToast(`Zero-Trust Offboarding für '${res.full_name}' erfolgreich abgeschlossen!`, 'success');
        loadLifecycleData();
        loadStats();
        if (state.activeTab === 'audit') loadAuditLogs();
        if (state.activeTab === 'directory') loadDirectoryData();
      } catch (err) {
        showToast(`Fehler beim Offboarding: ${err.message}`, 'error');
      }
    };
  }

  // --- Modal: Details & Checklist ---
  if (lcEl.closeDetailsBtn) lcEl.closeDetailsBtn.onclick = () => lcEl.modalDetails.classList.remove('open');
  if (lcEl.closeDetailsBottomBtn) lcEl.closeDetailsBottomBtn.onclick = () => lcEl.modalDetails.classList.remove('open');

  if (lcEl.btnTransferFromDetails) {
    lcEl.btnTransferFromDetails.onclick = () => {
      if (!currentDetailEmp) return;
      lcEl.modalDetails.classList.remove('open');
      window.argusLifecycle.openTransfer(currentDetailEmp.sam_account_name, currentDetailEmp.full_name, currentDetailEmp.department, currentDetailEmp.job_title);
    };
  }

  if (lcEl.btnOffboardFromDetails) {
    lcEl.btnOffboardFromDetails.onclick = () => {
      if (!currentDetailEmp) return;
      lcEl.modalDetails.classList.remove('open');
      window.argusLifecycle.quickOffboard(currentDetailEmp.sam_account_name);
    };
  }

  // --- Modal: Transfer ---
  if (lcEl.closeTransferBtn) lcEl.closeTransferBtn.onclick = () => lcEl.modalTransfer.classList.remove('open');
  if (lcEl.cancelTransferBtn) lcEl.cancelTransferBtn.onclick = () => lcEl.modalTransfer.classList.remove('open');

  if (lcEl.formTransfer) {
    lcEl.formTransfer.onsubmit = async (e) => {
      e.preventDefault();
      const sam = document.getElementById('transferSAM').value;
      const payload = {
        sam_account_name: sam,
        new_department: document.getElementById('transferNewDept').value,
        new_job_title: document.getElementById('transferNewTitle').value.trim(),
        new_profile_preset: document.getElementById('transferNewPreset').value,
        reason: document.getElementById('transferReason').value.trim()
      };

      try {
        const res = await api('/api/lifecycle/transfer', {
          method: 'POST',
          body: JSON.stringify(payload)
        });

        lcEl.modalTransfer.classList.remove('open');
        showToast(`Mitarbeiter '${res.full_name}' erfolgreich in Abteilung '${res.department}' übertragen!`, 'success');
        loadLifecycleData();
        loadStats();
      } catch (err) {
        showToast(`Fehler beim Transfer: ${err.message}`, 'error');
      }
    };
  }

  // Filters
  if (lcEl.searchInput) {
    lcEl.searchInput.oninput = debounce(() => loadLifecycleData(), 250);
  }
  if (lcEl.stageFilter) {
    lcEl.stageFilter.onchange = () => loadLifecycleData();
  }
  if (lcEl.deptFilter) {
    lcEl.deptFilter.onchange = () => renderLifecycleTable(lifecycleEmployees);
  }
  if (lcEl.btnRefresh) {
    lcEl.btnRefresh.onclick = () => {
      loadLifecycleData();
      showToast('Lifecycle-Daten aktualisiert', 'info');
    };
  }

  // Window global object for onclick actions
  window.argusLifecycle = {
    openDetails: async (id) => {
      try {
        const emp = await api(`/api/lifecycle/employees/${id}`);
        currentDetailEmp = emp;

        document.getElementById('lcDetailName').textContent = `Mitarbeiter-Akte: ${emp.full_name}`;
        document.getElementById('lcDetailSubtitle').textContent = `${emp.department} • ${emp.job_title} • ${emp.sam_account_name}`;
        document.getElementById('lcDetailFullName').textContent = emp.full_name;
        document.getElementById('lcDetailDeptTitle').textContent = `${emp.department} — ${emp.job_title}`;
        document.getElementById('lcDetailEmail').textContent = emp.email;

        const stageBadge = document.getElementById('lcDetailStageBadge');
        if (stageBadge) {
          stageBadge.textContent = emp.stage;
          stageBadge.className = `badge ${emp.stage === 'onboarded' ? 'badge-stage-onboarded' : emp.stage === 'pre_boarding' ? 'badge-stage-pre' : emp.stage === 'transferred' ? 'badge-stage-transferred' : 'badge-stage-offboarded'}`;
        }

        const enabledBadge = document.getElementById('lcDetailEnabledBadge');
        if (enabledBadge) {
          enabledBadge.textContent = emp.account_enabled ? 'Konto Aktiv' : 'Gesperrt';
          enabledBadge.className = `badge ${emp.account_enabled ? 'badge-status-active' : 'badge-status-suspended'}`;
        }

        document.getElementById('lcDetailDates').textContent = `Eintritt: ${emp.start_date || '-'}${emp.end_date ? ` • Austritt: ${emp.end_date}` : ''}`;
        document.getElementById('lcDetailManager').textContent = `Führungskraft: ${emp.manager || 'Nicht angegeben'}`;

        // Groups container
        const grpContainer = document.getElementById('lcDetailGroupsContainer');
        if (grpContainer) {
          const roles = (emp.assigned_roles || []).map(r => `<span class="badge badge-role-tag" style="border-color: #38bdf8;">IAM: ${escapeHtml(r)}</span>`).join('');
          const groups = (emp.assigned_groups || []).map(g => `<span class="badge badge-role-tag">AD: ${escapeHtml(g)}</span>`).join('');
          grpContainer.innerHTML = `<div class="flex flex-wrap gap-1">${roles} ${groups || '<span class="text-dim text-xs">Keine aktiven Gruppenmitgliedschaften</span>'}</div>`;
        }

        // Checklist tasks
        const checklistDiv = document.getElementById('lcDetailChecklist');
        if (checklistDiv && emp.checklist) {
          checklistDiv.innerHTML = Object.keys(emp.checklist).map(k => {
            const item = emp.checklist[k];
            return `
              <div class="checklist-task-row ${item.completed ? 'done' : ''}">
                <label class="checklist-task-label">
                  <input type="checkbox" ${item.completed ? 'checked' : ''} onchange="window.argusLifecycle.toggleChecklist('${emp.id}', '${item.key}', this.checked)" />
                  <span class="task-text font-medium text-main">${escapeHtml(item.label)}</span>
                </label>
                <div class="flex items-center gap-2">
                  <span class="text-xs text-dim">${item.completed_at ? formatDate(item.completed_at) : 'Ausstehend'}</span>
                  <span class="badge ${item.completed ? 'badge-status-active' : 'badge-status-suspended'}">${item.completed ? 'Erledigt' : 'Offen'}</span>
                </div>
              </div>
            `;
          }).join('');
        }

        // Notes
        const notesBox = document.getElementById('lcDetailNotesBox');
        const notesText = document.getElementById('lcDetailNotesText');
        if (emp.notes) {
          notesText.textContent = emp.notes;
          notesBox.style.display = 'block';
        } else {
          notesBox.style.display = 'none';
        }

        lcEl.modalDetails.classList.add('open');
      } catch (err) {
        showToast(`Fehler beim Laden der Details: ${err.message}`, 'error');
      }
    },

    toggleChecklist: async (recordId, itemKey, done) => {
      try {
        const updated = await api('/api/lifecycle/checklist', {
          method: 'POST',
          body: JSON.stringify({ record_id: recordId, item_key: itemKey, done })
        });
        showToast(`Checkliste aktualisiert: ${done ? 'Erledigt' : 'Wieder geöffnet'}`, 'info');
        loadLifecycleData();
      } catch (err) {
        showToast(`Fehler beim Aktualisieren: ${err.message}`, 'error');
      }
    },

    openTransfer: (sam, name, dept, title) => {
      document.getElementById('transferSAM').value = sam;
      document.getElementById('transferEmpLabel').textContent = `${name} (${sam})`;
      document.getElementById('transferNewDept').value = dept;
      document.getElementById('transferNewTitle').value = title;
      document.getElementById('transferReason').value = '';
      lcEl.modalTransfer.classList.add('open');
    },

    quickOffboard: (sam) => {
      updateOffboardSelectOptions();
      if (lcEl.offboardSelectEmployee) {
        lcEl.offboardSelectEmployee.value = sam;
      }
      const effDate = document.getElementById('offboardEffectiveDate');
      if (effDate) effDate.value = new Date().toISOString().split('T')[0];
      lcEl.modalOffboard.classList.add('open');
    }
  };

  // -------------------------------------------------------------
  // Enterprise Suite (40 Features) Frontend Logic
  // -------------------------------------------------------------
  async function loadEnterpriseData() {
    try {
      const [wormRes, deltaRes, clusterRes] = await Promise.all([
        fetch('/api/enterprise/crypto/worm-status', { headers: getAuthHeaders() }),
        fetch('/api/enterprise/ad/delta-sync', { headers: getAuthHeaders() }),
        fetch('/api/enterprise/cluster/nodes', { headers: getAuthHeaders() }),
      ]);
      if (wormRes.ok) {
        const w = await wormRes.json();
        const b = document.getElementById('badgeWORMStatus');
        if (b) b.textContent = `Aktiv (${w.record_count} Einträge)`;
      }
      if (deltaRes.ok) {
        const d = await deltaRes.json();
        const b = document.getElementById('deltaSyncBadge');
        if (b) b.textContent = `${d.sync_state} (USN ${d.highest_usn})`;
      }
      if (clusterRes.ok) {
        const c = await clusterRes.json();
        const b = document.getElementById('raftLeaderBadge');
        if (b && c.leader) b.textContent = `${c.leader.role} (${c.leader.node_id})`;
      }
    } catch (e) {
      console.warn('Fehler beim Laden der Enterprise-Daten:', e);
    }
  }

  function showResultBox(boxId, content) {
    const box = document.getElementById(boxId);
    if (!box) return;
    box.style.display = 'block';
    if (typeof content === 'object') {
      box.textContent = JSON.stringify(content, null, 2);
    } else {
      box.textContent = String(content);
    }
  }

  // Setup Enterprise Buttons Event Handlers
  document.addEventListener('DOMContentLoaded', () => {
    const bindBtn = (id, fn) => {
      const btn = document.getElementById(id);
      if (btn) btn.addEventListener('click', fn);
    };

    bindBtn('btnRefreshEnterpriseData', () => {
      loadEnterpriseData();
      showNotification('Enterprise-Status erfolgreich aktualisiert', 'success');
    });

    // 1-5. Crypto & Zero-Trust
    bindBtn('btnTestMerkle', async () => {
      const res = await fetch('/api/enterprise/crypto/merkle-root', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('cryptoResultBox', `Merkle-Root: ${data.root_hash}\nProof Valid: ${data.proof_valid}\nNotar: ${data.anchor.notary_proof}`);
    });

    bindBtn('btnTestSignBlock', async () => {
      const res = await fetch('/api/enterprise/crypto/sign-block', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ block_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' })
      });
      const data = await res.json();
      showResultBox('cryptoResultBox', `Ed25519 Sig: ${data.ed25519_sig.substring(0, 32)}...\nPQC Sig (ML-DSA-65): ${data.pqc_hybrid.pqc_sig.substring(0, 32)}...\nValid: ${data.signature_valid}`);
    });

    bindBtn('btnTestEnvelope', async () => {
      const res = await fetch('/api/enterprise/crypto/envelope-demo', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ plaintext: 'Vertrauliche Personaldaten: Gehalt €95.000 / IBAN DE89...' })
      });
      const data = await res.json();
      showResultBox('cryptoResultBox', `Ciphertext (AES-256-GCM): ${data.encrypted.ciphertext.substring(0, 40)}...\nDecrypted: ${data.decrypted}`);
    });

    // 6-10. Auth & Security
    bindBtn('btnTestWebAuthn', async () => {
      const res = await fetch('/api/enterprise/security/webauthn/challenge', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('authResultBox', `FIDO2 Challenge: ${data.challenge}\nExpires: ${data.expires_at}`);
    });

    bindBtn('btnTestTOTP', async () => {
      const res = await fetch('/api/enterprise/security/totp/setup', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('authResultBox', `TOTP Secret (Base32): ${data.secret}\nRecovery Codes:\n${data.recovery_codes.join('  ')}`);
    });

    bindBtn('btnTestRisk', async () => {
      const res = await fetch('/api/enterprise/security/risk-assess', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          username: 'sarah.connor',
          ip_address: '133.242.18.1',
          latitude: 35.6762,
          longitude: 139.6503,
          city: 'Tokyo',
          country: 'Japan'
        })
      });
      const data = await res.json();
      showResultBox('authResultBox', `Risk Level: ${data.level} (Score: ${data.score})\nStep-Up Required: ${data.step_up}\nFaktoren:\n- ${data.factors.join('\n- ')}`);
    });

    bindBtn('btnTestHIBP', async () => {
      const res = await fetch('/api/enterprise/security/pwned-check', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ password: 'admin123' })
      });
      const data = await res.json();
      showResultBox('authResultBox', `HIBP Check: ${data.message}\nKompromittiert: ${data.is_compromised} (${data.breach_count} Datenlecks)`);
    });

    // 11-15. AD Extended
    bindBtn('btnSwitchForestDomain', async () => {
      const current = document.getElementById('activeDomainLabel').textContent;
      const target = current === 'corp.local' ? 'emea.corp.local' : 'corp.local';
      const res = await fetch('/api/enterprise/ad/domains/switch', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ dns_name: target })
      });
      const data = await res.json();
      document.getElementById('activeDomainLabel').textContent = data.active_domain;
      showResultBox('adResultBox', `Aktive Domäne gewechselt auf: ${data.active_domain}`);
    });

    bindBtn('btnListPSOs', async () => {
      const res = await fetch('/api/enterprise/ad/pso', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('adResultBox', data);
    });

    bindBtn('btnRotateGMSA', async () => {
      const res = await fetch('/api/enterprise/ad/gmsa/gmsa-argus-svc$/rotate', { method: 'POST', headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('adResultBox', data.message);
    });

    bindBtn('btnRestoreDeletedAD', async () => {
      const res = await fetch('/api/enterprise/ad/recycle-bin/guid-dev-01/restore', { method: 'POST', headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('adResultBox', `AD-Konto florian.ex erfolgreich aus Papierkorb wiederhergestellt!`);
    });

    // 16-20. PAM & Governance
    bindBtn('btnTriggerBreakGlass', async () => {
      const res = await fetch('/api/enterprise/governance/breakglass', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ account_name: 'bg-admin-root', ticket_id: 'INC-2026-99', reason: 'DC Outage Disaster Recovery' })
      });
      const data = await res.json();
      showResultBox('pamResultBox', `Break-Glass Anfrage #${data.id} erstellt. Wartet auf Vier-Augen-Genehmigung.`);
    });

    bindBtn('btnIssueEphemeral', async () => {
      const res = await fetch('/api/enterprise/governance/ephemeral-credentials', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ username: 'sarah.connor', token_type: 'SSH_CERT', ttl_minutes: 15 })
      });
      const data = await res.json();
      showResultBox('pamResultBox', `Ephemeres Secret (15 Min TTL):\n${data.secret}`);
    });

    bindBtn('btnCheckSoD', async () => {
      const res = await fetch('/api/enterprise/governance/sod-conflicts', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('pamResultBox', `SoD Konflikte gefunden: ${data.conflict_count}\n` + data.violations.map(v => `${v.rule_name} (${v.severity})`).join('\n'));
    });

    bindBtn('btnListCertCampaigns', async () => {
      const res = await fetch('/api/enterprise/governance/certifications', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('pamResultBox', data);
    });

    bindBtn('btnViewSessionAudits', async () => {
      const res = await fetch('/api/enterprise/governance/session-audits', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('pamResultBox', data);
    });

    // 21-25. Policy-as-Code & Analytics
    bindBtn('btnEvaluateABAC', async () => {
      const res = await fetch('/api/enterprise/policy/evaluate', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ username: 'sarah.connor', action: 'production:deploy', device_compliant: false })
      });
      const data = await res.json();
      showResultBox('policyResultBox', `ABAC Policy Result:\nErlaubt: ${data.allowed}\nRegel: ${data.matched_rule}\nBegründung: ${data.reason}`);
    });

    bindBtn('btnRunRoleMining', async () => {
      const res = await fetch('/api/enterprise/policy/role-mining', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('policyResultBox', `Vorgeschlagene Rollenvorlagen:\n` + data.map(c => `${c.suggested_name} (Konfidenz: ${c.confidence_score * 100}%)\n  ${c.reason}`).join('\n\n'));
    });

    bindBtn('btnScanOrphans', async () => {
      const res = await fetch('/api/enterprise/policy/orphans', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('policyResultBox', data);
    });

    bindBtn('btnAnalyzeShadowAdmins', async () => {
      const res = await fetch('/api/enterprise/policy/shadow-admins', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('policyResultBox', `BloodHound Heuristik:\n${data.critical_alert}\n\nEskalationsschritte:\n` + data.edges.map(e => `${e.source} --[${e.relation}]--> ${e.target}`).join('\n'));
    });

    // 26-30. Compliance & Forensik
    bindBtn('btnShowComplianceControls', async () => {
      const res = await fetch('/api/enterprise/compliance/controls', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('complianceResultBox', `Erfüllte Kontrollpunkte:\n` + data.map(c => `[${c.framework}] ${c.control_ref}: ${c.title} -> ${c.status}`).join('\n'));
    });

    bindBtn('btnRunTimeTravel', async () => {
      const res = await fetch('/api/enterprise/compliance/time-travel', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ target_date: '2026-03-01T00:00:00Z' })
      });
      const data = await res.json();
      showResultBox('complianceResultBox', `Historischer Berechtigungsstand (Stand: ${data.target_timestamp}):\n` + JSON.stringify(data.user_states, null, 2));
    });

    bindBtn('btnExportSIEM', async () => {
      const res = await fetch('/api/enterprise/compliance/siem-export', { method: 'POST', headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('complianceResultBox', `Syslog RFC 5424 versendet:\n${data.rfc5424_syslog}\n\nElastic Common Schema (ECS):\n${data.elastic_ecs}`);
    });

    bindBtn('btnShredGDPR', async () => {
      const res = await fetch('/api/enterprise/compliance/gdpr-shred', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ username: 'ex.mitarbeiter', user_id: 'usr-994' })
      });
      const data = await res.json();
      showResultBox('complianceResultBox', `DSGVO Art. 17 Schlüssellöschung vollzogen:\nPseudonym: ${data.pseudonym_id}\nVernichteter Key: ${data.destroyed_key_id}\nZertifikat: ${data.certificate_proof}`);
    });

    bindBtn('btnGetComplianceCert', async () => {
      const res = await fetch('/api/enterprise/compliance/certificate', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('complianceResultBox', `Zertifikat #${data.certificate_id}\nSiegel: ${data.digital_seal}\nScore: ${data.compliance_score}%\nAuditor: ${data.auditor}`);
    });

    // 31-35. Cluster
    bindBtn('btnCheckCluster', async () => {
      const res = await fetch('/api/enterprise/cluster/nodes', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('clusterResultBox', data);
    });

    bindBtn('btnCacheStats', async () => {
      const res = await fetch('/api/enterprise/cluster/cache', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('clusterResultBox', data);
    });

    bindBtn('btnListReplicas', async () => {
      const res = await fetch('/api/enterprise/cluster/replicas', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('clusterResultBox', data);
    });

    // 36-40. DevOps
    bindBtn('btnExportTerraform', async () => {
      const res = await fetch('/api/enterprise/terraform/export', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('devopsResultBox', data.hcl_code);
    });

    bindBtn('btnTestSCIM', async () => {
      const res = await fetch('/scim/v2/Users', { headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('devopsResultBox', data);
    });

    bindBtn('btnTestWebhook', async () => {
      const res = await fetch('/api/enterprise/webhooks/wh-sec-alert/test', { method: 'POST', headers: getAuthHeaders() });
      const data = await res.json();
      showResultBox('devopsResultBox', data.result);
    });
  });

  // Helper Utilities
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function formatDate(isoStr) {
    if (!isoStr) return '-';
    const d = new Date(isoStr);
    return d.toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
  }

  function formatDateFull(isoStr) {
    if (!isoStr) return '-';
    const d = new Date(isoStr);
    return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  }

  function getActionBadgeClass(action) {
    if (!action) return '';
    if (action.includes('create')) return 'badge-user-create';
    if (action.includes('update')) return 'badge-user-update';
    if (action.includes('delete')) return 'badge-user-delete';
    if (action.includes('login_failed')) return 'badge-auth-failed';
    if (action.includes('login') || action.includes('logout')) return 'badge-auth-login';
    if (action.includes('role')) return 'badge-role-create';
    return 'badge-user-update';
  }

  // Initialization
  checkCurrentUser();

})();
