// ─── State ──────────────────────────────────────────────────────
let activeView = 'dashboard';
let logState = { page: 1, limit: 10, total: 0, filter: 'all', query: '' };
let selectedDomains = new Set();
let selectedSsl = new Set();
let _csrfToken = null;
let _autoRefresh = 0;
let _autoRefreshTimer = null;
let _viewMode = { full: 'cards', ssl_only: 'cards' };
let _domainFilter = { full: 'all', ssl_only: 'all' };
let _tldFilter = { full: '', ssl_only: '' };
let _groupByStatus = { full: false, ssl_only: false };
let _collapsedGroups = {};
let _cachedTlds = { full: [], ssl_only: [] };
let _pagination = { full: { page: 1, pageSize: 25 }, ssl_only: { page: 1, pageSize: 25 } };
let _visibleCols = { full: {}, ssl_only: {} };
let _prevStatuses = { full: {}, ssl_only: {} };
let _bulkCheckQueue = [];
let _bulkCheckRunning = false;
let _keyboardFocusIndex = -1;
let _userRole = 'admin'; // default admin until session check completes
let _settingsDirty = false;
let _settingsOriginal = {};
let _usersLoaded = false;
let _usersCache = [];
let _currentUsername = '';
let _userFilters = { search: '', role: 'all', status: 'all' };
let _apiKeys = [];
let _newApiKey = null;
let _pwPolicy = { minLength: 8, requireUpper: true, requireLower: true, requireNumber: true, requireSpecial: false };

// ─── Loading state helper ─────────────────────────────────────
function setLoading(btn, loading) {
  if (!btn) return;
  if (loading) { btn.classList.add('btn-loading'); btn.disabled = true; }
  else { btn.classList.remove('btn-loading'); btn.disabled = false; }
}

// ─── Count-up animation ───────────────────────────────────────
function animateCount(el, target, duration) {
  if (!el) return;
  duration = duration || (target > 100 ? 600 : 400);
  const start = performance.now();
  const from = 0;
  const step = (now) => {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(from + (target - from) * eased);
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// ─── Navigation (hash-based routing) ──────────────────────────
function activateView(viewName) {
  if (_userRole !== 'admin' && (viewName === 'settings' || viewName === 'logs' || viewName === 'backups')) {
    viewName = 'dashboard';
    window.location.hash = 'dashboard';
  }
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const tab = document.querySelector(`.nav-tab[data-view="${viewName}"]`);
  if (tab) tab.classList.add('active');
  const view = document.getElementById('view-' + viewName);
  if (view) view.classList.add('active');
  activeView = viewName;
  if (viewName === 'dashboard') loadDashboard();
  if (viewName === 'logs') refreshLogs();
  if (viewName === 'settings') loadSettings();
  if (viewName === 'backups') loadBackupsView();
  if (viewName === 'domains') loadDomains('full', true);
  if (viewName === 'sslcerts') loadDomains('ssl_only', true);
  if (viewName === 'webapps') loadWebApps(true);
}

document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    window.location.hash = tab.dataset.view;
  });
});

window.addEventListener('hashchange', () => {
  const viewName = window.location.hash.slice(1) || 'dashboard';
  activateView(viewName);
});

// ─── Global event delegation for data-action ──────────────────
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;

  if (action === 'toggle-theme') toggleTheme();
  else if (action === 'logout') logout();
  else if (action === 'check-all-full') checkAll('full');
  else if (action === 'check-all-ssl') checkAll('ssl_only');
  else if (action === 'refresh-domains') refreshDomains();
  else if (action === 'export-csv') exportDashboardCsv();
  else if (action === 'export') exportDomains();
  else if (action === 'import') importDomains();
  else if (action === 'add-domain-full') openAddModal('full');
  else if (action === 'add-domain-ssl') openAddModal('ssl_only');
  else if (action === 'test-smtp') testSmtp();
  else if (action === 'add-user') openUserModal();
  else if (action === 'refresh-users') refreshUsers();
  else if (action === 'clear-user-filters') clearUserFilters();
  else if (action === 'toggle-user-active') toggleUserActive(parseInt(btn.dataset.id), btn.dataset.name, btn.dataset.active === '1');
  else if (action === 'refresh-logs') refreshLogs();
  else if (action === 'log-prev') logPage(-1);
  else if (action === 'log-next') logPage(1);
  else if (action === 'close-domain-modal') closeDomainModal();
  else if (action === 'close-user-modal') closeUserModal();
  else if (action === 'close-confirm-modal') closeConfirmModal();
  else if (action === 'close-cert-modal') closeCertModal();
  else if (action === 'close-import-modal') closeImportModal();
  else if (action === 'do-import') doImport();
  else if (action === 'manual-check') manualCheck(parseInt(btn.dataset.id));
  else if (action === 'edit-domain') openEditModal(parseInt(btn.dataset.id));
  else if (action === 'delete-domain') confirmDelete(parseInt(btn.dataset.id), btn.dataset.name, 'domain');
  else if (action === 'edit-user') openEditUserModal(parseInt(btn.dataset.id), btn.dataset.name, btn.dataset.role);
  else if (action === 'delete-user') confirmDelete(parseInt(btn.dataset.id), btn.dataset.name, 'user');
  else if (action === 'view-cert') openCertModal(parseInt(btn.dataset.id));
  else if (action === 'bulk-check') bulkAction('full', 'check');
  else if (action === 'bulk-delete') bulkAction('full', 'delete');
  else if (action === 'bulk-deselect') deselectAll('full');
  else if (action === 'bulk-export') bulkExport('full');
  else if (action === 'bulk-notes') openBulkNotes('full');
  else if (action === 'ssl-bulk-check') bulkAction('ssl_only', 'check');
  else if (action === 'ssl-bulk-delete') bulkAction('ssl_only', 'delete');
  else if (action === 'ssl-bulk-deselect') deselectAll('ssl_only');
  else if (action === 'ssl-bulk-export') bulkExport('ssl_only');
  else if (action === 'ssl-bulk-notes') openBulkNotes('ssl_only');
  else if (action === 'toggle-view-full') toggleViewMode('full');
  else if (action === 'toggle-view-ssl') toggleViewMode('ssl_only');
  else if (action === 'clear-domain-filters') clearDomainFilters(btn.dataset.type);
  else if (action === 'download-template') downloadTemplate('full');
  else if (action === 'download-template-ssl') downloadTemplate('ssl_only');
  else if (action === 'download-template-webapp') downloadTemplate('webapp');
  else if (action === 'submit-bulk-notes') submitBulkNotes();
  else if (action === 'close-bulk-notes') closeBulkNotes();
  else if (action === 'toggle-columns-full') toggleColumnDropdown('full');
  else if (action === 'toggle-columns-ssl') toggleColumnDropdown('ssl_only');
  else if (action === 'bulk-compare') openCompareModal('full');
  else if (action === 'ssl-bulk-compare') openCompareModal('ssl_only');
  else if (action === 'bulk-tags') openBulkTags('full');
  else if (action === 'ssl-bulk-tags') openBulkTags('ssl_only');
  else if (action === 'submit-bulk-tags') submitBulkTags();
  else if (action === 'close-bulk-tags') closeBulkTags();
  else if (action === 'close-compare-modal') closeCompareModal();
  else if (action === 'print-view') window.print();
  else if (action === 'page-first-full') goToPage('full', 1);
  else if (action === 'page-prev-full') goToPage('full', _pagination.full.page - 1);
  else if (action === 'page-next-full') goToPage('full', _pagination.full.page + 1);
  else if (action === 'page-last-full') goToPage('full', totalPages('full'));
  else if (action === 'page-first-ssl') goToPage('ssl_only', 1);
  else if (action === 'page-prev-ssl') goToPage('ssl_only', _pagination.ssl_only.page - 1);
  else if (action === 'page-next-ssl') goToPage('ssl_only', _pagination.ssl_only.page + 1);
  else if (action === 'page-last-ssl') goToPage('ssl_only', totalPages('ssl_only'));
  else if (action === 'filter-domains') filterDomainsFromDash(btn.dataset.type, btn.dataset.status);
  else if (action === 'back-to-top') window.scrollTo({ top: 0, behavior: 'smooth' });
  else if (action === 'go-dashboard') { window.location.hash = 'dashboard'; activateView('dashboard'); }
  else if (action === 'go-webapps') { window.location.hash = 'webapps'; activateView('webapps'); }
  else if (action === 'go-domain') openDomainInNewTab(parseInt(btn.dataset.id));
  else if (action === 'quick-check') { e.stopPropagation(); quickCheck(parseInt(btn.dataset.id)); }
  else if (action === 'test-webhook') { testWebhook(btn.dataset.webhookType); }
  else if (action === 'export-settings') { exportSettings(); }
  else if (action === 'import-settings') { document.getElementById('settings-import-input').click(); }
  else if (action === 'bulk-revoke-apikeys') { bulkRevokeApiKeys(); }
  else if (action === 'refresh-api-keys') { loadApiKeys(true); }
  else if (action === 'refresh-backups') { loadBackups(true); }
  else if (action === 'refresh-backups-view') { loadBackupsView(); }
  else if (action === 'create-backup-view' || action === 'open-backup-create') { document.getElementById('backup-create-pane').style.display = ''; document.getElementById('backup-notes-input').value = ''; }
  else if (action === 'close-backup-create') { document.getElementById('backup-create-pane').style.display = 'none'; }
  else if (action === 'confirm-create-backup') { createBackupWithNotes(); }
  else if (action === 'open-backup-upload') { document.getElementById('backup-upload-pane').style.display = ''; document.getElementById('backup-upload-input').value = ''; }
  else if (action === 'close-backup-upload') { document.getElementById('backup-upload-pane').style.display = 'none'; }
  else if (action === 'confirm-upload-backup') { uploadAndRestoreBackup(); }
  else if (action === 'toggle-backup-schedule') { const c = document.getElementById('backup-schedule-card'); c.style.display = c.style.display === 'none' ? '' : 'none'; }
  else if (action === 'close-backup-schedule') { document.getElementById('backup-schedule-card').style.display = 'none'; }
  else if (action === 'save-backup-schedule') { saveBackupSchedule(); }
  else if (action === 'refresh-email-templates') { loadEmailTemplates(true); }
  else if (action === 'toggle-quickadd') { openQuickAddModal(); }
  else if (action === 'close-quickadd-modal') { closeQuickAddModal(); }

  // ─── Web Apps actions ──────────────────────────────────────────
  else if (action === 'toggle-actions-dropdown') {
    var dd = btn.closest('.actions-dropdown');
    if (dd) dd.classList.toggle('open');
  }
  else if (action === 'add-webapp') { openWebAppModal(null); }
  else if (action === 'close-webapp-modal') { closeWebAppModal(); }
  else if (action === 'toggle-view-webapps') {
    _webappViewMode = _webappViewMode === 'table' ? 'cards' : 'table';
    var label = btn.querySelector('.view-toggle-label');
    if (label) label.textContent = _webappViewMode === 'table' ? 'Cards' : 'Table';
    btn.querySelector('.view-toggle-icon').innerHTML = _webappViewMode === 'table' ? '&#9776;' : '&#9632;';
    applyWebAppFilters(_webappsCache || []);
  }
  else if (action === 'check-all-webapps') {
    api('POST', '/api/webapps/check-all').then(function () { loadWebApps(true); toast('All web apps checked'); }).catch(function (e) { toast(e.message, 'error'); });
  }
  else if (action === 'webapp-check-now') {
    var wid = parseInt(btn.dataset.id);
    var oldStatus = (_webappsCache || []).find(function (a) { return a.id === wid; });
    api('POST', '/api/webapps/' + wid + '/check').then(function () {
      loadWebApps(true);
      setTimeout(function () {
        var card = document.querySelector('[data-webapp-id="' + wid + '"]');
        if (card) { card.classList.add('status-changed'); setTimeout(function () { card.classList.remove('status-changed'); }, 1000); }
      }, 100);
    }).catch(function (e) { toast(e.message, 'error'); });
  }
  else if (action === 'webapp-edit') {
    var wid = parseInt(btn.dataset.id);
    var app = (_webappsCache || []).find(function (a) { return a.id === wid; });
    if (app) openWebAppModal(app);
  }
  else if (action === 'webapp-delete') {
    var wid = parseInt(btn.dataset.id);
    if (!confirm('Delete this web app?')) return;
    api('DELETE', '/api/webapps/' + wid).then(function () { loadWebApps(true); toast('Web app deleted'); }).catch(function (e) { toast(e.message, 'error'); });
  }
  else if (action === 'webapp-bulk-check') {
    var ids = Array.from(_selectedWebapps);
    if (!ids.length) return;
    Promise.all(ids.map(function (id) { return api('POST', '/api/webapps/' + id + '/check'); })).then(function () {
      _selectedWebapps.clear(); loadWebApps(true); toast('Checked ' + ids.length + ' web apps');
    }).catch(function (e) { toast(e.message, 'error'); });
  }
  else if (action === 'webapp-bulk-delete') {
    var ids = Array.from(_selectedWebapps);
    if (!ids.length) return;
    if (!confirm('Delete ' + ids.length + ' web apps?')) return;
    api('POST', '/api/webapps/bulk-delete', { ids: ids }).then(function () {
      _selectedWebapps.clear(); loadWebApps(true); toast('Deleted ' + ids.length + ' web apps');
    }).catch(function (e) { toast(e.message, 'error'); });
  }
  else if (action === 'webapp-bulk-deselect') { _selectedWebapps.clear(); applyWebAppFilters(_webappsCache || []); }
  else if (action === 'toggle-columns-webapp') {
    var dd = document.getElementById('col-dropdown-webapp');
    if (dd) dd.style.display = dd.style.display === 'none' ? '' : 'none';
  }
  else if (action === 'refresh-webapps') { loadWebApps(true); }
  else if (action === 'webapp-export-csv') {
    window.open('/api/webapps/export/csv', '_blank');
  }
  else if (action === 'webapp-toggle-active') {
    var wid = parseInt(btn.dataset.id);
    var app = (_webappsCache || []).find(function (a) { return a.id === wid; });
    if (!app) return;
    var newVal = app.is_active === 0 || app.is_active === false ? 1 : 0;
    api('PUT', '/api/webapps/' + wid, { is_active: !!newVal }).then(function () {
      loadWebApps(true);
      toast(newVal ? 'Web app resumed' : 'Web app paused');
    }).catch(function (e) { toast(e.message, 'error'); });
  }
  else if (action === 'webapp-detail') {
    var wid = parseInt(btn.dataset.id);
    var app = (_webappsCache || []).find(function (a) { return a.id === wid; });
    if (app) openWebAppDetail(app);
  }
  else if (action === 'close-webapp-detail') {
    document.getElementById('webapp-detail-modal').classList.remove('open');
  }
  else if (action === 'clear-webapp-filters') {
    document.getElementById('webapp-search').value = '';
    _webappFilter = 'all';
    document.querySelectorAll('#webapp-filters .log-filter').forEach(function (b) { b.classList.remove('active'); });
    var allBtn = document.querySelector('#webapp-filters [data-webapp-filter="all"]');
    if (allBtn) allBtn.classList.add('active');
    applyWebAppFilters(_webappsCache || []);
  }
});

// ─── Collapsible sections ──────────────────────────────────────
document.addEventListener('click', function (e) {
  var header = e.target.closest('.collapsible-header');
  if (!header) return;
  var body = header.nextElementSibling;
  if (!body || !body.classList.contains('collapsible-body')) return;
  var key = 'collapse-' + header.dataset.collapse;
  var isCollapsed = header.classList.toggle('collapsed');
  try { localStorage.setItem(key, isCollapsed ? '1' : ''); } catch (ex) {}
});

function applyCollapseStates() {
  document.querySelectorAll('.collapsible-header').forEach(function (h) {
    var key = 'collapse-' + h.dataset.collapse;
    if (key && localStorage.getItem(key) === '1') {
      h.classList.add('collapsed');
    }
  });
}

['ssl-expiring-list', 'domain-expiring-list'].forEach(function (id) {
  var container = document.getElementById(id);
  if (container) {
    container.addEventListener('click', function (e) {
      var item = e.target.closest('.top-item[data-id]');
      if (!item) return;
      navigateToDomain(parseInt(item.dataset.id));
    });
  }
});

// ─── Copy URL on click ─────────────────────────────────────────
document.addEventListener('click', (e) => {
  const urlEl = e.target.closest('[data-action="copy-url"]');
  if (urlEl) {
    e.stopPropagation();
    const url = urlEl.dataset.url;
    navigator.clipboard.writeText(url).then(() => toast(`Copied: ${url}`)).catch(() => {});
    return;
  }
});

// ─── Toggle expandable details ─────────────────────────────────
document.addEventListener('click', (e) => {
  const expandBtn = e.target.closest('[data-action="toggle-details"]');
  if (expandBtn) {
    const id = expandBtn.dataset.id;
    const suffix = expandBtn.closest('.domain-card').id.replace('card-', '').split('-')[0];
    const details = document.getElementById(`details-${suffix}-${id}`);
    if (details) {
      details.classList.toggle('expanded');
      expandBtn.innerHTML = details.classList.contains('expanded') ? '&#9660; Hide' : '&#9654; Details';
    }
    return;
  }
});

// ─── Inline notes editing ──────────────────────────────────────
function activateInlineNotes(notesEl) {
  if (!notesEl || notesEl.querySelector('textarea')) return;
  const id = notesEl.dataset.id;
  const current = notesEl.textContent.replace('✎', '').trim();
  notesEl.innerHTML = '<textarea class="notes-edit-area">' + escHtml(current) + '</textarea>';
  const ta = notesEl.querySelector('textarea');
  ta.focus();
  ta.select();
  ta.addEventListener('blur', async function () {
    var newVal = ta.value.trim();
    var parent = notesEl.closest('[id^="view-"]');
    var type = parent && parent.id === 'view-sslcerts' ? 'ssl_only' : 'full';
    try {
      if (newVal !== current) {
        await api('PUT', '/api/domains/' + id, { notes: newVal });
      }
      // Restore display with updated text
      notesEl.innerHTML = '<span class="notes-text">' + escHtml(newVal || '') + '</span><span class="notes-edit-icon">&#x270E;</span>';
      notesEl.classList.toggle('empty', !newVal);
      // Update cached domain data so sort/filter stay consistent
      var cache = _cachedDomains[type];
      if (cache) {
        var found = cache.find(function (d) { return d.id == id; });
        if (found) found.notes = newVal;
      }
    } catch (err) {
      toast(err.message, 'error');
      notesEl.innerHTML = '<span class="notes-text">' + escHtml(current || '') + '</span><span class="notes-edit-icon">&#x270E;</span>';
      notesEl.classList.toggle('empty', !current);
    }
  });
  ta.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') { ta.value = current; ta.blur(); }
    if (ev.key === 'Enter' && (ev.metaKey || ev.ctrlKey)) { ev.preventDefault(); ta.blur(); }
  });
}

document.addEventListener('click', function (e) {
  var notesEl = e.target.closest('.domain-notes[data-action="inline-notes"]');
  if (notesEl) activateInlineNotes(notesEl);
});

// ─── Kebab menu ────────────────────────────────────────────────
document.addEventListener('click', (e) => {
  const toggle = e.target.closest('[data-action="toggle-kebab"]');
  if (toggle) {
    e.stopPropagation();
    const dropdown = toggle.nextElementSibling;
    const isOpen = dropdown.style.display !== 'none';
    // Close all open dropdowns first
    document.querySelectorAll('.kebab-dropdown').forEach(d => d.style.display = 'none');
    if (!isOpen) {
      dropdown.style.display = 'block';
      dropdown.style.position = 'fixed';
      const btnRect = toggle.getBoundingClientRect();
      const ddW = dropdown.offsetWidth || 180;
      let left = btnRect.right - ddW;
      if (left < 8) left = btnRect.left;
      let top = btnRect.bottom + 4;
      if (top + dropdown.offsetHeight > window.innerHeight) {
        top = btnRect.top - dropdown.offsetHeight - 4;
      }
      dropdown.style.left = left + 'px';
      dropdown.style.top = top + 'px';
    }
    return;
  }
  // Close dropdown if clicking outside
  if (!e.target.closest('.kebab-menu')) {
    document.querySelectorAll('.kebab-dropdown').forEach(d => d.style.display = 'none');
  }
});

// ─── Global keydown ──────────────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.kebab-dropdown').forEach(d => d.style.display = 'none');
    document.querySelectorAll('.column-dropdown').forEach(d => d.style.display = 'none');
    ['domain-modal', 'user-modal', 'confirm-modal', 'cert-modal', 'import-modal', 'bulk-notes-modal', 'compare-modal', 'bulk-tags-modal'].forEach(id => {
      const el = document.getElementById(id);
      if (el && el.style.display !== 'none') {
        el.style.display = 'none';
        if (id === 'confirm-modal') { var cm = document.getElementById('confirm-modal'); if (cm) closeConfirmModal(); }
      }
    });
  }

  // Keyboard shortcuts (only on domains/ssl views, not in inputs)
  const tag = document.activeElement.tagName;
  const inInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
  if (!inInput && (activeView === 'domains' || activeView === 'sslcerts')) {
    const type = activeView === 'sslcerts' ? 'ssl_only' : 'full';
    const selSet = type === 'ssl_only' ? selectedSsl : selectedDomains;
    const filtered = getFilteredDomains(type);
    const pageItems = getPageItems(filtered, type);

    if (e.key === '/' || (e.key === 'f' && !e.ctrlKey && !e.metaKey)) {
      e.preventDefault();
      const searchId = type === 'ssl_only' ? 'ssl-search' : 'domain-search';
      document.getElementById(searchId).focus();
    }
    if (e.key === 'j' || e.key === 'ArrowDown') {
      e.preventDefault();
      _keyboardFocusIndex = Math.min(_keyboardFocusIndex + 1, pageItems.length - 1);
      highlightKeyboardFocus(pageItems);
    }
    if (e.key === 'k' || e.key === 'ArrowUp') {
      e.preventDefault();
      _keyboardFocusIndex = Math.max(_keyboardFocusIndex - 1, 0);
      highlightKeyboardFocus(pageItems);
    }
    if (e.key === 'x') {
      e.preventDefault();
      if (_keyboardFocusIndex >= 0 && _keyboardFocusIndex < pageItems.length) {
        const id = pageItems[_keyboardFocusIndex].id;
        if (selSet.has(id)) selSet.delete(id); else selSet.add(id);
        applyDomainFilters(type);
      }
    }
    if (e.key === 'a' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      pageItems.forEach(d => selSet.add(d.id));
      applyDomainFilters(type);
    }
    if (e.key === 'c') {
      e.preventDefault();
      if (selSet.size > 0) bulkAction(type, 'check');
    }
  }
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
    const active = document.activeElement;
    if (active) {
      const form = active.closest('form');
      if (form) { e.preventDefault(); form.requestSubmit(); }
    }
  }
});

// ─── Settings tab keyboard nav ─────────────────────────────────
document.addEventListener('keydown', (e) => {
  if (activeView !== 'settings') return;
  if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
    const tabs = [...document.querySelectorAll('.settings-tab')];
    const current = tabs.findIndex(t => t.classList.contains('active'));
    if (current === -1) return;
    e.preventDefault();
    const next = e.key === 'ArrowRight' ? (current + 1) % tabs.length : (current - 1 + tabs.length) % tabs.length;
    tabs[next].click();
    tabs[next].focus();
  }
});

// ─── Scroll to top button ─────────────────────────────────────────
let ticking = false;
document.addEventListener('scroll', () => {
  if (!ticking) {
    requestAnimationFrame(() => {
      document.getElementById('back-to-top').classList.toggle('visible', window.scrollY > 400);
      ticking = false;
    });
    ticking = true;
  }
});

// ─── Auto-refresh ─────────────────────────────────────────────────
document.getElementById('auto-refresh-select').addEventListener('change', (e) => {
  _autoRefresh = parseInt(e.target.value);
  clearInterval(_autoRefreshTimer);
  if (_autoRefresh > 0 && activeView === 'dashboard') {
    _autoRefreshTimer = setInterval(() => loadDashboard(true), _autoRefresh * 1000);
  }
});

var _relTimeTimer = null;
function refreshRelTimes() {
  document.querySelectorAll('.rel-time').forEach(function (el) {
    var raw = el.getAttribute('data-date');
    if (raw) el.textContent = relativeTime(raw);
  });
}

const origActivate = activateView;
activateView = function(viewName) {
  origActivate(viewName);
  clearInterval(_autoRefreshTimer);
  clearInterval(_relTimeTimer);
  if (_autoRefresh > 0 && viewName === 'dashboard') {
    _autoRefreshTimer = setInterval(() => loadDashboard(true), _autoRefresh * 1000);
  }
  if (viewName === 'domains' || viewName === 'sslcerts') {
    _relTimeTimer = setInterval(refreshRelTimes, 30000);
  }
};

// ─── Page size changes ─────────────────────────────────────────
document.getElementById('page-size-full').addEventListener('change', (e) => {
  _pagination.full.pageSize = parseInt(e.target.value);
  _pagination.full.page = 1;
  applyDomainFilters('full');
});
document.getElementById('page-size-ssl').addEventListener('change', (e) => {
  _pagination.ssl_only.pageSize = parseInt(e.target.value);
  _pagination.ssl_only.page = 1;
  applyDomainFilters('ssl_only');
});
document.getElementById('page-size-webapp').addEventListener('change', (e) => {
  _webappPagination.size = parseInt(e.target.value);
  _webappPagination.page = 0;
  applyWebAppFilters(_webappsCache || []);
});

// ─── Webapp search ──────────────────────────────────────────────
document.getElementById('webapp-search').addEventListener('input', function () {
  _webappPagination.page = 0;
  applyWebAppFilters(_webappsCache || []);
});
document.getElementById('webapp-filters').addEventListener('click', (e) => {
  var btn = e.target.closest('[data-webapp-filter]');
  if (!btn) return;
  document.querySelectorAll('#webapp-filters .log-filter').forEach(function (b) { b.classList.remove('active'); });
  btn.classList.add('active');
  _webappFilter = btn.dataset.webappFilter;
  _webappPagination.page = 0;
  applyWebAppFilters(_webappsCache || []);
});
document.getElementById('sort-webapp-select').addEventListener('change', (e) => {
  var opt = e.target.options[e.target.selectedIndex];
  _webappSort.key = opt.value;
  _webappSort.dir = parseInt(opt.dataset.dir) || 1;
  _webappPagination.page = 0;
  applyWebAppFilters(_webappsCache || []);
});
document.getElementById('pagination-webapp').addEventListener('click', (e) => {
  var btn = e.target.closest('[data-action^="page-"]');
  if (!btn) return;
  var action = btn.dataset.action;
  if (action === 'page-first-webapp') _webappPagination.page = 0;
  else if (action === 'page-prev-webapp') _webappPagination.page = Math.max(0, _webappPagination.page - 1);
  else if (action === 'page-next-webapp') _webappPagination.page = _webappPagination.page + 1;
  else if (action === 'page-last-webapp') _webappPagination.page = 9999;
  applyWebAppFilters(_webappsCache || []);
});

// ─── Webapp bulk select ─────────────────────────────────────────
document.addEventListener('change', (e) => {
  var cb = e.target.closest('.webapp-select');
  if (!cb) return;
  if (cb.checked) _selectedWebapps.add(parseInt(cb.value));
  else _selectedWebapps.delete(parseInt(cb.value));
  updateWebappBulkToolbar();
});
document.getElementById('select-all-webapp').addEventListener('change', (e) => {
  var checked = e.target.checked;
  document.querySelectorAll('.webapp-select').forEach(function (cb) {
    cb.checked = checked;
    var id = parseInt(cb.value);
    if (checked) _selectedWebapps.add(id);
    else _selectedWebapps.delete(id);
  });
  updateWebappBulkToolbar();
});

// ─── Webapp column visibility ──────────────────────────────────
document.addEventListener('change', (e) => {
  var colCheck = e.target.closest('#col-dropdown-webapp [data-col]');
  if (!colCheck) return;
  var tbody = document.getElementById('webapp-table-body');
  var cols = colCheck.dataset.col;
  document.querySelectorAll('#webapp-table .' + cols).forEach(function (el) {
    el.style.display = colCheck.checked ? '' : 'none';
  });
});

// ─── Webapp form submit ─────────────────────────────────────────
document.getElementById('webapp-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  var id = document.getElementById('webapp-id').value;
  var data = {
    name: document.getElementById('webapp-name').value.trim(),
    url: document.getElementById('webapp-url').value.trim(),
    method: document.getElementById('webapp-method').value,
    expected_status: parseInt(document.getElementById('webapp-expected-status').value) || 200,
    expected_body: document.getElementById('webapp-expected-body').value.trim() || null,
    timeout: parseInt(document.getElementById('webapp-timeout').value) || 10,
    check_interval: parseInt(document.getElementById('webapp-check-interval').value) || 300,
    headers: document.getElementById('webapp-headers').value.trim() || null,
    body: document.getElementById('webapp-body').value || null,
    notes: document.getElementById('webapp-notes').value.trim(),
    notify_on_down: document.getElementById('webapp-notify-down').checked,
    notify_on_recovery: document.getElementById('webapp-notify-recovery').checked,
  };
  if (!data.name || !data.url) { toast('Name and URL are required', 'error'); return; }
  try {
    if (id) {
      await api('PUT', '/api/webapps/' + id, data);
    } else {
      await api('POST', '/api/webapps', data);
    }
    closeWebAppModal();
    loadWebApps(true);
    toast(id ? 'Web app updated' : 'Web app added');
  } catch (e) { toast(e.message, 'error'); }
});

// ─── Column visibility ─────────────────────────────────────────
document.addEventListener('change', (e) => {
  const colCheck = e.target.closest('[data-col]');
  if (!colCheck) return;
  const parent = colCheck.closest('.column-dropdown');
  const type = parent.id.includes('full') ? 'full' : 'ssl_only';
  _visibleCols[type] = {};
  parent.querySelectorAll('[data-col]').forEach(c => { _visibleCols[type][c.dataset.col] = c.checked; });
  applyColumnVisibility(type);
  saveViewPrefs(type);
});

// Close column dropdown on outside click
document.addEventListener('click', (e) => {
  if (!e.target.closest('.column-toggle')) {
    document.querySelectorAll('.column-dropdown').forEach(d => d.style.display = 'none');
  }
});

// ─── Sort state ───────────────────────────────────────────────────
let sortState = { full: { field: 'url', dir: 1 }, ssl_only: { field: 'url', dir: 1 } };

function _updateSortArrows(type, field, dir) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const sortBar = document.getElementById('sort-bar-' + suffix);
  if (sortBar) {
    sortBar.querySelectorAll('.sort-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.sort === field);
      const arrow = b.querySelector('.sort-arrow');
      if (arrow) arrow.innerHTML = b.dataset.sort === field ? (dir === 1 ? '&#9650;' : '&#9660;') : '';
    });
  }
  const table = document.getElementById('domain-table-' + suffix);
  if (table) {
    table.querySelectorAll('th[data-sort]').forEach(th => {
      th.classList.toggle('active', th.dataset.sort === field);
      const arrow = th.querySelector('.sort-arrow');
      if (arrow) arrow.innerHTML = th.dataset.sort === field ? (dir === 1 ? '&#9650;' : '&#9660;') : '';
    });
  }
}

document.addEventListener('click', (e) => {
  const btn = e.target.closest('.sort-btn[data-sort]');
  if (!btn) return;
  const field = btn.dataset.sort;
  const type = btn.dataset.type;
  const s = sortState[type];
  if (s.field === field) { s.dir *= -1; } else { s.field = field; s.dir = 1; }
  _updateSortArrows(type, field, s.dir);
  renderDomains(_cachedDomains[type], type);
  renderPagination(type);
});

document.addEventListener('click', (e) => {
  const th = e.target.closest('th[data-sort]');
  if (!th) return;
  const field = th.dataset.sort;
  const type = th.dataset.type;
  if (type === 'webapp') {
    var sel = document.getElementById('sort-webapp-select');
    if (!sel) return;
    var opt;
    if (_webappSort.key === field) { _webappSort.dir *= -1; } else { _webappSort.key = field; _webappSort.dir = 1; }
    for (var i = 0; i < sel.options.length; i++) {
      if (sel.options[i].value === field && parseInt(sel.options[i].dataset.dir) === _webappSort.dir) {
        sel.selectedIndex = i; break;
      }
    }
    _webappPagination.page = 0;
    applyWebAppFilters(_webappsCache || []);
    return;
  }
  const s = sortState[type];
  if (s.field === field) { s.dir *= -1; } else { s.field = field; s.dir = 1; }
  _updateSortArrows(type, field, s.dir);
  renderDomains(_cachedDomains[type], type);
  renderPagination(type);
});

// ─── Column resize ────────────────────────────────────────────
let _resizeState = null;

document.addEventListener('mousedown', (e) => {
  const handle = e.target.closest('.col-resize-handle');
  if (!handle) return;
  const th = handle.closest('th');
  if (!th) return;
  const table = th.closest('table');
  if (!table) return;
  _resizeState = { th, table, startX: e.clientX, startW: th.offsetWidth };
  document.body.style.cursor = 'col-resize';
  document.body.style.userSelect = 'none';
  e.preventDefault();
});

document.addEventListener('mousemove', (e) => {
  if (!_resizeState) return;
  const { th, table, startX, startW } = _resizeState;
  const diff = e.clientX - startX;
  const newW = Math.max(40, startW + diff);
  const colIdx = Array.from(th.parentNode.children).indexOf(th);
  th.style.width = newW + 'px';
  table.querySelectorAll('tbody tr').forEach(tr => {
    const cell = tr.children[colIdx];
    if (cell) cell.style.width = newW + 'px';
  });
});

document.addEventListener('mouseup', () => {
  if (!_resizeState) return;
  _resizeState = null;
  document.body.style.cursor = '';
  document.body.style.userSelect = '';
});


// ─── Select All ───────────────────────────────────────────────────
document.addEventListener('change', (e) => {
  const el = e.target.closest('#select-all-full, #select-all-ssl');
  if (!el) return;
  const isSsl = el.id === 'select-all-ssl';
  const selSet = isSsl ? selectedSsl : selectedDomains;
  const checked = el.checked;
  const type = isSsl ? 'ssl_only' : 'full';
  const domains = getPageItems(getFilteredDomains(type), type);
  domains.forEach(d => { if (checked) selSet.add(d.id); else selSet.delete(d.id); });
  document.querySelectorAll(`input[data-${isSsl ? 'ssl' : 'domain'}-check]`).forEach(cb => cb.checked = checked);
  updateBulkToolbar(type);
});

// ─── Log filter ───────────────────────────────────────────────────
document.addEventListener('click', (e) => {
  const chip = e.target.closest('#log-filters .log-filter[data-log-filter]');
  if (!chip) return;
  document.querySelectorAll('#log-filters .log-filter').forEach(c => c.classList.remove('active'));
  chip.classList.add('active');
  logState.filter = chip.dataset.logFilter;
  logState.page = 1;
  refreshLogs();
});

document.getElementById('log-limit').addEventListener('change', () => {
  logState.limit = parseInt(document.getElementById('log-limit').value);
  logState.page = 1;
  refreshLogs();
});

let _logSearchTimer = null;
document.getElementById('log-search').addEventListener('input', (e) => {
  logState.query = e.target.value.trim();
  logState.page = 1;
  clearTimeout(_logSearchTimer);
  _logSearchTimer = setTimeout(() => refreshLogs(), 250);
});

// ─── Domain filter chips ─────────────────────────────────────────
document.addEventListener('click', (e) => {
  const chip = e.target.closest('[data-domain-filter]');
  if (chip) {
    const parent = chip.closest('.domain-filters');
    const type = parent.id === 'ssl-domain-filters' ? 'ssl_only' : 'full';
    parent.querySelectorAll('.log-filter').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    _domainFilter[type] = chip.dataset.domainFilter;
    _pagination[type].page = 1;
    applyDomainFilters(type);
    return;
  }
  const sslChip = e.target.closest('[data-ssl-filter]');
  if (sslChip) {
    const parent = sslChip.closest('.domain-filters');
    parent.querySelectorAll('.log-filter').forEach(c => c.classList.remove('active'));
    sslChip.classList.add('active');
    _domainFilter.ssl_only = sslChip.dataset.sslFilter;
    _pagination.ssl_only.page = 1;
    applyDomainFilters('ssl_only');
    return;
  }
});

// ─── TLD filter ─────────────────────────────────────────────────
document.getElementById('tld-filter').addEventListener('change', (e) => {
  _tldFilter.full = e.target.value;
  _pagination.full.page = 1;
  applyDomainFilters('full');
});
document.getElementById('ssl-tld-filter').addEventListener('change', (e) => {
  _tldFilter.ssl_only = e.target.value;
  _pagination.ssl_only.page = 1;
  applyDomainFilters('ssl_only');
});

// ─── Group by status toggle ─────────────────────────────────────
document.getElementById('group-by-status').addEventListener('change', (e) => {
  _groupByStatus.full = e.target.checked;
  applyDomainFilters('full');
});
document.getElementById('ssl-group-by-status').addEventListener('change', (e) => {
  _groupByStatus.ssl_only = e.target.checked;
  applyDomainFilters('ssl_only');
});
document.getElementById('webapp-group-by-status').addEventListener('change', (e) => {
  _webappGroupByStatus = e.target.checked;
  applyWebAppFilters(_webappsCache || []);
});

// Search filtering (debounced)
let _searchTimers = {};
['domain-search', 'ssl-search'].forEach(id => {
  document.getElementById(id).addEventListener('input', (e) => {
    const type = id === 'ssl-search' ? 'ssl_only' : 'full';
    clearTimeout(_searchTimers[id]);
    _pagination[type].page = 1;
    _searchTimers[id] = setTimeout(() => applyDomainFilters(type), 200);
  });
});

// ─── Settings tab switching ────────────────────────────────────
document.addEventListener('click', (e) => {
  const tab = e.target.closest('.settings-tab');
  if (!tab) return;
  switchSettingsTab(tab.dataset.stab);
});

function switchSettingsTab(stab) {
  document.querySelectorAll('.settings-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.settings-pane').forEach(p => p.classList.remove('active'));
  var tab = document.querySelector('.settings-tab[data-stab="' + stab + '"]');
  if (tab) tab.classList.add('active');
  var pane = document.getElementById('stab-' + stab);
  if (pane) pane.classList.add('active');
  try { localStorage.setItem('vigil-settings-tab', stab); } catch (e) {}
  if (stab === 'users') loadUsers();
  if (stab === 'apikeys') loadApiKeys();
  if (stab === 'backups') loadBackups();
  if (stab === 'emailtpl') loadEmailTemplates();
}

// ─── Toast (stacking) ───────────────────────────────────────────
function toast(msg, type = 'success') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.innerHTML = `<span>${msg}</span><button class="toast-close">&times;</button>`;
  container.appendChild(el);
  const close = () => { el.classList.add('removing'); setTimeout(() => el.remove(), 200); };
  el.querySelector('.toast-close').onclick = close;
  const duration = type === 'error' ? 8000 : 3500;
  setTimeout(close, duration);
}

// ─── API helper ────────────────────────────────────────────────
async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  if (method !== 'GET' && _csrfToken) {
    opts.headers['X-CSRF-Token'] = _csrfToken;
  }
  const res = await fetch(path, opts);
  const newToken = res.headers.get('X-CSRF-Token');
  if (newToken) _csrfToken = newToken;
  if (res.status === 401) {
    window.location.href = '/';
    return;
  }
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function _toUtcIso(dateStr) {
  if (!dateStr) return '';
  dateStr = dateStr.trim().replace(' ', 'T');
  if (/Z$|[+-]\d{2}:?\d{2}$/.test(dateStr)) return dateStr;
  return dateStr + 'Z';
}

function formatDate(dateStr) {
  if (!dateStr) return '';
  var d = new Date(_toUtcIso(dateStr));
  if (isNaN(d.getTime())) return dateStr;
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function relativeTime(dateStr) {
  if (!dateStr) return '';
  var d = new Date(_toUtcIso(dateStr));
  if (isNaN(d.getTime())) return dateStr;
  var diff = Date.now() - d.getTime();
  if (diff < 0) return 'just now';
  var sec = Math.floor(diff / 1000);
  if (sec < 60) return sec + 's ago';
  var min = Math.floor(sec / 60);
  if (min < 60) return min + 'm ago';
  var hr = Math.floor(min / 60);
  if (hr < 24) return hr + 'h ago';
  var days = Math.floor(hr / 24);
  if (days < 30) return days + 'd ago';
  return Math.floor(days / 30) + 'mo ago';
}

function formatDuration(ms) {
  if (ms <= 0) return 'now';
  var h = Math.floor(ms / 3600000);
  var m = Math.floor((ms % 3600000) / 60000);
  var parts = [];
  if (h > 0) parts.push(h + 'h');
  if (m > 0) parts.push(m + 'm');
  return parts.length ? parts.join(' ') : '0m';
}

function formatCountdownText(nextRun) {
  return formatDuration(new Date(nextRun) - Date.now());
}

function escHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

function toggleTheme() {
  const isLight = document.body.classList.toggle('light');
  localStorage.setItem('theme', isLight ? 'light' : 'dark');
  document.querySelector('.theme-icon-sun').style.display = isLight ? 'none' : '';
  document.querySelector('.theme-icon-moon').style.display = isLight ? '' : 'none';
}

function initTheme() {
  const saved = localStorage.getItem('theme');
  const isLight = saved === 'light';
  document.body.classList.toggle('light', isLight);
  const sun = document.querySelector('.theme-icon-sun');
  const moon = document.querySelector('.theme-icon-moon');
  if (sun) sun.style.display = isLight ? 'none' : '';
  if (moon) moon.style.display = isLight ? '' : 'none';
}

// ─── Dashboard ─────────────────────────────────────────────────
let _dashSummaryCache = { data: null, ts: 0, ttl: 30000 };
let _prevHealth = null;

async function loadDashboard(force = false) {
  const now = Date.now();
  if (!force && _dashSummaryCache.data && now - _dashSummaryCache.ts < _dashSummaryCache.ttl) {
    const [sched, sysinfo] = await Promise.all([
      api('GET', '/api/scheduler/status'),
      api('GET', '/api/system/info')
    ]);
    const summary = _dashSummaryCache.data;
    renderDashboardSummary(summary, sched);
    renderSystemInfo(sysinfo);
    return;
  }
  try {
    const [summary, sched, sysinfo] = await Promise.all([
      api('GET', '/api/dashboard/summary'),
      api('GET', '/api/scheduler/status'),
      api('GET', '/api/system/info')
    ]);
    _dashSummaryCache.data = summary;
    _dashSummaryCache.ts = now;
    renderDashboardSummary(summary, sched);
    renderSystemInfo(sysinfo);
    updateLastRefreshed();
    applyCollapseStates();
  } catch (e) {
    toast(e.message, 'error');
  }
}

function updateLastRefreshed() {
  const el = document.getElementById('last-refreshed');
  if (el) el.textContent = `Last refreshed: ${new Date().toLocaleTimeString()}`;
}

function openQuickAddModal() {
  document.getElementById('quickadd-modal').classList.add('open');
  document.getElementById('quickadd-url').focus();
}

function closeQuickAddModal() {
  document.getElementById('quickadd-modal').classList.remove('open');
  document.getElementById('quickadd-url').value = '';
}

document.getElementById('quickadd-form').addEventListener('submit', function (e) {
  e.preventDefault();
  var url = document.getElementById('quickadd-url').value.trim();
  var type = document.getElementById('quickadd-type').value;
  if (!url) return;
  var btn = document.getElementById('btn-quickadd-save');
  setLoading(btn, true);
  api('POST', '/api/domains', { url: url, type: type }).then(function () {
    toast('Domain added');
    closeQuickAddModal();
    clearDomainsCache();
    loadDashboard(true);
  }).catch(function (e) {
    toast(e.message, 'error');
  }).finally(function () {
    setLoading(btn, false);
  });
});

function renderDashboardSummary(summary, sched) {
  const { full_stats: fStats, ssl_stats: sStats, full_count, ssl_count, reachable, total, ssl_expiring, domain_expiring, expiry_buckets, last_check, snapshots, webapp_stats } = summary;
  const wStats = webapp_stats || { up: 0, down: 0, slow: 0, unknown: 0, total: 0 };

  document.getElementById('dash-counts').textContent = `${full_count} domains + ${ssl_count} SSL`;

  // Health scores
  const domainPct = full_count > 0 ? Math.round((fStats.healthy / full_count) * 100) : 0;
  const sslPct = ssl_count > 0 ? Math.round((sStats.healthy / ssl_count) * 100) : 0;
  const reachPct = total > 0 ? Math.round((reachable / total) * 100) : 0;

  setHealth('dash-domain-health', domainPct);
  setHealth('dash-ssl-health', sslPct);
  setHealth('dash-reachable', reachPct);
  const webappPct = wStats.total > 0 ? Math.round((wStats.up / wStats.total) * 100) : 0;
  setHealth('dash-webapp-health', webappPct);

  // Changed indicator
  if (_prevHealth !== null) {
    const dDiff = domainPct - _prevHealth.domain;
    const sDiff = sslPct - _prevHealth.ssl;
    const wDiff = webappPct - (_prevHealth.webapp || 0);
    const parts = [];
    if (dDiff !== 0) parts.push(`Domain health <span class="${dDiff > 0 ? 'chg-up' : 'chg-down'}">${dDiff > 0 ? '+' : ''}${dDiff}%</span>`);
    if (sDiff !== 0) parts.push(`SSL health <span class="${sDiff > 0 ? 'chg-up' : 'chg-down'}">${sDiff > 0 ? '+' : ''}${sDiff}%</span>`);
    if (wDiff !== 0) parts.push(`API health <span class="${wDiff > 0 ? 'chg-up' : 'chg-down'}">${wDiff > 0 ? '+' : ''}${wDiff}%</span>`);
    const el = document.getElementById('dash-changed');
    if (parts.length > 0) { el.innerHTML = 'Since last check: ' + parts.join(', '); el.classList.add('visible'); }
    else { el.classList.remove('visible'); }
  }
  _prevHealth = { domain: domainPct, ssl: sslPct, webapp: webappPct };

  // Stats with count-up
  const animStat = (id, v) => animateCount(document.getElementById(id), v);
  animStat('dash-full-total', full_count);
  animStat('dash-full-healthy', fStats.healthy);
  animStat('dash-full-warning', fStats.caution + fStats.warning + fStats.critical);
  animStat('dash-full-danger', fStats.expired);
  animStat('dash-full-error', fStats.error);
  animStat('dash-full-pending', fStats.pending);
  animStat('dash-ssl-total', ssl_count);
  animStat('dash-ssl-healthy', sStats.healthy);
  animStat('dash-ssl-warning', sStats.watch + sStats.caution + sStats.warning);
  animStat('dash-ssl-danger', sStats.expired);
  animStat('dash-ssl-error', sStats.error);
  animStat('dash-ssl-pending', sStats.pending);
  animStat('dash-webapp-total', wStats.total);
  animStat('dash-webapp-up', wStats.up);
  animStat('dash-webapp-down', wStats.down + wStats.slow);
  animStat('dash-webapp-unknown', wStats.unknown);

  const issueCount = fStats.expired + fStats.error + sStats.expired + sStats.error + wStats.down + wStats.slow;
  document.getElementById('hero-issue-count').textContent = issueCount;
  document.getElementById('hero-next-check').textContent = sched && sched.next_run ? formatCountdownText(sched.next_run) : 'Not scheduled';
  document.getElementById('hero-scheduler-note').textContent = sched && sched.next_run ? `Next run in ${formatDuration(new Date(sched.next_run) - Date.now())}` : 'Scheduler active — waiting for next run.';

  renderSchedulerStatus(sched, last_check);
  renderSparkline(snapshots);
  renderExpiringList('ssl-expiring-list', ssl_expiring);
  renderExpiringList('domain-expiring-list', domain_expiring);
  renderExpiryBuckets(expiry_buckets);
}

function formatUptime(seconds) {
  var d = Math.floor(seconds / 86400);
  var h = Math.floor((seconds % 86400) / 3600);
  var m = Math.floor((seconds % 3600) / 60);
  var parts = [];
  if (d > 0) parts.push(d + 'd');
  if (h > 0) parts.push(h + 'h');
  if (m > 0) parts.push(m + 'm');
  if (parts.length === 0) parts.push('0m');
  return parts.join(' ');
}

function renderSystemInfo(info) {
  var tbody = document.getElementById('sysinfo-table');
  if (!tbody) return;
  var rows = [
    ['Version', escHtml(info.version)],
    ['Uptime', formatUptime(info.uptime_seconds)],
    ['Started at', info.app_started_at],
    ['API response time', info.api_response_time_ms + 'ms'],
    ['Total domains', info.total_domains],
    ['Total web apps', info.total_webapps],
    ['Total users', info.total_users],
    ['Scheduler', info.scheduler_active ? 'Active' : 'Idle'],
  ];
  tbody.innerHTML = rows.map(function (r) {
    return '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td></tr>';
  }).join('');
}

// ─── Web Apps ──────────────────────────────────────────────────
let _webappsCache = null;
let _webappViewMode = 'cards';
let _webappFilter = 'all';
let _webappSort = { key: 'name', dir: 1 };
let _webappPagination = { page: 0, size: 25 };
let _selectedWebapps = new Set();
let _webappGroupByStatus = false;

function escUrl(u) {
  return escHtml(u.length > 60 ? u.slice(0, 57) + '...' : u);
}

function formatDurationLong(seconds) {
  if (seconds == null) return 'N/A';
  if (seconds < 60) return '< 1m';
  var min = Math.floor(seconds / 60);
  if (min < 60) return min + 'm';
  var hr = Math.floor(min / 60);
  if (hr < 24) return formatDurationCompact(hr, min % 60, 0, 0);
  var days = Math.floor(hr / 24);
  if (days < 30) return formatDurationCompact(0, 0, days, hr % 24);
  var months = Math.floor(days / 30);
  var remDays = days % 30;
  if (months < 12) return months + 'mo ' + remDays + 'd';
  var years = Math.floor(months / 12);
  return years + 'yr ' + (months % 12) + 'mo';
}
function formatDurationCompact(h, m, d, hr) {
  var parts = [];
  if (d > 0) parts.push(d + 'd');
  if (hr > 0) parts.push(hr + 'h');
  if (m > 0) parts.push(m + 'm');
  if (h > 0) parts.push(h + 'h');
  return parts.join(' ') || '0m';
}

function openWebAppDetail(wa) {
  var modal = document.getElementById('webapp-detail-modal');
  document.getElementById('webapp-detail-title').textContent = wa.name || wa.url;
  document.getElementById('detail-wa-url').textContent = wa.url || '';

  var status = wa.status || 'unknown';
  var isUp = status === 'up' || status === 'slow';
  var badge = document.getElementById('detail-wa-status-badge');
  badge.textContent = status.toUpperCase();
  badge.className = 'wa-detail-status-badge ' + (isUp ? 'status-up' : status === 'slow' ? 'status-slow' : 'status-down');

  var interval = wa.check_interval || 300;
  document.getElementById('detail-wa-interval').textContent = interval >= 3600 ? Math.round(interval / 3600) + 'h' : interval >= 60 ? Math.round(interval / 60) + 'm' : interval + 's';
  document.getElementById('detail-wa-last-checked-ago').textContent = wa.last_checked ? relativeTime(wa.last_checked) : 'Never';

  var durationEl = document.getElementById('detail-wa-current-duration');
  durationEl.textContent = 'Loading...';
  var chartEl = document.getElementById('detail-wa-chart');
  chartEl.innerHTML = 'Loading...';
  var incidentsEl = document.getElementById('detail-wa-incidents');
  incidentsEl.innerHTML = '';

  api('GET', '/api/webapps/' + wa.id + '/detail').then(function (resp) {
    var stats = resp.stats;
    var webapp = resp.webapp;

    durationEl.textContent = isUp
      ? 'Up for ' + formatDurationLong(stats.current_duration_seconds)
      : (stats.current_duration_seconds != null ? 'Down for ' + formatDurationLong(stats.current_duration_seconds) : '');

    function renderUptimeBar(period) {
      var pct = stats.uptime[period].uptime_pct;
      var incidents = stats.uptime[period].incidents;
      var downMin = stats.uptime[period].downtime_minutes;
      document.getElementById('uptime-' + period + '-pct').textContent = pct != null ? pct + '%' : '—';
      document.getElementById('uptime-' + period + '-bar').style.width = (pct != null ? pct : 0) + '%';
      document.getElementById('uptime-' + period + '-incidents').textContent = (incidents || 0);
      document.getElementById('uptime-' + period + '-down').textContent = (downMin || 0);
    }
    renderUptimeBar('24h');
    renderUptimeBar('7d');
    renderUptimeBar('30d');
    renderUptimeBar('365d');

    document.getElementById('detail-wa-avg-rt').textContent = stats.avg_response_time_ms != null ? stats.avg_response_time_ms + 'ms' : '—';
    document.getElementById('detail-wa-min-rt').textContent = stats.min_response_time_ms != null ? stats.min_response_time_ms + 'ms' : '—';
    document.getElementById('detail-wa-max-rt').textContent = stats.max_response_time_ms != null ? stats.max_response_time_ms + 'ms' : '—';
    document.getElementById('detail-wa-last-rt').textContent = webapp.response_time_ms != null ? webapp.response_time_ms + 'ms' : '—';

    if (stats.incidents && stats.incidents.length) {
      incidentsEl.innerHTML = stats.incidents.slice().reverse().map(function (inc) {
        var icon = inc.to === 'up' || inc.to === 'slow' ? '&#9673;' : '&#9888;';
        var cls = inc.to === 'up' || inc.to === 'slow' ? 'healthy' : 'expired';
        return '<div class="incident-row">' +
          '<span class="incident-icon ' + cls + '">' + icon + '</span>' +
          '<span class="incident-dir">' + inc.from.toUpperCase() + ' &rarr; ' + inc.to.toUpperCase() + '</span>' +
          '<span class="incident-time">' + relativeTime(inc.at) + '</span>' +
          '</div>';
      }).join('');
    } else {
      incidentsEl.innerHTML = '<div class="text-muted" style="padding:8px 0">No incidents recorded.</div>';
    }
  }).catch(function () {
    durationEl.textContent = '—';
    chartEl.innerHTML = '<span class="text-muted">Failed to load detail data</span>';
    incidentsEl.innerHTML = '';
  });

  api('GET', '/api/webapps/' + wa.id + '/results?days=7').then(function (data) {
    var rts = data.filter(function (d) { return d.response_time_ms != null; }).map(function (d) { return d.response_time_ms; });
    if (rts.length < 2) {
      chartEl.innerHTML = '<span class="text-muted">Not enough data</span>';
    } else {
      var w = chartEl.offsetWidth || 500;
      var h = 120;
      var pad = 4;
      var max = Math.max.apply(null, rts);
      var min = Math.min.apply(null, rts);
      var range = max - min || 1;
      var color = getComputedStyle(document.body).getPropertyValue('--primary').trim() || '#3b82f6';
      var areaColor = color + '22';
      var pts = rts.map(function (v, i) {
        var x = (i / (rts.length - 1)) * (w - pad * 2) + pad;
        var y = h - ((v - min) / range) * (h - pad * 2) - pad;
        return x + ',' + y;
      }).join(' ');
      var areaPts = pad + ',' + (h - pad) + ' ' + pts + ' ' + (w - pad) + ',' + (h - pad);
      chartEl.innerHTML = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '" style="display:block;width:100%;height:120px">' +
        '<polygon fill="' + areaColor + '" points="' + areaPts + '"/>' +
        '<polyline fill="none" stroke="' + color + '" stroke-width="2" points="' + pts + '"/>' +
        '</svg>';
    }
  }).catch(function () { chartEl.innerHTML = '<span class="text-muted">Failed to load</span>'; });

  modal.classList.add('open');
}

function showWebappSkeleton(show) {
  var list = document.getElementById('webapp-list');
  var sk = document.getElementById('webapp-skeleton');
  if (!sk) return;
  if (show) {
    list.style.display = 'none';
    sk.style.display = '';
    if (!sk.querySelector('.skeleton-card')) {
      sk.innerHTML = Array(6).fill('<div class="skeleton-card"><div class="sk-badge"></div><div class="sk-block"><div class="sk-row"></div><div class="sk-row"></div></div></div>').join('');
    }
  } else {
    sk.style.display = 'none';
    list.style.display = '';
  }
}

function loadWebApps(force) {
  if (force) _webappSparklineCache = {};
  showWebappSkeleton(true);
  var path = '/api/webapps' + (force ? '?_=' + Date.now() : '');
  api('GET', path).then(function (apps) {
    _webappsCache = apps;
    showWebappSkeleton(false);
    renderWebApps(apps);
    var empty = document.getElementById('empty-state-webapp');
    if (empty) empty.style.display = apps.length ? 'none' : '';
  }).catch(function (e) { showWebappSkeleton(false); toast(e.message, 'error'); });
}

function renderWebApps(apps) {
  renderWebAppStats(apps);
  applyWebAppFilters(apps);
}

function renderWebAppStats(apps) {
  var total = apps.length;
  var up = apps.filter(function (a) { return a.status === 'up'; }).length;
  var down = apps.filter(function (a) { return a.status === 'down'; }).length;
  var slow = apps.filter(function (a) { return a.status === 'slow'; }).length;
  var unknown = apps.filter(function (a) { return a.status === 'unknown' || !a.status; }).length;
  var rts = apps.filter(function (a) { return a.response_time_ms != null; }).map(function (a) { return a.response_time_ms; });
  var avg = rts.length ? Math.round(rts.reduce(function (a, b) { return a + b; }, 0) / rts.length) : '—';
  var ids = { 'all': total, 'up': up, 'down': down, 'slow': slow, 'unknown': unknown };
  Object.keys(ids).forEach(function (k) {
    var el = document.getElementById('wa-count-' + k);
    if (el) el.textContent = ids[k];
  });
  var avgEl = document.getElementById('wa-avg-response');
  if (avgEl) avgEl.textContent = avg === '—' ? '' : 'Avg ' + avg + 'ms';
}

function applyWebAppFilters(apps) {
  var filtered = apps;
  var f = _webappFilter;
  if (f !== 'all') filtered = apps.filter(function (a) { return (a.status || 'unknown') === f; });

  var q = (document.getElementById('webapp-search').value || '').toLowerCase().trim();
  if (q) filtered = filtered.filter(function (a) {
    return (a.name || '').toLowerCase().indexOf(q) !== -1 ||
           (a.url || '').toLowerCase().indexOf(q) !== -1;
  });

  var s = _webappSort;
  filtered.sort(function (a, b) {
    var va, vb;
    if (s.key === 'name') { va = (a.name || '').toLowerCase(); vb = (b.name || '').toLowerCase(); }
    else if (s.key === 'url') { va = (a.url || '').toLowerCase(); vb = (b.url || '').toLowerCase(); }
    else if (s.key === 'status') { va = a.status || 'unknown'; vb = b.status || 'unknown'; }
    else if (s.key === 'response_time') { va = a.response_time_ms || 999999; vb = b.response_time_ms || 999999; }
    else if (s.key === 'uptime_pct') {
      var ta = a.total_checks || 0, tb = b.total_checks || 0;
      va = ta ? ((a.successful_checks || 0) / ta) : 0;
      vb = tb ? ((b.successful_checks || 0) / tb) : 0;
    }
    else if (s.key === 'checked') {
      va = a.last_checked || ''; vb = b.last_checked || '';
      if (va < vb) return -1 * s.dir; if (va > vb) return 1 * s.dir; return 0;
    }
    if (va < vb) return -1 * s.dir; if (va > vb) return 1 * s.dir; return 0;
  });

  document.getElementById('webapp-result').textContent = 'Showing ' + filtered.length + ' web apps';
  var clearBtn = document.querySelector('[data-action="clear-webapp-filters"]');
  if (clearBtn) clearBtn.style.display = (f !== 'all' || q) ? '' : 'none';

  renderWebAppPagination(filtered);
  if (_webappViewMode === 'table') renderWebAppTable(filtered);
  else renderWebAppCards(filtered);
}

function renderWebAppCardHtml(a) {
  var st = a.status || 'unknown';
  var cls = st === 'up' ? 'healthy' : st === 'down' ? 'expired' : st === 'slow' ? 'warning' : 'pending';
  var rt = a.response_time_ms != null ? a.response_time_ms + 'ms' : '—';
  var code = a.last_status_code || '—';
  var checked = a.last_checked ? relativeTime(a.last_checked) : 'Never';
  var total = a.total_checks || 0;
  var uptimePct = total ? Math.round((a.successful_checks || 0) / total * 100) + '%' : '—';
  var paused = a.is_active === 0 || a.is_active === false;
  return '<div class="domain-card card-' + cls + (_selectedWebapps.has(a.id) ? ' selected' : '') + (paused ? ' paused' : '') + '" data-webapp-id="' + a.id + '">' +
    '<label class="bulk-check"><input type="checkbox" class="webapp-select" value="' + a.id + '"' + (_selectedWebapps.has(a.id) ? ' checked' : '') + '></label>' +
    '<div class="card-body' + (paused ? ' opacity-50' : '') + '" data-action="webapp-detail" data-id="' + a.id + '">' +
    '<div class="card-top">' +
    '<span class="domain-badge status-badge ' + cls + '">' + st.toUpperCase() + (paused ? ' (PAUSED)' : '') + '</span>' +
    '<strong class="card-url">' + escHtml(a.name || a.url) + '</strong>' +
    '<span class="card-time">' + escUrl(a.url) + '</span>' +
    '</div>' +
    '<div class="card-meta"><span>Response: ' + rt + '</span><span>HTTP ' + code + '</span><span>Uptime: ' + uptimePct + '</span><span>Checked: ' + checked + '</span></div>' +
    '<div class="webapp-sparkline" id="spark-wa-' + a.id + '" style="height:40px;margin-top:4px"></div>' +
    '</div>' +
    '<div class="card-actions">' +
    '<div class="actions-dropdown">' +
    '<button class="btn btn-sm btn-secondary" data-action="toggle-actions-dropdown">Actions &#9662;</button>' +
    '<div class="actions-dropdown-content">' +
    '<button data-action="webapp-check-now" data-id="' + a.id + '">&#x21bb; Check Now</button>' +
    '<button data-action="webapp-detail" data-id="' + a.id + '">&#x1F50D; View Details</button>' +
    '<button data-action="webapp-toggle-active" data-id="' + a.id + '">' + (paused ? '&#x25B6; Resume' : '&#x23F8; Pause') + '</button>' +
    '<button data-action="webapp-edit" data-id="' + a.id + '">&#x270E; Edit</button>' +
    '<button data-action="webapp-delete" data-id="' + a.id + '">&#x1F5D1; Delete</button>' +
    '</div></div></div></div>';
}

function renderWebAppCards(apps) {
  var container = document.getElementById('webapp-list');
  document.getElementById('webapp-table').style.display = 'none';
  container.style.display = '';
  var pg = _webappPagination;
  var start = pg.page * pg.size;
  var page = apps.slice(start, start + pg.size);

  if (page.length === 0 && apps.length > 0) {
    pg.page = Math.max(0, Math.ceil(apps.length / pg.size) - 1);
    start = pg.page * pg.size;
    page = apps.slice(start, start + pg.size);
  }

  if (page.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-illustration"><svg width="60" height="60" viewBox="0 0 80 80" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3"><circle cx="40" cy="40" r="28"/><path d="M30 40l8 8 14-14"/></svg></div><p>No web apps match your filters.</p><div class="empty-actions"><button class="btn btn-sm btn-secondary" data-action="clear-webapp-filters">Clear Filters</button></div></div>';
    updateWebappBulkToolbar();
    return;
  }

  if (_webappGroupByStatus) {
    var order = ['up', 'down', 'slow', 'unknown'];
    var groups = {};
    order.forEach(function (s) { groups[s] = []; });
    page.forEach(function (a) {
      var st = a.status || 'unknown';
      if (!groups[st]) groups[st] = [];
      groups[st].push(a);
    });
    var html = '';
    order.forEach(function (st) {
      if (!groups[st].length) return;
      var lbl = st.charAt(0).toUpperCase() + st.slice(1);
      html += '<div class="status-group">' +
        '<div class="status-group-header" data-action="toggle-group" data-key="wa-' + st + '">' +
        '<span class="chevron">&#9660;</span>' +
        '<span class="status-label">' + lbl + '</span>' +
        '<span class="status-group-count">(' + groups[st].length + ')</span></div>' +
        '<div class="status-group-body">' +
        groups[st].map(function (a) { return renderWebAppCardHtml(a); }).join('') +
        '</div></div>';
    });
    container.innerHTML = html;
  } else {
    container.innerHTML = page.map(function (a) { return renderWebAppCardHtml(a); }).join('');
  }

  updateWebappBulkToolbar();
  page.forEach(function (a) {
    if (a.id && a.status) loadWebappSparkline(a.id);
  });
}

function renderWebAppTable(apps) {
  document.getElementById('webapp-list').style.display = 'none';
  document.getElementById('webapp-table').style.display = '';
  var tbody = document.getElementById('webapp-table-body');
  var pg = _webappPagination;
  var start = pg.page * pg.size;
  var page = apps.slice(start, start + pg.size);

  if (page.length === 0 && apps.length > 0) {
    pg.page = Math.max(0, Math.ceil(apps.length / pg.size) - 1);
    start = pg.page * pg.size;
    page = apps.slice(start, start + pg.size);
  }

  tbody.innerHTML = page.map(function (a) {
    var st = a.status || 'unknown';
    var cls = st === 'up' ? 'healthy' : st === 'down' ? 'expired' : st === 'slow' ? 'warning' : 'pending';
    var rt = a.response_time_ms != null ? a.response_time_ms + 'ms' : '—';
    var code = a.last_status_code || '—';
    var checked = a.last_checked ? relativeTime(a.last_checked) : 'Never';
    var sel = _selectedWebapps.has(a.id) ? ' class="selected"' : '';
    var total = a.total_checks || 0;
    var uptimePct = total ? Math.round((a.successful_checks || 0) / total * 100) + '%' : '—';
    var paused = a.is_active === 0 || a.is_active === false;
    return '<tr' + sel + '>' +
      '<td class="col-checkbox"><input type="checkbox" class="webapp-select" value="' + a.id + '"' + (_selectedWebapps.has(a.id) ? ' checked' : '') + '></td>' +
      '<td class="col-name">' + escHtml(a.name) + (paused ? ' <span class="text-muted">(paused)</span>' : '') + '</td>' +
      '<td class="col-url" title="' + escHtml(a.url) + '">' + escUrl(a.url) + '</td>' +
      '<td class="col-status"><span class="domain-badge status-badge ' + cls + '">' + st.toUpperCase() + '</span></td>' +
      '<td class="col-response">' + rt + '</td>' +
      '<td class="col-code">' + code + '</td>' +
      '<td class="col-uptime">' + uptimePct + '</td>' +
      '<td class="col-sparkline"><div class="webapp-sparkline" id="spark-wa-' + a.id + '" style="height:40px"></div></td>' +
      '<td class="col-checked">' + checked + '</td>' +
      '<td class="col-actions">' +
      '<div class="actions-dropdown">' +
      '<button class="btn btn-sm btn-secondary" data-action="toggle-actions-dropdown">Actions &#9662;</button>' +
      '<div class="actions-dropdown-content">' +
      '<button data-action="webapp-check-now" data-id="' + a.id + '">&#x21bb; Check Now</button>' +
      '<button data-action="webapp-detail" data-id="' + a.id + '">&#x1F50D; View Details</button>' +
      '<button data-action="webapp-toggle-active" data-id="' + a.id + '">' + (paused ? '&#x25B6; Resume' : '&#x23F8; Pause') + '</button>' +
      '<button data-action="webapp-edit" data-id="' + a.id + '">&#x270E; Edit</button>' +
      '<button data-action="webapp-delete" data-id="' + a.id + '">&#x1F5D1; Delete</button>' +
      '</div></div></td></tr>';
  }).join('') || '<tr><td colspan="10" class="empty-state"><p>No web apps match your filters.</p></td></tr>';
  updateWebappBulkToolbar();
  page.forEach(function (a) {
    if (a.id && a.status) loadWebappSparkline(a.id);
  });
}

function renderWebAppPagination(apps) {
  var pg = _webappPagination;
  var total = apps.length;
  var pages = Math.ceil(total / pg.size) || 1;
  if (pg.page >= pages) pg.page = pages - 1;
  var start = pg.page * pg.size;
  var end = Math.min(start + pg.size, total);
  var wrapper = document.getElementById('pagination-webapp');
  if (total <= pg.size) { wrapper.style.display = 'none'; return; }
  wrapper.style.display = '';
  document.getElementById('page-from-webapp').textContent = total ? start + 1 : 0;
  document.getElementById('page-to-webapp').textContent = end;
  document.getElementById('page-total-webapp').textContent = total;
  document.getElementById('page-first-webapp').disabled = pg.page === 0;
  document.getElementById('page-prev-webapp').disabled = pg.page === 0;
  document.getElementById('page-next-webapp').disabled = pg.page >= pages - 1;
  document.getElementById('page-last-webapp').disabled = pg.page >= pages - 1;
}

function updateWebappBulkToolbar() {
  var count = _selectedWebapps.size;
  var tb = document.getElementById('webapp-bulk-toolbar');
  if (!tb) return;
  tb.style.display = count > 0 ? '' : 'none';
  document.getElementById('webapp-bulk-count').textContent = count + ' selected';

  // Check all checkbox sync
  var firstCheck = document.querySelector('.webapp-select');
  var allCheck = document.getElementById('select-all-webapp');
  if (allCheck && firstCheck) {
    var checks = document.querySelectorAll('.webapp-select');
    var allChecked = true;
    checks.forEach(function (c) { if (!c.checked) allChecked = false; });
    allCheck.checked = allChecked && checks.length > 0;
  }
}

function openWebAppModal(app) {
  var modal = document.getElementById('webapp-modal');
  document.getElementById('webapp-id').value = app ? app.id : '';
  document.getElementById('webapp-modal-title').textContent = app ? 'Edit Web App' : 'Add Web App';
  document.getElementById('webapp-name').value = app ? app.name : '';
  document.getElementById('webapp-url').value = app ? app.url : '';
  document.getElementById('webapp-method').value = app ? (app.method || 'GET') : 'GET';
  document.getElementById('webapp-expected-status').value = app ? (app.expected_status || 200) : 200;
  document.getElementById('webapp-expected-body').value = app ? (app.expected_body || '') : '';
  document.getElementById('webapp-timeout').value = app ? (app.timeout || 10) : 10;
  document.getElementById('webapp-check-interval').value = app ? (app.check_interval || 300) : 300;
  document.getElementById('webapp-headers').value = app && app.headers ? (typeof app.headers === 'string' ? app.headers : JSON.stringify(app.headers, null, 2)) : '';
  document.getElementById('webapp-body').value = app ? (app.body || '') : '';
  document.getElementById('webapp-notes').value = app ? (app.notes || '') : '';
  document.getElementById('webapp-notify-down').checked = app ? (app.notify_on_down ? true : false) : true;
  document.getElementById('webapp-notify-recovery').checked = app ? (app.notify_on_recovery ? true : false) : true;
  modal.classList.add('open');
}

function closeWebAppModal() {
  document.getElementById('webapp-modal').classList.remove('open');
}

function setHealth(prefix, pct) {
  document.getElementById(prefix + '-pct').textContent = pct + '%';
  const bar = document.getElementById(prefix + '-bar');
  bar.style.width = pct + '%';
  bar.style.background = pct >= 80 ? 'var(--green)' : pct >= 50 ? 'var(--yellow)' : 'var(--red)';
}

let _countdownInterval = null;

function renderSchedulerStatus(sched, lastCheck) {
  const el = document.getElementById('scheduler-text');
  const dot = document.getElementById('scheduler-dot');
  let text = '';
  if (sched && sched.next_run) {
    text = 'Next check: every 24h';
  } else {
    text = 'Scheduler active — not yet scheduled';
  }
  if (lastCheck) {
    const statusIcon = lastCheck.status === 'completed' ? '✓' : lastCheck.status === 'running' ? '⟳' : '✗';
    text += ` · Last run: ${statusIcon} ${lastCheck.started_at ? formatDate(lastCheck.started_at) : ''} (${lastCheck.domains_checked}/${lastCheck.domains_total})`;
    if (lastCheck.status === 'running') dot.classList.add('running');
    else dot.classList.remove('running');
  }
  el.textContent = text;

  // Add countdown span
  var cd = document.getElementById('scheduler-countdown');
  if (!cd) {
    cd = document.createElement('span');
    cd.id = 'scheduler-countdown';
    cd.className = 'countdown';
    el.parentNode.appendChild(cd);
  }

  if (_countdownInterval) clearInterval(_countdownInterval);
  _countdownInterval = null;

  if (sched && sched.next_run) {
    function tick() {
      var diff = new Date(sched.next_run) - Date.now();
      if (diff <= 0) { cd.textContent = 'Running...'; return; }
      var h = Math.floor(diff / 3600000);
      var m = Math.floor((diff % 3600000) / 60000);
      cd.textContent = '~' + h + 'h ' + m + 'm';
    }
    tick();
    _countdownInterval = setInterval(tick, 60000);
  } else {
    cd.textContent = '';
  }
}

function renderSparkline(snapshots) {
  var canvas = document.getElementById('sparkline-canvas');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var dpr = window.devicePixelRatio || 1;
  var w = canvas.offsetWidth;
  var h = 140;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  var tipEl = document.getElementById('sparkline-tooltip');
  var legendEl = document.getElementById('sparkline-legend');

  if (!snapshots || snapshots.length < 2) {
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--text-muted');
    ctx.font = '13px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Need at least 2 days of data', w / 2, h / 2);
    if (legendEl) legendEl.innerHTML = '';
    if (tipEl) tipEl.style.display = 'none';
    return;
  }

  var data = snapshots;
  var pad = { top: 14, bottom: 22, left: 36, right: 12 };
  var chartW = w - pad.left - pad.right;
  var chartH = h - pad.top - pad.bottom;

  var domainPcts = data.map(function (s) { return s.domain_total > 0 ? s.domain_healthy / s.domain_total : 0; });
  var sslPcts = data.map(function (s) { return s.ssl_total > 0 ? s.ssl_healthy / s.ssl_total : 0; });
  var allPcts = domainPcts.concat(sslPcts);
  var minPct = Math.min(0, Math.min.apply(null, allPcts));
  var maxPct = Math.max.apply(null, allPcts);
  var pctRange = maxPct - minPct || 1;

  function toY(pct) { return pad.top + chartH - ((pct - minPct) / pctRange) * chartH; }

  // Y-axis labels
  ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--text-muted');
  ctx.font = '9px sans-serif';
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  [0, 0.25, 0.5, 0.75, 1].forEach(function (frac) {
    var pctVal = Math.round((minPct + pctRange * frac) * 100);
    var y = toY(minPct + pctRange * frac);
    ctx.fillText(pctVal + '%', pad.left - 4, y);
  });
  ctx.textBaseline = 'alphabetic';

  // Grid lines (subtle)
  ctx.strokeStyle = 'rgba(128,128,128,0.06)';
  ctx.lineWidth = 1;
  [0, 0.25, 0.5, 0.75, 1].forEach(function (frac) {
    var y = toY(minPct + pctRange * frac);
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
  });

  // Date labels on x-axis
  ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--text-muted');
  ctx.font = '9px sans-serif';
  ctx.textAlign = 'center';
  [0, Math.floor((data.length - 1) / 2), data.length - 1].forEach(function (i) {
    var x = pad.left + (i / (data.length - 1)) * chartW;
    var d = new Date(data[i].date || data[i].snapshot_date);
    ctx.fillText(d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }), x, h - 4);
  });

  var primaryColor = getComputedStyle(document.body).getPropertyValue('--primary').trim() || '#3b82f6';
  var greenColor = getComputedStyle(document.body).getPropertyValue('--green').trim() || '#22c55e';

  // Smooth bezier helper
  function smoothPoints(pcts) {
    var pts = pcts.map(function (p, i) { return { x: pad.left + (i / (pcts.length - 1)) * chartW, y: toY(p) }; });
    if (pts.length < 2) return pts;
    // Add control points for smooth bezier
    var result = [];
    for (var i = 0; i < pts.length - 1; i++) {
      var p0 = pts[i === 0 ? 0 : i - 1];
      var p1 = pts[i];
      var p2 = pts[i + 1];
      var p3 = pts[i + 2 >= pts.length ? pts.length - 1 : i + 2];
      var cp1x = p1.x + (p2.x - p0.x) / 6;
      var cp1y = p1.y + (p2.y - p0.y) / 6;
      var cp2x = p2.x - (p3.x - p1.x) / 6;
      var cp2y = p2.y - (p3.y - p1.y) / 6;
      result.push({ p1: p1, p2: p2, cp1: { x: cp1x, y: cp1y }, cp2: { x: cp2x, y: cp2y } });
    }
    return result;
  }

  function drawSeries(pcts, color, bgColor, glowColor) {
    var segments = smoothPoints(pcts);
    if (segments.length === 0) return;
    var first = segments[0].p1;
    var last = segments[segments.length - 1].p2;

    // Glow behind line
    if (glowColor) {
      ctx.save();
      ctx.shadowColor = glowColor;
      ctx.shadowBlur = 8;
      ctx.beginPath();
      ctx.moveTo(first.x, first.y);
      segments.forEach(function (s) { ctx.bezierCurveTo(s.cp1.x, s.cp1.y, s.cp2.x, s.cp2.y, s.p2.x, s.p2.y); });
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.globalAlpha = 0.4;
      ctx.stroke();
      ctx.restore();
    }

    // Gradient fill under curve
    var grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + chartH);
    grad.addColorStop(0, bgColor);
    grad.addColorStop(1, 'transparent');
    ctx.beginPath();
    ctx.moveTo(first.x, pad.top + chartH);
    ctx.lineTo(first.x, first.y);
    segments.forEach(function (s) { ctx.bezierCurveTo(s.cp1.x, s.cp1.y, s.cp2.x, s.cp2.y, s.p2.x, s.p2.y); });
    ctx.lineTo(last.x, pad.top + chartH);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Main line
    ctx.beginPath();
    ctx.moveTo(first.x, first.y);
    segments.forEach(function (s) { ctx.bezierCurveTo(s.cp1.x, s.cp1.y, s.cp2.x, s.cp2.y, s.p2.x, s.p2.y); });
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();

    // Dots — end dot larger with glow
    var allPts = [first].concat(segments.map(function (s) { return s.p2; }));
    allPts.forEach(function (p, i) {
      var r = (i === allPts.length - 1) ? 4 : 2.5;
      // Outer glow on end dot
      if (i === allPts.length - 1) {
        ctx.beginPath(); ctx.arc(p.x, p.y, 7, 0, Math.PI * 2);
        ctx.fillStyle = color; ctx.globalAlpha = 0.15; ctx.fill(); ctx.globalAlpha = 1;
      }
      ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = getComputedStyle(document.body).getPropertyValue('--bg-card');
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });

    return allPts;
  }

  drawSeries(domainPcts, greenColor, 'rgba(34,197,94,0.08)', 'rgba(34,197,94,0.15)');
  drawSeries(sslPcts, primaryColor, 'rgba(59,130,246,0.08)', 'rgba(59,130,246,0.15)');

  // Legend with latest values
  if (legendEl) {
    var latestDomain = Math.round(domainPcts[domainPcts.length - 1] * 100);
    var latestSsl = Math.round(sslPcts[sslPcts.length - 1] * 100);
    legendEl.innerHTML =
      '<span class="legend-item"><span class="legend-dot" style="background:' + greenColor + '"></span>Domain <span class="legend-value">' + latestDomain + '%</span></span>' +
      '<span class="legend-item"><span class="legend-dot" style="background:' + primaryColor + '"></span>SSL <span class="legend-value">' + latestSsl + '%</span></span>';
  }

  // Hover tooltip
  var tooltipData = [];
  for (var i = 0; i < data.length; i++) {
    var x = pad.left + (i / (data.length - 1)) * chartW;
    var d = new Date(data[i].date || data[i].snapshot_date);
    tooltipData.push({ x: x, domainPct: Math.round(domainPcts[i] * 100), sslPct: Math.round(sslPcts[i] * 100), label: d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) });
  }

  function onMove(mx) {
    if (!tipEl) return;
    var rect = canvas.getBoundingClientRect();
    var relX = mx - rect.left;
    var closest = tooltipData[0];
    var minDist = Infinity;
    tooltipData.forEach(function (t) {
      var d = Math.abs(t.x - relX);
      if (d < minDist) { minDist = d; closest = t; }
    });
    tipEl.style.display = 'block';
    tipEl.style.left = closest.x + 'px';
    tipEl.style.top = pad.top + 'px';
    tipEl.innerHTML =
      '<div style="font-size:10px;color:var(--text-muted);margin-bottom:4px">' + closest.label + '</div>' +
      '<div class="tt-row"><span class="tt-dot" style="background:' + greenColor + '"></span><span class="tt-label">Domain</span><span class="tt-value">' + closest.domainPct + '%</span></div>' +
      '<div class="tt-row"><span class="tt-dot" style="background:' + primaryColor + '"></span><span class="tt-label">SSL</span><span class="tt-value">' + closest.sslPct + '%</span></div>';
  }

  canvas.onmousemove = function (e) { onMove(e.clientX); };
  canvas.onmouseleave = function () { if (tipEl) tipEl.style.display = 'none'; };
}

function renderExpiringList(containerId, list) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const isViewer = _userRole !== 'admin';
  if (!list || list.length === 0) { el.innerHTML = '<div class="top-empty">None expiring soon</div>'; return; }
  const maxDays = containerId === 'domain-expiring-list' ? 90 : 30;
  el.innerHTML = list.map(d => {
    const half = maxDays / 2;
    const cls = d.days <= half * 0.34 ? 'expired' : d.days <= half ? 'warning' : 'caution';
    const checkBtn = isViewer ? '' : `<button class="top-check" data-action="quick-check" data-id="${d.id}">Check</button>`;
    var severityPct = maxDays > 0 ? Math.min(100, Math.round((1 - d.days / maxDays) * 100)) : 0;
    var sevClass = d.days <= half * 0.34 ? 'danger' : d.days <= half ? 'warning' : 'caution';
    return `<div class="top-item ${cls}" data-action="go-domain" data-id="${d.id}">
      <div class="severity-bar ${sevClass}" style="width:${severityPct}%"></div>
      <div class="top-left"><a class="top-url" href="https://${escHtml(d.url)}" target="_blank" rel="noopener">${escHtml(d.url)}</a></div>
      <div class="top-right"><span class="top-days">${d.days}d</span>${checkBtn}</div>
    </div>`;
  }).join('');
}

function renderExpiryBuckets(buckets) {
  var el = document.getElementById('expiry-buckets');
  if (!el) return;
  if (!buckets) { el.innerHTML = ''; return; }

  var sslLabels = { expired: 'Expired', critical: '≤5d', warning: '≤15d', caution: '≤30d', healthy: '>30d' };
  var domainLabels = { expired: 'Expired', critical: '≤30d', warning: '≤60d', caution: '≤90d', healthy: '>90d' };
  var bucketOrder = ['expired', 'critical', 'warning', 'caution', 'healthy'];
  var tierClass = { expired: 'danger', critical: 'danger', warning: 'warning', caution: 'caution', healthy: 'healthy' };

  var sslTotal = 0, domainTotal = 0;
  bucketOrder.forEach(function (k) { sslTotal += (buckets.ssl[k] || 0); domainTotal += (buckets.domain[k] || 0); });

  var html = '';
  html += '<div class="bucket" style="grid-column:1/-1;border-color:var(--primary);display:flex;gap:12px;align-items:center;"><span class="bucket-header" style="margin:0;">SSL</span><span style="font-size:12px;color:var(--text-muted);font-weight:400;">' + sslTotal + ' total</span></div>';
  bucketOrder.forEach(function (k) {
    var v = buckets.ssl[k] || 0;
    html += '<div class="bucket ' + tierClass[k] + '"><div class="bucket-header">' + sslLabels[k] + '</div><div class="bucket-count">' + v + '</div></div>';
  });

  html += '<div class="bucket" style="grid-column:1/-1;border-color:var(--primary);display:flex;gap:12px;align-items:center;"><span class="bucket-header" style="margin:0;">Domain</span><span style="font-size:12px;color:var(--text-muted);font-weight:400;">' + domainTotal + ' total</span></div>';
  bucketOrder.forEach(function (k) {
    var v = buckets.domain[k] || 0;
    html += '<div class="bucket ' + tierClass[k] + '"><div class="bucket-header">' + domainLabels[k] + '</div><div class="bucket-count">' + v + '</div></div>';
  });

  el.innerHTML = html;
}

// ─── Export Dashboard CSV ──────────────────────────────────────
function exportDashboardCsv() {
  api('GET', '/api/domains').then(domains => {
    const headers = ['url', 'type', 'status', 'ssl_days_left', 'ssl_expiry', 'domain_days_left', 'domain_expiry', 'last_checked', 'notes'];
    const rows = domains.map(d => headers.map(h => JSON.stringify(d[h] ?? '')).join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `ssl-dashboard-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Dashboard exported');
  }).catch(e => toast(e.message, 'error'));
}

function filterDomainsFromDash(type, status) {
  if (type === 'all') {
    window.location.hash = 'domains';
    activateView('domains');
    return;
  }
  const targetView = type === 'ssl_only' ? 'sslcerts' : 'domains';
  window.location.hash = targetView;
  activateView(targetView);
  const apply = () => {
    clearDomainFilters(type);
    _domainFilter[type] = status === 'warning' ? (type === 'ssl_only' ? 'watch' : 'warning') : status;
    const root = document.getElementById(type === 'ssl_only' ? 'ssl-domain-filters' : 'domain-filters');
    if (root) {
      root.querySelectorAll('.log-filter').forEach(chip => {
        const val = chip.dataset.sslFilter || chip.dataset.domainFilter;
        chip.classList.toggle('active', val === _domainFilter[type]);
      });
    }
    applyDomainFilters(type);
  };
  if ((_cachedDomains[type] || []).length) apply();
  else setTimeout(apply, 350);
}

// ─── Domains / SSL Certs list ─────────────────────────────────
let _cachedDomains = { full: [], ssl_only: [] };

const STATUS_ORDER = { error: 0, expired: 1, critical: 2, warning: 3, caution: 4, watch: 5, healthy: 6, pending: 7 };

async function loadDomains(type, forceRefresh) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const list = document.getElementById('domain-list-' + suffix);
  const table = document.getElementById('domain-table-' + suffix);
  const empty = document.getElementById('empty-state-' + suffix);
  empty.style.display = 'none';
  list.innerHTML = Array(5).fill(0).map(() =>
    `<div class="domain-card skeleton-card"><div class="skeleton skeleton-line wide"></div><div class="skeleton skeleton-line medium"></div><div class="skeleton skeleton-line narrow"></div></div>`
  ).join('');
  if (table) table.style.display = 'none';

  if (!forceRefresh) {
    const cached = getCachedDomains(type);
    if (cached) {
      _cachedDomains[type] = cached;
      loadViewPrefs(type);
      updateViewToggleButton(type);
      renderDomains(cached, type);
      renderPagination(type);
      return;
    }
  }

  try {
    const domains = await api('GET', `/api/domains?type=${type}`);
    _cachedDomains[type] = domains;
    setCachedDomains(type, domains);
    loadViewPrefs(type);
    updateViewToggleButton(type);
    renderDomains(domains, type);
    renderPagination(type);
  } catch (e) {
    toast(e.message, 'error');
    list.innerHTML = '';
  }
}

function applyDomainFilters(type) {
  const filtered = getFilteredDomains(type);
  _keyboardFocusIndex = -1;
  renderDomains(filtered, type);
  renderPagination(type);
  saveViewPrefs(type);
}

function extractTlds(domains) {
  const tldSet = new Set();
  domains.forEach(d => {
    const parts = d.url.split('.');
    if (parts.length > 1) tldSet.add('.' + parts.slice(-2).join('.'));
  });
  return [...tldSet].sort();
}

function _isRecentlyAlerted(d) {
  if (!d.last_alerted) return false;
  const t = new Date(d.last_alerted + (d.last_alerted.includes('T') ? '' : 'T00:00:00Z'));
  return (Date.now() - t.getTime()) < 86400000;
}

function populateTldFilter(tlds, type) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const select = document.getElementById(type === 'ssl_only' ? 'ssl-tld-filter' : 'tld-filter');
  if (!select) return;
  const current = select.value;
  select.innerHTML = '<option value="">All TLDs</option>' + tlds.map(t => `<option value="${escHtml(t)}">${escHtml(t)}</option>`).join('');
  select.value = current;
}

function _sortDomains(domains, type) {
  const s = sortState[type];
  const dir = s.dir;
  return [...domains].sort((a, b) => {
    let va, vb;
    if (s.field === 'url') { va = a.url.toLowerCase(); vb = b.url.toLowerCase(); return dir * va.localeCompare(vb); }
    if (s.field === 'status') {
      const statusField = type === 'ssl_only' ? 'ssl_status' : 'domain_status';
      va = STATUS_ORDER[a[statusField] || 'pending'] ?? 99;
      vb = STATUS_ORDER[b[statusField] || 'pending'] ?? 99;
      return dir * (va - vb);
    }
    if (s.field === 'days') {
      va = _sortDaysValue(a, type); vb = _sortDaysValue(b, type); return dir * (va - vb);
    }
    if (s.field === 'checked') {
      va = a.last_checked ? new Date(a.last_checked).getTime() : 0;
      vb = b.last_checked ? new Date(b.last_checked).getTime() : 0;
      return dir * (va - vb);
    }
    if (s.field === 'registrar') {
      va = (a.domain_registrar || '').toLowerCase();
      vb = (b.domain_registrar || '').toLowerCase();
      return dir * va.localeCompare(vb);
    }
    if (s.field === 'issuer') {
      va = (a.ssl_issuer || '').toLowerCase();
      vb = (b.ssl_issuer || '').toLowerCase();
      return dir * va.localeCompare(vb);
    }
    return 0;
  });
}

function _sortDaysValue(domain, type) {
  if (type === 'ssl_only') return domain.ssl_days_left ?? 9999;
  const values = [domain.domain_days_left, domain.ssl_days_left].filter(v => v !== null && v !== undefined);
  if (values.length) return Math.min(...values);
  if (domain.manual_expiry_date) {
    const d1 = new Date(domain.manual_expiry_date + 'T00:00:00Z');
    return Math.round((d1 - new Date()) / 86400000);
  }
  return 9999;
}

function renderDomains(domains, type) {
  domains = _sortDomains(domains, type);
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const isSslOnly = type === 'ssl_only';
  const list = document.getElementById('domain-list-' + suffix);
  const table = document.getElementById('domain-table-' + suffix);
  const tableBody = document.getElementById('domain-table-body-' + suffix);
  const empty = document.getElementById('empty-state-' + suffix);
  const stats = { healthy: 0, watch: 0, caution: 0, warning: 0, critical: 0, expired: 0, error: 0, pending: 0 };
  const selSet = isSslOnly ? selectedSsl : selectedDomains;
  const viewMode = _viewMode[type];
  const groupByStatus = _groupByStatus[type];

  // Stats always from full dataset, not filtered
  const allDomains = _cachedDomains[type] || [];
  const statusField = isSslOnly ? 'ssl_status' : 'domain_status';
  allDomains.forEach(d => {
    const st = d[statusField] || 'pending';
    stats[st] = (stats[st] || 0) + 1;
  });

  // Apply pagination
  const maxPage = Math.max(1, Math.ceil(domains.length / _pagination[type].pageSize));
  if (_pagination[type].page > maxPage) _pagination[type].page = maxPage;
  const pageItems = getPageItems(domains, type);
  updateDomainResultSummary(type, domains.length, allDomains.length);

  if (pageItems.length === 0 && domains.length === 0) {
    list.innerHTML = '';
    if (tableBody) tableBody.innerHTML = '';
    empty.style.display = 'block';
    empty.querySelector('p').textContent = allDomains.length ? 'No domains match the current filters.' : (isSslOnly ? 'No SSL-only domains monitored yet.' : 'No domains monitored yet.');
    updateStats(stats, suffix);
    populateTldFilter(extractTlds(allDomains), type);
    if (allDomains.length) {
      const suggestions = document.getElementById(`${suffix}-empty-suggestions`);
      if (suggestions) suggestions.innerHTML = '';
    } else {
      renderEmptySuggestions(type);
    }
    return;
  }
  empty.style.display = 'none';

  const tlds = extractTlds(allDomains);
  populateTldFilter(tlds, type);

  if (viewMode === 'table') {
    list.style.display = 'none';
    table.style.display = 'table';
    renderTableRows(pageItems, type, tableBody, selSet, isSslOnly, null);
  } else {
    list.style.display = '';
    table.style.display = 'none';
    if (groupByStatus) {
      renderGroupedCards(pageItems, type, list, selSet, isSslOnly, null);
    } else {
      list.innerHTML = pageItems.map(d => renderCardHtml(d, type, selSet, isSslOnly)).join('');
    }
  }
  if (Object.keys(_prevStatuses[type]).length) _prevStatuses[type] = {};

  updateStats(stats, suffix);
  updateBulkToolbar(type);
  _observeSparklines();
}

function renderTableRows(domains, type, tbody, selSet, isSslOnly, _stats) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const statusField = isSslOnly ? 'ssl_status' : 'domain_status';
  tbody.innerHTML = domains.map(d => {
    const status = d[statusField] || 'pending';
    const statusLabel = isSslOnly ? _sslStatusLabel(status) : _domainStatusLabel(status);
    const checked = selSet.has(d.id);
    const prevStatus = _prevStatuses[type][d.id];
    const changedClass = prevStatus && prevStatus !== status ? 'status-changed' : '';
    const expiryBar = renderExpiryBar(d, type);
    const lastChecked = d.last_checked ? '<span class="rel-time" data-date="' + d.last_checked + '" title="' + formatDate(d.last_checked) + '">' + relativeTime(d.last_checked) + '</span>' : 'Never';
    const alertBadge = _isRecentlyAlerted(d) ? '<span class="alert-badge" title="Alert sent within 24h">🔔</span>' : '';

    let expiryCells = '';
    if (isSslOnly) {
      expiryCells = `<td>${formatSslExpiry(d)}${expiryBar}<span class="sparkline-cell" data-domain-id="${d.id}"></span></td>`;
    } else {
      expiryCells = `<td>${formatDomainExpiry(d)}</td><td>${formatSslExpiry(d)}${expiryBar}<span class="sparkline-cell" data-domain-id="${d.id}"></span></td>`;
    }

    let infoCell = '';
    if (isSslOnly) {
      infoCell = `<td>${d.ssl_issuer ? escHtml(d.ssl_issuer.substring(0, 30)) : ''}</td>`;
    } else {
      infoCell = `<td>${(d.manual_registrar || d.domain_registrar) ? escHtml(d.manual_registrar || d.domain_registrar) : ''}</td>`;
    }

    const __isViewer = _userRole !== 'admin';
    return `<tr class="${checked ? 'selected' : ''} ${changedClass}">
      <td><input type="checkbox" data-${isSslOnly ? 'ssl' : 'domain'}-check="${d.id}" ${checked ? 'checked' : ''}></td>
      <td><div style="display:flex;align-items:center;gap:2px"><a class="table-url" href="https://${escHtml(d.url)}" target="_blank" rel="noopener">${escHtml(d.url)}</a><button class="btn-icon" data-action="copy-url" data-url="${escHtml(d.url)}" title="Copy URL" style="font-size:11px;padding:1px 4px">&#x2398;</button>${alertBadge}</div></td>
      <td><span class="table-status ${status}">${statusLabel}</span></td>
      ${expiryCells}
      ${infoCell}
      <td>${lastChecked}</td>
      <td class="table-actions-cell">
        <div class="kebab-menu">
          <button class="kebab-btn" data-action="toggle-kebab" data-id="${d.id}" aria-label="Actions">&#8942;</button>
          <div class="kebab-dropdown" id="kebab-tbl-${suffix}-${d.id}" style="display:none">
            ${__isViewer ? '' : `<button class="kebab-item" data-action="manual-check" data-id="${d.id}">&#x21bb; Check</button>`}
            <button class="kebab-item" data-action="view-cert" data-id="${d.id}">&#x1F50E; View Cert</button>
            ${__isViewer ? '' : `<button class="kebab-item" data-action="edit-domain" data-id="${d.id}">&#x270E; Edit</button>`}
            ${__isViewer ? '' : `<button class="kebab-item kebab-item-danger" data-action="delete-domain" data-id="${d.id}" data-name="${escHtml(d.url)}">&#x2716; Delete</button>`}
          </div>
        </div>
      </td>
    </tr>`;
  }).join('');
}

function renderGroupedCards(domains, type, list, selSet, isSslOnly, _stats) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const statusField = isSslOnly ? 'ssl_status' : 'domain_status';
  const groups = {};
  const order = ['expired', 'error', 'critical', 'warning', 'caution', 'watch', 'healthy', 'pending'];

  domains.forEach(d => {
    const status = d[statusField] || 'pending';
    if (!groups[status]) groups[status] = [];
    groups[status].push(d);
  });

  let html = '';
  order.forEach(status => {
    if (!groups[status]) return;
    const key = `${suffix}-${status}`;
    const collapsed = _collapsedGroups[key] || false;
    const label = isSslOnly ? _sslStatusLabel(status) : _domainStatusLabel(status);
    html += `<div class="status-group">
      <div class="status-group-header ${collapsed ? 'collapsed' : ''}" data-action="toggle-group" data-key="${key}">
        <span class="chevron">&#9660;</span>
        <span class="status-label">${label}</span>
        <span class="status-group-count">(${groups[status].length})</span>
      </div>
      <div class="status-group-body ${collapsed ? 'collapsed' : ''}">
        ${groups[status].map(d => renderCardHtml(d, type, selSet, isSslOnly)).join('')}
      </div>
    </div>`;
  });
  list.innerHTML = html;
}

document.addEventListener('click', (e) => {
  const header = e.target.closest('[data-action="toggle-group"]');
  if (header) {
    const key = header.dataset.key;
    _collapsedGroups[key] = !_collapsedGroups[key];
    const body = header.nextElementSibling;
    header.classList.toggle('collapsed');
    body.classList.toggle('collapsed');
  }
});

function renderCardHtml(d, type, selSet, isSslOnly) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const statusField = isSslOnly ? 'ssl_status' : 'domain_status';
  const status = d[statusField] || 'pending';
  const statusLabel = isSslOnly ? _sslStatusLabel(status) : _domainStatusLabel(status);
  const checked = selSet.has(d.id);
  const selectedClass = checked ? 'selected' : '';
  const prevStatus = _prevStatuses[type][d.id];
  const changedClass = prevStatus && prevStatus !== status ? 'status-changed' : '';

  const sslDate = d.ssl_expiry;
  const sslDays = d.ssl_days_left;
  const domDate = d.domain_expiry;
  const domDays = d.domain_days_left;

  let expiryLines = [];
  if (sslDate) {
    const datePart = sslDate.slice(0, 10);
    const daysPart = sslDays !== null ? `(${sslDays}d)` : '';
    const sslStat = _sslStatusFromDays(sslDays);
    const cls = sslStat || '';
    expiryLines.push(`<span class="expiry ${cls}" title="SSL: ${escHtml(sslDate)}">SSL: ${datePart} ${daysPart}</span>`);
  } else {
    expiryLines.push(`<span class="expiry muted">SSL: No cert</span>`);
  }

  if (!isSslOnly) {
    const manExp = d.manual_expiry_date;
    let manDays = null;
    if (manExp) {
      const d1 = new Date(manExp + 'T00:00:00Z');
      const d2 = new Date();
      manDays = Math.round((d1 - d2) / 86400000);
    }

    if (domDate) {
      const datePart = domDate.slice(0, 10);
      const daysPart = domDays !== null ? `(${domDays}d)` : '';
      const domCls = _domainExpiryClass(domDays);
      expiryLines.push(`<span class="expiry ${domCls}" title="Domain: ${escHtml(domDate)}">Domain: ${datePart} ${daysPart}</span>`);
    } else if (manExp) {
      const cls = _domainExpiryClass(manDays);
      expiryLines.push(`<span class="expiry ${cls}" title="Manually set: ${escHtml(manExp)}">Domain: ${manExp} (${manDays}d) <span class="manual-tag" title="Manually set">M</span></span>`);
    } else {
      expiryLines.push(`<span class="expiry muted">Domain: N/A</span>`);
    }
  }

  const expiryBar = renderExpiryBar(d, type);
  const sparklineHtml = `<span class="sparkline-cell" data-domain-id="${d.id}"></span>`;
  const expiryHtml = `<div class="expiry-row">${expiryLines.join(' · ')}</div>`;
  const registrarVal = d.manual_registrar || d.domain_registrar;
  const registrarHtml = (!isSslOnly && registrarVal) ? `<div class="domain-registrar">Registrar:&nbsp;${escHtml(registrarVal)}</div>` : '';
  var notesText = d.notes || '';
  var notesPlaceholder = notesText ? '' : 'empty';
  var notesIcon = notesText ? '&#x270E;' : '&#x270E;';
  const notesHtml = '<div class="domain-notes ' + notesPlaceholder + '" data-action="inline-notes" data-id="' + d.id + '"><span class="notes-text">' + escHtml(notesText) + '</span><span class="notes-edit-icon">' + notesIcon + '</span></div>';
  const typeTag = isSslOnly ? '<span class="type-tag ssl">SSL</span>' : '<span class="type-tag domain">Full</span>';
  const alertBadge = _isRecentlyAlerted(d) ? '<span class="alert-badge" title="Alert sent within 24h">🔔</span>' : '';

  let sslExtra = '';
  if (isSslOnly && d.ssl_issuer) {
    sslExtra = `<div class="ssl-cert-info">
      <div class="ssl-row"><span class="ssl-label">Issuer:&nbsp;</span><span class="ssl-value">${escHtml(d.ssl_issuer)}</span></div>
    </div>`;
  }

  const checkboxHtml = isSslOnly
    ? `<label class="domain-check"><input type="checkbox" data-ssl-check="${d.id}" ${checked ? 'checked' : ''}></label>`
    : `<label class="domain-check"><input type="checkbox" data-domain-check="${d.id}" ${checked ? 'checked' : ''}></label>`;

  const isViewer = _userRole !== 'admin';
  const menuHtml = `
    <div class="kebab-menu">
      <button class="kebab-btn" data-action="toggle-kebab" data-id="${d.id}" aria-label="Actions">&#8942;</button>
      <div class="kebab-dropdown" id="kebab-${suffix}-${d.id}" style="display:none">
        ${isViewer ? '' : `<button class="kebab-item" data-action="manual-check" data-id="${d.id}">&#x21bb; Check</button>`}
        <button class="kebab-item" data-action="view-cert" data-id="${d.id}">&#x1F50E; View Cert</button>
        ${isViewer ? '' : `<button class="kebab-item" data-action="edit-domain" data-id="${d.id}">&#x270E; Edit</button>`}
        ${isViewer ? '' : `<button class="kebab-item kebab-item-danger" data-action="delete-domain" data-id="${d.id}" data-name="${escHtml(d.url)}">&#x2716; Delete</button>`}
      </div>
    </div>`;

  return `
    <div class="domain-card ${selectedClass} ${changedClass}" id="card-${suffix}-${d.id}" data-id="${d.id}">
      ${checkboxHtml}
      <div class="status-dot ${status}"></div>
      <div class="domain-info">
        <div class="domain-card-header">
          <div class="domain-url-wrapper">
            <a class="domain-url" href="https://${escHtml(d.url)}" target="_blank" rel="noopener" title="Open in new tab">${escHtml(d.url)}</a>
            <button class="btn-icon" data-action="copy-url" data-url="${escHtml(d.url)}" title="Copy URL">&#x2398;</button>
            ${alertBadge}
          </div>
          ${typeTag}
          <div class="domain-status ${status}">${statusLabel}</div>
        </div>
        ${expiryHtml}
        ${expiryBar}
        ${sparklineHtml}
        ${registrarHtml}
        ${sslExtra}
        <div class="domain-meta">${d.last_checked ? 'Checked: <span class="rel-time" data-date="' + d.last_checked + '" title="' + formatDate(d.last_checked) + '">' + relativeTime(d.last_checked) + '</span>' : 'Never checked'}
          <button class="domain-card-expand" data-action="toggle-details" data-id="${d.id}">&#9654; Details</button>
        </div>
        ${notesHtml}
        <div class="domain-card-details" id="details-${suffix}-${d.id}">
          <div class="detail-row"><span class="detail-label">ID:</span><span class="detail-value">${d.id}</span></div>
          <div class="detail-row"><span class="detail-label">SSL Issuer:</span><span class="detail-value">${d.ssl_issuer ? escHtml(d.ssl_issuer) : 'N/A'}</span></div>
          <div class="detail-row"><span class="detail-label">SSL Fingerprint:</span><span class="detail-value">${d.ssl_fingerprint ? escHtml(d.ssl_fingerprint.substring(0, 40)) + '...' : 'N/A'}</span></div>
          ${!isSslOnly ? `<div class="detail-row"><span class="detail-label">Registrar:</span><span class="detail-value">${registrarVal ? escHtml(registrarVal) : 'N/A'}</span></div>` : ''}
          <div class="detail-row"><span class="detail-label">Created:</span><span class="detail-value">${formatDate(d.created_at)}</span></div>
        </div>
      </div>
      ${menuHtml}
    </div>
  `;
}

function renderExpiryBar(d, type) {
  const isSslOnly = type === 'ssl_only';
  const days = isSslOnly ? d.ssl_days_left : (d.domain_days_left !== null ? d.domain_days_left : (() => {
    if (d.manual_expiry_date) {
      const d1 = new Date(d.manual_expiry_date + 'T00:00:00Z');
      const d2 = new Date();
      return Math.round((d1 - d2) / 86400000);
    }
    return null;
  })());

  if (days === null || days === undefined) return '';

  const maxDays = isSslOnly ? 90 : 365;
  const pct = Math.max(0, Math.min(100, (days / maxDays) * 100));
  const cls = isSslOnly ? _sslStatusFromDays(days) : _domainExpiryClass(days);
  return `<div class="expiry-bar"><div class="expiry-bar-fill ${cls}" style="width:${pct}%"></div></div>`;
}

function formatSslExpiry(d) {
  if (!d.ssl_expiry) return 'N/A';
  const days = d.ssl_days_left;
  return `${d.ssl_expiry.slice(0, 10)} ${days !== null ? `(${days}d)` : ''}`;
}

function formatDomainExpiry(d) {
  if (d.domain_expiry) {
    return `${d.domain_expiry.slice(0, 10)} ${d.domain_days_left !== null ? `(${d.domain_days_left}d)` : ''}`;
  }
  if (d.manual_expiry_date) {
    const d1 = new Date(d.manual_expiry_date + 'T00:00:00Z');
    const d2 = new Date();
    const days = Math.round((d1 - d2) / 86400000);
    return `${d.manual_expiry_date} (${days}d) M`;
  }
  return 'N/A';
}

function renderEmptySuggestions(type) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const container = document.getElementById(`${suffix}-empty-suggestions`);
  if (!container) return;
  const existing = (_cachedDomains[type] || []).map(d => d.url);
  const suggestions = ['google.com', 'github.com', 'example.com'].filter(s => !existing.includes(s));
  if (suggestions.length === 0) { container.innerHTML = ''; return; }
  container.innerHTML = `<div>Quick add suggestions:</div><div class="suggestion-chips">${suggestions.map(s => `<span class="suggestion-chip" data-action="quick-add" data-url="${escHtml(s)}" data-type="${type}">${escHtml(s)}</span>`).join('')}</div>`;
}

document.addEventListener('click', (e) => {
  const chip = e.target.closest('.suggestion-chip');
  if (chip) {
    openAddModal(chip.dataset.type, chip.dataset.url);
    return;
  }
});

function toggleViewMode(type) {
  _viewMode[type] = _viewMode[type] === 'cards' ? 'table' : 'cards';
  updateViewToggleButton(type);
  applyDomainFilters(type);
}

function updateViewToggleButton(type) {
  const isSsl = type === 'ssl_only';
  const btn = document.querySelector(`[data-action="${isSsl ? 'toggle-view-ssl' : 'toggle-view-full'}"]`);
  if (!btn) return;
  const mode = _viewMode[type];
  const icon = btn.querySelector('.view-toggle-icon');
  const label = btn.querySelector('.view-toggle-label');
  if (mode === 'cards') {
    icon.innerHTML = '&#9776;';
    label.textContent = 'Table';
    btn.title = 'Switch to table view';
  } else {
    icon.innerHTML = '&#9638;';
    label.textContent = 'Cards';
    btn.title = 'Switch to card view';
  }
}

function clearDomainFilters(type) {
  const isSsl = type === 'ssl_only';
  const search = document.getElementById(isSsl ? 'ssl-search' : 'domain-search');
  const tld = document.getElementById(isSsl ? 'ssl-tld-filter' : 'tld-filter');
  if (search) search.value = '';
  if (tld) tld.value = '';
  _domainFilter[type] = 'all';
  _tldFilter[type] = '';
  _pagination[type].page = 1;
  const filterRoot = document.getElementById(isSsl ? 'ssl-domain-filters' : 'domain-filters');
  if (filterRoot) {
    filterRoot.querySelectorAll('.log-filter').forEach(chip => chip.classList.toggle('active', (chip.dataset.sslFilter || chip.dataset.domainFilter) === 'all'));
  }
  applyDomainFilters(type);
}

function downloadTemplate(type) {
  var picker = document.createElement('div');
  picker.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:20px;z-index:9999;box-shadow:0 4px 20px rgba(0,0,0,0.3);display:flex;flex-direction:column;gap:8px;min-width:180px;';
  picker.innerHTML = '<div style="font-weight:600;margin-bottom:4px;">Download template as…</div>' +
    '<button class="btn btn-primary" style="width:100%;">CSV</button>' +
    '<button class="btn btn-secondary" style="width:100%;">JSON</button>';
  document.body.appendChild(picker);
  var btns = picker.querySelectorAll('button');
  btns.forEach(function (btn, i) {
    btn.addEventListener('click', function () {
      picker.remove();
      if (type === 'webapp') {
        var csvContent = 'name,url,method,expected_status,expected_body,timeout,check_interval,notes\nMy API,https://api.example.com/health,GET,200,,10,300,\n';
        var jsonContent = '[{"name":"My API","url":"https://api.example.com/health","method":"GET","expected_status":200,"check_interval":300}]';
        var content = i === 0 ? csvContent : jsonContent;
        var ext = i === 0 ? 'csv' : 'json';
        var mime = i === 0 ? 'text/csv' : 'application/json';
        var blob = new Blob([content], { type: mime });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'import-template-webapp.' + ext;
        a.click();
        URL.revokeObjectURL(a.href);
      } else {
        var csv, template;
        if (i === 0) {
          csv = type === 'ssl_only'
            ? 'url,type,notes\nexample.com,ssl_only,\n'
            : 'url,type,notes,manual_registrar,manual_expiry_date\nexample.com,full,,GoDaddy,2027-01-01\n';
          var blob = new Blob([csv], { type: 'text/csv' });
          var a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = 'import-template-' + type + '.csv';
          a.click();
          URL.revokeObjectURL(a.href);
        } else {
          template = type === 'ssl_only'
            ? '[{"url": "example.com", "type": "ssl_only", "notes": ""}]'
            : '[{"url": "example.com", "type": "full", "manual_registrar": "GoDaddy", "manual_expiry_date": "2027-01-01", "notes": ""}]';
          var blob = new Blob([template], { type: 'application/json' });
          var a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = 'import-template-' + type + '.json';
          a.click();
          URL.revokeObjectURL(a.href);
        }
      }
      toast('Template downloaded');
    });
  });
}

// ─── Bulk selection ────────────────────────────────────────────
let _lastChecked = { full: null, ssl_only: null };

document.addEventListener('change', (e) => {
  const cb = e.target.closest('input[type="checkbox"]');
  if (!cb) return;
  const did = cb.dataset.domainCheck;
  const sid = cb.dataset.sslCheck;
  const id = did || sid;
  const type = did ? 'full' : 'ssl_only';
  const selSet = did ? selectedDomains : selectedSsl;
  if (!id) return;

  if (cb.checked) selSet.add(parseInt(id)); else selSet.delete(parseInt(id));

  // Shift+click range
  if (e.shiftKey && _lastChecked[type] !== null) {
    const domains = _cachedDomains[type] || [];
    const lastIdx = domains.findIndex(d => d.id === _lastChecked[type]);
    const curIdx = domains.findIndex(d => d.id === parseInt(id));
    if (lastIdx !== -1 && curIdx !== -1) {
      const [start, end] = lastIdx < curIdx ? [lastIdx, curIdx] : [curIdx, lastIdx];
      for (let i = start; i <= end; i++) {
        const d = domains[i];
        if (d) {
          if (cb.checked) selSet.add(d.id); else selSet.delete(d.id);
          const checkEl = document.querySelector(`input[data-${did ? 'domain' : 'ssl'}-check="${d.id}"]`);
          if (checkEl) checkEl.checked = cb.checked;
        }
      }
    }
  }
  _lastChecked[type] = parseInt(id);
  updateBulkToolbar(type);
});

function openDomainInNewTab(id) {
  const full = _cachedDomains.full || [];
  const ssl = _cachedDomains.ssl_only || [];
  const d = full.find(x => x.id === id) || ssl.find(x => x.id === id);
  if (d) {
    const url = d.url.startsWith('http') ? d.url : 'https://' + d.url;
    window.open(url, '_blank', 'noopener');
  }
}

function navigateToDomain(id) {
  const full = _cachedDomains.full || [];
  const ssl = _cachedDomains.ssl_only || [];
  const dFull = full.find(d => d.id === id);
  const dSsl = ssl.find(d => d.id === id);
  if (dFull) {
    window.location.hash = 'domains';
    activateView('domains');
    setTimeout(() => highlightCard('full', id), 300);
  } else if (dSsl) {
    window.location.hash = 'sslcerts';
    activateView('sslcerts');
    setTimeout(() => highlightCard('ssl_only', id), 300);
  } else {
    api('GET', '/api/domains?type=full').then(data => {
      _cachedDomains.full = data;
      const found = data.find(d => d.id === id);
      if (found) {
        window.location.hash = 'domains';
        activateView('domains');
        setTimeout(() => highlightCard('full', id), 300);
        return;
      }
      api('GET', '/api/domains?type=ssl_only').then(data2 => {
        _cachedDomains.ssl_only = data2;
        window.location.hash = 'sslcerts';
        activateView('sslcerts');
        setTimeout(() => highlightCard('ssl_only', id), 300);
      });
    });
  }
}

function highlightCard(type, id) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const card = document.getElementById(`card-${suffix}-${id}`);
  if (card) {
    card.style.borderColor = 'var(--primary)';
    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setTimeout(() => { card.style.borderColor = ''; }, 3000);
  }
}

async function quickCheck(id) {
  try {
    await api('POST', `/api/domains/${id}/check`);
    toast('Check complete');
    loadDashboard(true);
  } catch (e) {
    toast(e.message, 'error');
  }
}

function updateBulkToolbar(type) {
  if (_userRole !== 'admin') return;
  const isSsl = type === 'ssl_only';
  const sel = isSsl ? selectedSsl : selectedDomains;
  const toolbar = document.getElementById(isSsl ? 'ssl-bulk-toolbar' : 'bulk-toolbar');
  const countEl = document.getElementById(isSsl ? 'ssl-bulk-count' : 'bulk-count');
  const visibleIds = getPageItems(getFilteredDomains(type), type).map(d => d.id);
  const selectAll = document.getElementById(isSsl ? 'select-all-ssl' : 'select-all-full');
  if (selectAll) {
    const visibleSelected = visibleIds.filter(id => sel.has(id)).length;
    selectAll.checked = visibleIds.length > 0 && visibleSelected === visibleIds.length;
    selectAll.indeterminate = visibleSelected > 0 && visibleSelected < visibleIds.length;
  }
  if (sel.size > 0) {
    toolbar.style.display = 'flex';
    const visibleSelected = visibleIds.filter(id => sel.has(id)).length;
    countEl.textContent = visibleSelected === sel.size ? `${sel.size} selected` : `${sel.size} selected (${visibleSelected} visible)`;
  } else {
    toolbar.style.display = 'none';
  }
}

function deselectAll(type) {
  const isSsl = type === 'ssl_only';
  const sel = isSsl ? selectedSsl : selectedDomains;
  sel.clear();
  const suffix = isSsl ? 'ssl' : 'full';
  const checkboxes = document.querySelectorAll(`input[data-${isSsl ? 'ssl' : 'domain'}-check]`);
  checkboxes.forEach(cb => cb.checked = false);
  updateBulkToolbar(type);
}


function openBulkNotes(type) {
  if (_userRole !== 'admin') { toast('Admin access required', 'error'); return; }
  const sel = type === 'ssl_only' ? selectedSsl : selectedDomains;
  if (sel.size === 0) return;
  const modal = document.getElementById('bulk-notes-modal');
  if (!modal) {
    const html = `<div id="bulk-notes-modal" class="modal"><div class="modal-content bulk-notes-modal"><h3>Add Notes to ${sel.size} Domains</h3><textarea id="bulk-notes-text" class="bulk-notes-textarea" placeholder="Enter notes to append..."></textarea><div class="modal-actions"><button class="btn btn-secondary" data-action="close-bulk-notes">Cancel</button><button class="btn btn-primary" data-action="submit-bulk-notes" data-type="${type}">Add Notes</button></div></div></div>`;
    document.body.insertAdjacentHTML('beforeend', html);
    modal = document.getElementById('bulk-notes-modal');
  }
  modal.classList.add('open');
}

function closeBulkNotes() {
  const modal = document.getElementById('bulk-notes-modal');
  if (modal) modal.classList.remove('open');
}

async function submitBulkNotes() {
  const modal = document.getElementById('bulk-notes-modal');
  const type = modal.querySelector('[data-action="submit-bulk-notes"]').dataset.type;
  const text = sanitizeInput(document.getElementById('bulk-notes-text').value.trim());
  if (!text) return;
  const sel = type === 'ssl_only' ? selectedSsl : selectedDomains;
  const ids = [...sel];
  for (const id of ids) {
    try {
      const domain = (_cachedDomains[type] || []).find(d => d.id === id);
      const newNotes = domain.notes ? domain.notes + '\n' + text : text;
      await api('PUT', `/api/domains/${id}`, { notes: newNotes });
    } catch (e) {}
  }
  toast(`Notes added to ${ids.length} domains`);
  closeBulkNotes();
  try { await api('POST', '/api/logs', { message: `Bulk notes on ${ids.length} domains`, type: 'bulk_action' }); } catch {}
  clearDomainsCache(type);
  loadDomains(type);
}

function updateStats(stats, suffix) {
  const total = (stats.healthy || 0) + (stats.watch || 0) + (stats.caution || 0) + (stats.warning || 0) + (stats.critical || 0) + (stats.expired || 0) + (stats.error || 0) + (stats.pending || 0);
  animateCount(document.getElementById('stat-' + suffix + '-total'), total);
  animateCount(document.getElementById('stat-' + suffix + '-healthy'), stats.healthy || 0);
  animateCount(document.getElementById('stat-' + suffix + '-warning'), (stats.watch || 0) + (stats.caution || 0) + (stats.warning || 0) + (stats.critical || 0));
  animateCount(document.getElementById('stat-' + suffix + '-danger'), stats.expired || 0);
  animateCount(document.getElementById('stat-' + suffix + '-pending'), stats.pending || 0);
  animateCount(document.getElementById('stat-' + suffix + '-error'), stats.error || 0);
}

function updateDomainResultSummary(type, filteredCount, totalCount) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const label = type === 'ssl_only' ? 'SSL certificates' : 'domains';
  const el = document.getElementById('domain-result-' + suffix);
  const clearBtn = document.querySelector(`[data-action="clear-domain-filters"][data-type="${type}"]`);
  const hasFilters = Boolean(
    (document.getElementById(type === 'ssl_only' ? 'ssl-search' : 'domain-search')?.value || '').trim() ||
    _domainFilter[type] !== 'all' ||
    _tldFilter[type]
  );
  if (el) {
    el.textContent = hasFilters
      ? `Showing ${filteredCount} of ${totalCount} ${label}`
      : `Showing ${totalCount} ${label}`;
  }
  if (clearBtn) clearBtn.style.display = hasFilters ? '' : 'none';
}

function _sslStatusFromDays(days) {
  if (days === null || days === undefined) return null;
  if (days < 0) return 'expired';
  if (days < 5) return 'critical';
  if (days < 15) return 'warning';
  if (days < 20) return 'caution';
  if (days < 30) return 'watch';
  return 'healthy';
}

function _sslStatusLabel(status) {
  if (!status) return 'Pending';
  const labels = {
    healthy: 'Healthy (>30d)',
    watch: 'Watch (≤30d)',
    caution: 'Caution (≤20d)',
    warning: 'Warning (≤15d)',
    critical: 'Critical (≤5d)',
    expired: 'Expired',
    error: 'Error',
    pending: 'Pending',
  };
  return labels[status] || status.charAt(0).toUpperCase() + status.slice(1).replace('_', ' ');
}

function _domainExpiryClass(days) {
  if (days === null || days === undefined) return '';
  if (days < 0) return 'expired';
  if (days < 30) return 'critical';
  if (days < 60) return 'warning';
  if (days < 90) return 'caution';
  return 'healthy';
}

function _domainStatusLabel(status) {
  if (!status) return 'Pending';
  const labels = {
    healthy: 'Healthy (>90d)',
    caution: 'Watch (≤90d)',
    warning: 'Warning (≤60d)',
    critical: 'Critical (≤30d)',
    expired: 'Expired',
    error: 'Error',
    pending: 'Pending',
  };
  return labels[status] || status.charAt(0).toUpperCase() + status.slice(1).replace('_', ' ');
}

// ─── CRUD: Add / Edit / Delete ────────────────────────────────
function openAddModal(type, prefillUrl) {
  const label = type === 'ssl_only' ? 'Add SSL Domain' : 'Add Domain';
  document.getElementById('modal-title').textContent = label;
  document.getElementById('domain-type-input').value = type;
  document.getElementById('domain-id').value = '';
  document.getElementById('domain-form').reset();
  document.getElementById('domain-interval').value = 360;
  document.getElementById('domain-manual-expiry').value = '';
  document.getElementById('domain-manual-registrar').value = '';
  document.getElementById('domain-url').value = prefillUrl || '';
  document.getElementById('domain-modal').classList.add('open');
  document.getElementById('domain-url').focus();
}

async function openEditModal(id) {
  try {
    const typeFilter = activeView === 'sslcerts' ? 'ssl_only' : activeView === 'domains' ? 'full' : null;
    const url = typeFilter ? `/api/domains?type=${typeFilter}` : '/api/domains';
    const domains = await api('GET', url);
    const d = domains.find(x => x.id === id);
    if (!d) { toast('Domain not found', 'error'); return; }
    document.getElementById('modal-title').textContent = d.type === 'ssl_only' ? 'Edit SSL Domain' : 'Edit Domain';
    document.getElementById('domain-type-input').value = d.type || 'full';
    document.getElementById('domain-id').value = d.id;
    document.getElementById('domain-url').value = d.url;
    document.getElementById('domain-interval').value = d.check_interval || 360;
    document.getElementById('domain-notes').value = d.notes || '';
    document.getElementById('domain-manual-expiry').value = d.manual_expiry_date || '';
    document.getElementById('domain-manual-registrar').value = d.manual_registrar || '';
    document.getElementById('domain-modal').classList.add('open');
  } catch (e) {
    toast(e.message, 'error');
  }
}

function closeDomainModal() {
  document.getElementById('domain-modal').classList.remove('open');
}

document.getElementById('domain-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('btn-save-domain');
  const id = document.getElementById('domain-id').value;
  const url = document.getElementById('domain-url').value.trim();
  const interval = parseInt(document.getElementById('domain-interval').value) || 360;
  const notes = document.getElementById('domain-notes').value.trim();
  const domainType = document.getElementById('domain-type-input').value || 'full';
  const manualExpiry = document.getElementById('domain-manual-expiry').value || '';
  const manualRegistrar = document.getElementById('domain-manual-registrar').value.trim() || '';

  setLoading(btn, true);
  try {
    if (id) {
      await api('PUT', `/api/domains/${id}`, { url, check_interval: interval, notes, type: domainType, manual_expiry_date: manualExpiry, manual_registrar: manualRegistrar });
      toast('Domain updated');
    } else {
      await api('POST', '/api/domains', { url, type: domainType, check_interval: interval, notes, manual_expiry_date: manualExpiry, manual_registrar: manualRegistrar });
      toast(domainType === 'ssl_only' ? 'SSL domain added' : 'Domain added');
    }
    closeDomainModal();
    const v = activeView;
    if (v === 'domains') { clearDomainsCache('full'); loadDomains('full'); }
    else if (v === 'sslcerts') { clearDomainsCache('ssl_only'); loadDomains('ssl_only'); }
    else if (v === 'dashboard') loadDashboard();
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    setLoading(btn, false);
  }
});

// ─── Manual Check ─────────────────────────────────────────────
const checkingDomains = new Set();

async function manualCheck(id) {
  if (checkingDomains.has(id)) return;
  checkingDomains.add(id);
  const card = document.querySelector(`[id$="-${id}"]`);
  if (card) card.classList.add('checking');
  try {
    const type = activeView === 'sslcerts' ? 'ssl_only' : 'full';
    const d = (_cachedDomains[type] || []).find(x => x.id === id);
    if (d) {
      const sf = type === 'ssl_only' ? 'ssl_status' : 'domain_status';
      _prevStatuses[type][id] = d[sf];
    }
    const result = await api('POST', `/api/domains/${id}/check`);
    toast(`Check complete: ${result.status}`);
    const v = activeView;
    if (v === 'domains') { clearDomainsCache('full'); loadDomains('full'); }
    else if (v === 'sslcerts') { clearDomainsCache('ssl_only'); loadDomains('ssl_only'); }
    else loadDashboard();
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    checkingDomains.delete(id);
    if (card) card.classList.remove('checking');
  }
}

const checkingAll = { full: false, ssl_only: false };

async function checkAll(type) {
  if (checkingAll[type]) return;
  checkingAll[type] = true;
  const btnId = type === 'ssl_only' ? 'btn-check-all-ssl' : 'btn-check-all-full';
  const btn = document.getElementById(btnId);
  setLoading(btn, true);
  document.querySelectorAll(`#view-${type === 'ssl_only' ? 'sslcerts' : 'domains'} .domain-card`).forEach(c => c.classList.add('checking'));

  const progEl = document.getElementById('check-progress');
  if (progEl) { progEl.style.display = 'block'; progEl.style.width = '0%'; }
  let prog = 0;
  const progTimer = setInterval(() => { prog = Math.min(prog + Math.random() * 8, 90); if (progEl) progEl.style.width = prog + '%'; }, 500);

  toast('Checking all...', 'success');
  try {
    await api('POST', '/api/check-all');
    clearInterval(progTimer);
    if (progEl) { progEl.style.width = '100%'; setTimeout(() => { if (progEl) { progEl.style.display = 'none'; progEl.style.width = '0%'; } }, 500); }
    toast('Check all complete');
    const v = activeView;
    if (v === 'domains') { clearDomainsCache('full'); loadDomains('full'); }
    else if (v === 'sslcerts') { clearDomainsCache('ssl_only'); loadDomains('ssl_only'); }
    else loadDashboard();
  } catch (e) {
    clearInterval(progTimer);
    if (progEl) { progEl.style.display = 'none'; progEl.style.width = '0%'; }
    toast(e.message, 'error');
  } finally {
    checkingAll[type] = false;
    setLoading(btn, false);
    document.querySelectorAll(`#view-${type === 'ssl_only' ? 'sslcerts' : 'domains'} .domain-card`).forEach(c => c.classList.remove('checking'));
  }
}

// ─── Settings ──────────────────────────────────────────────────
function loadSettings() {
  // Restore last active settings tab
  try {
    var savedStab = localStorage.getItem('vigil-settings-tab');
    if (savedStab) switchSettingsTab(savedStab);
  } catch (e) {}

  // Try cache first
  const cached = sessionStorage.getItem('vigil-settings');
  if (cached) {
    try {
      const s = JSON.parse(cached);
      populateSettingsForm(s);
      loadSecuritySettings();
      loadSettingsTabData();
      return;
    } catch {}
  }

  api('GET', '/api/settings').then(s => {
    sessionStorage.setItem('vigil-settings', JSON.stringify(s));
    populateSettingsForm(s);
  }).catch(e => toast(e.message, 'error'));

  loadSecuritySettings();
  loadSettingsTabData();
}

function loadSettingsTabData() {
  const activeTab = document.querySelector('.settings-tab.active')?.dataset.stab;
  if (activeTab === 'users') loadUsers();
  if (activeTab === 'apikeys') loadApiKeys();
  if (activeTab === 'backups') loadBackups();
  if (activeTab === 'emailtpl') loadEmailTemplates();
}

function populateSettingsForm(s) {
  var fromEnv = s.smtp_from_env === true;

  var envBanner = document.getElementById('smtp-env-banner');
  if (envBanner) envBanner.style.display = fromEnv ? 'block' : 'none';

  document.querySelectorAll('#settings-form [data-env-managed]').forEach(function (el) {
    el.disabled = fromEnv;
  });
  document.querySelectorAll('#settings-form .env-badge').forEach(function (el) {
    el.style.display = fromEnv ? 'inline' : 'none';
  });

  document.getElementById('smtp_server').value = s.smtp_server || 'smtp.gmail.com';
  document.getElementById('smtp_port').value = s.smtp_port || 587;
  document.getElementById('smtp_email').value = s.smtp_email || '';
  document.getElementById('alert_emails').value = (s.alert_emails || '').split(',').join(', ');
  document.getElementById('ssl_alert_threshold').value = s.ssl_alert_threshold || 30;
  document.getElementById('domain_alert_threshold').value = s.domain_alert_threshold || 30;
  document.getElementById('smtp_enabled').checked = s.smtp_enabled !== 0;

  var pwInput = document.getElementById('smtp_password');
  pwInput.value = '';
  if (s.has_password) {
    pwInput.placeholder = fromEnv ? '•••••••• (set via .env)' : '•••••••• (leave blank to keep current)';
    document.getElementById('smtp-pw-hint').textContent = 'Password is set';
  } else {
    pwInput.placeholder = fromEnv ? 'Not configured in .env' : 'Enter password';
    document.getElementById('smtp-pw-hint').textContent = '';
  }

  document.getElementById('slack_webhook_url').value = s.slack_webhook_url || '';
  document.getElementById('slack_enabled').checked = s.slack_enabled !== 0;
  document.getElementById('zulip_webhook_url').value = s.zulip_webhook_url || '';
  document.getElementById('zulip_enabled').checked = s.zulip_enabled !== 0;

  _settingsOriginal = getSettingsFormData();
  _settingsDirty = false;
  updateUnsavedIndicator();
}

function getSettingsFormData() {
  return {
    smtp_server: document.getElementById('smtp_server').value,
    smtp_port: document.getElementById('smtp_port').value,
    smtp_email: document.getElementById('smtp_email').value,
    alert_emails: document.getElementById('alert_emails').value,
    ssl_alert_threshold: document.getElementById('ssl_alert_threshold').value,
    domain_alert_threshold: document.getElementById('domain_alert_threshold').value,
    smtp_enabled: document.getElementById('smtp_enabled').checked,
    slack_webhook_url: document.getElementById('slack_webhook_url').value,
    slack_enabled: document.getElementById('slack_enabled').checked,
    zulip_webhook_url: document.getElementById('zulip_webhook_url').value,
    zulip_enabled: document.getElementById('zulip_enabled').checked,
  };
}

function updateUnsavedIndicator() {
  const el = document.getElementById('unsaved-indicator');
  if (!el) return;
  const current = getSettingsFormData();
  const dirty = JSON.stringify(current) !== JSON.stringify(_settingsOriginal);
  _settingsDirty = dirty;
  el.style.display = dirty ? 'inline' : 'none';
}

// Track changes on settings form
document.getElementById('settings-form').addEventListener('input', () => updateUnsavedIndicator());
document.getElementById('settings-form').addEventListener('change', () => updateUnsavedIndicator());
document.getElementById('webhooks-form').addEventListener('input', () => updateUnsavedIndicator());
document.getElementById('webhooks-form').addEventListener('change', () => updateUnsavedIndicator());

// Unsaved changes warning
window.addEventListener('beforeunload', (e) => {
  if (_settingsDirty) { e.preventDefault(); e.returnValue = ''; }
});

document.getElementById('settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('btn-save-settings');
  const msgEl = document.getElementById('settings-message');
  msgEl.className = 'form-message';
  msgEl.style.display = 'none';

  // Validate all fields
  const fields = document.querySelectorAll('#settings-form [data-validate]');
  let valid = true;
  fields.forEach(f => { if (!validateField(f)) valid = false; });
  if (!valid) { msgEl.textContent = 'Please fix the errors above'; msgEl.className = 'form-message error'; msgEl.style.display = 'block'; return; }

  // Delta save: only send changed fields
  const current = getSettingsFormData();
  const changes = {};
  for (const key in current) {
    if (String(current[key]) !== String(_settingsOriginal[key])) changes[key] = current[key];
  }

  const pwd = document.getElementById('smtp_password').value;
  if (pwd) changes.smtp_password = pwd;

  if (Object.keys(changes).length === 0 && !pwd) { toast('No changes to save'); return; }

  setLoading(btn, true);
  try {
    await api('PUT', '/api/settings', changes);
    _settingsOriginal = current;
    _settingsDirty = false;
    updateUnsavedIndicator();
    msgEl.textContent = 'Settings saved successfully';
    msgEl.className = 'form-message success';
    msgEl.style.display = 'block';
    setTimeout(() => { msgEl.style.display = 'none'; }, 3000);
    toast('Settings saved');
    try { await api('POST', '/api/logs', { message: 'Settings updated', type: 'settings_change' }); } catch {}
    sessionStorage.removeItem('vigil-settings');
  } catch (e) {
    msgEl.textContent = e.message;
    msgEl.className = 'form-message error';
    msgEl.style.display = 'block';
  } finally {
    setLoading(btn, false);
  }
});

// ─── Webhooks save ────────────────────────────────────────────
document.getElementById('webhooks-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('btn-save-webhooks');
  const changes = {
    slack_webhook_url: document.getElementById('slack_webhook_url').value || '',
    slack_enabled: document.getElementById('slack_enabled').checked ? 1 : 0,
    zulip_webhook_url: document.getElementById('zulip_webhook_url').value || '',
    zulip_enabled: document.getElementById('zulip_enabled').checked ? 1 : 0,
  };
  setLoading(btn, true);
  try {
    await api('PUT', '/api/settings', changes);
    _settingsOriginal = getSettingsFormData();
    _settingsDirty = false;
    updateUnsavedIndicator();
    toast('Webhook settings saved');
    sessionStorage.removeItem('vigil-settings');
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    setLoading(btn, false);
  }
});

// ─── Inline validation ─────────────────────────────────────────
function validateField(el) {
  const type = el.dataset.validate;
  const val = el.value.trim();
  const errEl = document.getElementById('err-' + el.id);
  let msg = '';

  if (type === 'hostname') {
    if (val && !/^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$/.test(val)) msg = 'Invalid hostname';
  } else if (type === 'port') {
    const n = parseInt(val);
    if (isNaN(n) || n < 1 || n > 65535) msg = 'Port must be 1-65535';
  } else if (type === 'email') {
    if (val && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) msg = 'Invalid email';
  } else if (type === 'emails') {
    if (val) {
      const emails = val.split(',').map(e => e.trim()).filter(Boolean);
      for (const em of emails) { if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) { msg = 'Invalid email: ' + em; break; } }
    }
  } else if (type === 'positive-int') {
    const n = parseInt(val);
    if (isNaN(n) || n < 1) msg = 'Must be a positive number';
  }

  if (errEl) errEl.textContent = msg;
  el.classList.toggle('invalid', !!msg);
  el.classList.toggle('valid', !msg && !!val);
  return !msg;
}

document.querySelectorAll('[data-validate]').forEach(el => {
  el.addEventListener('blur', () => validateField(el));
  el.addEventListener('input', () => { if (el.classList.contains('invalid')) validateField(el); });
});

// ─── Reset to defaults ─────────────────────────────────────────
document.addEventListener('click', (e) => {
  if (e.target.dataset.action === 'reset-smtp') {
    document.getElementById('smtp_server').value = 'smtp.gmail.com';
    document.getElementById('smtp_port').value = 587;
    document.getElementById('smtp_email').value = '';
    document.getElementById('smtp_password').value = '';
    document.getElementById('alert_emails').value = '';
    document.getElementById('ssl_alert_threshold').value = 30;
    document.getElementById('domain_alert_threshold').value = 30;
    document.getElementById('smtp_enabled').checked = false;
    updateUnsavedIndicator();
    toast('SMTP settings reset to defaults');
  }
  if (e.target.dataset.action === 'reset-security') {
    document.getElementById('session_timeout').value = 60;
    document.getElementById('max_login_attempts').value = 5;
    document.getElementById('lockout_duration').value = 15;
    document.getElementById('min_password_length').value = 8;
    document.getElementById('require_uppercase').checked = true;
    document.getElementById('require_lowercase').checked = true;
    document.getElementById('require_number').checked = true;
    document.getElementById('require_special').checked = false;
    toast('Security settings reset to defaults');
  }
});

// ─── Async SMTP test with live output ──────────────────────────
async function testSmtp() {
  const btn = document.getElementById('btn-test-smtp');
  const logEl = document.getElementById('smtp-test-log');
  setLoading(btn, true);
  logEl.style.display = 'block';
  logEl.innerHTML = '';

  const addLog = (msg, cls) => { logEl.innerHTML += `<div class="log-step ${cls}">${msg}</div>`; logEl.scrollTop = logEl.scrollHeight; };

  addLog('Resolving SMTP server...', 'wait');
  try {
    const result = await api('POST', '/api/settings/test-smtp');
    if (result.steps) {
      result.steps.forEach(s => addLog(s.message, s.ok ? 'ok' : 'fail'));
    } else {
      addLog('Test SMTP sent! Check your inbox.', 'ok');
    }
    document.querySelector('#smtp-status .dot').className = 'dot success';
    document.getElementById('smtp-status-text').textContent = 'Sent successfully';
  } catch (e) {
    addLog('Failed: ' + e.message, 'fail');
    document.querySelector('#smtp-status .dot').className = 'dot failed';
    document.getElementById('smtp-status-text').textContent = 'Failed: ' + e.message;
  } finally {
    setLoading(btn, false);
  }
}

// ─── Test webhook ──────────────────────────────────────────────
function testWebhook(type) {
  var urlInput = document.getElementById(type + '_webhook_url');
  var url = urlInput ? urlInput.value : '';
  if (!url) { toast('Enter a ' + type + ' webhook URL first', 'error'); return; }
  var btn = document.querySelector('[data-action="test-webhook"][data-webhook-type="' + type + '"]');
  var resultEl = document.getElementById('test-' + type + '-result');
  resultEl.textContent = 'Sending...';
  if (btn) { btn.classList.add('btn-loading'); btn.disabled = true; }
  api('POST', '/api/settings/test-webhook', { type: type, url: url }).then(function () {
    resultEl.textContent = '✓ Sent';
    toast(type.charAt(0).toUpperCase() + type.slice(1) + ' test sent');
  }).catch(function (err) {
    resultEl.textContent = '✗ ' + err.message;
  }).finally(function () {
    if (btn) { btn.classList.remove('btn-loading'); btn.disabled = false; }
  });
}

// ─── Settings export/import ──────────────────────────────────
function exportSettings() {
  api('GET', '/api/settings/export').then(function (data) {
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vigil-settings-' + new Date().toISOString().slice(0, 10) + '.json';
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Settings exported');
  }).catch(function (e) { toast(e.message, 'error'); });
}

document.getElementById('settings-import-input').addEventListener('change', function (e) {
  var file = e.target.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function (ev) {
    try {
      var data = JSON.parse(ev.target.result);
      api('POST', '/api/settings/import', data).then(function () {
        toast('Settings imported. Reloading...');
        sessionStorage.removeItem('vigil-settings');
        setTimeout(function () { window.location.reload(); }, 1500);
      }).catch(function (err) { toast(err.message, 'error'); });
    } catch (err) {
      toast('Invalid JSON file: ' + err.message, 'error');
    }
  };
  reader.readAsText(file);
  e.target.value = '';
});

// ─── Bulk API key revoke ─────────────────────────────────────
function bulkRevokeApiKeys() {
  var checked = document.querySelectorAll('#api-keys-list input[type="checkbox"]:checked');
  var ids = [];
  checked.forEach(function (cb) { ids.push(parseInt(cb.value)); });
  if (ids.length === 0) { toast('Select API keys to revoke', 'error'); return; }
  if (!confirm('Revoke ' + ids.length + ' API key(s)?')) return;
  api('POST', '/api/api-keys/bulk-revoke', { ids: ids }).then(function () {
    loadApiKeys();
    toast(ids.length + ' API key(s) revoked');
  }).catch(function (e) { toast(e.message, 'error'); });
}

// ─── Toggle password visibility ────────────────────────────────
document.addEventListener('click', (e) => {
  if (e.target.dataset.action === 'toggle-pw-visibility') {
    const input = document.getElementById(e.target.dataset.target);
    if (input) input.type = input.type === 'password' ? 'text' : 'password';
  }
});

// ─── Password strength meter ───────────────────────────────────
document.getElementById('user-password').addEventListener('input', (e) => {
  const pw = e.target.value;
  const fill = document.getElementById('pw-strength-fill');
  const label = document.getElementById('pw-strength-label');
  const reqs = document.querySelectorAll('.pw-req');

  if (!pw) { fill.className = 'pw-strength-fill'; label.textContent = ''; reqs.forEach(r => r.classList.remove('met')); return; }

  let score = 0;
  const hasUpper = /[A-Z]/.test(pw);
  const hasLower = /[a-z]/.test(pw);
  const hasNumber = /\d/.test(pw);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pw);
  const meetsLen = pw.length >= _pwPolicy.minLength;

  if (meetsLen) score++;
  if (hasUpper && _pwPolicy.requireUpper) score++;
  if (hasLower && _pwPolicy.requireLower) score++;
  if (hasNumber && _pwPolicy.requireNumber) score++;
  if (hasSpecial && _pwPolicy.requireSpecial) score++;

  const total = 1 + (_pwPolicy.requireUpper ? 1 : 0) + (_pwPolicy.requireLower ? 1 : 0) + (_pwPolicy.requireNumber ? 1 : 0) + (_pwPolicy.requireSpecial ? 1 : 0);
  const pct = score / total;

  fill.className = 'pw-strength-fill';
  if (pct <= 0.3) { fill.classList.add('weak'); label.textContent = 'Weak'; }
  else if (pct <= 0.5) { fill.classList.add('fair'); label.textContent = 'Fair'; }
  else if (pct <= 0.75) { fill.classList.add('good'); label.textContent = 'Good'; }
  else { fill.classList.add('strong'); label.textContent = 'Strong'; }

  document.querySelector('[data-req="length"]').classList.toggle('met', meetsLen);
  document.querySelector('[data-req="upper"]').classList.toggle('met', hasUpper);
  document.querySelector('[data-req="lower"]').classList.toggle('met', hasLower);
  document.querySelector('[data-req="number"]').classList.toggle('met', hasNumber);
  document.querySelector('[data-req="special"]').classList.toggle('met', hasSpecial);
});

// ─── Password policy validation ────────────────────────────────
function validatePassword(pw) {
  const errors = [];
  if (pw.length < _pwPolicy.minLength) errors.push(`Min ${_pwPolicy.minLength} characters`);
  if (_pwPolicy.requireUpper && !/[A-Z]/.test(pw)) errors.push('Uppercase letter required');
  if (_pwPolicy.requireLower && !/[a-z]/.test(pw)) errors.push('Lowercase letter required');
  if (_pwPolicy.requireNumber && !/\d/.test(pw)) errors.push('Number required');
  if (_pwPolicy.requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pw)) errors.push('Special character required');
  return errors;
}

// ─── Security settings ─────────────────────────────────────────
function loadSecuritySettings() {
  api('GET', '/api/security-settings').then(s => {
    document.getElementById('session_timeout').value = s.session_timeout || 60;
    document.getElementById('max_login_attempts').value = s.max_login_attempts || 5;
    document.getElementById('lockout_duration').value = s.lockout_duration || 15;
    document.getElementById('min_password_length').value = s.min_password_length || 8;
    document.getElementById('require_uppercase').checked = s.require_uppercase !== false;
    document.getElementById('require_lowercase').checked = s.require_lowercase !== false;
    document.getElementById('require_number').checked = s.require_number !== false;
    document.getElementById('require_special').checked = s.require_special || false;
    _pwPolicy = {
      minLength: s.min_password_length || 8,
      requireUpper: s.require_uppercase !== false,
      requireLower: s.require_lowercase !== false,
      requireNumber: s.require_number !== false,
      requireSpecial: s.require_special || false
    };
  }).catch(() => {});
}

document.getElementById('security-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('btn-save-security');
  const settings = {
    session_timeout: parseInt(document.getElementById('session_timeout').value) || 60,
    max_login_attempts: parseInt(document.getElementById('max_login_attempts').value) || 5,
    lockout_duration: parseInt(document.getElementById('lockout_duration').value) || 15,
    min_password_length: parseInt(document.getElementById('min_password_length').value) || 8,
    require_uppercase: document.getElementById('require_uppercase').checked,
    require_lowercase: document.getElementById('require_lowercase').checked,
    require_number: document.getElementById('require_number').checked,
    require_special: document.getElementById('require_special').checked,
  };
  setLoading(btn, true);
  try {
    await api('PUT', '/api/security-settings', settings);
    _pwPolicy = {
      minLength: settings.min_password_length,
      requireUpper: settings.require_uppercase,
      requireLower: settings.require_lowercase,
      requireNumber: settings.require_number,
      requireSpecial: settings.require_special
    };
    toast('Security settings saved');
    try { await api('POST', '/api/logs', { message: 'Security settings updated', type: 'settings_change' }); } catch {}
  } catch (e) { toast(e.message, 'error'); }
  finally { setLoading(btn, false); }
});

// ─── API Keys ──────────────────────────────────────────────────
function loadApiKeys(force) {
  const container = document.getElementById('api-keys-list');
  if (container && (force || _apiKeys.length === 0)) {
    container.innerHTML = '<div class="settings-list-state">Loading API keys...</div>';
  }
  api('GET', '/api/api-keys').then(keys => {
    _apiKeys = keys;
    renderApiKeys();
  }).catch(e => {
    if (container) container.innerHTML = '<div class="settings-list-state error">Failed to load API keys: ' + escHtml(e.message) + '</div>';
  });
}

function renderApiKeys() {
  const container = document.getElementById('api-keys-list');
  if (!container) return;
  const newKeyHtml = _newApiKey ? `
    <div class="api-key-new">
      <div class="key-name">New API Key (copy now; it will not be shown again)</div>
      <div class="key-value">${escHtml(_newApiKey)}</div>
    </div>
  ` : '';
  if (_apiKeys.length === 0) {
    container.innerHTML = newKeyHtml + '<div class="settings-list-state">No API keys generated.</div>';
    updateBulkRevokeBtn();
    return;
  }
  container.innerHTML = newKeyHtml + _apiKeys.map(k => `
    <div class="api-key-card">
      <label style="display:flex;align-items:center;gap:10px;flex:1;cursor:pointer">
        <input type="checkbox" class="api-key-cb" value="${k.id}" style="width:16px;height:16px;accent-color:var(--primary);flex-shrink:0">
        <div class="key-info" style="flex:1">
          <div class="key-name">${escHtml(k.name || 'Key')}</div>
          <div class="key-value">${escHtml(k.key_masked || 'Key hidden')}</div>
          <div class="key-meta">Created: ${formatDate(k.created_at)}${k.last_used ? ' · Last used: ' + formatDate(k.last_used) : ''}</div>
        </div>
      </label>
      <div class="key-actions">
        <button class="btn btn-sm btn-danger" data-action="revoke-apikey" data-id="${k.id}">Revoke</button>
      </div>
    </div>
  `).join('');
  updateBulkRevokeBtn();
}

function updateBulkRevokeBtn() {
  var btn = document.getElementById('btn-bulk-revoke');
  if (!btn) return;
  var checked = document.querySelectorAll('#api-keys-list input[type="checkbox"]:checked');
  btn.style.display = checked.length > 0 ? 'inline-block' : 'none';
  btn.textContent = 'Revoke Selected (' + checked.length + ')';
}

document.addEventListener('click', (e) => {
  if (e.target.dataset.action === 'generate-apikey') {
    const name = prompt('Name this API key', 'Key-' + new Date().toISOString().slice(0, 10));
    if (name === null) return;
    const trimmedName = name.trim() || 'Key-' + Date.now();
    api('POST', '/api/api-keys', { name: trimmedName }).then(data => {
      _newApiKey = data.key;
      loadApiKeys();
      toast('API key generated');
    }).catch(e => toast(e.message, 'error'));
  }
  if (e.target.dataset.action === 'revoke-apikey') {
    if (!confirm('Revoke this API key?')) return;
    api('DELETE', `/api/api-keys/${e.target.dataset.id}`).then(() => {
      loadApiKeys();
      toast('API key revoked');
    }).catch(e => toast(e.message, 'error'));
  }
});

// ─── Backups ──────────────────────────────────────────────────
function loadBackups(force) {
  const container = document.getElementById('backups-list');
  if (container && force) container.innerHTML = '<div class="settings-list-state">Loading backups...</div>';
  api('GET', '/api/backups').then(backups => {
    if (!container) return;
    if (backups.length === 0) { container.innerHTML = '<div class="settings-list-state">No backups yet.</div>'; return; }
    container.innerHTML = backups.map(b => {
      var meta = '';
      if (b.domain_count !== undefined && b.domain_count !== null) {
        meta += '<span style="margin-right:8px">' + b.domain_count + ' domains</span>';
      }
      if (b.db_size) {
        var pct = ((1 - b.size / b.db_size) * 100).toFixed(0);
        meta += '<span style="color:var(--green)">' + formatSize(b.size) + ' (' + pct + '% smaller)</span>';
      } else {
        meta += formatSize(b.size);
      }
      return '<div class="backup-card">' +
        '<div class="backup-info">' +
          '<div class="backup-name">' + escHtml(b.filename) + '</div>' +
          '<div class="backup-meta">' + meta + ' · Created: ' + formatDate(b.created) + '</div>' +
        '</div>' +
        '<div class="backup-actions">' +
          '<button class="btn btn-sm btn-secondary" data-action="download-backup" data-file="' + escHtml(b.filename) + '">Download</button>' +
          '<button class="btn btn-sm btn-secondary" data-action="restore-backup" data-file="' + escHtml(b.filename) + '">Restore</button>' +
          '<button class="btn btn-sm btn-danger" data-action="delete-backup" data-file="' + escHtml(b.filename) + '">Delete</button>' +
        '</div>' +
      '</div>';
    }).join('');
  }).catch(e => {
    if (container) container.innerHTML = '<div class="settings-list-state error">Failed to load backups: ' + escHtml(e.message) + '</div>';
  });
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

document.addEventListener('click', (e) => {
  if (e.target.dataset.action === 'create-backup') {
    api('POST', '/api/backups').then(() => {
      toast('Backup created');
      loadBackups(true);
    }).catch(e => toast(e.message, 'error'));
  }
  if (e.target.dataset.action === 'download-backup') {
    window.open(`/api/backups/download/${e.target.dataset.file}`, '_blank');
  }
  if (e.target.dataset.action === 'restore-backup') {
    if (!confirm(`Restore database from ${e.target.dataset.file}? This will replace the current database.`)) return;
    api('POST', '/api/backups/restore', { filename: e.target.dataset.file }).then(() => {
      toast('Database restored. Reloading...');
      setTimeout(() => window.location.reload(), 1500);
    }).catch(e => toast(e.message, 'error'));
  }
  if (e.target.dataset.action === 'delete-backup') {
    if (!confirm(`Delete backup ${e.target.dataset.file}?`)) return;
    api('DELETE', `/api/backups/${e.target.dataset.file}`).then(() => {
      toast('Backup deleted');
      loadBackups(true);
    }).catch(e => toast(e.message, 'error'));
  }
});

// ─── Backup dedicated view ────────────────────────────────────
function loadBackupsView() {
  loadBackupDbInfo();
  loadBackupsViewList();
}

function loadBackupDbInfo() {
  const container = document.getElementById('backup-db-info');
  if (!container) return;
  container.innerHTML = '<div class="settings-list-state">Loading database info...</div>';
  api('GET', '/api/backups/info').then(info => {
    var typeBadge = info.type === 'postgresql' ? 'PostgreSQL' : 'SQLite';
    var typeClass = info.type === 'postgresql' ? 'badge-pg' : 'badge-sqlite';
    var sizeStr = info.size ? formatSize(info.size) : 'N/A';
    var connInfo = '';
    if (info.type === 'postgresql') {
      connInfo = '<span class="backup-meta-item">Host: ' + escHtml(info.host || 'localhost') + '</span>' +
                 '<span class="backup-meta-item">DB: ' + escHtml(info.db || 'vigil') + '</span>' +
                 '<span class="backup-meta-item">Schema: ' + escHtml(info.schema || 'vigil') + '</span>';
    } else {
      connInfo = '<span class="backup-meta-item">Size: ' + sizeStr + '</span>';
    }
    container.innerHTML =
      '<div class="backup-db-card">' +
        '<div class="backup-db-header">' +
          '<span class="backup-db-label">Database</span>' +
          '<span class="badge ' + typeClass + '">' + typeBadge + '</span>' +
        '</div>' +
        '<div class="backup-db-body">' +
          '<div class="backup-meta-row">' +
            '<span class="backup-meta-item">Domains: <strong>' + (info.domain_count !== null && info.domain_count !== undefined ? info.domain_count : 'N/A') + '</strong></span>' +
            '<span class="backup-meta-item">Backups: <strong>' + info.backup_count + '</strong></span>' +
            '<span class="backup-meta-item">Max Retention: <strong>' + info.max_backups + '</strong></span>' +
            connInfo +
          '</div>' +
        '</div>' +
      '</div>';
  }).catch(e => {
    if (container) container.innerHTML = '<div class="settings-list-state error">Failed to load DB info: ' + escHtml(e.message) + '</div>';
  });
}

function loadBackupsViewList() {
  const container = document.getElementById('backups-view-list');
  if (!container) return;
  const label = document.getElementById('backup-count-label');
  container.innerHTML = '<div class="settings-list-state">Loading backups...</div>';
  api('GET', '/api/backups').then(backups => {
    if (!container) return;
    if (backups.length === 0) {
      container.innerHTML = '<div class="settings-list-state">No backups yet. Create one to get started.</div>';
      if (label) label.textContent = '0 backups';
      return;
    }
    if (label) label.textContent = backups.length + ' backup' + (backups.length !== 1 ? 's' : '');
    container.innerHTML = backups.map(b => {
      var meta = '';
      var formatBadge = '';
      var fmt = b.filename ? b.filename.split('.').slice(-2, -1)[0] || '' : '';
      if (b.filename && b.filename.endsWith('.sql.gz')) formatBadge = '<span class="badge badge-pg">pg_dump</span>';
      else if (b.filename && b.filename.endsWith('.json.gz')) formatBadge = '<span class="badge badge-json">JSON</span>';
      else formatBadge = '<span class="badge badge-sqlite">SQLite</span>';
      if (b.domain_count !== undefined && b.domain_count !== null) {
        meta += '<span class="backup-meta-item">' + b.domain_count + ' domains</span>';
      }
      meta += '<span class="backup-meta-item">' + formatSize(b.size) + '</span>';
      if (b.notes) {
        meta += '<span class="backup-meta-item backup-notes">Notes: ' + escHtml(b.notes) + '</span>';
      }
      return '<div class="backup-card">' +
        '<div class="backup-info">' +
          '<div class="backup-name">' + formatBadge + ' ' + escHtml(b.filename) + '</div>' +
          '<div class="backup-meta">' + meta + ' · Created: ' + formatDate(b.created) + '</div>' +
        '</div>' +
        '<div class="backup-actions">' +
          '<button class="btn btn-sm btn-secondary" data-action="download-backup" data-file="' + escHtml(b.filename) + '">Download</button>' +
          '<button class="btn btn-sm btn-secondary" data-action="restore-backup" data-file="' + escHtml(b.filename) + '">Restore</button>' +
          '<button class="btn btn-sm btn-danger" data-action="delete-backup" data-file="' + escHtml(b.filename) + '">Delete</button>' +
        '</div>' +
      '</div>';
    }).join('');
  }).catch(e => {
    if (container) container.innerHTML = '<div class="settings-list-state error">Failed to load backups: ' + escHtml(e.message) + '</div>';
  });
}

function createBackupWithNotes() {
  var notes = document.getElementById('backup-notes-input').value.trim();
  api('POST', '/api/backups', notes ? { notes: notes } : undefined).then(() => {
    toast('Backup created');
    document.getElementById('backup-create-pane').style.display = 'none';
    loadBackupsViewList();
    loadBackupDbInfo();
  }).catch(e => toast(e.message, 'error'));
}

function uploadAndRestoreBackup() {
  var input = document.getElementById('backup-upload-input');
  if (!input.files || !input.files[0]) { toast('Please select a backup file', 'error'); return; }
  if (!confirm('Restore database from uploaded file "' + input.files[0].name + '"? This will replace the current database. A pre-restore snapshot will be created.')) return;
  var formData = new FormData();
  formData.append('file', input.files[0]);
  fetch('/api/backups/upload', {
    method: 'POST',
    headers: { 'X-CSRF-Token': _csrfToken },
    body: formData
  }).then(res => {
    var newToken = res.headers.get('X-CSRF-Token');
    if (newToken) _csrfToken = newToken;
    if (res.status === 401) { window.location.href = '/'; throw new Error('Session expired'); }
    return res.json().then(d => { if (!res.ok) throw new Error(d.error || 'Upload failed'); return d; });
  }).then(() => {
    toast('Database restored from uploaded backup. Reloading...');
    setTimeout(() => window.location.reload(), 1500);
  }).catch(e => toast(e.message, 'error'));
}

function saveBackupSchedule() {
  var hour = parseInt(document.getElementById('backup-schedule-hour').value);
  var minute = parseInt(document.getElementById('backup-schedule-minute').value);
  var maxBackups = parseInt(document.getElementById('backup-max-retention').value);
  if (isNaN(hour) || hour < 0 || hour > 23) { toast('Invalid hour (0-23)', 'error'); return; }
  if (isNaN(minute) || minute < 0 || minute > 59) { toast('Invalid minute (0-59)', 'error'); return; }
  if (isNaN(maxBackups) || maxBackups < 1 || maxBackups > 365) { toast('Max backups must be 1-365', 'error'); return; }

  api('PUT', '/api/settings', { backup_schedule_hour: hour, backup_schedule_minute: minute, max_backups: maxBackups }).then(() => {
    toast('Backup schedule saved. Restart required for schedule change to take effect.');
    document.getElementById('backup-schedule-card').style.display = 'none';
    loadBackupDbInfo();
  }).catch(e => toast(e.message, 'error'));
}

// API key checkbox → bulk revoke button
document.addEventListener('change', function (e) {
  if (e.target.classList.contains('api-key-cb')) updateBulkRevokeBtn();
});

// ─── Email Templates ──────────────────────────────────────────
let _emailTplDefaults = {};
let _currentEmailTpl = 'ssl_alert';
let _emailTplLoaded = false;

function loadEmailTemplates(force) {
  const form = document.getElementById('email-tpl-form');
  if (form && (force || !_emailTplLoaded)) form.classList.add('settings-loading');
  api('GET', '/api/email-templates').then(tpls => {
    _emailTplDefaults = tpls;
    _emailTplLoaded = true;
    renderEmailTplTab(_currentEmailTpl);
  }).catch(e => {
    toast('Failed to load email templates: ' + e.message, 'error');
  }).finally(() => {
    if (form) form.classList.remove('settings-loading');
  });
}

function renderEmailTplTab(tplName) {
  _currentEmailTpl = tplName;
  document.querySelectorAll('.email-tpl-tab').forEach(t => t.classList.toggle('active', t.dataset.tpl === tplName));

  const tpl = _emailTplDefaults[tplName] || {};
  document.getElementById('email-tpl-subject').value = tpl.subject || '';
  document.getElementById('email-tpl-html').value = tpl.body_html || '';
  document.getElementById('email-tpl-text').value = tpl.body_text || '';
  document.getElementById('email-tpl-preview').style.display = 'none';
}

document.addEventListener('click', (e) => {
  if (e.target.closest('.email-tpl-tab')) {
    const tab = e.target.closest('.email-tpl-tab');
    renderEmailTplTab(tab.dataset.tpl);
  }
  if (e.target.dataset.action === 'preview-email-tpl') {
    const subject = document.getElementById('email-tpl-subject').value;
    const html = document.getElementById('email-tpl-html').value;
    const preview = document.getElementById('email-tpl-preview');
    preview.style.display = 'block';
    const safeHtml = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '').replace(/on\w+\s*=\s*"[^"]*"/gi, '').replace(/on\w+\s*=\s*'[^']*'/gi, '');
    preview.innerHTML = `<div style="font-size:13px;color:var(--text-muted);margin-bottom:8px">Subject: ${escHtml(subject)}</div>${safeHtml}`;
  }
  if (e.target.dataset.action === 'reset-email-templates') {
    if (!confirm('Reset all email templates to defaults?')) return;
    api('PUT', '/api/email-templates/reset', {}).then(() => {
      loadEmailTemplates(true);
      toast('Templates reset to defaults');
    });
  }
});

document.getElementById('email-tpl-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('btn-save-template');
  const tpl = {
    subject: document.getElementById('email-tpl-subject').value,
    body_html: document.getElementById('email-tpl-html').value,
    body_text: document.getElementById('email-tpl-text').value,
  };
  setLoading(btn, true);
  try {
    await api('PUT', `/api/email-templates/${_currentEmailTpl}`, tpl);
    _emailTplDefaults[_currentEmailTpl] = tpl;
    toast('Template saved');
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    setLoading(btn, false);
  }
});


// ─── Users ─────────────────────────────────────────────────────
async function loadUsers() {
  if (_usersLoaded) return;
  try {
    const tbody = document.getElementById('user-body');
    if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="user-loading">Loading users...</td></tr>';
    const users = await api('GET', '/api/users');
    _usersCache = users;
    renderUsers();
    _usersLoaded = true;
  } catch (e) {
    toast(e.message, 'error');
  }
}

function refreshUsers() {
  _usersLoaded = false;
  loadUsers();
}

function clearUserFilters() {
  _userFilters = { search: '', role: 'all', status: 'all' };
  const search = document.getElementById('user-search');
  const role = document.getElementById('user-role-filter');
  const status = document.getElementById('user-status-filter');
  if (search) search.value = '';
  if (role) role.value = 'all';
  if (status) status.value = 'all';
  renderUsers();
}

function filteredUsers() {
  const q = _userFilters.search.toLowerCase();
  return _usersCache.filter(u => {
    const role = u.role || 'admin';
    const active = u.is_active !== 0;
    if (q && !String(u.username || '').toLowerCase().includes(q)) return false;
    if (_userFilters.role !== 'all' && role !== _userFilters.role) return false;
    if (_userFilters.status === 'active' && !active) return false;
    if (_userFilters.status === 'inactive' && active) return false;
    return true;
  });
}

function renderUserSummary(users) {
  users = users || [];
  const admins = users.filter(u => (u.role || 'admin') === 'admin').length;
  const active = users.filter(u => u.is_active !== 0).length;
  const risks = users.filter(u => (u.login_fails || 0) > 0).length;
  const set = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };
  set('user-total-count', users.length);
  set('user-admin-count', admins);
  set('user-active-count', active);
  set('user-risk-count', risks);
}

function renderUsers() {
  const tbody = document.getElementById('user-body');
  const empty = document.getElementById('user-empty');
  if (!tbody) return;
  renderUserSummary(_usersCache);
  const users = filteredUsers();
  if (empty) empty.style.display = users.length ? 'none' : '';
  tbody.innerHTML = users.map(u => {
    const rowId = `user-${u.id}`;
    const role = u.role || 'admin';
    const lastLogin = u.last_login ? formatDate(u.last_login) : 'Never';
    const fails = u.login_fails || 0;
    const active = u.is_active !== 0;
    const activeLabel = active ? 'Active' : 'Inactive';
    const activeClass = active ? 'active' : 'inactive';
    const isCurrent = u.username === _currentUsername;
    const currentBadge = isCurrent ? '<span class="current-user-badge">You</span>' : '';
    const selfTitle = isCurrent ? ' title="You cannot disable or delete your own account"' : '';
    const selfDisabled = isCurrent ? ' disabled' : '';
    return `<tr id="${rowId}">
      <td><div class="user-name-cell"><span>${escHtml(u.username)}</span>${currentBadge}<small>ID ${u.id}</small></div></td>
      <td><span class="role-badge ${role}">${role}</span></td>
      <td><span class="status-indicator ${activeClass}">${activeLabel}</span></td>
      <td>${lastLogin}</td>
      <td>${fails > 0 ? '<span class="login-fail-count">' + fails + '</span>' : '0'}</td>
      <td class="table-actions-cell">
        <div class="kebab-menu">
          <button class="kebab-btn" data-action="toggle-kebab" data-id="${u.id}" aria-label="Actions">&#8942;</button>
          <div class="kebab-dropdown" id="kebab-user-${u.id}" style="display:none">
            <button class="kebab-item" data-action="edit-user" data-id="${u.id}" data-name="${escHtml(u.username)}" data-role="${role}">&#x270E; Edit</button>
            <button class="kebab-item" data-action="toggle-user-active" data-id="${u.id}" data-name="${escHtml(u.username)}" data-active="${active ? '1' : '0'}"${selfDisabled}${selfTitle}>${active ? '&#10007; Deactivate' : '&#10003; Reactivate'}</button>
            <button class="kebab-item kebab-item-danger" data-action="delete-user" data-id="${u.id}" data-name="${escHtml(u.username)}"${selfDisabled}${selfTitle}>&#x2716; Delete</button>
          </div>
        </div>
      </td>
    </tr>`;
  }).join('');
}

function openUserModal() {
  document.getElementById('user-modal-title').textContent = 'Add User';
  document.getElementById('user-id').value = '';
  document.getElementById('user-form').reset();
  document.getElementById('user-username').disabled = false;
  document.getElementById('user-username-hint').textContent = '';
  document.getElementById('user-password').required = true;
  document.getElementById('user-password').placeholder = '';
  document.getElementById('user-role').value = 'viewer';
  document.getElementById('pw-strength-fill').className = 'pw-strength-fill';
  document.getElementById('pw-strength-label').textContent = '';
  document.querySelectorAll('.pw-req').forEach(r => r.classList.remove('met'));
  document.getElementById('user-modal').classList.add('open');
  document.getElementById('user-username').focus();
}

function openEditUserModal(id, username, role) {
  document.getElementById('user-modal-title').textContent = `Edit User: ${username}`;
  document.getElementById('user-id').value = id;
  document.getElementById('user-username').value = username;
  document.getElementById('user-username').disabled = true;
  document.getElementById('user-username-hint').textContent = 'Usernames cannot be changed after creation.';
  document.getElementById('user-password').value = '';
  document.getElementById('user-password').required = false;
  document.getElementById('user-password').placeholder = 'Leave blank to keep current';
  document.getElementById('user-role').value = role || 'viewer';
  document.getElementById('pw-strength-fill').className = 'pw-strength-fill';
  document.getElementById('pw-strength-label').textContent = '';
  document.querySelectorAll('.pw-req').forEach(r => r.classList.remove('met'));
  document.getElementById('user-modal').classList.add('open');
}

function closeUserModal() {
  document.getElementById('user-modal').classList.remove('open');
}

document.getElementById('user-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('btn-save-user');
  const id = document.getElementById('user-id').value;
  const username = document.getElementById('user-username').value.trim();
  const password = document.getElementById('user-password').value;
  const role = document.getElementById('user-role').value;

  if (password) {
    const errors = validatePassword(password);
    if (errors.length > 0) { toast('Password: ' + errors.join(', '), 'error'); return; }
  }

  setLoading(btn, true);
  try {
    if (id) {
      const body = { role };
      if (password) { body.password = password; }
      await api('PUT', `/api/users/${id}`, body);
      toast('User updated');
    } else {
      if (!password) { toast('Password required'); return; }
      await api('POST', '/api/users', { username, password, role });
      toast('User created');
    }
    closeUserModal();
    _usersLoaded = false;
    loadUsers();
    try { await api('POST', '/api/logs', { message: `User ${id ? 'updated' : 'created'}: ${username}`, type: 'settings_change' }); } catch {}
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    setLoading(btn, false);
  }
});

// ─── Confirm delete with username ──────────────────────────────
let _confirmDeleteTarget = null;
let _confirmDeleteType = null;

function confirmDelete(id, name, type) {
  if (type === 'user' && name === _currentUsername) {
    toast('You cannot delete your own account', 'error');
    return;
  }
  _confirmDeleteTarget = { id, name };
  _confirmDeleteType = type || 'domain';
  const modal = document.getElementById('confirm-modal');
  const title = document.getElementById('confirm-modal-title');
  const text = document.getElementById('confirm-text');
  const row = document.getElementById('confirm-username-row');
  const input = document.getElementById('confirm-username-input');
  const btn = document.getElementById('confirm-delete-btn');

  btn.disabled = true;
  input.value = '';

  if (_confirmDeleteType === 'user') {
    title.textContent = 'Confirm Delete User';
    text.textContent = `Delete user "${name}"? This cannot be undone.`;
    row.style.display = 'block';
    input.placeholder = `Type "${name}" to confirm`;
    input.oninput = () => { btn.disabled = input.value !== name; };
  } else {
    title.textContent = 'Confirm Delete';
    text.textContent = `Delete "${name}"?`;
    row.style.display = 'none';
    btn.disabled = false;
  }

  modal.classList.add('open');
}

document.getElementById('confirm-delete-btn').addEventListener('click', async () => {
  if (!_confirmDeleteTarget) return;
  const btn = document.getElementById('confirm-delete-btn');
  const { id, name } = _confirmDeleteTarget;
  setLoading(btn, true);

  if (_confirmDeleteType !== 'user') {
    const suffix = activeView === 'sslcerts' ? 'ssl' : 'full';
    const card = document.getElementById(`card-${suffix}-${id}`);
    if (card) card.classList.add('removing');
    else {
      const row = document.querySelector(`.kebab-btn[data-id="${id}"]`)?.closest('tr');
      if (row) row.classList.add('removing');
    }
  }

  try {
    if (_confirmDeleteType === 'user') {
      await api('DELETE', `/api/users/${id}`);
      toast(`User ${name} deleted`);
      _usersLoaded = false;
      loadUsers();
    } else {
      const type = activeView === 'sslcerts' ? 'ssl_only' : 'full';
      await new Promise(r => setTimeout(r, 350));
      const cached = _cachedDomains[type] || [];
      const idx = cached.findIndex(d => d.id === id);
      const removed = idx !== -1 ? cached.splice(idx, 1)[0] : null;
      clearDomainsCache(type);
      renderDomains(_cachedDomains[type], type);
      renderPagination(type);
      try {
        await api('DELETE', `/api/domains/${id}`);
        toast(`Domain ${name} deleted`);
      } catch (e) {
        toast(`Delete failed: ${e.message}`, 'error');
        if (removed) _cachedDomains[type] = [...(_cachedDomains[type] || []), removed];
        clearDomainsCache(type);
        renderDomains(_cachedDomains[type], type);
        renderPagination(type);
      }
    }
    try { await api('POST', '/api/logs', { message: `Deleted ${_confirmDeleteType}: ${name}`, type: 'bulk_delete' }); } catch {}
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    setLoading(btn, false);
  }
  closeConfirmModal();
});

function closeConfirmModal() {
  document.getElementById('confirm-modal').classList.remove('open');
  _confirmDeleteTarget = null;
  _confirmDeleteType = null;
}

function deleteUser(id, username) {
  confirmDelete(id, username, 'user');
}

async function toggleUserActive(id, username, currentlyActive) {
  if (username === _currentUsername) { toast('You cannot deactivate your own account', 'error'); return; }
  if (!confirm(`${currentlyActive ? 'Deactivate' : 'Reactivate'} user "${username}"?`)) return;
  try {
    await api('PUT', `/api/users/${id}`, { is_active: !currentlyActive });
    toast(`User ${username} ${currentlyActive ? 'deactivated' : 'reactivated'}`);
    _usersLoaded = false;
    loadUsers();
  } catch (e) {
    toast(e.message, 'error');
  }
}

['user-search', 'user-role-filter', 'user-status-filter'].forEach(id => {
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener('input', () => {
    _userFilters.search = document.getElementById('user-search').value.trim();
    _userFilters.role = document.getElementById('user-role-filter').value;
    _userFilters.status = document.getElementById('user-status-filter').value;
    renderUsers();
  });
  el.addEventListener('change', () => {
    _userFilters.search = document.getElementById('user-search').value.trim();
    _userFilters.role = document.getElementById('user-role-filter').value;
    _userFilters.status = document.getElementById('user-status-filter').value;
    renderUsers();
  });
});

// ─── Lazy-load users on tab switch ─────────────────────────────
const origTabClick = document.querySelector('.settings-tab')?.onclick;
document.addEventListener('click', (e) => {
  const tab = e.target.closest('.settings-tab');
  if (tab && tab.dataset.stab === 'users') { loadUsers(); }
});

// ─── Export / Import ───────────────────────────────────────────
function exportDomains() {
  const picker = document.createElement('div');
  picker.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:20px;z-index:9999;box-shadow:0 4px 20px rgba(0,0,0,0.3);display:flex;flex-direction:column;gap:8px;min-width:180px;';
  picker.innerHTML = '<div style="font-weight:600;margin-bottom:4px;">Export as…</div>' +
    '<button class="btn btn-primary" style="width:100%;">CSV</button>' +
    '<button class="btn btn-secondary" style="width:100%;">JSON</button>' +
    '<button class="btn btn-secondary" style="width:100%;">TXT (one URL per line)</button>';
  document.body.appendChild(picker);
  picker.querySelectorAll('button').forEach((btn, i) => {
    btn.addEventListener('click', () => {
      picker.remove();
      const fmt = ['csv', 'json', 'txt'][i];
      const url = `/api/domains/export?format=${fmt}`;
      const ext = fmt === 'txt' ? 'txt' : fmt;
      fetch(url, { headers: { 'X-CSRF-Token': _csrfToken } })
        .then(r => r.blob())
        .then(blob => {
          const a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = `domains-${new Date().toISOString().slice(0, 10)}.${ext}`;
          a.click();
          URL.revokeObjectURL(a.href);
          toast(`Exported as ${fmt.toUpperCase()}`);
        }).catch(e => toast(e.message, 'error'));
    });
  });
}

function importDomains() {
  var isWebapp = activeView === 'webapps';
  var type = isWebapp ? 'webapp' : (activeView === 'sslcerts' ? 'ssl_only' : 'full');
  document.getElementById('import-modal').dataset.importType = type;
  document.getElementById('import-modal-title').textContent = isWebapp ? 'Import Web Apps' : 'Import SSL Domains';
  document.getElementById('import-json').placeholder = isWebapp
    ? 'Paste JSON or one URL per line (e.g. https://api.example.com/health)'
    : "Paste JSON or one domain per line (e.g. example.com)";
  resetImportModal();
  document.getElementById('import-modal').classList.add('open');
}

function closeImportModal() {
  resetImportModal();
  document.getElementById('import-modal').classList.remove('open');
}

function doImport() {
  var importType = document.getElementById('import-modal').dataset.importType || 'full';
  var isWebapp = importType === 'webapp';
  var endpoint = isWebapp ? '/api/webapps/import' : '/api/domains/import';

  var fileInput = document.getElementById('import-file');
  var file = fileInput.files[0];

  if (file) {
    var reader = new FileReader();
    reader.onload = function (e) {
      var fd = new FormData();
      fd.append('file', file);
      fetch(endpoint, {
        method: 'POST',
        headers: { 'X-CSRF-Token': _csrfToken },
        body: fd,
      }).then(function (r) { return r.json(); }).then(handleImportResult).catch(function (err) {
        document.getElementById('import-result').textContent = err.message;
        document.getElementById('import-result').className = 'form-message error';
      });
    };
    reader.readAsArrayBuffer(file);
    return;
  }

  var text = document.getElementById('import-json').value.trim();
  if (!text) { document.getElementById('import-result').textContent = 'Paste JSON, one URL per line, or upload a file'; document.getElementById('import-result').className = 'form-message error'; return; }

  var items;
  try {
    items = JSON.parse(text);
  } catch (e) {
    items = text.split('\n').map(function (line) {
      line = line.trim();
      return line && !line.startsWith('#') ? {url: line, name: line} : null;
    }).filter(Boolean);
    if (!items.length) {
      document.getElementById('import-result').textContent = 'No valid entries found';
      document.getElementById('import-result').className = 'form-message error';
      return;
    }
  }
  api('POST', endpoint, isWebapp ? { webapps: items } : { domains: items }).then(handleImportResult).catch(function (e) {
    document.getElementById('import-result').textContent = e.message;
    document.getElementById('import-result').className = 'form-message error';
  });
}

function refreshDomains() {
  var type = activeView === 'sslcerts' ? 'ssl_only' : 'full';
  loadDomains(type);
}


function handleImportResult(result) {
  document.getElementById('import-form').style.display = 'none';
  document.getElementById('import-result').className = 'form-message success';
  document.getElementById('import-result').style.display = 'block';

  const hasErrors = result.errors && result.errors.length;
  const parts = [`${result.added} added`, `${result.skipped} skipped`];
  if (hasErrors) parts.push(`${result.errors.length} errors`);
  document.getElementById('import-result').textContent = 'Import complete — ' + parts.join(', ');

  let detailsHtml = '';
  if (result.added_list && result.added_list.length) {
    detailsHtml += '<div class="collapsible-header" onclick="this.classList.toggle(\'collapsed\')"><span class="collapse-arrow">&#9660;</span><strong>Added (' + result.added_list.length + ')</strong></div>';
    detailsHtml += '<div class="collapsible-body" style="margin:4px 0 10px 20px;font-size:12px;color:var(--green);">' + result.added_list.map(function(u) { return '<div>' + u + '</div>'; }).join('') + '</div>';
  }
  if (result.skipped_list && result.skipped_list.length) {
    detailsHtml += '<div class="collapsible-header collapsed" onclick="this.classList.toggle(\'collapsed\')"><span class="collapse-arrow">&#9660;</span><strong>Skipped (' + result.skipped_list.length + ')</strong></div>';
    detailsHtml += '<div class="collapsible-body" style="margin:4px 0 10px 20px;font-size:12px;color:var(--text-muted);">' + result.skipped_list.map(function(s) { return '<div>' + s.url + ' <span style="color:var(--text-muted)">\u2014 ' + s.reason + '</span></div>'; }).join('') + '</div>';
  }
  if (hasErrors) {
    detailsHtml += '<div class="collapsible-header collapsed" onclick="this.classList.toggle(\'collapsed\')"><span class="collapse-arrow">&#9660;</span><strong>Errors (' + result.errors.length + ')</strong></div>';
    detailsHtml += '<div class="collapsible-body" style="margin:4px 0 10px 20px;font-size:12px;color:var(--red);">' + result.errors.map(function(e) { return '<div>' + e + '</div>'; }).join('') + '</div>';
  }
  var detailsContainer = document.getElementById('import-details');
  detailsContainer.innerHTML = detailsHtml;
  detailsContainer.style.display = 'block';

  toast('Import complete');
  if (activeView === 'webapps') loadWebApps(true);
  else if (activeView === 'domains') loadDomains('full');
  else if (activeView === 'sslcerts') loadDomains('ssl_only');
}

function resetImportModal() {
  document.getElementById('import-form').style.display = 'block';
  document.getElementById('import-json').value = '';
  document.getElementById('import-file').value = '';
  document.getElementById('import-result').textContent = '';
  document.getElementById('import-result').className = 'form-message';
  document.getElementById('import-result').style.display = 'none';
  document.getElementById('import-details').innerHTML = '';
  document.getElementById('import-details').style.display = 'none';
}

// ─── Cert Details Modal ────────────────────────────────────────
function openCertModal(id) {
  document.getElementById('cert-details').innerHTML = '<div class="cert-loading">Loading...</div>';
  document.getElementById('cert-modal').classList.add('open');
  api('GET', `/api/domains/${id}/cert`).then(d => {
    const rows = [
      ['Domain', d.url],
      ['Status', d.status],
      ['Issuer', d.ssl_issuer || 'N/A'],
      ['Subject', d.ssl_subject || 'N/A'],
      ['Valid From', d.ssl_valid_from ? d.ssl_valid_from.slice(0, 10) : 'N/A'],
      ['Valid Until', d.ssl_valid_until ? d.ssl_valid_until.slice(0, 10) : 'N/A'],
      ['Expiry', d.ssl_expiry || 'N/A'],
      ['SANs', d.ssl_sans || 'N/A'],
      ['Last Checked', d.last_checked ? formatDate(d.last_checked) : 'N/A'],
    ];
    document.getElementById('cert-details').innerHTML = rows.map(([k, v]) =>
      `<div class="cert-row"><div class="cert-label">${k}</div><div class="cert-value">${escHtml(String(v))}</div></div>`
    ).join('');
  }).catch(e => {
    document.getElementById('cert-details').innerHTML = `<div class="cert-loading">Error: ${e.message}</div>`;
  });
}

function closeCertModal() {
  document.getElementById('cert-modal').classList.remove('open');
}

// ─── Logs ──────────────────────────────────────────────────────
async function refreshLogs() {
  const tbody = document.getElementById('log-body');
  const mobileEl = document.getElementById('log-mobile');
  const offset = (logState.page - 1) * logState.limit;
  const params = new URLSearchParams({
    limit: String(logState.limit),
    offset: String(offset),
    type: logState.filter || 'all',
    q: logState.query || ''
  });
  tbody.innerHTML = '<tr><td colspan="5" class="log-state-cell">Loading logs...</td></tr>';
  mobileEl.innerHTML = '<div class="log-card log-state-card">Loading logs...</div>';
  try {
    const data = await api('GET', `/api/logs?${params.toString()}`);
    const logs = data.logs || [];
    logState.total = data.total || 0;

    tbody.innerHTML = logs.map(log => {
      const typeClass = (log.type || 'info').replace(/\s+/g, '_');
      const domainCell = log.domain_url ? escHtml(log.domain_url) : '—';
      const userCell = log.username ? escHtml(log.username) : '—';
      const typeLabel = formatLogType(log.type || 'info');
      return `<tr>
        <td>${formatDate(log.created_at)}</td>
        <td>${domainCell}</td>
        <td>${userCell}</td>
        <td><span class="log-type ${typeClass}">${escHtml(typeLabel)}</span></td>
        <td class="log-message-cell">${escHtml(log.message || '')}</td>
      </tr>`;
    }).join('');

    mobileEl.innerHTML = logs.map(log => {
      const typeClass = (log.type || 'info').replace(/\s+/g, '_');
      const typeLabel = formatLogType(log.type || 'info');
      const userCell = log.username ? escHtml(log.username) : 'system';
      return `<div class="log-card">
        <div class="log-card-head"><span class="log-time">${formatDate(log.created_at)}</span><span class="log-type ${typeClass}">${escHtml(typeLabel)}</span></div>
        <div class="log-domain">${log.domain_url ? escHtml(log.domain_url) : 'No domain'}</div>
        <div class="log-user">User: ${userCell}</div>
        <div class="log-msg">${escHtml(log.message || '')}</div>
      </div>`;
    }).join('');

    if (logs.length === 0) {
      const emptyText = logState.query ? 'No logs match the current search.' : 'No logs found.';
      tbody.innerHTML = `<tr><td colspan="5" class="log-state-cell">${emptyText}</td></tr>`;
      mobileEl.innerHTML = `<div class="log-card log-state-card">${emptyText}</div>`;
    }
    renderLogSummary(data.summary || {});
    updateLogPagination();
    renderActivityBar(logs);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="log-state-cell">Failed to load logs: ${escHtml(e.message)}</td></tr>`;
    mobileEl.innerHTML = `<div class="log-card log-state-card">Failed to load logs: ${escHtml(e.message)}</div>`;
  }
}

function formatLogType(type) {
  return String(type || 'info').replace(/_/g, ' ');
}

var _webappSparklineCache = {};

function loadWebappSparkline(id) {
  if (_webappSparklineCache[id]) {
    renderWebappSparkline(id, _webappSparklineCache[id]);
    return;
  }
  api('GET', '/api/webapps/' + id + '/results?days=7').then(function (data) {
    _webappSparklineCache[id] = data;
    renderWebappSparkline(id, data);
  }).catch(function () {});
}

function renderWebappSparkline(id, data) {
  var el = document.getElementById('spark-wa-' + id);
  if (!el) return;
  var rts = data.filter(function (d) { return d.response_time_ms != null; }).map(function (d) { return d.response_time_ms; });
  if (rts.length < 2) { el.innerHTML = ''; return; }
  var w = el.offsetWidth || 120;
  var h = 40;
  var max = Math.max.apply(null, rts);
  var min = Math.min.apply(null, rts);
  var range = max - min || 1;
  var points = rts.map(function (v, i) {
    var x = (i / (rts.length - 1)) * w;
    var y = h - ((v - min) / range) * (h - 2) - 1;
    return x + ',' + y;
  }).join(' ');
  var color = getComputedStyle(document.body).getPropertyValue('--primary').trim() || '#3b82f6';
  el.innerHTML = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '" style="display:block">' +
    '<polyline fill="none" stroke="' + color + '" stroke-width="1.5" points="' + points + '"/>' +
    '</svg>';
}

function renderLogSummary(summary) {
  const set = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value || 0;
  };
  const errors = Object.keys(summary).reduce((sum, key) => key.includes('error') ? sum + summary[key] : sum, 0);
  set('log-total-count', summary.total);
  set('log-check-count', summary.check);
  set('log-webapp-check-count', summary.webapp_check);
  set('log-alert-count', summary.alert);
  set('log-webapp-alert-count', summary.webapp_alert);
  set('log-error-count', errors);
}

function renderActivityBar(logs) {
  const hours = Array.from({ length: 24 }, (_, i) => ({ hour: i, count: 0 }));
  const now = new Date();
  const today = now.toISOString().slice(0, 10);
  logs.forEach(l => {
    if (l.created_at && l.created_at.startsWith(today)) {
      const h = new Date(l.created_at).getHours();
      if (h >= 0 && h < 24) hours[h].count++;
    }
  });
  const max = Math.max(...hours.map(h => h.count), 1);
  const bars = document.getElementById('activity-bars');
  const labels = document.getElementById('activity-labels');
  bars.innerHTML = hours.map(h => {
    const height = Math.max(2, (h.count / max) * 36);
    const tip = `${h.hour}:00 — ${h.count} event(s)`;
    return `<div class="activity-bar" style="height:${height}px"><div class="bar-tip">${tip}</div></div>`;
  }).join('');
  labels.innerHTML = hours.map((_, i) => i % 3 === 0 ? `<span>${i}:00</span>` : '<span></span>').join('');
}

function logPage(delta) {
  const newPage = logState.page + delta;
  if (newPage < 1) return;
  logState.page = newPage;
  refreshLogs();
}

function updateLogPagination() {
  const totalPages = Math.max(1, Math.ceil(logState.total / logState.limit));
  if (logState.page > totalPages) logState.page = totalPages;
  const from = logState.total === 0 ? 0 : ((logState.page - 1) * logState.limit) + 1;
  const to = Math.min(logState.page * logState.limit, logState.total);
  document.getElementById('log-page-info').textContent = `Page ${logState.page} of ${totalPages}`;
  document.getElementById('log-range-info').textContent = `Showing ${from}-${to} of ${logState.total}`;
  document.getElementById('log-prev-btn').disabled = logState.page <= 1;
  document.getElementById('log-next-btn').disabled = logState.page >= totalPages;
}

// ─── Auth ──────────────────────────────────────────────────────
async function logout() {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = '/';
}

async function checkSession() {
  try {
    const res = await fetch('/api/me');
    if (!res.ok) { window.location.href = '/'; return; }
    const data = await res.json();
    _userRole = data.role || 'admin';
    _currentUsername = data.username || '';
    document.getElementById('nav-username').textContent = data.username || '';
    applyRoleBasedUI();
    const csrf = await fetch('/api/csrf-token');
    if (csrf.ok) _csrfToken = (await csrf.json()).csrf_token;
  } catch {
    window.location.href = '/';
  }
}

function applyRoleBasedUI() {
  const isViewer = _userRole !== 'admin';
  document.querySelectorAll('.nav-tab[data-view="settings"], .nav-tab[data-view="logs"], .nav-tab[data-view="backups"]').forEach(tab => {
    tab.style.display = isViewer ? 'none' : '';
  });
  // Hide mutation buttons on dashboard
  document.querySelectorAll('[data-action="check-all-full"], [data-action="check-all-ssl"], [data-action="export-csv"]').forEach(btn => {
    btn.style.display = isViewer ? 'none' : '';
  });
  // Hide mutation buttons on domains view
  document.querySelectorAll('#view-domains [data-action="export"], #view-domains [data-action="import"], #view-domains [data-action="check-all-full"], #view-domains [data-action="add-domain-full"], #view-domains [data-action="download-template"]').forEach(btn => {
    btn.style.display = isViewer ? 'none' : '';
  });
  // Hide mutation buttons on SSL view
  document.querySelectorAll('#view-sslcerts [data-action="export"], #view-sslcerts [data-action="import"], #view-sslcerts [data-action="check-all-ssl"], #view-sslcerts [data-action="add-domain-ssl"], #view-sslcerts [data-action="download-template-ssl"]').forEach(btn => {
    btn.style.display = isViewer ? 'none' : '';
  });
  // Hide mutation buttons on webapps view
  document.querySelectorAll('#view-webapps [data-action="import"], #view-webapps [data-action="check-all-webapps"], #view-webapps [data-action="add-webapp"], #view-webapps [data-action="download-template-webapp"], #view-webapps [data-action="webapp-export-csv"]').forEach(btn => {
    btn.style.display = isViewer ? 'none' : '';
  });
  // Hide bulk toolbars entirely for viewers (no actionable bulk ops)
  document.querySelectorAll('#bulk-toolbar, #ssl-bulk-toolbar, #webapp-bulk-toolbar').forEach(el => {
    el.style.display = isViewer ? 'none' : '';
  });
}

// ─── Pagination ────────────────────────────────────────────────
function totalPages(type) {
  const filtered = getFilteredDomains(type);
  return Math.max(1, Math.ceil(filtered.length / _pagination[type].pageSize));
}

function getPageItems(domains, type) {
  const p = _pagination[type];
  const start = (p.page - 1) * p.pageSize;
  return domains.slice(start, start + p.pageSize);
}

function goToPage(type, page) {
  const tp = totalPages(type);
  page = Math.max(1, Math.min(page, tp));
  _pagination[type].page = page;
  applyDomainFilters(type);
}

function renderPagination(type) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const filtered = getFilteredDomains(type);
  const p = _pagination[type];
  const tp = totalPages(type);
  const wrapper = document.getElementById('pagination-' + suffix);

  if (filtered.length <= p.pageSize) { wrapper.style.display = 'none'; return; }
  wrapper.style.display = 'flex';

  const start = (p.page - 1) * p.pageSize + 1;
  const end = Math.min(p.page * p.pageSize, filtered.length);
  document.getElementById('page-from-' + suffix).textContent = start;
  document.getElementById('page-to-' + suffix).textContent = end;
  document.getElementById('page-total-' + suffix).textContent = filtered.length;
  document.getElementById('page-first-' + suffix).disabled = p.page <= 1;
  document.getElementById('page-prev-' + suffix).disabled = p.page <= 1;
  document.getElementById('page-next-' + suffix).disabled = p.page >= tp;
  document.getElementById('page-last-' + suffix).disabled = p.page >= tp;
  document.getElementById('page-size-' + suffix).value = p.pageSize;
}

// ─── Column visibility ─────────────────────────────────────────
function toggleColumnDropdown(type) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const dd = document.getElementById('col-dropdown-' + suffix);
  const isOpen = dd.style.display !== 'none';
  document.querySelectorAll('.column-dropdown').forEach(d => d.style.display = 'none');
  if (!isOpen) dd.style.display = 'block';
}

function applyColumnVisibility(type) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const table = document.getElementById('domain-table-' + suffix);
  if (!table || table.style.display === 'none') return;
  const cols = _visibleCols[type];
  if (Object.keys(cols).length === 0) return;
  table.querySelectorAll('th, td').forEach(cell => {
    const cls = [...cell.classList].find(c => c.startsWith('col-'));
    if (cls && cols[cls] === false) cell.style.display = 'none';
    else cell.style.display = '';
  });
}

// ─── View preferences (localStorage) ───────────────────────────
function saveViewPrefs(type) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const prefs = {
    viewMode: _viewMode[type],
    sort: sortState[type],
    filter: _domainFilter[type],
    tld: _tldFilter[type],
    groupBy: _groupByStatus[type],
    pageSize: _pagination[type].pageSize,
    cols: _visibleCols[type]
  };
  localStorage.setItem('vigil-prefs-' + suffix, JSON.stringify(prefs));
}

function loadViewPrefs(type) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const raw = localStorage.getItem('vigil-prefs-' + suffix);
  if (!raw) return;
  try {
    const p = JSON.parse(raw);
    _viewMode[type] = p.viewMode || 'cards';
    if (p.sort) sortState[type] = p.sort;
    _domainFilter[type] = p.filter || 'all';
    _tldFilter[type] = p.tld || '';
    _groupByStatus[type] = !!p.groupBy;
    _pagination[type].pageSize = p.pageSize || 25;
    _visibleCols[type] = p.cols || {};
  } catch {}
}

// ─── API cache (sessionStorage) ────────────────────────────────
function getCachedDomains(type) {
  try {
    const raw = sessionStorage.getItem('vigil-domains-' + type);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Date.now() - parsed.ts < 60000) return parsed.data;
    }
  } catch {}
  return null;
}

function setCachedDomains(type, data) {
  try {
    sessionStorage.setItem('vigil-domains-' + type, JSON.stringify({ data, ts: Date.now() }));
  } catch {}
}

function clearDomainsCache(type) {
  sessionStorage.removeItem('vigil-domains-' + type);
  // Always clear the other type too so cross-tab navigation gets fresh data
  const other = type === 'full' ? 'ssl_only' : 'full';
  sessionStorage.removeItem('vigil-domains-' + other);
}

// ─── Delta re-render ───────────────────────────────────────────
function deltaRender(type, updatedIds) {
  const suffix = type === 'ssl_only' ? 'ssl' : 'full';
  const isSslOnly = type === 'ssl_only';
  const selSet = isSslOnly ? selectedSsl : selectedDomains;

  updatedIds.forEach(id => {
    const d = (_cachedDomains[type] || []).find(x => x.id === id);
    if (!d) return;
    const card = document.getElementById('card-' + suffix + '-' + id);
    if (card) {
      const newHtml = renderCardHtml(d, type, selSet, isSslOnly);
      const tmp = document.createElement('div');
      tmp.innerHTML = newHtml;
      card.replaceWith(tmp.firstElementChild);
    }
  });
}

// ─── Rate-limited bulk check ───────────────────────────────────
async function processBulkCheckQueue() {
  if (_bulkCheckRunning || _bulkCheckQueue.length === 0) return;
  _bulkCheckRunning = true;
  const total = _bulkCheckQueue.length;
  const type = activeView === 'sslcerts' ? 'ssl_only' : 'full';
  const sf = type === 'ssl_only' ? 'ssl_status' : 'domain_status';

  // Save previous statuses
  _bulkCheckQueue.forEach(id => {
    const d = (_cachedDomains[type] || []).find(x => x.id === id);
    if (d) _prevStatuses[type][id] = d[sf];
  });

  let done = 0;
  toast(`Checking ${total} domains...`);

  while (_bulkCheckQueue.length > 0) {
    const id = _bulkCheckQueue.shift();
    try { await api('POST', `/api/domains/${id}/check`); } catch (e) {}
    done++;
    if (done % 5 === 0) {
      const bar = document.getElementById('check-progress-bar');
      const prog = document.getElementById('check-progress');
      if (bar) bar.style.width = (done / total * 100) + '%';
      if (prog) prog.style.display = 'block';
    }
  }

  _bulkCheckRunning = false;
  toast(`${total} checks complete`);
  const bar = document.getElementById('check-progress-bar');
  const prog = document.getElementById('check-progress');
  if (bar) bar.style.width = '0';
  if (prog) prog.style.display = 'none';

  clearDomainsCache(type);
  loadDomains(type);
}

async function bulkAction(type, action) {
  if (_userRole !== 'admin') { toast('Admin access required', 'error'); return; }
  const sel = type === 'ssl_only' ? selectedSsl : selectedDomains;
  if (sel.size === 0) return;
  const ids = [...sel];

  if (action === 'delete') {
    if (!confirm(`Delete ${ids.length} domain(s)? This cannot be undone.`)) return;
    // Animate all selected items simultaneously
    const suffix = type === 'ssl_only' ? 'ssl' : 'full';
    ids.forEach(id => {
      const card = document.getElementById(`card-${suffix}-${id}`);
      if (card) card.classList.add('removing');
      else {
        const row = document.querySelector(`.kebab-btn[data-id="${id}"]`)?.closest('tr');
        if (row) row.classList.add('removing');
      }
    });
    // Wait for animation, then optimistically remove from local cache
    await new Promise(r => setTimeout(r, 350));
    const idSet = new Set(ids);
    _cachedDomains[type] = (_cachedDomains[type] || []).filter(d => !idSet.has(d.id));
    clearDomainsCache(type);
    sel.clear();
    updateBulkToolbar(type);
    renderDomains(_cachedDomains[type], type);
    renderPagination(type);
    // Fire API calls in background
    let failed = 0;
    for (const id of ids) {
      try { await api('DELETE', `/api/domains/${id}`); } catch { failed++; }
    }
    if (failed === 0) toast(`${ids.length} domains deleted`);
    else toast(`${ids.length - failed} deleted, ${failed} failed`, 'error');
    try { await api('POST', '/api/logs', { message: `Bulk deleted ${ids.length} domains`, type: 'bulk_delete' }); } catch {}
    return;
  } else if (action === 'check') {
    _bulkCheckQueue = ids;
    processBulkCheckQueue();
    sel.clear();
    updateBulkToolbar(type);
    return;
  }

  sel.clear();
  loadDomains(type);
}

// ─── Bulk export (compressed) ──────────────────────────────────
function bulkExport(type) {
  if (_userRole !== 'admin') { toast('Admin access required', 'error'); return; }
  const sel = type === 'ssl_only' ? selectedSsl : selectedDomains;
  if (sel.size === 0) return;
  const domains = (_cachedDomains[type] || []).filter(d => sel.has(d.id));
  const json = JSON.stringify(domains.map(d => ({ url: d.url, type: d.type, notes: d.notes || '', manual_registrar: d.manual_registrar || '', manual_expiry_date: d.manual_expiry_date || '' })), null, 2);

  if (typeof CompressionStream !== 'undefined') {
    const blob = new Blob([json], { type: 'application/json' });
    const cs = new CompressionStream('gzip');
    const writer = cs.writable.getWriter();
    writer.write(blob.stream());
    writer.close();
    new Response(cs.readable).blob().then(gz => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(gz);
      a.download = `domains-export-${Date.now()}.json.gz`;
      a.click();
      URL.revokeObjectURL(a.href);
      toast(`Exported ${domains.length} domains (gzipped)`);
    });
  } else {
    const blob = new Blob([json], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `domains-export-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast(`Exported ${domains.length} domains`);
  }
}

// ─── Bulk tags ─────────────────────────────────────────────────
function openBulkTags(type) {
  if (_userRole !== 'admin') { toast('Admin access required', 'error'); return; }
  const sel = type === 'ssl_only' ? selectedSsl : selectedDomains;
  if (sel.size === 0) return;
  const modal = document.getElementById('bulk-tags-modal');
  modal.querySelector('h3').textContent = `Manage Tags for ${sel.size} Domains`;
  document.getElementById('bulk-tags-input').value = '';
  document.getElementById('bulk-tags-mode').value = 'replace';
  modal.querySelector('[data-action="submit-bulk-tags"]').dataset.type = type;
  modal.classList.add('open');
}

function closeBulkTags() {
  document.getElementById('bulk-tags-modal').classList.remove('open');
}

async function submitBulkTags() {
  const modal = document.getElementById('bulk-tags-modal');
  const type = modal.querySelector('[data-action="submit-bulk-tags"]').dataset.type;
  const raw = document.getElementById('bulk-tags-input').value.trim();
  const mode = document.getElementById('bulk-tags-mode').value;
  const newTags = raw.split(',').map(t => t.trim()).filter(Boolean);
  if (newTags.length === 0 && mode !== 'remove') return;

  const sel = type === 'ssl_only' ? selectedSsl : selectedDomains;
  const ids = [...sel];
  for (const id of ids) {
    try {
      const domain = (_cachedDomains[type] || []).find(d => d.id === id);
      let tags = domain.tags ? JSON.parse(domain.tags) : [];
      if (mode === 'replace') tags = newTags;
      else if (mode === 'add') tags = [...new Set([...tags, ...newTags])];
      else if (mode === 'remove') tags = tags.filter(t => !newTags.includes(t));
      await api('PUT', `/api/domains/${id}`, { tags: JSON.stringify(tags) });
    } catch (e) {}
  }
  toast(`Tags updated for ${ids.length} domains`);
  closeBulkTags();
  try { await api('POST', '/api/logs', { message: `Bulk tags (${mode}) on ${ids.length} domains`, type: 'bulk_action' }); } catch {}
  clearDomainsCache(type);
  loadDomains(type);
}

// ─── Compare modal ─────────────────────────────────────────────
function openCompareModal(type) {
  const sel = type === 'ssl_only' ? selectedSsl : selectedDomains;
  if (sel.size < 2) { toast('Select at least 2 domains to compare', 'error'); return; }
  const domains = (_cachedDomains[type] || []).filter(d => sel.has(d.id));
  const isSslOnly = type === 'ssl_only';
  const container = document.getElementById('compare-content');

  container.innerHTML = domains.map(d => {
    const statusField = isSslOnly ? 'ssl_status' : 'domain_status';
    const prevStatus = _prevStatuses[type][d.id];
    const currentStatus = d[statusField] || 'pending';
    const changed = prevStatus && prevStatus !== currentStatus;

    return `<div class="compare-card">
      <h4>${escHtml(d.url)}${changed ? '<span class="change-dot" title="Status changed"></span>' : ''}</h4>
      <div class="compare-row"><span class="compare-label">Status</span><span class="compare-value ${changed ? 'changed' : ''}">${currentStatus}</span></div>
      <div class="compare-row"><span class="compare-label">SSL Expiry</span><span class="compare-value">${d.ssl_expiry ? d.ssl_expiry.slice(0, 10) : 'N/A'} ${d.ssl_days_left !== null ? `(${d.ssl_days_left}d)` : ''}</span></div>
      ${!isSslOnly ? `<div class="compare-row"><span class="compare-label">Domain Exp</span><span class="compare-value">${d.domain_expiry ? d.domain_expiry.slice(0, 10) : (d.manual_expiry_date || 'N/A')} ${d.domain_days_left !== null ? `(${d.domain_days_left}d)` : ''}</span></div>` : ''}
      <div class="compare-row"><span class="compare-label">Registrar</span><span class="compare-value">${(d.manual_registrar || d.domain_registrar) || 'N/A'}</span></div>
      <div class="compare-row"><span class="compare-label">Last Checked</span><span class="compare-value">${d.last_checked ? formatDate(d.last_checked) : 'Never'}</span></div>
      <div class="compare-row"><span class="compare-label">Notes</span><span class="compare-value">${d.notes ? escHtml(d.notes.substring(0, 50)) : '—'}</span></div>
    </div>`;
  }).join('');

  document.getElementById('compare-modal').classList.add('open');
}

function closeCompareModal() {
  document.getElementById('compare-modal').classList.remove('open');
}

// ─── Keyboard navigation ───────────────────────────────────────
function highlightKeyboardFocus(items) {
  document.querySelectorAll('.domain-card.kb-focus').forEach(c => c.classList.remove('kb-focus'));
  if (_keyboardFocusIndex < 0 || _keyboardFocusIndex >= items.length) return;
  const suffix = activeView === 'sslcerts' ? 'ssl' : 'full';
  const card = document.getElementById('card-' + suffix + '-' + items[_keyboardFocusIndex].id);
  if (card) { card.classList.add('kb-focus'); card.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
}

// ─── Sanitize helper ───────────────────────────────────────────
function sanitizeInput(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ─── Filtered domains helper ───────────────────────────────────
function getFilteredDomains(type) {
  const searchInput = document.getElementById(type === 'ssl_only' ? 'ssl-search' : 'domain-search');
  const query = searchInput ? searchInput.value.toLowerCase() : '';
  const filter = _domainFilter[type];
  const tld = _tldFilter[type];
  let domains = _cachedDomains[type] || [];

  if (query) {
    domains = domains.filter(d =>
      d.url.toLowerCase().includes(query) ||
      (d.manual_registrar && d.manual_registrar.toLowerCase().includes(query)) ||
      (d.notes && d.notes.toLowerCase().includes(query))
    );
  }

  if (filter !== 'all') {
    const statusField = type === 'ssl_only' ? 'ssl_status' : 'domain_status';
    if (filter === 'healthy') domains = domains.filter(d => d[statusField] === 'healthy');
    else if (filter === 'warning' || filter === 'watch') domains = domains.filter(d => ['watch', 'warning'].includes(d[statusField]));
    else if (filter === 'caution') domains = domains.filter(d => d[statusField] === 'caution');
    else if (filter === 'critical') domains = domains.filter(d => d[statusField] === 'critical');
    else if (filter === 'expired') domains = domains.filter(d => d[statusField] === 'expired');
    else if (filter === 'error') domains = domains.filter(d => d[statusField] === 'error');
  }

  if (tld) {
    domains = domains.filter(d => {
      const parts = d.url.split('.');
      return parts.length > 1 && '.' + parts.slice(-2).join('.') === tld;
    });
  }

  return domains;
}

// ─── Sparklines (lazy-loaded per-domain trend) ────────────────
let _sparklineObserver = null;

function _observeSparklines() {
  if (!_sparklineObserver) {
    _sparklineObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        const el = entry.target;
        el.dataset.sparklineLoading = '1';
        _sparklineObserver.unobserve(el);
        const domainId = el.dataset.domainId;
        if (!domainId) return;
        fetch(`/api/domains/${domainId}/history?days=7`)
          .then(r => r.json())
          .then(data => { _renderSparklineSvg(el, data); })
          .catch(() => { el.style.display = 'none'; });
      });
    }, { rootMargin: '200px' });
  }
  document.querySelectorAll('.sparkline-cell:not([data-sparkline-loading])').forEach(el => {
    _sparklineObserver.observe(el);
  });
}

function _renderSparklineSvg(container, data) {
  if (!data || data.length < 2) { container.style.display = 'none'; return; }
  const values = data.map(d => d.ssl_days_left).filter(v => v !== null && v !== undefined);
  if (values.length < 2) { container.style.display = 'none'; return; }
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const w = 60, h = 18;
  const pts = values.map((v, i) => `${i * (w / (values.length - 1))},${h - ((v - min) / range) * (h - 2) - 1}`).join(' ');
  const color = getComputedStyle(document.body).getPropertyValue('--primary').trim() || '#3b82f6';
  container.innerHTML = `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" style="vertical-align:middle"><polyline fill="none" stroke="${color}" stroke-width="1.5" points="${pts}"/></svg>`;
}

document.addEventListener('click', (e) => {
  if (!e.target.closest('.actions-dropdown')) {
    document.querySelectorAll('.actions-dropdown.open').forEach(function (d) { d.classList.remove('open'); });
  }
});

// ─── Init ──────────────────────────────────────────────────────
checkSession().then(() => {
  initTheme();
  _updateSortArrows('full', 'url', 1);
  _updateSortArrows('ssl_only', 'url', 1);
  const viewName = window.location.hash.slice(1) || 'dashboard';
  activateView(viewName);
});
