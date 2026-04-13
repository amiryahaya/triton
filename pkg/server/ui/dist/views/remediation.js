// views/remediation.js — Remediation Tracker view
// Analytics Phase 4B
(function() {
  'use strict';

  window.renderRemediation = renderRemediation;

  // Current filter state
  var currentStatus = '';
  var currentHostname = '';
  var currentPqcStatus = '';

  // Track known hostnames for the filter dropdown
  var knownHostnames = [];

  function escHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function renderRemediation() {
    var content = document.getElementById('content');
    content.innerHTML =
      '<div class="page-header"><h2>Remediation Tracker</h2></div>' +
      '<div id="remediation-summary" class="remediation-summary"></div>' +
      '<div id="remediation-filters" class="filter-bar" style="margin-bottom:1rem;display:flex;gap:0.75rem;flex-wrap:wrap;align-items:center;"></div>' +
      '<div id="remediation-table"></div>' +
      '<div id="accept-risk-modal"></div>';

    fetchSummary();
    fetchRows();
  }

  function fetchSummary() {
    fetchWithAuth('/api/v1/remediation/summary')
      .then(function(data) { renderSummary(data); })
      .catch(function(err) {
        var el = document.getElementById('remediation-summary');
        if (el) el.innerHTML = '<p class="error">Failed to load summary: ' + escHtml(err.message) + '</p>';
      });
  }

  function fetchRows() {
    var params = [];
    if (currentStatus) params.push('status=' + encodeURIComponent(currentStatus));
    if (currentHostname) params.push('hostname=' + encodeURIComponent(currentHostname));
    if (currentPqcStatus) params.push('pqc_status=' + encodeURIComponent(currentPqcStatus));
    var url = '/api/v1/remediation' + (params.length ? '?' + params.join('&') : '');

    fetchWithAuth(url)
      .then(function(data) {
        // Collect unique hostnames for filter dropdown
        var seen = {};
        (data.data || []).forEach(function(row) {
          if (row.hostname) seen[row.hostname] = true;
        });
        // Merge with already-known hostnames so clearing a filter still shows all options
        Object.keys(seen).forEach(function(h) {
          if (knownHostnames.indexOf(h) === -1) knownHostnames.push(h);
        });
        knownHostnames.sort();
        renderFilters();
        renderTable(data.data || []);
      })
      .catch(function(err) {
        var el = document.getElementById('remediation-table');
        if (el) el.innerHTML = '<p class="error">Failed to load remediation data: ' + escHtml(err.message) + '</p>';
      });
  }

  // fetchWithAuth mirrors the app.js api() helper but is self-contained
  // so this view can be loaded as a standalone script without depending
  // on closure-scoped variables from app.js.
  function fetchWithAuth(url) {
    var token = localStorage.getItem('tritonJWT') || '';
    var headers = {};
    if (token) headers['Authorization'] = 'Bearer ' + token;
    return fetch(url, { headers: headers }).then(function(resp) {
      if (resp.status === 401) {
        location.hash = '#/login';
        throw new Error('Authentication required');
      }
      if (!resp.ok) {
        return resp.json().catch(function() { return {}; }).then(function(body) {
          throw new Error(body.error || ('API error: ' + resp.status));
        });
      }
      if (resp.status === 204) return null;
      return resp.json();
    });
  }

  function postWithAuth(url, body) {
    var token = localStorage.getItem('tritonJWT') || '';
    var headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = 'Bearer ' + token;
    return fetch(url, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(body),
    }).then(function(resp) {
      if (resp.status === 401) {
        location.hash = '#/login';
        throw new Error('Authentication required');
      }
      if (!resp.ok) {
        return resp.json().catch(function() { return {}; }).then(function(body) {
          throw new Error(body.error || ('API error: ' + resp.status));
        });
      }
      if (resp.status === 204) return null;
      return resp.json();
    });
  }

  function isAdmin() {
    var token = localStorage.getItem('tritonJWT') || '';
    if (!token) return false;
    try {
      var payload = token.split('.')[1];
      var json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
      var claims = JSON.parse(json);
      return claims && claims.role === 'org_admin';
    } catch (e) { return false; }
  }

  // ─── Summary cards ──────────────────────────────────────────────────

  function renderSummary(data) {
    var cards = [
      { key: 'open',        label: 'Open',        count: data.open || 0 },
      { key: 'in_progress', label: 'In Progress',  count: data.inProgress || 0 },
      { key: 'resolved',    label: 'Resolved',     count: data.resolved || 0 },
      { key: 'accepted',    label: 'Accept Risk',  count: data.accepted || 0 },
    ];
    var html = '';
    cards.forEach(function(card) {
      var active = currentStatus === card.key ? ' active' : '';
      html +=
        '<div class="remediation-card' + active + '" data-status="' + escHtml(card.key) + '">' +
          '<div class="count">' + escHtml(String(card.count)) + '</div>' +
          '<div class="label">' + escHtml(card.label) + '</div>' +
        '</div>';
    });
    var el = document.getElementById('remediation-summary');
    if (!el) return;
    el.innerHTML = html;
    el.querySelectorAll('.remediation-card').forEach(function(card) {
      card.addEventListener('click', function() {
        var status = card.getAttribute('data-status');
        currentStatus = (currentStatus === status) ? '' : status;
        fetchSummary();
        fetchRows();
      });
    });
  }

  // ─── Filters ────────────────────────────────────────────────────────

  function renderFilters() {
    var el = document.getElementById('remediation-filters');
    if (!el) return;

    // Status filter
    var statusOptions = [
      { value: '', label: 'All Statuses' },
      { value: 'open', label: 'Open' },
      { value: 'in_progress', label: 'In Progress' },
      { value: 'resolved', label: 'Resolved' },
      { value: 'accepted', label: 'Accept Risk' },
    ];
    var statusHtml = '<label style="font-size:0.85rem;color:var(--text-secondary)">Status: <select id="rem-status-filter" class="action-select">';
    statusOptions.forEach(function(opt) {
      statusHtml += '<option value="' + escHtml(opt.value) + '"' +
        (currentStatus === opt.value ? ' selected' : '') + '>' +
        escHtml(opt.label) + '</option>';
    });
    statusHtml += '</select></label>';

    // Hostname filter
    var hostnameHtml = '<label style="font-size:0.85rem;color:var(--text-secondary)">Host: <select id="rem-host-filter" class="action-select">';
    hostnameHtml += '<option value="">All Hosts</option>';
    knownHostnames.forEach(function(h) {
      hostnameHtml += '<option value="' + escHtml(h) + '"' +
        (currentHostname === h ? ' selected' : '') + '>' +
        escHtml(h) + '</option>';
    });
    hostnameHtml += '</select></label>';

    // PQC Status filter
    var pqcOptions = [
      { value: '', label: 'All PQC' },
      { value: 'UNSAFE', label: 'Unsafe' },
      { value: 'DEPRECATED', label: 'Deprecated' },
      { value: 'TRANSITIONAL', label: 'Transitional' },
      { value: 'SAFE', label: 'Safe' },
    ];
    var pqcHtml = '<label style="font-size:0.85rem;color:var(--text-secondary)">PQC: <select id="rem-pqc-filter" class="action-select">';
    pqcOptions.forEach(function(opt) {
      pqcHtml += '<option value="' + escHtml(opt.value) + '"' +
        (currentPqcStatus === opt.value ? ' selected' : '') + '>' +
        escHtml(opt.label) + '</option>';
    });
    pqcHtml += '</select></label>';

    el.innerHTML = statusHtml + ' ' + hostnameHtml + ' ' + pqcHtml;

    document.getElementById('rem-status-filter').addEventListener('change', function() {
      currentStatus = this.value;
      fetchSummary();
      fetchRows();
    });
    document.getElementById('rem-host-filter').addEventListener('change', function() {
      currentHostname = this.value;
      fetchRows();
    });
    document.getElementById('rem-pqc-filter').addEventListener('change', function() {
      currentPqcStatus = this.value;
      fetchRows();
    });
  }

  // ─── Table ──────────────────────────────────────────────────────────

  var PQC_COLORS = {
    'SAFE':        '#4ade80',
    'TRANSITIONAL':'#fbbf24',
    'DEPRECATED':  '#fb923c',
    'UNSAFE':      '#f87171',
  };

  function pqcBadge(status) {
    var color = PQC_COLORS[status] || 'var(--text-secondary)';
    return '<span style="color:' + color + ';font-weight:600;font-size:0.8rem;">' + escHtml(status || '—') + '</span>';
  }

  function statusBadge(status) {
    var cls = 'status-badge status-' + escHtml(status || 'open');
    var label = (status || 'open').replace(/_/g, ' ');
    return '<span class="' + cls + '">' + escHtml(label) + '</span>';
  }

  function formatDate(iso) {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    } catch (e) { return iso; }
  }

  function renderTable(rows) {
    var el = document.getElementById('remediation-table');
    if (!el) return;

    if (rows.length === 0) {
      el.innerHTML = '<p class="empty-state">No remediation items match the current filters.</p>';
      return;
    }

    var admin = isAdmin();

    var html =
      '<table class="data-table">' +
        '<thead><tr>' +
          '<th>Hostname</th>' +
          '<th>Algorithm</th>' +
          '<th>Key Size</th>' +
          '<th>PQC Status</th>' +
          '<th>Module</th>' +
          '<th>Priority</th>' +
          '<th>Status</th>' +
          '<th>Changed</th>' +
          (admin ? '<th>Action</th>' : '') +
        '</tr></thead>' +
        '<tbody>';

    rows.forEach(function(row) {
      var findingId = escHtml(row.findingId || '');
      var hostname   = escHtml(row.hostname || '—');
      var algorithm  = escHtml(row.algorithm || '—');
      var keySize    = escHtml(row.keySize ? String(row.keySize) : '—');
      var module     = escHtml(row.module || '—');
      var priority   = escHtml(row.priority ? String(row.priority) : '—');
      var changedBy  = escHtml(row.changedBy || '—');
      var rowStatus  = row.status || 'open';

      var actionCell = '';
      if (admin) {
        if (rowStatus === 'open' || rowStatus === 'in_progress') {
          // Dropdown to transition to in_progress / resolved / accepted
          actionCell =
            '<td>' +
              '<select class="action-select rem-action-select" data-finding-id="' + findingId + '" data-current-status="' + escHtml(rowStatus) + '">' +
                '<option value="">— Change —</option>' +
                (rowStatus !== 'in_progress' ? '<option value="in_progress">In Progress</option>' : '') +
                '<option value="resolved">Resolved</option>' +
                '<option value="accepted">Accept Risk…</option>' +
              '</select>' +
            '</td>';
        } else {
          // Revert button for resolved / accepted
          actionCell =
            '<td>' +
              '<button class="btn-revert rem-revert-btn" data-finding-id="' + findingId + '">Revert</button>' +
            '</td>';
        }
      }

      // Clickable hostname cell navigates to machine detail
      var hostnameCell =
        '<td><span class="link" style="cursor:pointer;color:var(--accent);text-decoration:underline;" ' +
          'data-hostname="' + escHtml(row.hostname || '') + '">' +
          hostname +
        '</span></td>';

      html +=
        '<tr>' +
          hostnameCell +
          '<td>' + algorithm + '</td>' +
          '<td>' + keySize + '</td>' +
          '<td>' + pqcBadge(row.pqcStatus) + '</td>' +
          '<td>' + module + '</td>' +
          '<td>' + priority + '</td>' +
          '<td>' + statusBadge(rowStatus) + '</td>' +
          '<td style="font-size:0.8rem;color:var(--text-secondary);">' + formatDate(row.changedAt) +
            (changedBy !== '—' ? '<br><span style="font-size:0.75rem;">' + changedBy + '</span>' : '') +
          '</td>' +
          actionCell +
        '</tr>';
    });

    html += '</tbody></table>';
    el.innerHTML = html;

    // Wire hostname clicks
    el.querySelectorAll('[data-hostname]').forEach(function(span) {
      span.addEventListener('click', function() {
        var h = span.getAttribute('data-hostname');
        if (h) location.hash = '#/machines/' + encodeURIComponent(h);
      });
    });

    if (admin) {
      // Wire action dropdowns
      el.querySelectorAll('.rem-action-select').forEach(function(sel) {
        sel.addEventListener('change', function() {
          var findingId = sel.getAttribute('data-finding-id');
          var newStatus = sel.value;
          if (!newStatus) return;
          if (newStatus === 'accepted') {
            showAcceptRiskModal(findingId);
            sel.value = ''; // reset
          } else {
            postStatus(findingId, newStatus, '', '');
          }
        });
      });

      // Wire revert buttons
      el.querySelectorAll('.rem-revert-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var findingId = btn.getAttribute('data-finding-id');
          postRevert(findingId, '');
        });
      });
    }
  }

  // ─── API actions ─────────────────────────────────────────────────────

  function postStatus(findingId, status, reason, expiresAt) {
    var body = { status: status };
    if (reason) body.reason = reason;
    if (expiresAt) body.expiresAt = expiresAt;
    postWithAuth('/api/v1/findings/' + encodeURIComponent(findingId) + '/status', body)
      .then(function() { renderRemediation(); })
      .catch(function(err) { alert('Failed to update status: ' + err.message); });
  }

  function postRevert(findingId, reason) {
    var body = {};
    if (reason) body.reason = reason;
    postWithAuth('/api/v1/findings/' + encodeURIComponent(findingId) + '/revert', body)
      .then(function() { renderRemediation(); })
      .catch(function(err) { alert('Failed to revert: ' + err.message); });
  }

  // ─── Accept Risk modal ───────────────────────────────────────────────

  function showAcceptRiskModal(findingId) {
    // Default expiry: 1 year from today
    var defaultExpiry = '';
    try {
      var d = new Date();
      d.setFullYear(d.getFullYear() + 1);
      defaultExpiry = d.toISOString().slice(0, 10);
    } catch (e) {}

    var modalEl = document.getElementById('accept-risk-modal');
    if (!modalEl) return;

    modalEl.innerHTML =
      '<div class="modal-overlay" id="rem-modal-overlay">' +
        '<div class="modal-content">' +
          '<h3>Accept Risk</h3>' +
          '<p style="color:var(--text-secondary);font-size:0.9rem;margin-top:0;">' +
            'Provide a reason for accepting this risk. An optional expiry date can be set after which the status will no longer be considered accepted.' +
          '</p>' +
          '<label style="font-size:0.85rem;color:var(--text-secondary);">Reason <span style="color:#f87171;">*</span>' +
            '<textarea id="rem-risk-reason" placeholder="e.g. Legacy system — migration scheduled for Q3 2026"></textarea>' +
          '</label>' +
          '<label style="font-size:0.85rem;color:var(--text-secondary);display:block;margin-top:0.5rem;">Expiry date (optional)' +
            '<br><input type="date" id="rem-risk-expiry" value="' + escHtml(defaultExpiry) + '" style="margin-top:0.25rem;">' +
          '</label>' +
          '<div id="rem-modal-error" style="color:#f87171;font-size:0.85rem;margin-top:0.5rem;"></div>' +
          '<div class="modal-actions">' +
            '<button class="btn-cancel" id="rem-modal-cancel">Cancel</button>' +
            '<button class="btn-primary" id="rem-modal-submit">Accept Risk</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    document.getElementById('rem-modal-cancel').addEventListener('click', function() {
      modalEl.innerHTML = '';
    });

    // Close on overlay click
    document.getElementById('rem-modal-overlay').addEventListener('click', function(e) {
      if (e.target === this) modalEl.innerHTML = '';
    });

    document.getElementById('rem-modal-submit').addEventListener('click', function() {
      var reasonEl = document.getElementById('rem-risk-reason');
      var expiryEl = document.getElementById('rem-risk-expiry');
      var errEl    = document.getElementById('rem-modal-error');

      var reason  = reasonEl ? reasonEl.value.trim() : '';
      var expiry  = expiryEl ? expiryEl.value.trim() : '';

      if (!reason) {
        if (errEl) errEl.textContent = 'A reason is required.';
        return;
      }

      modalEl.innerHTML = '';
      postStatus(findingId, 'accepted', reason, expiry);
    });
  }

})();
