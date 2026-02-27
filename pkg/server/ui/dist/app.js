// Triton Dashboard SPA
(function() {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);
  const content = $('#content');

  // API helper
  async function api(path) {
    const resp = await fetch('/api/v1' + path);
    if (!resp.ok) throw new Error(`API error: ${resp.status}`);
    return resp.json();
  }

  // Chart colors
  const COLORS = {
    safe: '#2e7d32',
    transitional: '#e65100',
    deprecated: '#c62828',
    unsafe: '#b71c1c',
    info: '#1565c0'
  };

  // Router
  function route() {
    const hash = location.hash || '#/';
    const parts = hash.slice(2).split('/');
    const view = parts[0] || '';
    const param = parts[1] || '';

    // Update active nav
    $$('.sidebar nav a').forEach(a => {
      a.classList.toggle('active', a.dataset.view === (view || 'overview'));
    });

    switch(view) {
      case '':
      case 'overview': renderOverview(); break;
      case 'machines': param ? renderMachineDetail(param) : renderMachines(); break;
      case 'scans': param ? renderScanDetail(param) : renderScans(); break;
      case 'diff': renderDiff(); break;
      case 'trend': renderTrend(); break;
      default: content.innerHTML = '<div class="error">Page not found</div>';
    }
  }

  // Render helpers
  function badge(status) {
    const s = (status || '').toUpperCase();
    return `<span class="badge badge-${s.toLowerCase()}">${s}</span>`;
  }

  function formatDate(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
  }

  // Overview
  async function renderOverview() {
    content.innerHTML = '<div class="loading">Loading overview...</div>';
    try {
      const agg = await api('/aggregate');
      let html = `<h2>Organization Overview</h2>`;

      html += `<div class="card-grid">
        <div class="card info"><div class="value">${agg.machineCount}</div><div class="label">Machines</div></div>
        <div class="card info"><div class="value">${agg.totalFindings}</div><div class="label">Total Findings</div></div>
        <div class="card safe"><div class="value">${agg.safe}</div><div class="label">Safe</div></div>
        <div class="card transitional"><div class="value">${agg.transitional}</div><div class="label">Transitional</div></div>
        <div class="card deprecated"><div class="value">${agg.deprecated}</div><div class="label">Deprecated</div></div>
        <div class="card unsafe"><div class="value">${agg.unsafe}</div><div class="label">Unsafe</div></div>
      </div>`;

      html += `<div class="charts-row">
        <div class="chart-box"><h3>PQC Status Distribution</h3><canvas id="donutChart" width="300" height="300"></canvas></div>
        <div class="chart-box"><h3>Machines by Risk</h3><canvas id="barChart" width="400" height="300"></canvas></div>
      </div>`;

      // Machines table
      if (agg.machines && agg.machines.length > 0) {
        html += `<h2>Machines</h2><table>
          <tr><th>Hostname</th><th>Last Scan</th><th>Findings</th><th>Safe</th><th>Trans.</th><th>Depr.</th><th>Unsafe</th></tr>`;
        for (const m of agg.machines) {
          html += `<tr style="cursor:pointer" onclick="location.hash='#/machines/${m.hostname}'">
            <td>${m.hostname}</td><td>${formatDate(m.timestamp)}</td>
            <td>${m.totalFindings}</td>
            <td>${m.safe}</td><td>${m.transitional}</td>
            <td>${m.deprecated}</td><td>${m.unsafe}</td></tr>`;
        }
        html += `</table>`;
      }

      content.innerHTML = html;

      // Charts
      renderDonutChart(agg);
      renderBarChart(agg);
    } catch(e) {
      content.innerHTML = `<div class="error">Failed to load: ${e.message}</div>`;
    }
  }

  function renderDonutChart(agg) {
    const ctx = document.getElementById('donutChart');
    if (!ctx) return;
    new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Safe', 'Transitional', 'Deprecated', 'Unsafe'],
        datasets: [{
          data: [agg.safe, agg.transitional, agg.deprecated, agg.unsafe],
          backgroundColor: [COLORS.safe, COLORS.transitional, COLORS.deprecated, COLORS.unsafe]
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: 'bottom' } }
      }
    });
  }

  function renderBarChart(agg) {
    const ctx = document.getElementById('barChart');
    if (!ctx || !agg.machines) return;
    const sorted = [...agg.machines].sort((a,b) => (b.unsafe*4+b.deprecated*3) - (a.unsafe*4+a.deprecated*3));
    const top = sorted.slice(0, 10);

    new Chart(ctx, {
      type: 'bar',
      data: {
        labels: top.map(m => m.hostname),
        datasets: [
          { label: 'Unsafe', data: top.map(m => m.unsafe), backgroundColor: COLORS.unsafe },
          { label: 'Deprecated', data: top.map(m => m.deprecated), backgroundColor: COLORS.deprecated },
          { label: 'Transitional', data: top.map(m => m.transitional), backgroundColor: COLORS.transitional },
          { label: 'Safe', data: top.map(m => m.safe), backgroundColor: COLORS.safe }
        ]
      },
      options: {
        responsive: true,
        scales: { x: { stacked: true }, y: { stacked: true } },
        plugins: { legend: { position: 'bottom' } }
      }
    });
  }

  // Machines list
  async function renderMachines() {
    content.innerHTML = '<div class="loading">Loading machines...</div>';
    try {
      const machines = await api('/machines');
      let html = `<h2>Machines</h2><table>
        <tr><th>Hostname</th><th>Latest Scan ID</th><th>Scan Time</th><th>Findings</th></tr>`;
      for (const m of machines) {
        html += `<tr style="cursor:pointer" onclick="location.hash='#/machines/${m.hostname}'">
          <td>${m.hostname}</td><td>${m.id}</td>
          <td>${formatDate(m.timestamp)}</td><td>${m.totalFindings}</td></tr>`;
      }
      html += `</table>`;
      content.innerHTML = html;
    } catch(e) {
      content.innerHTML = `<div class="error">Failed to load: ${e.message}</div>`;
    }
  }

  // Machine detail
  async function renderMachineDetail(hostname) {
    content.innerHTML = '<div class="loading">Loading machine...</div>';
    try {
      const scans = await api(`/machines/${hostname}`);
      let html = `<div class="view-header"><h2>Machine: ${hostname}</h2>
        <button class="btn btn-outline" onclick="location.hash='#/machines'">Back</button></div>`;

      html += `<table>
        <tr><th>Scan ID</th><th>Time</th><th>Profile</th><th>Findings</th><th>Safe</th><th>Trans.</th><th>Depr.</th><th>Unsafe</th></tr>`;
      for (const s of scans) {
        html += `<tr style="cursor:pointer" onclick="location.hash='#/scans/${s.id}'">
          <td>${s.id.slice(0,8)}...</td>
          <td>${formatDate(s.timestamp)}</td><td>${s.profile}</td>
          <td>${s.totalFindings}</td>
          <td>${s.safe}</td><td>${s.transitional}</td>
          <td>${s.deprecated}</td><td>${s.unsafe}</td></tr>`;
      }
      html += `</table>`;

      // Trend chart
      if (scans.length >= 2) {
        html += `<div class="chart-box"><h3>Trend</h3><canvas id="trendChart" width="600" height="300"></canvas></div>`;
      }

      content.innerHTML = html;

      if (scans.length >= 2) {
        renderMachineTrend(scans);
      }
    } catch(e) {
      content.innerHTML = `<div class="error">Failed to load: ${e.message}</div>`;
    }
  }

  function renderMachineTrend(scans) {
    const ctx = document.getElementById('trendChart');
    if (!ctx) return;
    const reversed = [...scans].reverse();
    new Chart(ctx, {
      type: 'line',
      data: {
        labels: reversed.map(s => new Date(s.timestamp).toLocaleDateString()),
        datasets: [
          { label: 'Safe', data: reversed.map(s => s.safe), borderColor: COLORS.safe, fill: false },
          { label: 'Transitional', data: reversed.map(s => s.transitional), borderColor: COLORS.transitional, fill: false },
          { label: 'Deprecated', data: reversed.map(s => s.deprecated), borderColor: COLORS.deprecated, fill: false },
          { label: 'Unsafe', data: reversed.map(s => s.unsafe), borderColor: COLORS.unsafe, fill: false }
        ]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: 'bottom' } }
      }
    });
  }

  // Scans list
  async function renderScans() {
    content.innerHTML = '<div class="loading">Loading scans...</div>';
    try {
      const scans = await api('/scans');
      let html = `<h2>All Scans</h2><table>
        <tr><th>ID</th><th>Hostname</th><th>Time</th><th>Profile</th><th>Findings</th><th>Safe</th><th>Unsafe</th></tr>`;
      for (const s of scans) {
        html += `<tr style="cursor:pointer" onclick="location.hash='#/scans/${s.id}'">
          <td>${s.id.slice(0,8)}...</td><td>${s.hostname}</td>
          <td>${formatDate(s.timestamp)}</td><td>${s.profile}</td>
          <td>${s.totalFindings}</td><td>${s.safe}</td><td>${s.unsafe}</td></tr>`;
      }
      html += `</table>`;
      content.innerHTML = html;
    } catch(e) {
      content.innerHTML = `<div class="error">Failed to load: ${e.message}</div>`;
    }
  }

  // Scan detail
  async function renderScanDetail(id) {
    content.innerHTML = '<div class="loading">Loading scan...</div>';
    try {
      const scan = await api(`/scans/${id}`);
      let html = `<div class="view-header"><h2>Scan: ${id.slice(0,12)}...</h2>
        <button class="btn btn-outline" onclick="location.hash='#/scans'">Back</button></div>`;

      html += `<div class="card-grid">
        <div class="card info"><div class="value">${scan.metadata.hostname}</div><div class="label">Hostname</div></div>
        <div class="card info"><div class="value">${scan.metadata.scanProfile}</div><div class="label">Profile</div></div>
        <div class="card info"><div class="value">${scan.summary.totalFindings}</div><div class="label">Total Findings</div></div>
        <div class="card safe"><div class="value">${scan.summary.safe}</div><div class="label">Safe</div></div>
        <div class="card transitional"><div class="value">${scan.summary.transitional}</div><div class="label">Transitional</div></div>
        <div class="card deprecated"><div class="value">${scan.summary.deprecated}</div><div class="label">Deprecated</div></div>
        <div class="card unsafe"><div class="value">${scan.summary.unsafe}</div><div class="label">Unsafe</div></div>
      </div>`;

      // Findings table
      if (scan.findings && scan.findings.length > 0) {
        html += `<h2>Findings</h2><table>
          <tr><th>Module</th><th>Source</th><th>Algorithm</th><th>PQC Status</th><th>Key Size</th></tr>`;
        for (const f of scan.findings) {
          const algo = f.cryptoAsset ? f.cryptoAsset.algorithm : '-';
          const status = f.cryptoAsset ? f.cryptoAsset.pqcStatus : '-';
          const keySize = f.cryptoAsset && f.cryptoAsset.keySize ? f.cryptoAsset.keySize : '-';
          const source = f.source.path || f.source.endpoint || '-';
          html += `<tr>
            <td>${f.module}</td><td>${source}</td>
            <td>${algo}</td><td>${badge(status)}</td><td>${keySize}</td></tr>`;
        }
        html += `</table>`;
      }

      // Systems table
      if (scan.systems && scan.systems.length > 0) {
        html += `<h2>Systems</h2><table>
          <tr><th>Name</th><th>Criticality</th><th>Crypto Assets</th></tr>`;
        for (const sys of scan.systems) {
          html += `<tr><td>${sys.name}</td><td>${sys.criticalityLevel || '-'}</td>
            <td>${(sys.cryptoAssets || []).length}</td></tr>`;
        }
        html += `</table>`;
      }

      content.innerHTML = html;
    } catch(e) {
      content.innerHTML = `<div class="error">Failed to load: ${e.message}</div>`;
    }
  }

  // Diff view
  async function renderDiff() {
    content.innerHTML = `<h2>Scan Comparison</h2>
      <div style="margin-bottom:20px">
        <label>Base Scan ID: <input id="diffBase" type="text" placeholder="scan-id-1" style="padding:6px;border:1px solid var(--border);border-radius:4px"></label>
        <label style="margin-left:12px">Compare Scan ID: <input id="diffCompare" type="text" placeholder="scan-id-2" style="padding:6px;border:1px solid var(--border);border-radius:4px"></label>
        <button class="btn" style="margin-left:12px" onclick="runDiff()">Compare</button>
      </div>
      <div id="diffResult"></div>`;
  }

  window.runDiff = async function() {
    const base = $('#diffBase').value.trim();
    const compare = $('#diffCompare').value.trim();
    const el = $('#diffResult');
    if (!base || !compare) { el.innerHTML = '<div class="error">Enter both scan IDs</div>'; return; }

    el.innerHTML = '<div class="loading">Computing diff...</div>';
    try {
      const diff = await api(`/diff?base=${base}&compare=${compare}`);
      let html = `<div class="card-grid">
        <div class="card safe"><div class="value">${diff.addedCount || 0}</div><div class="label">Added</div></div>
        <div class="card unsafe"><div class="value">${diff.removedCount || 0}</div><div class="label">Removed</div></div>
        <div class="card transitional"><div class="value">${diff.changedCount || 0}</div><div class="label">Changed</div></div>
      </div>`;

      if (diff.added && diff.added.length > 0) {
        html += `<h3>Added Findings</h3><table class="diff-added">
          <tr><th>Module</th><th>Algorithm</th><th>Status</th></tr>`;
        for (const f of diff.added) {
          html += `<tr><td>${f.module}</td><td>${f.cryptoAsset ? f.cryptoAsset.algorithm : '-'}</td>
            <td>${badge(f.cryptoAsset ? f.cryptoAsset.pqcStatus : '')}</td></tr>`;
        }
        html += `</table>`;
      }

      if (diff.removed && diff.removed.length > 0) {
        html += `<h3>Removed Findings</h3><table class="diff-removed">
          <tr><th>Module</th><th>Algorithm</th><th>Status</th></tr>`;
        for (const f of diff.removed) {
          html += `<tr><td>${f.module}</td><td>${f.cryptoAsset ? f.cryptoAsset.algorithm : '-'}</td>
            <td>${badge(f.cryptoAsset ? f.cryptoAsset.pqcStatus : '')}</td></tr>`;
        }
        html += `</table>`;
      }

      el.innerHTML = html;
    } catch(e) {
      el.innerHTML = `<div class="error">Diff failed: ${e.message}</div>`;
    }
  };

  // Trend view
  async function renderTrend() {
    content.innerHTML = `<h2>Migration Trend</h2>
      <div style="margin-bottom:20px">
        <label>Hostname: <input id="trendHost" type="text" placeholder="hostname" style="padding:6px;border:1px solid var(--border);border-radius:4px"></label>
        <label style="margin-left:12px">Last N: <input id="trendLast" type="number" value="10" min="2" max="50" style="padding:6px;border:1px solid var(--border);border-radius:4px;width:60px"></label>
        <button class="btn" style="margin-left:12px" onclick="runTrend()">Show Trend</button>
      </div>
      <div id="trendResult"></div>`;
  }

  window.runTrend = async function() {
    const host = $('#trendHost').value.trim();
    const last = $('#trendLast').value || 10;
    const el = $('#trendResult');

    let url = `/trend?last=${last}`;
    if (host) url += `&hostname=${host}`;

    el.innerHTML = '<div class="loading">Computing trend...</div>';
    try {
      const trend = await api(url);

      let html = '';
      if (trend.direction) {
        const dir = trend.direction;
        const cls = dir === 'improving' ? 'safe' : dir === 'declining' ? 'unsafe' : 'info';
        html += `<div class="card ${cls}" style="display:inline-block;margin-bottom:16px">
          <div class="value" style="font-size:1.2em;text-transform:capitalize">${dir}</div>
          <div class="label">Overall Direction</div></div>`;
      }

      if (trend.points && trend.points.length > 0) {
        html += `<div class="chart-box"><canvas id="trendLineChart" width="600" height="300"></canvas></div>`;
      }

      el.innerHTML = html;

      if (trend.points && trend.points.length > 0) {
        const ctx = document.getElementById('trendLineChart');
        new Chart(ctx, {
          type: 'line',
          data: {
            labels: trend.points.map(p => new Date(p.timestamp).toLocaleDateString()),
            datasets: [
              { label: 'Safe', data: trend.points.map(p => p.safe), borderColor: COLORS.safe, fill: false },
              { label: 'Transitional', data: trend.points.map(p => p.transitional), borderColor: COLORS.transitional, fill: false },
              { label: 'Deprecated', data: trend.points.map(p => p.deprecated), borderColor: COLORS.deprecated, fill: false },
              { label: 'Unsafe', data: trend.points.map(p => p.unsafe), borderColor: COLORS.unsafe, fill: false }
            ]
          },
          options: {
            responsive: true,
            plugins: { legend: { position: 'bottom' } }
          }
        });
      }
    } catch(e) {
      el.innerHTML = `<div class="error">Trend failed: ${e.message}</div>`;
    }
  };

  // Init
  window.addEventListener('hashchange', route);
  route();
})();
