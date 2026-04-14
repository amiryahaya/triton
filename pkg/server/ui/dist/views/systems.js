// views/systems.js — Systems Health view
// Analytics Phase 4A
(function() {
  // Register with the router — app.js will call window.renderSystems()
  window.renderSystems = renderSystems;

  var sparklineCharts = [];

  function renderSystems() {
    // Clean up previous sparkline Chart instances
    sparklineCharts.forEach(function(c) { c.destroy(); });
    sparklineCharts = [];

    var content = document.getElementById('content');
    content.innerHTML =
      '<div class="page-header"><h2>Systems Health</h2></div>' +
      '<div id="staleness-bar"></div>' +
      '<div id="systems-filter" class="filter-bar"></div>' +
      '<div id="systems-summary"></div>' +
      '<div id="systems-table"></div>';

    fetchSystems('');
  }

  function fetchSystems(pqcFilter) {
    var url = '/api/v1/systems';
    if (pqcFilter) url += '?pqc_status=' + encodeURIComponent(pqcFilter);

    fetch(url)
      .then(function(r) { return r.json(); })
      .then(function(resp) {
        renderStalenessBar('staleness-bar', resp.dataAsOf, resp.pipelineLag);
        renderFilter(pqcFilter);
        renderSummary(resp.data);
        renderTable(resp.data);
      })
      .catch(function(err) {
        document.getElementById('systems-table').innerHTML =
          '<p class="error">Failed to load systems: ' + err.message + '</p>';
      });
  }

  function renderFilter(active) {
    var statuses = ['', 'UNSAFE', 'DEPRECATED', 'TRANSITIONAL', 'SAFE'];
    var labels = ['All', 'Unsafe', 'Deprecated', 'Transitional', 'Safe'];
    var html = '<label>PQC Status: </label><select id="systems-pqc-filter">';
    for (var i = 0; i < statuses.length; i++) {
      html += '<option value="' + statuses[i] + '"' +
        (statuses[i] === active ? ' selected' : '') + '>' +
        labels[i] + '</option>';
    }
    html += '</select>';
    document.getElementById('systems-filter').innerHTML = html;
    document.getElementById('systems-pqc-filter').addEventListener('change', function() {
      fetchSystems(this.value);
    });
  }

  function renderSummary(data) {
    var red = 0, yellow = 0, green = 0;
    data.forEach(function(row) {
      if (row.unsafeFindings > 0) red++;
      else if (row.deprecatedFindings > 0) yellow++;
      else green++;
    });
    document.getElementById('systems-summary').innerHTML =
      '<div class="systems-summary">' +
        '<span>' + data.length + ' systems</span>' +
        '<span class="tier-badge tier-green">' + green + ' green</span>' +
        '<span class="tier-badge tier-yellow">' + yellow + ' yellow</span>' +
        '<span class="tier-badge tier-red">' + red + ' red</span>' +
      '</div>';
  }

  function renderTable(data) {
    if (data.length === 0) {
      document.getElementById('systems-table').innerHTML =
        '<p class="empty-state">No systems found. Scans will appear here once processed by the pipeline.</p>';
      return;
    }

    var html = '<table class="analytics-table">' +
      '<thead><tr>' +
        '<th>Hostname</th>' +
        '<th>Readiness</th>' +
        '<th>Trend</th>' +
        '<th>Sparkline</th>' +
        '<th>Unsafe</th>' +
        '<th>Deprecated</th>' +
        '<th>Last Scanned</th>' +
      '</tr></thead><tbody>';

    data.forEach(function(row, i) {
      var trendArrow = row.trendDirection === 'improving' ? '<span class="trend-up">&#x2191;</span>' :
                       row.trendDirection === 'declining' ? '<span class="trend-down">&#x2193;</span>' :
                       '<span class="trend-stable">&#x2192;</span>';

      var readyClass = row.readinessPct >= 80 ? 'ready-good' :
                       row.readinessPct >= 50 ? 'ready-warn' : 'ready-bad';

      html += '<tr>' +
        '<td><a href="#/inventory?hostname=' + encodeURIComponent(row.hostname) + '" class="hostname-link">' + escapeHtml(row.hostname) + '</a></td>' +
        '<td class="' + readyClass + '">' + row.readinessPct.toFixed(1) + '%</td>' +
        '<td>' + trendArrow + ' ' + (row.trendDeltaPct > 0 ? '+' : '') + row.trendDeltaPct.toFixed(1) + '%</td>' +
        '<td class="sparkline-cell"><canvas id="spark-' + i + '" width="80" height="24"></canvas></td>' +
        '<td>' + row.unsafeFindings + '</td>' +
        '<td>' + row.deprecatedFindings + '</td>' +
        '<td>' + formatDate(row.scannedAt) + '</td>' +
      '</tr>';
    });

    html += '</tbody></table>';
    document.getElementById('systems-table').innerHTML = html;

    // Render sparklines after DOM is updated
    data.forEach(function(row, i) {
      if (row.sparkline && row.sparkline.length >= 2) {
        var chart = renderSparkline('spark-' + i, row.sparkline);
        if (chart) sparklineCharts.push(chart);
      }
    });
  }

  function formatDate(isoStr) {
    if (!isoStr) return '-';
    var d = new Date(isoStr);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
  }

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
})();
