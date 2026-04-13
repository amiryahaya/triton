// views/trends.js — Migration Trends view
// Analytics Phase 4A
(function() {
  window.renderTrends = renderTrends;

  var trendChart = null;

  function renderTrends() {
    // Clean up previous chart
    if (trendChart) { trendChart.destroy(); trendChart = null; }

    var content = document.getElementById('content');
    content.innerHTML =
      '<div class="page-header"><h2>Migration Trend</h2></div>' +
      '<div id="staleness-bar"></div>' +
      '<div class="chart-container" style="position:relative;height:350px;margin-bottom:2rem;">' +
        '<canvas id="trend-chart"></canvas>' +
      '</div>' +
      '<div id="trend-delta-table"></div>';

    fetch('/api/v1/trends')
      .then(function(r) { return r.json(); })
      .then(function(resp) {
        renderStalenessBar('staleness-bar', resp.dataAsOf, resp.pipelineLag);
        renderChart(resp.monthlyPoints || []);
        renderDeltaTable(resp.monthlyPoints || []);
      })
      .catch(function(err) {
        document.getElementById('trend-delta-table').innerHTML =
          '<p class="error">Failed to load trends: ' + err.message + '</p>';
      });
  }

  function renderChart(points) {
    var canvas = document.getElementById('trend-chart');
    if (!canvas || points.length === 0) {
      canvas.parentElement.innerHTML = '<p class="empty-state">Not enough data for trend chart. At least 2 months of scans are needed.</p>';
      return;
    }

    var labels = points.map(function(p) { return p.month; });
    var data = points.map(function(p) { return p.readiness; });

    // Target line at 80% (default org target)
    var targetData = points.map(function() { return 80; });

    trendChart = new Chart(canvas, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Readiness %',
            data: data,
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            borderWidth: 2,
            pointRadius: 4,
            pointBackgroundColor: '#3b82f6',
            fill: true,
            tension: 0.3
          },
          {
            label: 'Target (80%)',
            data: targetData,
            borderColor: '#94a3b8',
            borderWidth: 1,
            borderDash: [5, 5],
            pointRadius: 0,
            fill: false
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'top' },
          tooltip: {
            callbacks: {
              label: function(ctx) {
                return ctx.dataset.label + ': ' + ctx.parsed.y.toFixed(1) + '%';
              }
            }
          }
        },
        scales: {
          y: {
            min: 0,
            max: 100,
            title: { display: true, text: 'Readiness %' },
            ticks: { callback: function(v) { return v + '%'; } }
          },
          x: {
            title: { display: true, text: 'Month' }
          }
        }
      }
    });
  }

  function renderDeltaTable(points) {
    var container = document.getElementById('trend-delta-table');
    if (points.length === 0) {
      container.innerHTML = '';
      return;
    }

    var html = '<h3>Monthly Delta</h3>' +
      '<table class="analytics-table">' +
      '<thead><tr><th>Month</th><th>Readiness</th><th>Delta</th><th>Direction</th></tr></thead>' +
      '<tbody>';

    for (var i = 0; i < points.length; i++) {
      var delta = i > 0 ? (points[i].readiness - points[i-1].readiness) : 0;
      var arrow = delta > 1 ? '<span class="trend-up">&#x2191;</span>' :
                  delta < -1 ? '<span class="trend-down">&#x2193;</span>' :
                  '<span class="trend-stable">&#x2192;</span>';
      var sign = delta > 0 ? '+' : '';

      html += '<tr>' +
        '<td>' + points[i].month + '</td>' +
        '<td>' + points[i].readiness.toFixed(1) + '%</td>' +
        '<td>' + (i > 0 ? sign + delta.toFixed(1) + '%' : '-') + '</td>' +
        '<td>' + (i > 0 ? arrow : '-') + '</td>' +
      '</tr>';
    }

    html += '</tbody></table>';
    container.innerHTML = html;
  }
})();
