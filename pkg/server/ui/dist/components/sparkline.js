// components/sparkline.js — Chart.js inline sparkline renderer
// Analytics Phase 4A
(function() {
  window.renderSparkline = renderSparkline;

  function renderSparkline(canvasId, points) {
    var canvas = document.getElementById(canvasId);
    if (!canvas || !points || points.length < 2) return null;
    return new Chart(canvas, {
      type: 'line',
      data: {
        labels: points.map(function(p) { return p.month; }),
        datasets: [{
          data: points.map(function(p) { return p.readiness; }),
          borderColor: '#3b82f6',
          borderWidth: 1.5,
          pointRadius: 0,
          fill: false,
          tension: 0.3
        }]
      },
      options: {
        responsive: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: {
          x: { display: false },
          y: { display: false, min: 0, max: 100 }
        },
        animation: false
      }
    });
  }
})();
