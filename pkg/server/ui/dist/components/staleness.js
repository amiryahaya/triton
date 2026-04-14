// components/staleness.js — Data-as-of bar + pipeline status polling
// Analytics Phase 4A
(function() {
  window.renderStalenessBar = renderStalenessBar;
  window.startPipelinePoll = startPipelinePoll;
  window.stopPipelinePoll = stopPipelinePoll;

  var pollInterval = null;
  var lastPipelineStatus = 'idle';

  function renderStalenessBar(containerId, dataAsOf) {
    var container = document.getElementById(containerId);
    if (!container) return;
    var dateStr = dataAsOf ? new Date(dataAsOf).toLocaleString() : 'No data yet';
    var statusText = lastPipelineStatus === 'processing'
      ? ' \u00b7 Pipeline: processing'
      : ' \u00b7 Pipeline: idle';
    container.innerHTML =
      '<div class="staleness-bar">' +
        '<span>Data as of: ' + dateStr + '</span>' +
        '<span class="staleness-status">' + statusText + '</span>' +
      '</div>';

    // Start polling pipeline status to keep the indicator live
    startPipelinePoll(function(status) {
      lastPipelineStatus = status.status || 'idle';
      renderStalenessBar(containerId, dataAsOf);
      if (lastPipelineStatus === 'idle') {
        stopPipelinePoll();
      }
    });
  }

  function startPipelinePoll(callback) {
    if (pollInterval) return;
    // Fetch immediately, then poll every 10s
    fetch('/api/v1/pipeline/status')
      .then(function(r) { return r.json(); })
      .then(callback)
      .catch(function() {});
    pollInterval = setInterval(function() {
      fetch('/api/v1/pipeline/status')
        .then(function(r) { return r.json(); })
        .then(callback)
        .catch(function() {});
    }, 10000);
  }

  function stopPipelinePoll() {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  }
})();
