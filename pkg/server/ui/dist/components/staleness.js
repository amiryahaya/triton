// components/staleness.js — Data-as-of bar + pipeline status polling
// Analytics Phase 4A
(function() {
  window.renderStalenessBar = renderStalenessBar;
  window.startPipelinePoll = startPipelinePoll;
  window.stopPipelinePoll = stopPipelinePoll;

  var pollInterval = null;

  function renderStalenessBar(containerId, dataAsOf, pipelineLag) {
    var container = document.getElementById(containerId);
    if (!container) return;
    var dateStr = dataAsOf ? new Date(dataAsOf).toLocaleString() : 'No data yet';
    var lagText = '';
    if (pipelineLag && pipelineLag > 0) {
      lagText = ' \u00b7 Pipeline: processing';
    } else {
      lagText = ' \u00b7 Pipeline: idle';
    }
    container.innerHTML =
      '<div class="staleness-bar">' +
        '<span>Data as of: ' + dateStr + '</span>' +
        '<span class="staleness-status">' + lagText + '</span>' +
      '</div>';
  }

  function startPipelinePoll(callback) {
    if (pollInterval) return;
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
