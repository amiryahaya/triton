// Triton Download Page
(function() {
  'use strict';

  var licenseID = '';
  var latestVersion = '';
  var platforms = [];

  var stepLicense = document.getElementById('step-license');
  var stepPlatform = document.getElementById('step-platform');
  var stepInstructions = document.getElementById('step-instructions');
  var licenseInput = document.getElementById('license-id');
  var licenseError = document.getElementById('license-error');
  var btnContinue = document.getElementById('btn-continue');
  var platformsDiv = document.getElementById('platforms');
  var noPlatforms = document.getElementById('no-platforms');
  var instructionsDiv = document.getElementById('instructions');

  function escapeHtml(s) {
    var div = document.createElement('div');
    div.textContent = s || '';
    return div.innerHTML;
  }

  function detectPlatform() {
    var ua = navigator.userAgent.toLowerCase();
    var platform = navigator.platform.toLowerCase();
    var os = 'linux';
    var arch = 'amd64';

    if (platform.indexOf('mac') >= 0 || ua.indexOf('mac') >= 0) {
      os = 'darwin';
    } else if (platform.indexOf('win') >= 0 || ua.indexOf('win') >= 0) {
      os = 'windows';
    }

    // Check for ARM architecture indicators in user agent.
    if (ua.indexOf('arm64') >= 0 || ua.indexOf('aarch64') >= 0) {
      arch = 'arm64';
    } else if (os === 'darwin') {
      // Cannot reliably detect Intel vs Apple Silicon from browser JS.
      // Default to arm64 as most modern Macs are Apple Silicon;
      // both options will be shown regardless.
      arch = 'arm64';
    }

    return { os: os, arch: arch };
  }

  function platformLabel(os, arch) {
    var labels = {
      'darwin-arm64': 'macOS (Apple Silicon)',
      'darwin-amd64': 'macOS (Intel)',
      'linux-amd64': 'Linux (x86_64)',
      'linux-arm64': 'Linux (ARM64)',
      'windows-amd64': 'Windows (x86_64)',
      'windows-arm64': 'Windows (ARM64)'
    };
    return labels[os + '-' + arch] || os + '/' + arch;
  }

  function downloadURL(version, os, arch) {
    return '/api/v1/license/download/' + encodeURIComponent(version) +
      '/' + encodeURIComponent(os) + '/' + encodeURIComponent(arch) +
      '?license_id=' + encodeURIComponent(licenseID);
  }

  btnContinue.onclick = function() {
    licenseID = licenseInput.value.trim();
    if (!licenseID) {
      licenseError.textContent = 'Please enter your license ID.';
      licenseError.hidden = false;
      return;
    }
    licenseError.hidden = true;
    fetchLatestVersion();
  };

  licenseInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') btnContinue.click();
  });

  function fetchLatestVersion() {
    fetch('/api/v1/license/download/latest-version')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error) {
          licenseError.textContent = 'No binaries available for download.';
          licenseError.hidden = false;
          return;
        }
        latestVersion = data.version;
        platforms = data.platforms || [];
        showPlatformStep();
      })
      .catch(function() {
        licenseError.textContent = 'Failed to connect to server.';
        licenseError.hidden = false;
      });
  }

  function showPlatformStep() {
    stepPlatform.hidden = false;

    if (platforms.length === 0) {
      noPlatforms.hidden = false;
      platformsDiv.innerHTML = '';
      return;
    }

    var detected = detectPlatform();
    var html = '';

    // Find matching platform.
    var match = null;
    for (var i = 0; i < platforms.length; i++) {
      if (platforms[i].os === detected.os && platforms[i].arch === detected.arch) {
        match = platforms[i];
        break;
      }
    }

    // Main download button.
    if (match) {
      html += '<div class="platform-main">';
      html += '<p class="detected">Detected: ' + escapeHtml(platformLabel(detected.os, detected.arch)) + '</p>';
      html += '<a class="btn btn-download" href="' + escapeHtml(downloadURL(latestVersion, match.os, match.arch)) + '"';
      html += ' data-os="' + escapeHtml(match.os) + '" data-arch="' + escapeHtml(match.arch) + '"';
      html += '>Download Triton v' + escapeHtml(latestVersion) + '</a>';
      html += '</div>';
    }

    // Other platforms.
    var others = [];
    for (var j = 0; j < platforms.length; j++) {
      if (match && platforms[j].os === match.os && platforms[j].arch === match.arch) continue;
      others.push(platforms[j]);
    }

    if (others.length > 0) {
      html += '<div class="platform-others">';
      html += '<span>' + (match ? 'Other platforms:' : 'Available platforms:') + '</span>';
      for (var k = 0; k < others.length; k++) {
        html += ' <a class="btn btn-secondary" href="' + escapeHtml(downloadURL(latestVersion, others[k].os, others[k].arch)) + '"';
        html += ' data-os="' + escapeHtml(others[k].os) + '" data-arch="' + escapeHtml(others[k].arch) + '"';
        html += '>' + escapeHtml(platformLabel(others[k].os, others[k].arch)) + '</a>';
      }
      html += '</div>';
    }

    html += '<p class="version-info">Version ' + escapeHtml(latestVersion) + '</p>';
    platformsDiv.innerHTML = html;

    // Attach click handlers to show instructions.
    var links = platformsDiv.querySelectorAll('a[data-os]');
    for (var l = 0; l < links.length; l++) {
      links[l].addEventListener('click', function() {
        showInstructions(this.dataset.os, this.dataset.arch);
      });
    }
  }

  function showInstructions(os, arch) {
    stepInstructions.hidden = false;
    var serverURL = window.location.origin;
    var lic = escapeHtml(licenseID);
    var html = '';

    if (os === 'windows') {
      html += '<div class="instructions-block">';
      html += '<h3>PowerShell Instructions</h3>';
      html += '<div class="code-block">';
      html += '<span class="comment"># 1. Move to a directory in your PATH</span>\n';
      html += 'Move-Item triton.exe C:\\Windows\\triton.exe\n\n';
      html += '<span class="comment"># 2. Activate your license</span>\n';
      html += 'triton license activate --license-server ' + escapeHtml(serverURL) + ' --license-id ' + lic + '\n\n';
      html += '<span class="comment"># 3. Verify installation</span>\n';
      html += 'triton --version\ntriton license show';
      html += '</div></div>';
    } else {
      var binaryName = 'triton';
      html += '<div class="instructions-block">';
      html += '<h3>' + (os === 'darwin' ? 'macOS' : 'Linux') + ' Instructions</h3>';
      html += '<div class="code-block">';
      html += '<span class="comment"># 1. Make the binary executable</span>\n';
      html += 'chmod +x ' + binaryName + '\n\n';
      html += '<span class="comment"># 2. Move to a directory in your PATH</span>\n';
      html += 'sudo mv ' + binaryName + ' /usr/local/bin/triton\n\n';
      html += '<span class="comment"># 3. Activate your license</span>\n';
      html += 'triton license activate --license-server ' + escapeHtml(serverURL) + ' --license-id ' + lic + '\n\n';
      html += '<span class="comment"># 4. Verify installation</span>\n';
      html += 'triton --version\ntriton license show';
      html += '</div></div>';
    }

    instructionsDiv.innerHTML = html;

    // Scroll to instructions.
    stepInstructions.scrollIntoView({ behavior: 'smooth' });
  }
})();
