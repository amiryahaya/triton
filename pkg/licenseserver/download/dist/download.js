// Triton Download Page
(function() {
  'use strict';

  var licenseID = '';
  var latestVersion = '';
  var platforms = [];
  var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
    if (licenseID.length > 100 || !UUID_RE.test(licenseID)) {
      licenseError.textContent = 'Invalid license ID format. Expected UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).';
      licenseError.hidden = false;
      return;
    }
    licenseError.hidden = true;
    btnContinue.disabled = true;
    fetchLatestVersion();
  };

  licenseInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') btnContinue.click();
  });

  function fetchLatestVersion() {
    fetch('/api/v1/license/download/latest-version')
      .then(function(r) {
        if (!r.ok) throw new Error('Server error');
        return r.json().catch(function() { throw new Error('Invalid response'); });
      })
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
      })
      .finally(function() {
        btnContinue.disabled = false;
      });
  }

  // Build a lookup for sha3 by os-arch key.
  var sha3Map = {};

  function showPlatformStep() {
    stepPlatform.hidden = false;

    if (platforms.length === 0) {
      noPlatforms.hidden = false;
      platformsDiv.innerHTML = '';
      return;
    }

    // Build sha3 lookup.
    for (var s = 0; s < platforms.length; s++) {
      if (platforms[s].sha3) {
        sha3Map[platforms[s].os + '-' + platforms[s].arch] = platforms[s].sha3;
      }
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

    // Quick Install section — one-liner for the detected platform.
    if (match) {
      var serverURL = window.location.origin;
      var dlURL = serverURL + downloadURL(latestVersion, match.os, match.arch);
      var lic = escapeHtml(licenseID);

      html += '<div class="quick-install" style="margin-top:2em;padding:1.5em;background:#0d1b2a;border-radius:8px;border:1px solid #1b2838">';
      html += '<h3 style="margin:0 0 0.5em 0;color:#00d4ff;font-size:1em">Quick Install (Recommended)</h3>';
      html += '<p style="color:#8892a4;margin:0 0 1em 0;font-size:0.9em">Paste this into your terminal to download, install, and activate in one step.</p>';

      if (match.os === 'windows') {
        var ps1Cmd = '# Run in PowerShell as Administrator\n'
          + '$ProgressPreference="SilentlyContinue"\n'
          + 'New-Item -ItemType Directory -Path "C:\\Program Files\\Triton" -Force | Out-Null\n'
          + 'Invoke-WebRequest -Uri "' + dlURL + '" -OutFile "C:\\Program Files\\Triton\\triton.exe" -UseBasicParsing\n'
          + '& "C:\\Program Files\\Triton\\triton.exe" license activate --license-server ' + serverURL + ' --license-id ' + lic + '\n'
          + '& "C:\\Program Files\\Triton\\triton.exe" agent --check-config';
        html += '<div class="code-block" style="position:relative;cursor:pointer" id="quick-install-code">';
        html += escapeHtml(ps1Cmd);
        html += '</div>';
      } else {
        // Linux/macOS — single curl | sh pipeline won't work here because
        // we need multiple steps. Use a multi-line command block instead.
        var shCmd = 'sudo bash -c \''
          + 'mkdir -p /opt/triton/reports'
          + ' && curl -sSfL "' + dlURL + '" -o /opt/triton/triton'
          + ' && chmod 755 /opt/triton/triton';
        if (match.os === 'darwin') {
          shCmd += ' && xattr -d com.apple.quarantine /opt/triton/triton 2>/dev/null || true';
        }
        shCmd += ' && /opt/triton/triton license activate --license-server ' + serverURL + ' --license-id ' + lic
          + ' && /opt/triton/triton agent --check-config'
          + '\'';
        html += '<div class="code-block" style="position:relative;cursor:pointer" id="quick-install-code">';
        html += escapeHtml(shCmd);
        html += '</div>';
      }

      html += '<button class="btn btn-secondary" id="btn-copy-quick" style="margin-top:0.75em;font-size:0.85em">Copy to clipboard</button>';
      html += '</div>';
    }

    platformsDiv.innerHTML = html;

    // Wire copy button.
    var copyBtn = document.getElementById('btn-copy-quick');
    var codeBlock = document.getElementById('quick-install-code');
    if (copyBtn && codeBlock) {
      copyBtn.onclick = function() {
        var text = codeBlock.textContent;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function() {
            copyBtn.textContent = 'Copied!';
            setTimeout(function() { copyBtn.textContent = 'Copy to clipboard'; }, 2000);
          });
        } else {
          // Fallback: select the text.
          var range = document.createRange();
          range.selectNodeContents(codeBlock);
          var sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
        }
      };
    }

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

    var checksum = sha3Map[os + '-' + arch] || '';

    if (os === 'windows') {
      html += '<div class="instructions-block">';
      html += '<h3>PowerShell Instructions (Run as Administrator)</h3>';
      html += '<div class="code-block">';
      if (checksum) {
        html += '<span class="comment"># 1. Verify the download (SHA3-256)</span>\n';
        html += 'openssl dgst -sha3-256 triton.exe\n';
        html += '<span class="comment"># Expected: ' + escapeHtml(checksum) + '</span>\n\n';
      }
      html += '<span class="comment"># ' + (checksum ? '2' : '1') + '. If SmartScreen blocks the file, click "More info" then "Run anyway"</span>\n\n';
      html += '<span class="comment"># ' + (checksum ? '3' : '2') + '. Move to a directory in your PATH</span>\n';
      html += 'Move-Item triton.exe C:\\Windows\\triton.exe\n\n';
      html += '<span class="comment"># ' + (checksum ? '4' : '3') + '. Activate your license</span>\n';
      html += 'triton license activate --license-server ' + escapeHtml(serverURL) + ' --license-id ' + lic + '\n\n';
      html += '<span class="comment"># ' + (checksum ? '5' : '4') + '. Verify installation</span>\n';
      html += 'triton --version\ntriton license show\n\n';
      html += '<span class="comment"># If Windows Defender blocks the binary, add an exclusion:</span>\n';
      html += '<span class="comment"># Add-MpPreference -ExclusionPath "C:\\Windows\\triton.exe"</span>';
      html += '</div></div>';
    } else if (os === 'darwin') {
      html += '<div class="instructions-block">';
      html += '<h3>macOS Instructions</h3>';
      html += '<div class="code-block">';
      var step = 1;
      if (checksum) {
        html += '<span class="comment"># ' + step + '. Verify the download (SHA3-256)</span>\n';
        html += 'openssl dgst -sha3-256 triton\n';
        html += '<span class="comment"># Expected: ' + escapeHtml(checksum) + '</span>\n\n';
        step++;
      }
      html += '<span class="comment"># ' + step + '. Make the binary executable</span>\n';
      html += 'chmod +x triton\n\n';
      step++;
      html += '<span class="comment"># ' + step + '. Move to a directory in your PATH</span>\n';
      html += 'sudo mv triton /usr/local/bin/triton\n\n';
      step++;
      html += '<span class="comment"># ' + step + '. Remove macOS quarantine (Gatekeeper)</span>\n';
      html += 'xattr -d com.apple.quarantine /usr/local/bin/triton\n\n';
      step++;
      html += '<span class="comment"># ' + step + '. Activate your license</span>\n';
      html += 'triton license activate --license-server ' + escapeHtml(serverURL) + ' --license-id ' + lic + '\n\n';
      step++;
      html += '<span class="comment"># ' + step + '. Verify installation</span>\n';
      html += 'triton --version\ntriton license show\n\n';
      html += '<span class="comment"># For comprehensive scans, grant Full Disk Access to your terminal:</span>\n';
      html += '<span class="comment"># System Settings > Privacy & Security > Full Disk Access</span>';
      html += '</div></div>';
    } else {
      html += '<div class="instructions-block">';
      html += '<h3>Linux Instructions</h3>';
      html += '<div class="code-block">';
      var lstep = 1;
      if (checksum) {
        html += '<span class="comment"># ' + lstep + '. Verify the download (SHA3-256)</span>\n';
        html += 'openssl dgst -sha3-256 triton\n';
        html += '<span class="comment"># Expected: ' + escapeHtml(checksum) + '</span>\n\n';
        lstep++;
      }
      html += '<span class="comment"># ' + lstep + '. Make the binary executable</span>\n';
      html += 'chmod +x triton\n\n';
      lstep++;
      html += '<span class="comment"># ' + lstep + '. Move to a directory in your PATH</span>\n';
      html += 'sudo mv triton /usr/local/bin/triton\n\n';
      lstep++;
      html += '<span class="comment"># ' + lstep + '. Activate your license</span>\n';
      html += 'triton license activate --license-server ' + escapeHtml(serverURL) + ' --license-id ' + lic + '\n\n';
      lstep++;
      html += '<span class="comment"># ' + lstep + '. Verify installation</span>\n';
      html += 'triton --version\ntriton license show\n\n';
      html += '<span class="comment"># For comprehensive scans, run with sudo:</span>\n';
      html += '<span class="comment"># sudo triton --profile comprehensive</span>';
      html += '</div></div>';
    }

    instructionsDiv.innerHTML = html;

    // Scroll to instructions.
    stepInstructions.scrollIntoView({ behavior: 'smooth' });
  }
})();
