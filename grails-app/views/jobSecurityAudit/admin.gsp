<%@ page import="org.rundeck.core.auth.AuthConstants" %>
<html>
<head>
    <meta name="layout" content="base"/>
    <meta name="tabpage" content="Security & Compliance"/>
    <title><g:message code="jobSecurityAudit.page.title" default="Security & Compliance Scan"/></title>
    <style>
        .jsa-card { border: 1px solid #d9d9d9; border-radius: 6px; padding: 12px; margin-bottom: 12px; background: #fff; }
        .jsa-kpi { display: inline-block; margin-right: 16px; font-weight: 600; }
        .jsa-kpi.critical { color: #7a271a; }
        .jsa-kpi.high { color: #b42318; }
        .jsa-kpi.medium { color: #b54708; }
        .jsa-kpi.low { color: #175cd3; }
        .jsa-muted { color: #667085; }
        .jsa-actions { margin-bottom: 12px; }
        .jsa-findings-table code { font-size: 11px; }
        .jsa-sev { font-weight: 700; }
        .jsa-sev-critical { color: #7a271a; }
        .jsa-sev-high { color: #b42318; }
        .jsa-sev-medium { color: #b54708; }
        .jsa-sev-low { color: #175cd3; }
        .jsa-help ul { margin-bottom: 0; }
        .jsa-modal-body ul { margin-left: 18px; }
        .jsa-preview-section h5 { margin-top: 0; }
        .jsa-preview-actions { margin-top: 10px; }
    </style>
</head>
<body>
<div class="container-fluid">
    <h3><g:message code="jobSecurityAudit.page.title" default="Security & Compliance Scan"/></h3>

    <div class="jsa-actions">
        <button id="jsa-run-scan" class="btn btn-cta"><g:message code="jobSecurityAudit.scan.button" default="Run Security Scan"/></button>
        <button id="jsa-notify" class="btn btn-default"><g:message code="jobSecurityAudit.notify.button" default="Notify"/></button>
        <button id="jsa-generate-ai" class="btn btn-default">Generate AI Report</button>
        <span id="jsa-selected-count" class="jsa-muted" style="margin-left:10px;">0 findings selected</span>
        <span id="jsa-last-status" class="jsa-muted" style="margin-left:10px;"></span>
        <div id="jsa-notify-hint" class="jsa-muted" style="display:none;margin-top:6px;">
            Notifications are not configured yet. Configure webhook or notification user in Project Settings - Security & Compliance.
        </div>
    </div>

    <div class="jsa-card jsa-help">
        <h4>How This Audit Works</h4>
        <ul>
            <li>Scans current job definitions for plaintext credentials and risky patterns.</li>
            <li>Does not execute or mutate jobs. Findings are advisory only.</li>
            <li>Redacts sensitive evidence before display and notification.</li>
            <li>Configure policies, recipients, and rule behavior under Project Settings - Security & Compliance tab.</li>
        </ul>
    </div>

    <div class="jsa-card">
        <div id="jsa-summary"></div>
    </div>

    <div class="jsa-card" id="jsa-ai-preview-card" style="display:none;">
        <h4>AI Report Preview</h4>
        <div class="row">
            <div class="col-sm-12 jsa-preview-section">
                <h5>Management Summary</h5>
                <div id="jsa-ai-management" class="jsa-muted"></div>
            </div>
        </div>
        <div class="row" style="margin-top:8px;">
            <div class="col-sm-6 jsa-preview-section">
                <h5>Details</h5>
                <ul id="jsa-ai-details"></ul>
            </div>
            <div class="col-sm-6 jsa-preview-section">
                <h5>Suggestions</h5>
                <ul id="jsa-ai-recommendations"></ul>
            </div>
        </div>
        <div class="jsa-preview-actions">
            <button id="jsa-download-md" class="btn btn-default" disabled>Download .md</button>
            <button id="jsa-download-txt" class="btn btn-default" disabled>Download .txt</button>
            <span class="jsa-muted" style="margin-left:8px;">Review before sending notification.</span>
        </div>
    </div>

    <div class="jsa-card">
        <table class="table table-condensed table-hover jsa-findings-table">
            <thead>
            <tr>
                <th><input type="checkbox" id="jsa-select-all"/></th>
                <th>Severity</th>
                <th>Job</th>
                <th>Rule</th>
                <th>Description</th>
                <th>Why It Matters</th>
                <th>Detected Snippet</th>
                <th>Remediation</th>
            </tr>
            </thead>
            <tbody id="jsa-findings"></tbody>
        </table>
    </div>
</div>

<div id="jsa-guidance-modal" class="modal fade" tabindex="-1" role="dialog" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title">Before Running Security & Compliance Scan</h4>
            </div>
            <div class="modal-body jsa-modal-body">
                <ul>
                    <li>Scope: current job definitions, options, and workflow config strings.</li>
                    <li>Not in scope: historical execution logs and external secrets managers content.</li>
                    <li>Handling: findings are redacted and intended for triage, not secret extraction.</li>
                    <li>Severity: Critical/High indicates immediate risk and potential policy violations.</li>
                    <li>Notifications are manual; external systems are the remediation source of truth.</li>
                </ul>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-cta" id="jsa-modal-run">Run Scan</button>
            </div>
        </div>
    </div>
</div>

<script>
(function () {
  'use strict';

  var project = '${enc(attr: params.project ?: request.project)}';
  var base = (function () {
    var rd = window._rundeck || {};
    var b = rd.rdBase || '/';
    if (!b.endsWith('/')) {
      b += '/';
    }
    return b;
  })();
  var findings = [];
  var currentExecutionId = null;
  var currentAiReport = null;
  var notifyConfigured = false;

  function endpoint(path) {
    return base + 'project/' + encodeURIComponent(project) + '/jobSecurity/' + path;
  }

  function llmEndpoint(path) {
    return base + 'project/' + encodeURIComponent(project) + '/jobSecurity/llm/' + path;
  }

  function esc(text) {
    return String(text == null ? '' : text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function setStatus(msg) {
    document.getElementById('jsa-last-status').textContent = msg || '';
  }

  function setNotifyConfigured(configured) {
    notifyConfigured = !!configured;
    var hint = document.getElementById('jsa-notify-hint');
    if (hint) {
      hint.style.display = notifyConfigured ? 'none' : '';
    }
  }

  function loadNotifyConfig() {
    return fetch(endpoint('settings'))
      .then(function (r) { return r.json(); })
      .then(function (resp) {
        if (!resp || !resp.success) {
          setNotifyConfigured(false);
          return false;
        }
        var settings = resp.settings || {};
        var hasWebhook = !!(settings.webhookUrl && String(settings.webhookUrl).trim());
        var hasRecipients = !!(settings.emailRecipients && String(settings.emailRecipients).trim());
        var hasSelectedUser = !!(settings.emailRecipientUser && String(settings.emailRecipientUser).trim());
        var configured = hasWebhook || hasRecipients || hasSelectedUser;
        setNotifyConfigured(configured);
        return configured;
      })
      .catch(function () {
        setNotifyConfigured(false);
        return false;
      });
  }

  function updateSelectedCount() {
    var count = document.querySelectorAll('.jsa-select:checked').length;
    document.getElementById('jsa-selected-count').textContent = count + ' findings selected';
  }

  function sevClass(sev) {
    if (sev === 'CRITICAL') return 'jsa-sev-critical';
    if (sev === 'HIGH') return 'jsa-sev-high';
    if (sev === 'MEDIUM') return 'jsa-sev-medium';
    return 'jsa-sev-low';
  }

  function renderSummary(summary) {
    if (!summary) {
      document.getElementById('jsa-summary').innerHTML = '<span class="jsa-muted">No scan results yet.</span>';
      return;
    }
    var counts = summary.riskCounts || {};
    document.getElementById('jsa-summary').innerHTML =
      '<div class="jsa-kpi critical">CRITICAL: ' + (counts.CRITICAL || 0) + '</div>' +
      '<div class="jsa-kpi high">HIGH: ' + (counts.HIGH || 0) + '</div>' +
      '<div class="jsa-kpi medium">MEDIUM: ' + (counts.MEDIUM || 0) + '</div>' +
      '<div class="jsa-kpi low">LOW: ' + (counts.LOW || 0) + '</div>' +
      '<div class="jsa-kpi">Risk score: ' + (summary.riskScore || 0) + '/100 (' + (summary.riskLevel || 'Low') + ')</div>' +
      '<div class="jsa-kpi">Risky jobs: ' + (summary.riskyJobs || 0) + '</div>' +
      '<div class="jsa-muted">Execution #' + (summary.executionId || '-') + ' at ' + (summary.scannedAt || '-') + '</div>';
  }

  function renderFindings(rows) {
    var tbody = document.getElementById('jsa-findings');
    tbody.innerHTML = '';
    rows.forEach(function (f) {
      var tr = document.createElement('tr');
      tr.innerHTML =
        '<td><input class="jsa-select" type="checkbox" value="' + f.id + '"></td>' +
        '<td class="jsa-sev ' + sevClass(f.severity) + '">' + f.severity + '</td>' +
        '<td>' + (f.jobRef || '') + '</td>' +
        '<td><code>' + (f.ruleName || f.ruleId || '') + '</code></td>' +
        '<td>' + (f.description || f.message || '') + '</td>' +
        '<td>' + (f.whyMatters || '') + '</td>' +
        '<td><code>' + (f.evidenceSnippetMasked || '') + '</code></td>' +
        '<td>' + (f.remediation || '') + '</td>';
      tbody.appendChild(tr);
    });
    updateSelectedCount();
  }

  function renderList(elId, values) {
    var ul = document.getElementById(elId);
    ul.innerHTML = '';
    (values || []).forEach(function (line) {
      var li = document.createElement('li');
      li.textContent = line;
      ul.appendChild(li);
    });
  }

  function renderAiPreview(ai) {
    var card = document.getElementById('jsa-ai-preview-card');
    if (!ai || !ai.report) {
      card.style.display = 'none';
      document.getElementById('jsa-download-md').disabled = true;
      document.getElementById('jsa-download-txt').disabled = true;
      return;
    }
    card.style.display = '';
    document.getElementById('jsa-ai-management').innerHTML = esc(ai.report.managementSummary || '');
    renderList('jsa-ai-details', ai.report.detailedFindings || []);
    renderList('jsa-ai-recommendations', ai.report.recommendations || []);
    document.getElementById('jsa-download-md').disabled = false;
    document.getElementById('jsa-download-txt').disabled = false;
  }

  function getUiRequestToken() {
    var ids = ['web_ui_token', 'ui_token', 'uiplugin_tokens'];
    for (var i = 0; i < ids.length; i++) {
      var el = document.getElementById(ids[i]);
      if (!el) continue;
      var raw = (el.textContent || el.innerText || '').trim();
      if (!raw) continue;
      try {
        var parsed = JSON.parse(raw);
        if (parsed && parsed.TOKEN) return parsed.TOKEN;
      } catch (_e) {}
    }
    return null;
  }

  function postJson(url, data) {
    var headers = { 'Content-Type': 'application/json' };
    var token = getUiRequestToken();
    if (token) headers['X-Rundeck-Auth-Token'] = token;
    return fetch(url, { method: 'POST', headers: headers, body: JSON.stringify(data || {}) }).then(function (r) {
      return r.json();
    });
  }

  function loadLatest() {
    fetch(endpoint('results/latest'))
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.success) {
          setStatus(data.error || 'No results available');
          return;
        }
        findings = data.findings || [];
        currentExecutionId = data.summary && data.summary.executionId;
        currentAiReport = null;
        renderSummary(data.summary);
        renderFindings(findings);
        renderAiPreview(null);
      })
      .catch(function () { setStatus('Failed to load latest results'); });
  }

  function runScan() {
    setStatus('Running scan...');
    postJson(endpoint('scan'), {}).then(function (data) {
      if (!data.success) {
        setStatus(data.error || 'Scan failed');
        return;
      }
      findings = data.findings || [];
      currentExecutionId = data.summary && data.summary.executionId;
      currentAiReport = null;
      renderSummary(data.summary);
      renderFindings(findings);
      renderAiPreview(null);
      setStatus('Scan completed');
    }).catch(function () {
      setStatus('Scan request failed');
    });
  }

  function notifySelected() {
    var selected = Array.prototype.slice.call(document.querySelectorAll('.jsa-select:checked')).map(function (el) {
      return el.value;
    });
    if (!currentExecutionId) {
      setStatus('Run a scan before notifying');
      return;
    }
    loadNotifyConfig().then(function (configured) {
      if (!configured) {
        setStatus('Notify unavailable: configure webhook or notification user first in Project Settings - Security & Compliance.');
        return;
      }
      setStatus('Sending notification...');
      var payload = { executionId: currentExecutionId, selectedFindingIds: selected };
      if (currentAiReport && currentAiReport.report) {
        payload.aiReport = currentAiReport.report;
      }
      postJson(endpoint('notify'), payload).then(function (data) {
        if (!data.success) {
          setStatus(data.error || 'Notify failed');
          return;
        }
        var n = data.notification || {};
        var parts = ['Notification processed (webhook=' + !!n.webhookSent + ', email=' + !!n.emailSent + ')'];
        if (n.emailRecipients && n.emailRecipients.length) {
          parts.push('recipients=' + n.emailRecipients.join(', '));
        }
        if (n.errors && n.errors.length) {
          parts.push('details=' + n.errors.join(' | '));
        }
        setStatus(parts.join(' ; '));
      }).catch(function () {
        setStatus('Notify request failed');
      });
    });
  }

  function generateAiReport() {
    var selected = Array.prototype.slice.call(document.querySelectorAll('.jsa-select:checked')).map(function (el) {
      return el.value;
    });
    if (!currentExecutionId) {
      setStatus('Run a scan before generating AI report');
      return;
    }
    if (!selected.length) {
      setStatus('Select at least one finding to generate AI report');
      return;
    }
    setStatus('Generating AI report...');
    postJson(llmEndpoint('generate'), {
      executionId: currentExecutionId,
      selectedFindingIds: selected
    }).then(function (data) {
      if (!data.success) {
        setStatus(data.error || 'AI report generation failed');
        return;
      }
      currentAiReport = data;
      renderAiPreview(data);
      setStatus('AI report generated');
    }).catch(function () {
      setStatus('AI report generation request failed');
    });
  }

  function downloadAi(format) {
    if (!currentExecutionId) {
      setStatus('No execution selected for download');
      return;
    }
    window.location = llmEndpoint('download/' + encodeURIComponent(currentExecutionId) + '?format=' + encodeURIComponent(format));
  }

  document.getElementById('jsa-run-scan').addEventListener('click', function () {
    if (window.localStorage && window.localStorage.getItem('jobSecurityAuditGuidanceSeen') === '1') {
      runScan();
      return;
    }
    if (window.jQuery) {
      window.jQuery('#jsa-guidance-modal').modal('show');
    } else {
      runScan();
    }
  });

  document.getElementById('jsa-modal-run').addEventListener('click', function () {
    if (window.localStorage) {
      window.localStorage.setItem('jobSecurityAuditGuidanceSeen', '1');
    }
    if (window.jQuery) {
      window.jQuery('#jsa-guidance-modal').modal('hide');
    }
    runScan();
  });

  document.getElementById('jsa-notify').addEventListener('click', notifySelected);
  document.getElementById('jsa-generate-ai').addEventListener('click', generateAiReport);
  document.getElementById('jsa-download-md').addEventListener('click', function () { downloadAi('md'); });
  document.getElementById('jsa-download-txt').addEventListener('click', function () { downloadAi('txt'); });

  document.getElementById('jsa-select-all').addEventListener('change', function (e) {
    var checked = e.target.checked;
    Array.prototype.slice.call(document.querySelectorAll('.jsa-select')).forEach(function (el) {
      el.checked = checked;
    });
    updateSelectedCount();
  });

  document.getElementById('jsa-findings').addEventListener('change', function (e) {
    if (e.target && e.target.classList.contains('jsa-select')) {
      updateSelectedCount();
    }
  });

  loadLatest();
  loadNotifyConfig();
})();
</script>
</body>
</html>
