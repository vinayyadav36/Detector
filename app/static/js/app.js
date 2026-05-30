const storageKey = 'detector-recent-results';
let deferredInstallPrompt = null;

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('\"', '&quot;')
    .replaceAll(\"'\", '&#39;');
}

function safeLabel(value) {
  return ['safe', 'suspicious', 'phishing'].includes(value) ? value : 'safe';
}

function getCsrfToken() {
  return window._csrfToken || '';
}

function readRecentResults() {
  try {
    return JSON.parse(localStorage.getItem(storageKey) || '[]');
  } catch {
    return [];
  }
}

function writeRecentResults(items) {
  localStorage.setItem(storageKey, JSON.stringify(items.slice(0, 10)));
}

function loadRecentSidebar() {
  const container = document.getElementById('recent-results');
  if (!container) return;
  const items = readRecentResults();
  container.innerHTML = items.map((item) => {
    const label = safeLabel(item.label);
    return `<a class="recent-item" href="/result/${escapeHtml(item.analysis_id)}" data-route><span class="pill pill-${label}">${escapeHtml(label)}</span><strong>${escapeHtml(item.domain)}</strong><small>${escapeHtml(item.url)}</small></a>`;
  }).join('') || '<p class="muted">No recent analysis.</p>';
}

function renderResult(target, result) {
  const label = safeLabel(result.label);
  const reasons = (result.reasons || [])
    .map((reason) => `<li>${escapeHtml(reason)}</li>`)
    .join('');
  target.innerHTML = `
    <div class="pill pill-${label}">${escapeHtml(result.risk_score)}/100 · ${escapeHtml(label)}</div>
    <p><strong>${escapeHtml(result.domain)}</strong></p>
    <p class="muted">${escapeHtml(result.url)}</p>
    <p>Reachability: ${result.reachability.replaceAll('_', ' ')}</p>
    <ul class="bullet-list">${reasons}</ul>
    <a class="ghost-button" href="/result/${escapeHtml(result.analysis_id)}" data-route>Open details</a>
  `;
}

function prependRecentResult(result) {
  const items = [result, ...readRecentResults().filter((item) => item.url !== result.url)];
  writeRecentResults(items);
  loadRecentSidebar();
}

async function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  try {
    const registration = await navigator.serviceWorker.register('/sw.js');
    // Notification setup can go here
  } catch (error) {
    console.error('Failed to register service worker', error);
  }
}

function setupThemeToggle() {
  const toggle = document.getElementById('theme-toggle');
  const saved = localStorage.getItem('detector-theme') || 'dark';
  document.documentElement.dataset.theme = saved;
  if (!toggle) return;
  // Clear old listeners by cloning if necessary, but it's only called once per app load now
  toggle.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('detector-theme', next);
  });
}

function flashMessage(msg, type='error') {
  const stack = document.getElementById('flash-stack');
  stack.innerHTML = `<div class="flash flash-${type}">${escapeHtml(msg)}</div>`;
  stack.style.display = 'block';
  setTimeout(() => { stack.style.display = 'none'; }, 5000);
}

// --- Routing ---
const routes = {
  '/': viewIndex,
  '/result/:id': viewResult,
  '/disclaimer': viewSimple('Disclaimer', '<p>This tool is for educational purposes...</p>'),
  '/privacy': viewSimple('Privacy Policy', '<p>We store hashed URLs...</p>'),
  '/terms': viewSimple('Terms of Service', '<p>Do not use this tool for malicious purposes...</p>'),
  '/offline': viewOffline,
  '/admin': viewAdmin
};

function router() {
  const path = window.location.pathname;
  console.log("Routing to: ", path);
  const appView = document.getElementById('app-view');
  appView.innerHTML = ''; // Clear current

  let matched = false;
  for (const [route, handler] of Object.entries(routes)) {
    if (route.includes(':')) {
      const base = route.split(':')[0];
      if (path.startsWith(base)) {
        const id = path.slice(base.length);
        if (id) {
          handler(id);
          matched = true;
          break;
        }
      }
    } else if (path === route) {
      handler();
      matched = true;
      break;
    }
  }

  if (!matched) {
    console.log("Route not matched!");
    appView.innerHTML = '<div class="hero"><h1>404 Not Found</h1><p>The page you requested could not be found.</p></div>';
  }
}

function viewIndex() {
  loadTemplate('view-index');
  loadRecentSidebar();

  const form = document.getElementById('analyze-form');
  const resultContent = document.getElementById('result-content');
  const errorBox = document.getElementById('analysis-error');

  if (form) {
    console.log('Form bound!');
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      errorBox.classList.add('hidden');
      const formData = new FormData(form);
      const url = String(formData.get('url') || '').trim();

      try {
        // Fetch CSRF token if needed, or rely on API not needing it if we change auth
        const response = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ url }),
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.error?.message || 'Unable to analyze URL.');
        }
        renderResult(resultContent, payload);
        prependRecentResult(payload);

        // Re-attach routing to the new result link
        const detailLink = resultContent.querySelector('a');
        if (detailLink) {
          detailLink.addEventListener('click', e => {
            e.preventDefault();
            window.history.pushState({}, '', detailLink.href);
            router();
          });
        }
      } catch (error) {
        errorBox.textContent = error.message;
        errorBox.classList.remove('hidden');
      }
    });
  }
}

async function viewResult(id) {
  loadTemplate('view-result');
  const content = document.getElementById('result-detail-content');
  const form = document.getElementById('feedback-form');

  try {
    const res = await fetch(`/api/result/${id}`);
    if (!res.ok) throw new Error('Result not found');
    const result = await res.json();

    const label = safeLabel(result.label);
    const reasons = (result.reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');
    const redirectChain = (result.redirect_chain || []).map(url => `<li><code>${escapeHtml(url)}</code></li>`).join('');

    content.innerHTML = `
      <div class="card">
        <h2 class="h2"><span class="pill pill-${label}">${escapeHtml(label)}</span> ${escapeHtml(result.domain)}</h2>
        <p class="muted" style="margin-bottom:1.5rem;word-break:break-all;">${escapeHtml(result.url)}</p>
        <div class="split-layout">
          <div>
            <h3>Risk score</h3>
            <div class="big-score ${label === 'safe' ? 'success' : (label === 'suspicious' ? 'warning' : 'danger')}">${result.risk_score}<span>/100</span></div>
          </div>
          <div>
            <h3>Details</h3>
            <p><strong>Reachability:</strong> ${result.reachability.replaceAll('_', ' ')}</p>
            <p><strong>Status code:</strong> ${result.status_code || 'N/A'}</p>
          </div>
        </div>
        <h3 style="margin-top:2rem;">Reasons</h3>
        <ul class="bullet-list">${reasons || '<li>None</li>'}</ul>
        <h3 style="margin-top:2rem;">Redirect chain</h3>
        <ol class="bullet-list" style="list-style-type:decimal;">${redirectChain}</ol>
      </div>
    `;

    if (form) {
      form.action = `/feedback/${id}`;
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const feedbackRes = await fetch(form.action, { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } });
        if (feedbackRes.ok) form.innerHTML = '<p class="helper">Feedback recorded for future tuning.</p>';
      });
    }
  } catch (err) {
    content.innerHTML = '<p class="muted">Error loading result.</p>';
  }
}

function viewSimple(title, bodyHtml) {
  return () => {
    loadTemplate('view-simple');
    document.getElementById('simple-title').textContent = title;
    document.getElementById('simple-content').innerHTML = bodyHtml;
  };
}

function viewOffline() {
  loadTemplate('view-simple');
  document.getElementById('simple-title').textContent = 'Offline';

  const items = readRecentResults();
  const list = items.map((item) => {
    const label = safeLabel(item.label);
    return `<a class="recent-item" href="/result/${escapeHtml(item.analysis_id)}"><span class="pill pill-${label}">${escapeHtml(label)}</span><strong>${escapeHtml(item.domain)}</strong><small>${escapeHtml(item.url)}</small></a>`;
  }).join('') || '<p class="muted">No cached results yet.</p>';

  document.getElementById('simple-content').innerHTML = `
    <p>You are currently offline. Here are your recent cached results:</p>
    <div class="recent-list" style="margin-top:1rem;">${list}</div>
    <button id="retry-online" class="button" style="margin-top:2rem;">Retry connection</button>
  `;

  document.getElementById('retry-online')?.addEventListener('click', () => {
    window.location.reload();
  });
}


async function viewAdmin() {
  document.getElementById('app-view').innerHTML = ''; loadTemplate('view-admin-dashboard'); // Try loading dashboard first
  const contentNode = document.getElementById('admin-health-content');
  if (!contentNode) {
    // If we can't find it, we might have loaded the wrong template somehow, but let's just proceed
  }

  try {
    const res = await fetch('/api/admin/dashboard');
    if (res.status === 401) {
      // Not logged in, show login form
      showAdminLogin();
      return;
    }
    if (!res.ok) throw new Error('Failed to load dashboard');

    const data = await res.json();
    renderAdminDashboard(data);
  } catch (err) {
    flashMessage(err.message);
    showAdminLogin();
  }
}

function showAdminLogin() {
  const appView = document.getElementById('app-view');
  appView.innerHTML = '';
  loadTemplate('view-admin-login');

  const form = document.getElementById('admin-login-form');
  const errorBox = document.getElementById('login-error');

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      errorBox.classList.add('hidden');
      const formData = new FormData(form);
      const username = formData.get('username');
      const password = formData.get('password');

      try {
        const res = await fetch('/api/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window._csrfToken },
          body: JSON.stringify({ username, password })
        });

        const data = await res.json();
        if (res.ok && (data.status === 'success' || data.status === 'already_authenticated')) {
          viewAdmin();
        } else {
          throw new Error(data.error || 'Login failed');
        }
      } catch (err) {
        errorBox.textContent = err.message;
        errorBox.classList.remove('hidden');
      }
    });
  }
}

function renderAdminDashboard(data) {
  // Bind Logout
  document.getElementById('admin-logout-btn')?.addEventListener('click', async () => {
    await fetch('/api/admin/logout', { method: 'POST', headers: { 'X-CSRFToken': window._csrfToken } });
    viewIndex();
    window.history.pushState({}, '', '/');
  });

  // Health
  const healthDiv = document.getElementById('admin-health-content');
  if (healthDiv) {
    fetch('/api/admin/health')
      .then(res => res.json())
      .then(health => {
        healthDiv.innerHTML = `
          <p><strong>Status:</strong> ${escapeHtml(health.status)}</p>
          <p><strong>Database:</strong> ${health.database ? 'OK' : 'Error'}</p>
          <p><strong>Redis:</strong> ${health.redis ? 'OK' : 'Error'}</p>
          <p><strong>Model Loaded:</strong> ${health.model_loaded ? 'Yes' : 'No'}</p>
        `;
      });
  }

  // Stats
  const statsDiv = document.getElementById('admin-stats-content');
  if (statsDiv) {
    statsDiv.innerHTML = `
      <p><strong>Total Analyses:</strong> ${data.total}</p>
      <p><strong>Safe:</strong> ${data.counts?.safe || 0}</p>
      <p><strong>Suspicious:</strong> ${data.counts?.suspicious || 0}</p>
      <p><strong>Phishing:</strong> ${data.counts?.phishing || 0} (${data.phishing_pct}%)</p>
    `;
  }

  // Batch
  const batchForm = document.getElementById('admin-batch-form');
  const batchError = document.getElementById('batch-error');
  if (batchForm) {
    batchForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      batchError.classList.add('hidden');
      const formData = new FormData(batchForm);
      try {
        const res = await fetch('/api/admin/batch', {
          method: 'POST',
          headers: { 'X-CSRFToken': window._csrfToken },
          body: formData
        });
        if (!res.ok) throw new Error('Batch upload failed');

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'batch-analysis-results.csv';
        document.body.appendChild(a);
        a.click();
        a.remove();
        viewAdmin(); // reload dashboard
      } catch (err) {
        batchError.textContent = err.message;
        batchError.classList.remove('hidden');
      }
    });
  }

  // Blacklist
  const blTable = document.getElementById('admin-blacklist-content');
  if (blTable) {
    blTable.innerHTML = data.blacklist.length ? data.blacklist.map(b => `
      <tr>
        <td>${escapeHtml(b.domain)}</td>
        <td>${escapeHtml(b.reason || '-')}</td>
        <td>
          <button class="button button-danger" onclick="deleteBlacklist(${b.id})">Remove</button>
        </td>
      </tr>
    `).join('') : '<tr><td colspan="3">No blacklisted domains.</td></tr>';
  }

  const blForm = document.getElementById('admin-blacklist-form');
  if (blForm) {
    blForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(blForm);
      try {
        await fetch('/api/admin/blacklist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window._csrfToken },
          body: JSON.stringify({ domain: fd.get('domain'), reason: fd.get('reason') })
        });
        viewAdmin(); // reload
      } catch (err) {
        flashMessage(err.message);
      }
    });
  }

  // Reports
  const repTable = document.getElementById('admin-reports-content');
  if (repTable) {
    repTable.innerHTML = data.reports.length ? data.reports.map(r => `
      <tr>
        <td>${escapeHtml(r.created_at)}</td>
        <td>${escapeHtml(r.domain)}</td>
        <td>${escapeHtml(r.risk_score)}</td>
        <td><span class="pill pill-${safeLabel(r.label)}">${escapeHtml(r.label)}</span></td>
      </tr>
    `).join('') : '<tr><td colspan="4">No recent reports.</td></tr>';
  }
}

window.deleteBlacklist = async function(id) {
  if (confirm('Are you sure you want to remove this domain from the blacklist?')) {
    await fetch(`/api/admin/blacklist/${id}/delete`, {
      method: 'POST',
      headers: { 'X-CSRFToken': window._csrfToken }
    });
    viewAdmin();
  }
};



async function fetchCsrfToken() {
  try {
    const res = await fetch('/api/csrf-token');
    const data = await res.json();
    window._csrfToken = data.csrf_token;
  } catch (e) {
    console.error('Failed to fetch CSRF token', e);
  }
}

// Initialization

async function init() {
  console.log("App init running");
  await fetchCsrfToken();
  setupThemeToggle();
  registerServiceWorker();

  // Global delegated click listener for internal navigation
  document.body.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (link && link.hostname === window.location.hostname && link.getAttribute('href')?.startsWith('/') && !link.hasAttribute('data-external')) {
      e.preventDefault();
      const href = link.getAttribute('href');
      if (window.location.pathname !== href) {
        window.history.pushState({}, '', href);
        router();
      }
    }
  });

  window.addEventListener('popstate', router);
  router(); // Initial route
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
