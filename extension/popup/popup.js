/* global chrome */

const qs = (s) => document.querySelector(s);

function setStatusUI(url, result) {
  qs('#site').textContent = url || 'Current site';
  const riskEl = qs('#risk');
  const reasonEl = qs('#reason');
  if (!result) {
    riskEl.className = 'risk pill';
    riskEl.textContent = 'Unknown';
    reasonEl.textContent = 'No data';
    return;
  }
  riskEl.className = `risk pill ${result.riskLevel}`;
  const label = result.isMalicious ? `${result.riskLevel.toUpperCase()}` : 'LOW';
  riskEl.textContent = result.isMalicious ? `Risk: ${label}` : 'No obvious risk';
  reasonEl.textContent = result.reason || '';
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function scanActiveTab() {
  const tab = await getActiveTab();
  if (!tab?.id || !tab.url) return setStatusUI('', null);
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url: tab.url }, (resp) => {
      setStatusUI(tab.url, resp?.result);
      resolve();
    });
  });
}

async function refreshSettings() {
  chrome.runtime.sendMessage({ type: 'GET_ENABLED' }, (r1) => {
    qs('#toggle-enabled').checked = !!(r1 && r1.enabled !== false);
  });
  chrome.runtime.sendMessage({ type: 'GET_SENSITIVITY' }, (r2) => {
    const v = (r2 && r2.sensitivity) || 'medium';
    qs('#sensitivity').value = v;
  });
}

function renderHistory(results) {
  const ul = qs('#history');
  ul.innerHTML = '';
  const last = (results || []).slice(-15).reverse();
  let total = results?.length || 0;
  let warn = 0;
  let high = 0;
  for (const item of results || []) {
    if (item?.result?.isMalicious) warn++;
    if ((item?.result?.riskLevel || '') === 'high') high++;
  }
  qs('#statTotal').textContent = String(total);
  qs('#statWarn').textContent = String(warn);
  qs('#statHigh').textContent = String(high);
  for (const item of last) {
    const li = document.createElement('li');
    const time = document.createElement('div');
    time.className = 'time';
    time.textContent = new Date(item.ts).toLocaleString();
    const url = document.createElement('div');
    url.className = 'url';
    url.textContent = item.url;
    const meta = document.createElement('div');
    meta.className = 'meta';
    const tag = document.createElement('span');
    tag.className = `pill risk ${item.result.riskLevel}`;
    tag.textContent = item.result.isMalicious ? item.result.riskLevel.toUpperCase() : 'OK';
    const src = document.createElement('span');
    src.textContent = (item.result.source || 'n/a');
    meta.appendChild(tag);
    meta.appendChild(src);
    li.appendChild(time);
    li.appendChild(url);
    li.appendChild(meta);
    ul.appendChild(li);
  }
}

function loadHistory() {
  chrome.runtime.sendMessage({ type: 'GET_RESULTS' }, (resp) => {
    renderHistory(resp?.results || []);
  });
}

function exportBlocked() {
  chrome.runtime.sendMessage({ type: 'GET_RESULTS' }, (resp) => {
    const results = resp?.results || [];
    const blocked = results.filter(r => r?.result?.isMalicious).map(r => ({ url: r.url, risk: r.result.riskLevel, reason: r.result.reason, ts: r.ts }));
    const blob = new Blob([JSON.stringify(blocked, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'safeguard_blocked_sites.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });
}

qs('#rescan').addEventListener('click', scanActiveTab);
qs('#export').addEventListener('click', exportBlocked);
qs('#toggle-enabled').addEventListener('change', (e) => {
  chrome.runtime.sendMessage({ type: 'SET_ENABLED', enabled: e.target.checked });
});
qs('#sensitivity').addEventListener('change', (e) => {
  chrome.runtime.sendMessage({ type: 'SET_SENSITIVITY', sensitivity: e.target.value });
});

async function init() {
  await refreshSettings();
  await scanActiveTab();
  loadHistory();
}

init();


