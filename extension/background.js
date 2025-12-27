/* global chrome */

const KEYWORDS = ['phishing','free','urgent','click','verify','security','account','update','login','win','prize'];
const RATE_LIMIT_WINDOW_MS = 30000;
const STORAGE_RESULTS_KEY = 'sg_results_cache';
const STORAGE_ENDPOINT_KEY = 'sg_api_endpoint';
const STORAGE_AUTH_KEY = 'sg_api_auth'; // { type: 'bearer'|'basic'|'custom', value: string, header?: string }
const STORAGE_CACHE_KEY = 'sg_api_cache'; // { [url]: { result, ts } }
const DEFAULT_API_ENDPOINT = 'https://YOUR-LOVABLE-URL.example/check-url';
const STORAGE_ENABLED_KEY = 'sg_enabled';
const STORAGE_SENS_KEY = 'sg_sensitivity'; // 'low' | 'medium' | 'high'

const lastCallByOrigin = new Map();

function isIpAddress(host) {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return true;
  if (/^[\[]?[0-9a-fA-F:]+[\]]?$/.test(host) && host.includes(':')) return true;
  return false;
}

function subdomainCount(host) {
  const parts = (host || '').split('.').filter(Boolean);
  return parts.length > 2 ? parts.length - 2 : 0;
}

function hasKeywords(text) {
  const t = (text || '').toLowerCase();
  return KEYWORDS.some(k => t.includes(k));
}

function heuristicAnalyze(urlString) {
  let u;
  try { u = new URL(urlString); } catch { return { isMalicious: true, riskLevel: 'high', reason: 'Invalid URL' }; }
  const host = u.hostname;
  const rest = u.pathname + u.search + u.hash;
  const indicators = [];
  if (isIpAddress(host)) indicators.push('IP address host');
  const sc = subdomainCount(host);
  if (sc >= 3) indicators.push(`Excessive subdomains (${sc})`);
  if (hasKeywords(host) || hasKeywords(rest)) indicators.push('Suspicious keywords');
  if (urlString.length > 200) indicators.push('Unusually long URL');

  let riskLevel = 'low';
  if (indicators.length >= 3) riskLevel = 'high';
  else if (indicators.length === 2) riskLevel = 'medium';

  return { isMalicious: indicators.length > 0, riskLevel, reason: indicators.join('; ') || 'No obvious risk' };
}

async function getApiEndpoint() {
  const data = await chrome.storage.local.get(STORAGE_ENDPOINT_KEY);
  return data[STORAGE_ENDPOINT_KEY] || DEFAULT_API_ENDPOINT;
}

async function setApiEndpoint(endpoint) {
  await chrome.storage.local.set({ [STORAGE_ENDPOINT_KEY]: endpoint || '' });
}

async function getAuthHeaders() {
  const data = await chrome.storage.local.get(STORAGE_AUTH_KEY);
  const cfg = data[STORAGE_AUTH_KEY];
  if (!cfg || !cfg.type) return {};
  if (cfg.type === 'bearer' && cfg.value) return { Authorization: `Bearer ${cfg.value}` };
  if (cfg.type === 'basic' && cfg.value) return { Authorization: `Basic ${cfg.value}` };
  if (cfg.type === 'custom' && cfg.header && cfg.value) return { [cfg.header]: cfg.value };
  return {};
}

async function tryFetchWithRetry(url, options, tries = 3) {
  let attempt = 0;
  let lastErr;
  while (attempt < tries) {
    try {
      const res = await fetch(url, options);
      if (!res.ok) throw new Error(`API ${res.status}`);
      return await res.json();
    } catch (e) {
      lastErr = e;
      attempt++;
      const backoff = Math.min(2000, 500 * Math.pow(2, attempt - 1)) + Math.floor(Math.random() * 150);
      await new Promise(r => setTimeout(r, backoff));
    }
  }
  throw lastErr || new Error('API failed');
}

async function getCached(urlString) {
  const data = await chrome.storage.local.get(STORAGE_CACHE_KEY);
  const cache = data[STORAGE_CACHE_KEY] || {};
  const entry = cache[urlString];
  if (!entry) return null;
  const oneHour = 60 * 60 * 1000;
  if (Date.now() - entry.ts < oneHour) return entry.result;
  return null;
}

async function putCached(urlString, result) {
  const data = await chrome.storage.local.get(STORAGE_CACHE_KEY);
  const cache = data[STORAGE_CACHE_KEY] || {};
  cache[urlString] = { result, ts: Date.now() };
  // trim
  const keys = Object.keys(cache);
  if (keys.length > 500) {
    keys.sort((a,b) => (cache[a].ts - cache[b].ts));
    for (let i = 0; i < keys.length - 500; i++) delete cache[keys[i]];
  }
  await chrome.storage.local.set({ [STORAGE_CACHE_KEY]: cache });
}

async function callExternalApi(urlString, signal) {
  const cached = await getCached(urlString);
  if (cached) return cached;
  const endpoint = await getApiEndpoint();
  if (!endpoint) throw new Error('No endpoint configured');
  const u = new URL(endpoint);
  u.searchParams.set('url', urlString);
  const headers = { 'Content-Type': 'application/json', ...(await getAuthHeaders()) };
  const body = JSON.stringify({ url: urlString });
  const data = await tryFetchWithRetry(u.toString(), { method: 'POST', headers, body, signal }, 3);
  const isMalicious = Boolean(data.ismalicious ?? data.isMalicious);
  const riskLevel = String(data.riskLevel || 'low');
  const reason = String(data.reason || '');
  const result = { isMalicious, riskLevel, reason };
  await putCached(urlString, result);
  return result;
}

async function storeResult(urlString, result) {
  const existing = await chrome.storage.local.get(STORAGE_RESULTS_KEY);
  const cache = existing[STORAGE_RESULTS_KEY] || [];
  cache.push({ url: urlString, result, ts: Date.now() });
  while (cache.length > 200) cache.shift();
  await chrome.storage.local.set({ [STORAGE_RESULTS_KEY]: cache });
}

async function analyzeWithApiAndFallback(urlString) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const apiResult = await callExternalApi(urlString, controller.signal);
    clearTimeout(timer);
    await storeResult(urlString, { source: 'api', ...apiResult });
    return { source: 'api', ...apiResult };
  } catch {
    clearTimeout(timer);
    const fb = heuristicAnalyze(urlString);
    await storeResult(urlString, { source: 'heuristic', ...fb });
    return { source: 'heuristic', ...fb };
  }
}

async function getEnabled() {
  const data = await chrome.storage.local.get(STORAGE_ENABLED_KEY);
  return data[STORAGE_ENABLED_KEY] !== false; // default true
}

async function setEnabled(val) {
  await chrome.storage.local.set({ [STORAGE_ENABLED_KEY]: Boolean(val) });
}

async function getSensitivity() {
  const data = await chrome.storage.local.get(STORAGE_SENS_KEY);
  const v = data[STORAGE_SENS_KEY];
  return v === 'low' || v === 'medium' || v === 'high' ? v : 'medium';
}

async function setSensitivity(val) {
  const v = (val || '').toLowerCase();
  const norm = v === 'low' || v === 'medium' || v === 'high' ? v : 'medium';
  await chrome.storage.local.set({ [STORAGE_SENS_KEY]: norm });
}

function applySensitivity(result, sensitivity) {
  // For API or heuristic results: gate isMalicious by user sensitivity
  const level = (result.riskLevel || 'low').toLowerCase();
  let malicious = Boolean(result.isMalicious);
  if (sensitivity === 'low') malicious = level === 'high';
  else if (sensitivity === 'medium') malicious = level === 'medium' || level === 'high';
  // 'high' keeps any detection
  return { ...result, isMalicious: malicious };
}

async function maybeRateLimitedAnalyze(tabId, urlString) {
  let u;
  try { u = new URL(urlString); } catch { return heuristicAnalyze(urlString); }
  const enabled = await getEnabled();
  const sensitivity = await getSensitivity();
  if (!enabled) {
    const r = { isMalicious: false, riskLevel: 'low', reason: 'Protection disabled', source: 'disabled' };
    await setBadge(tabId, r);
    return r;
  }
  const origin = u.origin;
  const now = Date.now();
  const last = lastCallByOrigin.get(origin) || 0;
  if (now - last < RATE_LIMIT_WINDOW_MS) {
    let r = heuristicAnalyze(urlString);
    r = applySensitivity(r, sensitivity);
    await setBadge(tabId, r);
    return r;
  }
  lastCallByOrigin.set(origin, now);
  let r = await analyzeWithApiAndFallback(urlString);
  r = applySensitivity(r, sensitivity);
  await setBadge(tabId, r);
  if (r.isMalicious && r.riskLevel === 'high') {
    await notify(tabId, 'Potentially Malicious Site', `${r.riskLevel.toUpperCase()}: ${r.reason}`);
  }
  return r;
}

async function setBadge(tabId, result) {
  try {
    await chrome.action.setBadgeText({ tabId, text: result.isMalicious ? '!' : '' });
    if (result.isMalicious) await chrome.action.setBadgeBackgroundColor({ tabId, color: '#dc2626' });
  } catch {}
}

async function notify(tabId, title, message) {
  try {
    await chrome.notifications.create(`warn-${Date.now()}`, { type: 'basic', iconUrl: 'icons/icon128.png', title, message, priority: 2 });
  } catch {}
  try {
    await chrome.action.setBadgeText({ tabId, text: '!' });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: '#dc2626' });
  } catch {}
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg?.type === 'ANALYZE_URL') {
      const url = msg.url || '';
      const tabId = sender.tab?.id;
      const result = await maybeRateLimitedAnalyze(tabId, url);
      sendResponse({ ok: true, result });
      return;
    }
    if (msg?.type === 'GET_ENABLED') {
      sendResponse({ ok: true, enabled: await getEnabled() });
      return;
    }
    if (msg?.type === 'SET_ENABLED') {
      await setEnabled(Boolean(msg.enabled));
      sendResponse({ ok: true });
      return;
    }
    if (msg?.type === 'GET_SENSITIVITY') {
      sendResponse({ ok: true, sensitivity: await getSensitivity() });
      return;
    }
    if (msg?.type === 'SET_SENSITIVITY') {
      await setSensitivity(msg.sensitivity);
      sendResponse({ ok: true });
      return;
    }
    if (msg?.type === 'GET_RESULTS') {
      const data = await chrome.storage.local.get(STORAGE_RESULTS_KEY);
      sendResponse({ ok: true, results: data[STORAGE_RESULTS_KEY] || [] });
      return;
    }
    if (msg?.type === 'SET_API_ENDPOINT') {
      await setApiEndpoint(msg.endpoint || '');
      sendResponse({ ok: true });
      return;
    }
    if (msg?.type === 'GET_API_ENDPOINT') {
      const ep = await getApiEndpoint();
      sendResponse({ ok: true, endpoint: ep });
      return;
    }
    if (msg?.type === 'SET_API_AUTH') {
      const cfg = msg.auth && typeof msg.auth === 'object' ? msg.auth : null;
      await chrome.storage.local.set({ [STORAGE_AUTH_KEY]: cfg });
      sendResponse({ ok: true });
      return;
    }
    if (msg?.type === 'GET_API_AUTH') {
      const data = await chrome.storage.local.get(STORAGE_AUTH_KEY);
      sendResponse({ ok: true, auth: data[STORAGE_AUTH_KEY] || null });
      return;
    }
  })();
  return true;
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if ((changeInfo.status === 'complete' || changeInfo.url) && tab?.url) {
    const url = tab.url;
    if (!/^https?:\/\//i.test(url)) return;
    maybeRateLimitedAnalyze(tabId, url);
  }
});


