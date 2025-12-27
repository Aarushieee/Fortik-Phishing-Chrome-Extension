(() => {
  // Configurable suspicious pattern settings
  const SUSPICIOUS_KEYWORDS = [
    "phishing","malware","suspicious","danger","free-gift",
    "hacked","login","verify","urgent","bank","account","click","update"
  ];

  function isIpAddress(host) {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) ||
      (/^[\[]?[0-9a-fA-F:]+[\]]?$/.test(host) && host.includes(':'));
  }

  function isSuspicious(href) {
    if (!href) return false;
    try {
      const u = new URL(href, location.href);
      if (isIpAddress(u.hostname)) return true;
      if (u.hostname.split('.').length - 2 >= 3) return true; // Ex: a.b.c.d.com
      if (href.length > 200) return true;
      const lower = href.toLowerCase();
      if (SUSPICIOUS_KEYWORDS.some(kw => lower.includes(kw))) return true;
    } catch {
      return false;
    }
    return false;
  }

  // Floating warning label logic
  let warningEl = null;
  let warningFollow = false;
  function showWarning(e) {
    if (!warningEl) {
      warningEl = document.createElement('div');
      warningEl.textContent = "This is a malicious website";
      warningEl.style.position = 'fixed';
      warningEl.style.zIndex = 2147483647;
      warningEl.style.pointerEvents = 'none';
      warningEl.style.background = 'linear-gradient(90deg, #b91c1c, #ea580c)';
      warningEl.style.color = '#fff';
      warningEl.style.fontWeight = 'bold';
      warningEl.style.fontSize = '13px';
      warningEl.style.fontFamily = 'system-ui,-apple-system,Segoe UI,Roboto,Arial';
      warningEl.style.padding = '7px 13px';
      warningEl.style.borderRadius = '7px';
      warningEl.style.boxShadow = '0 2px 6px rgba(0,0,0,0.18)';
      warningEl.style.maxWidth = '330px';
      warningEl.style.whiteSpace = 'normal';
      document.body.appendChild(warningEl);
    }
    warningEl.style.display = 'block';
    moveWarning(e);
    warningFollow = true;
  }
  function hideWarning() {
    if (warningEl) warningEl.style.display = 'none';
    warningFollow = false;
  }
  function moveWarning(e) {
    if (!warningEl) return;
    // Place near cursor, but not off screen
    let x = e.clientX + 16;
    let y = e.clientY + 14;
    // Guard against page edge
    if (x + 220 > window.innerWidth) x = window.innerWidth - 220;
    if (y + 40 > window.innerHeight) y = window.innerHeight - 40;
    warningEl.style.left = x + 'px';
    warningEl.style.top = y + 'px';
  }

  // Modal confirmation logic
  function askToProceed(linkHref) {
    // Overlay root
    let overlay = document.getElementById('__sg_modal_overlay');
    if (overlay) overlay.remove();
    overlay = document.createElement('div');
    overlay.id = '__sg_modal_overlay';
    overlay.style.position = 'fixed';
    overlay.style.inset = '0';
    overlay.style.zIndex = 2147483647;
    overlay.style.background = 'rgba(0,0,0,.35)';
    overlay.style.display = 'flex';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    // Modal
    const modal = document.createElement('div');
    modal.style.background = 'linear-gradient(180deg,#1e293b,#0f172a)';
    modal.style.borderRadius = '12px';
    modal.style.boxShadow = '0 10px 32px rgba(0,0,0,0.25)';
    modal.style.color = '#fff';
    modal.style.fontFamily = 'system-ui,-apple-system,Segoe UI,Roboto,Arial';
    modal.style.padding = '26px 30px 18px 30px';
    modal.style.maxWidth = '90vw';
    modal.style.minWidth = '280px';
    modal.style.textAlign = 'center';
    // Banner
    const banner = document.createElement('div');
    banner.textContent = 'Malicious Website Detected';
    banner.style.fontSize = '17px';
    banner.style.fontWeight = '700';
    banner.style.background = 'linear-gradient(90deg,#7f1d1d,#ef4444 80%)';
    banner.style.color = 'white';
    banner.style.padding = '8px 10px';
    banner.style.borderRadius = '8px';
    banner.style.marginBottom = '15px';
    modal.appendChild(banner);
    // Question
    const question = document.createElement('div');
    question.textContent = 'Do you still want to visit this website?';
    question.style.fontSize = '15px';
    question.style.margin = '10px 0 8px 0';
    modal.appendChild(question);
    // Href display
    const urlbox = document.createElement('div');
    urlbox.textContent = linkHref;
    urlbox.style.fontSize = '12px';
    urlbox.style.color = '#ffeeee';
    urlbox.style.wordBreak = 'break-all';
    urlbox.style.margin = '4px 0 10px 0';
    modal.appendChild(urlbox);
    // Yes/No buttons
    const btnRow = document.createElement('div');
    btnRow.style.display = 'flex';
    btnRow.style.justifyContent = 'center';
    btnRow.style.gap = '14px';
    const yesBtn = document.createElement('button');
    yesBtn.textContent = 'Yes';
    yesBtn.style.background = '#ef4444';
    yesBtn.style.color = 'white';
    yesBtn.style.border = 'none';
    yesBtn.style.fontWeight = 'bold';
    yesBtn.style.borderRadius = '8px';
    yesBtn.style.padding = '10px 18px';
    yesBtn.style.cursor = 'pointer';
    const noBtn = document.createElement('button');
    noBtn.textContent = 'No';
    noBtn.style.background = '#334155';
    noBtn.style.color = 'white';
    noBtn.style.border = 'none';
    noBtn.style.fontWeight = 'bold';
    noBtn.style.borderRadius = '8px';
    noBtn.style.padding = '10px 18px';
    noBtn.style.cursor = 'pointer';
    btnRow.appendChild(yesBtn);
    btnRow.appendChild(noBtn);
    modal.appendChild(btnRow);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    // Promise resolved by user
    return new Promise(resolve => {
      yesBtn.onclick = () => { overlay.remove(); resolve(true); };
      noBtn.onclick = () => { overlay.remove(); resolve(false); };
    });
  }

  // Hover and click handlers
  function processLink(link) {
    if (link.__sgListenersAdded) return;
    link.__sgListenersAdded = true;
    link.addEventListener('mouseenter', onMouseEnter);
    link.addEventListener('mousemove', onMouseMove);
    link.addEventListener('mouseleave', onMouseLeave);
    link.addEventListener('click', onMaliciousClick, true);
  }
  // State to signal which links
  const maliciousLinks = new WeakSet();

  // Hover events
  function onMouseEnter(e) {
    const a = e.currentTarget;
    if (!maliciousLinks.has(a)) return;
    showWarning(e);
  }
  function onMouseMove(e) {
    const a = e.currentTarget;
    if (!maliciousLinks.has(a)) return;
    if (warningFollow) moveWarning(e);
  }
  function onMouseLeave(e) {
    hideWarning();
  }

  // Click event
  async function onMaliciousClick(e) {
    const a = e.currentTarget; // anchor element
    if (!maliciousLinks.has(a)) return;
    // Only intercept normal left click (not right-click or modifiers)
    if (e.button !== 0) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    const proceed = await askToProceed(a.href);
    if (proceed) {
      hideWarning();
      // Open as default (support _blank etc)
      if (a.target === '_blank' || e.ctrlKey || e.metaKey) {
        window.open(a.href, '_blank', 'noopener');
      } else {
        window.location.assign(a.href);
      }
    }
    // else, canceled, stay on page
  }

  // Main function: scan & instrument links
  function scanAndHook(root = document) {
    let count = 0;
    const anchors = root.querySelectorAll('a[href]');
    for (const a of anchors) {
      if (a.__sgChecked) continue;
      a.__sgChecked = true;
      if (isSuspicious(a.getAttribute('href'))) {
        maliciousLinks.add(a);
        processLink(a);
        count++;
      }
    }
    if (count > 0) {
      console.log(`[SafeGuard] Found and hooked ${count} suspicious/malicious links on: ${window.location.href}`);
    }
  }
  scanAndHook();
  // Dynamic content observation for SPAs/AJAX (e.g., Whatsapp web)
  const mo = new MutationObserver(muts => {
    for (const m of muts) {
      for (const node of m.addedNodes) {
        if (node.nodeType === 1) scanAndHook(node);
      }
    }
  });
  try {
    mo.observe(document.documentElement, { childList: true, subtree: true });
  } catch { }
})();