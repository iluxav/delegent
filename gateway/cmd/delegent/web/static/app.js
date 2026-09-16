/* Dashboard interactions stay delegated so partial htmx updates keep working. */
(() => {
  'use strict';
  const body = document.body;
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const stored = (key) => { try { return localStorage.getItem('delegent.' + key); } catch (_) { return null; } };
  const remember = (key, value) => { try { localStorage.setItem('delegent.' + key, value); } catch (_) { /* Optional preference. */ } };
  const compact = window.matchMedia('(max-width: 1199px)');
  const mobile = window.matchMedia('(max-width: 760px)');
  let returnFocus = null;
  let consentFocus = null;
  let toastTimer;
  let client = stored('client');
  let openConnectionDetails = [];
  let connectionScrollTop = 0;
  let connectionFocusID = '';
  let confirming = false;
  let targetNavObserver;
  let observedTargetNav;
  const fingerprints = new WeakMap();
  const fingerprint = (form) => JSON.stringify([...new FormData(form).entries()]);
  const dirtyForms = () => $$('[data-track-changes][data-dirty="true"]');
  const visible = (el) => el.getClientRects().length > 0 && !el.closest('[inert]');
  const focusables = (root) => $$('a[href], button:not(:disabled), input:not([type="hidden"]):not(:disabled), select:not(:disabled), summary, [tabindex="0"]', root).filter(visible);

  function toast(message) {
    const el = $('#toast');
    clearTimeout(toastTimer);
    el.textContent = message;
    el.hidden = false;
    toastTimer = setTimeout(() => { el.hidden = true; }, 4200);
  }

  function overlayPanel() {
    if (body.classList.contains('connect-open') && compact.matches) return $('#connect');
    if (body.classList.contains('side-open') && mobile.matches) return $('#side');
    return null;
  }

  function syncPanels() {
    const panel = overlayPanel();
    $('[data-close-panels]').hidden = !panel;
    $$('[data-panel-toggle][aria-controls]').forEach((el) => el.setAttribute('aria-expanded', String(body.classList.contains(el.dataset.panelToggle + '-open'))));
    const consent = $('.consent-dialog');
    $('.app-shell').inert = !!consent;
    $('.workspace').inert = !!panel;
    $('#side').inert = !!panel && panel.id !== 'side';
    $('#connect').inert = !!panel && panel.id !== 'connect';
    ['side', 'connect'].forEach((id) => {
      const el = $('#' + id);
      if (panel === el) { el.setAttribute('role', 'dialog'); el.setAttribute('aria-modal', 'true'); }
      else { el.removeAttribute('role'); el.removeAttribute('aria-modal'); }
    });
  }

  function setPanel(id, open, trigger) {
    if (open) {
      returnFocus = trigger || document.activeElement;
      if (compact.matches) body.classList.remove(id === 'side' ? 'connect-open' : 'side-open');
    }
    body.classList.toggle(id + '-open', open);
    if (id === 'connect' && !compact.matches) remember('connect-open', String(open));
    syncPanels();
    if (open && overlayPanel()) focusables($('#' + id))[0]?.focus();
    if (!open && returnFocus?.isConnected && visible(returnFocus)) returnFocus.focus();
  }

  function selectClient(id, focus = false) {
    const tabs = $$('.ctab');
    if (!tabs.some((tab) => tab.dataset.client === id)) id = tabs[0]?.dataset.client;
    client = id;
    tabs.forEach((tab) => {
      const on = tab.dataset.client === id;
      tab.classList.toggle('ctab-on', on);
      tab.setAttribute('aria-selected', String(on));
      tab.tabIndex = on ? 0 : -1;
      if (on && focus) tab.focus();
    });
    $$('.client-pane').forEach((pane) => pane.classList.toggle('hidden', pane.dataset.client !== id));
  }

  function filterTools() {
    const term = ($('#tool-search')?.value || '').trim().toLowerCase();
    const unknownOnly = $('#unclassified-only')?.checked;
    const rows = $$('[data-tool-row]');
    let count = 0;
    rows.forEach((row) => {
      const effect = $('select[data-fx]', row).value;
      const scope = $('input[name^="scope."]', row).value;
      const matches = (row.textContent + ' ' + scope).toLowerCase().includes(term);
      // Keep a previously unclassified row visible while its scope is being edited.
      row.hidden = !matches || (unknownOnly && effect !== 'unknown' && row.dataset.originalEffect !== 'unknown');
      if (!row.hidden) count++;
    });
    if ($('#tool-no-results')) $('#tool-no-results').hidden = !rows.length || count > 0;
  }

  function observeTargetNavigation() {
    const nav = $('.target-navigation');
    if (nav === observedTargetNav) return;
    targetNavObserver?.disconnect();
    observedTargetNav = nav;
    if (!nav) return;
    const main = $('#main');
    const marker = $('.target-nav-marker');
    const nameHeight = parseFloat(getComputedStyle(nav).getPropertyValue('--context-name-height'));
    const update = () => nav.classList.toggle('is-stuck', marker.getBoundingClientRect().bottom <= main.getBoundingClientRect().top + nameHeight);
    update();
    targetNavObserver = new IntersectionObserver(update, { root: main, rootMargin: `-${nameHeight}px 0px 0px 0px`, threshold: [0, 1] });
    targetNavObserver.observe(marker);
  }

  function prepareToolDescriptions() {
    $$('.tool-description:not([data-prepared])').forEach((description) => {
      const text = description.textContent.trim();
      description.dataset.prepared = 'true';
      if (text.length <= 180) return;
      // Keep the original in the row for searching and lossless reading. The
      // preview is only an excerpt, never a replacement for the server's text.
      description.hidden = true;
      const preview = document.createElement('p');
      preview.className = 'tool-description-preview';
      const excerpt = text.replace(/^\s*#{1,6}\s+.*$/gm, '').replace(/\s+/g, ' ').trim();
      preview.textContent = excerpt.length > 240 ? excerpt.slice(0, 240).replace(/\s+\S*$/, '') + '…' : excerpt;
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'tool-description-open';
      button.dataset.readDescription = '';
      button.textContent = 'Read description';
      button.setAttribute('aria-haspopup', 'dialog');
      button.setAttribute('aria-label', 'Read description for ' + $('.tool-name', description.closest('tr')).textContent);
      description.after(preview, button);
    });
  }

  function openToolDescription(button) {
    const row = button.closest('[data-tool-row]');
    const dialog = $('#tool-description-dialog');
    $('#tool-description-title').textContent = $('.tool-name', row).textContent;
    const content = $('#tool-description-content');
    content.replaceChildren();
    // Descriptions are untrusted server text. Preserve paragraphs and line
    // breaks with textContent, without interpreting embedded HTML or links.
    $('.tool-description', row).textContent.trim().split(/\n\s*\n/).forEach((block) => {
      const heading = block.match(/^#{1,6}\s+([^\n]+)$/);
      const element = document.createElement(heading ? 'h3' : 'p');
      element.textContent = heading ? heading[1] : block;
      content.append(element);
    });
    dialog.showModal();
    content.scrollTop = 0;
  }

  function initialize() {
    observeTargetNavigation();
    prepareToolDescriptions();
    $$('[data-track-changes]').forEach((form) => { if (!fingerprints.has(form)) fingerprints.set(form, fingerprint(form)); });
    $$('[data-tool-row]').forEach((row) => {
      const effect = $('select[data-fx]', row).value;
      if (!row.dataset.originalEffect) row.dataset.originalEffect = effect;
      $('input[name^="scope."]', row).required = effect !== 'unknown';
    });
    const target = $('[data-target-id]')?.dataset.targetId || '';
    $$('.server-link').forEach((link) => {
      const selected = link.dataset.server === target;
      link.classList.toggle('is-active', selected);
      if (selected) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    });
    $('#targets').setAttribute('hx-get', '/targets?s=' + encodeURIComponent(target));
    selectClient(client);
    const name = $('#name');
    if (name && $('#slug')) $('#slug').textContent = name.value.toLowerCase().replace(/[^a-z0-9 _-]/g, '').replace(/[ _-]/g, '-').replace(/^-+|-+$/g, '') || 'name';
    syncPanels();
  }

  function confirmAction(message, onConfirm) {
    if (confirming) return;
    confirming = true;
    const dialog = $('#confirm-dialog');
    $('#confirm-message').textContent = message;
    dialog.returnValue = 'cancel';
    dialog.addEventListener('close', () => {
      confirming = false;
      if (dialog.returnValue === 'confirm') onConfirm();
    }, { once: true });
    dialog.showModal();
  }

  document.addEventListener('input', (event) => {
    const el = event.target;
    if (el.id === 'name') initialize();
    if (el.id === 'server-search') {
      const term = el.value.trim().toLowerCase();
      let count = 0;
      $$('.server-link').forEach((link) => { link.hidden = !link.textContent.toLowerCase().includes(term); if (!link.hidden) count++; });
      $('#server-no-results').hidden = count > 0;
    }
    if (el.id === 'tool-search') filterTools();
    updateDirty(el);
  });

  function updateDirty(el) {
    const form = el.closest('[data-track-changes]');
    if (!form) return;
    const dirty = fingerprint(form) !== fingerprints.get(form);
    form.dataset.dirty = String(dirty);
    $('[data-dirty-note]', form).hidden = !dirty;
    const hint = $('[data-save-hint]', form);
    if (hint) hint.hidden = dirty;
  }

  document.addEventListener('change', (event) => {
    const el = event.target;
    if (el.matches('select[data-fx]')) {
      el.className = el.className.replace(/\bfx-\w+/, 'fx-' + el.value);
      $('input[name^="scope."]', el.closest('tr')).required = el.value !== 'unknown';
    }
    if (el.id === 'unclassified-only' || el.matches('select[data-fx]')) filterTools();
    updateDirty(el);
  });

  // Reveal a filtered-out field before native validation tries to focus it.
  document.addEventListener('invalid', (event) => {
    if (!event.target.closest('[data-tool-row][hidden]')) return;
    $('#tool-search').value = '';
    $('#unclassified-only').checked = false;
    filterTools();
  }, true);

  document.addEventListener('click', async (event) => {
    const description = event.target.closest('[data-read-description]');
    if (description) { openToolDescription(description); return; }
    const toggle = event.target.closest('[data-panel-toggle]');
    if (toggle) { const id = toggle.dataset.panelToggle; setPanel(id, !body.classList.contains(id + '-open'), toggle); return; }
    if (event.target.closest('[data-close-panels]')) { setPanel('connect', false); setPanel('side', false); return; }
    if (event.target.closest('[data-focus-servers]')) {
      if (mobile.matches) setPanel('side', true, event.target);
      ($('#server-search') || $('.server-link'))?.focus();
      return;
    }
    const tab = event.target.closest('.ctab');
    if (tab) { selectClient(tab.dataset.client); remember('client', client); return; }
    $$('.target-actions details[open]').forEach((menu) => { if (!menu.contains(event.target)) menu.open = false; });
    const copy = event.target.closest('[data-copy]');
    if (copy) {
      const source = $(copy.dataset.copy);
      if (!source) return;
      try {
        if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(source.textContent);
        else {
          const textarea = document.createElement('textarea');
          textarea.value = source.textContent;
          textarea.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
          document.body.append(textarea);
          textarea.select();
          try { if (!document.execCommand('copy')) throw new Error('Copy failed'); }
          finally { textarea.remove(); copy.focus(); }
        }
        if (!copy.dataset.originalLabel) copy.dataset.originalLabel = copy.textContent;
        copy.textContent = 'Copied';
        setTimeout(() => { if (copy.isConnected) copy.textContent = copy.dataset.originalLabel; }, 1600);
        toast('Copied to clipboard.');
      } catch (_) { toast('Could not copy. Select the configuration and copy it manually.'); }
      return;
    }
    const link = event.target.closest('a[href]');
    if (link && !link.hasAttribute('hx-get') && !link.getAttribute('href').startsWith('#') && dirtyForms().length) {
      event.preventDefault();
      confirmAction('You have unsaved changes. Leave this page and discard them?', () => { dirtyForms().forEach((form) => form.dataset.dirty = 'false'); location.assign(link.href); });
    }
  });

  document.addEventListener('keydown', (event) => {
    const tab = event.target.closest('.ctab');
    if (tab && ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      const tabs = $$('.ctab');
      const index = tabs.indexOf(tab);
      const step = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -2, ArrowDown: 2 }[event.key];
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + step + tabs.length) % tabs.length;
      selectClient(tabs[next].dataset.client, true); remember('client', client);
    }
    if ($('#confirm-dialog').open || $('#tool-description-dialog').open) return;
    const modal = $('.consent-dialog') || overlayPanel();
    if (event.key === 'Escape' && !$('.consent-dialog')) {
      if (overlayPanel()) { event.preventDefault(); setPanel('connect', false); setPanel('side', false); }
      $$('.target-actions details[open]').forEach((menu) => { menu.open = false; $('summary', menu).focus(); });
    }
    if (event.key === 'Tab' && modal) {
      const items = focusables(modal);
      if (!items.length) { event.preventDefault(); return; }
      if (event.shiftKey && (document.activeElement === items[0] || !items.includes(document.activeElement))) { event.preventDefault(); items.at(-1).focus(); }
      else if (!event.shiftKey && (document.activeElement === items.at(-1) || !items.includes(document.activeElement))) { event.preventDefault(); items[0].focus(); }
    }
  });

  body.addEventListener('htmx:confirm', (event) => {
    const el = event.detail.elt;
    const form = el.closest('form');
    const dirty = dirtyForms().filter((item) => item !== form);
    const replacesMain = el.closest('[hx-target="#main"]');
    const unsaved = replacesMain && dirty.length;
    if (!event.detail.question && !unsaved) return;
    event.preventDefault();
    const message = [event.detail.question, unsaved ? 'Unsaved changes in this workspace will be discarded.' : ''].filter(Boolean).join(' ');
    confirmAction(message, () => event.detail.issueRequest(true));
  });

  body.addEventListener('htmx:beforeSwap', (event) => {
    if (event.target.id !== 'connect') return;
    openConnectionDetails = $$('#connect details[data-panel-disclosure][open]').map((el) => el.dataset.panelDisclosure);
    connectionScrollTop = $('#connect .connect-content')?.scrollTop || 0;
    connectionFocusID = $('#connect').contains(document.activeElement) ? document.activeElement.id : '';
  });
  body.addEventListener('htmx:afterSettle', (event) => {
    if (event.target.id !== 'connect') return;
    // htmx restores incoming class attributes during settling. Reapply the chosen client
    // afterwards so its highlighted tab always matches the visible configuration.
    selectClient(client);
    $$('#connect details[data-panel-disclosure]').forEach((el) => { el.open = openConnectionDetails.includes(el.dataset.panelDisclosure); });
    const minted = $('#minted');
    if (minted) {
      minted.closest('.minted-key').scrollIntoView({ block: 'nearest' });
      $('[data-copy="#minted"]').focus({ preventScroll: true });
    } else {
      $('#connect .connect-content').scrollTop = connectionScrollTop;
      const field = document.getElementById(connectionFocusID);
      if (field && $('#connect').contains(field)) field.focus({ preventScroll: true });
    }
  });
  body.addEventListener('htmx:afterSwap', (event) => {
    if (event.target.id === 'consentpop') {
      const dialog = $('.consent-dialog');
      document.title = dialog ? 'Delegent — approval needed' : 'Delegent · Gateway';
      if (dialog) {
        $('#tool-description-dialog').close();
        if (!consentFocus) consentFocus = document.activeElement;
        // The same request can also be rendered in the Approvals tab.
        $$('[id]', dialog).forEach((input) => {
          const oldID = input.id;
          input.id = 'popup-' + oldID;
          $$('label[for]', dialog).forEach((label) => { if (label.htmlFor === oldID) label.htmlFor = input.id; });
        });
        syncPanels();
        dialog.focus();
      } else {
        syncPanels();
        if (consentFocus?.isConnected && visible(consentFocus)) consentFocus.focus();
        consentFocus = null;
      }
    }
    if (['main', 'targets', 'connect'].includes(event.target.id)) {
      initialize();
      if (event.target.id === 'main') {
        // A request already seen in Approvals still needs a popup after leaving the tab.
        if ($('#pkn')) $('#pkn').value = '';
        if (mobile.matches) setPanel('side', false);
        $('#main').scrollTop = 0;
        ($('#main [autofocus]') || $('#main')).focus({ preventScroll: true });
      }
    }
  });
  body.addEventListener('htmx:historyRestore', initialize);
  body.addEventListener('htmx:responseError', () => toast('The request failed. Your changes are still here. Please try again.'));
  body.addEventListener('htmx:sendError', () => toast('Cannot reach the gateway. Check the connection and try again.'));
  window.addEventListener('beforeunload', (event) => { if (dirtyForms().length) { event.preventDefault(); event.returnValue = ''; } });

  // Remembered pane sizes are clamped so an old preference cannot crowd out the workspace.
  $$('.grip').forEach((grip) => {
    const pane = $('#' + grip.dataset.resize);
    const min = Number(grip.getAttribute('aria-valuemin'));
    const max = Number(grip.getAttribute('aria-valuemax'));
    const setWidth = (value) => {
      const width = Math.min(max, Math.max(min, value));
      pane.style.width = width + 'px';
      grip.setAttribute('aria-valuenow', String(Math.round(width)));
    };
    const saved = Number(stored(grip.dataset.resize));
    if (saved) setWidth(saved);
    grip.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
      event.preventDefault();
      const direction = (event.key === 'ArrowRight' ? 1 : -1) * (grip.dataset.edge === 'right' ? -1 : 1);
      setWidth(pane.getBoundingClientRect().width + direction * 16);
      remember(grip.dataset.resize, parseFloat(pane.style.width));
    });
    grip.addEventListener('pointerdown', (event) => {
      event.preventDefault();
      const startX = event.clientX;
      const startWidth = pane.getBoundingClientRect().width;
      grip.setPointerCapture(event.pointerId);
      body.classList.add('resizing');
      const move = (e) => setWidth(startWidth + (e.clientX - startX) * (grip.dataset.edge === 'right' ? -1 : 1));
      const end = () => {
        body.classList.remove('resizing');
        remember(grip.dataset.resize, parseFloat(pane.style.width));
        grip.removeEventListener('pointermove', move);
        grip.removeEventListener('pointerup', end);
        grip.removeEventListener('pointercancel', end);
      };
      grip.addEventListener('pointermove', move);
      grip.addEventListener('pointerup', end);
      grip.addEventListener('pointercancel', end);
    });
  });
  compact.addEventListener('change', () => { body.classList.remove('connect-open', 'side-open'); syncPanels(); });
  mobile.addEventListener('change', () => { body.classList.remove('side-open'); syncPanels(); });
  if (!compact.matches && (stored('connect-open') === 'true' || (stored('connect-open') === null && innerWidth >= 1480))) body.classList.add('connect-open');
  initialize();
})();
