/**
 * hunt_import.js — Phoenix CTI Forge
 * Hunt Import module: load CTI-ATTACKCollector JSON, triage ATT&CK techniques.
 * Australian Phoenix CyberOps
 *
 * CSP-safe: zero inline event handlers.
 * All listeners attached via addEventListener after DOMContentLoaded.
 */

(function () {
  'use strict';

  // ── State ──────────────────────────────────────────────────────────────────
  var reportData   = null;
  var triageState  = {};
  var activePhase  = 'all';
  var activeStatus = 'all';

  // ── Boot ───────────────────────────────────────────────────────────────────
  function init() {
    if (document.body.dataset.page !== 'hunt-import') return;
    bindStaticControls();
    bindDropZone();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // ── Bind static controls (elements that exist on page load) ───────────────
  function bindStaticControls() {
    // Drop zone click → open file dialog
    var dropZone  = document.getElementById('dropZone');
    var fileInput = document.getElementById('fileInput');
    if (dropZone && fileInput) {
      dropZone.addEventListener('click', function () { fileInput.click(); });
      dropZone.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
      });
    }

    // File input change
    if (fileInput) {
      fileInput.addEventListener('change', function () {
        if (this.files && this.files[0]) handleFile(this.files[0]);
        // Reset so same file can be re-selected
        this.value = '';
      });
    }

    // Textarea focus/blur styling
    var ta = document.getElementById('jsonPaste');
    if (ta) {
      ta.addEventListener('focus', function () { this.style.borderColor = 'var(--border-focus)'; });
      ta.addEventListener('blur',  function () { this.style.borderColor = 'var(--border)'; });
    }

    // Parse button
    var btnParse = document.getElementById('btnParse');
    if (btnParse) btnParse.addEventListener('click', loadReport);

    // Clear button
    var btnClear = document.getElementById('btnClear');
    if (btnClear) btnClear.addEventListener('click', clearAll);

    // New Import button
    var btnNew = document.getElementById('btnNewImport');
    if (btnNew) btnNew.addEventListener('click', clearAll);

    // Export button
    var btnExport = document.getElementById('btnExport');
    if (btnExport) btnExport.addEventListener('click', exportTriage);

    // Static phase filter (the "All" button present at load time)
    bindPhaseButtons();

    // Status filter buttons (all present at load time)
    document.querySelectorAll('.status-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        activeStatus = this.dataset.status;
        document.querySelectorAll('.status-btn').forEach(function (b) { b.classList.remove('active'); });
        this.classList.add('active');
        if (reportData) renderCards();
      });
    });
  }

  // ── Bind phase buttons (called once at init for the static "All" button,
  //    and again after renderTriage inserts dynamic phase buttons) ────────────
  function bindPhaseButtons() {
    document.querySelectorAll('.phase-btn').forEach(function (btn) {
      // Avoid double-binding
      if (btn.dataset.bound) return;
      btn.dataset.bound = '1';
      btn.addEventListener('click', function () {
        activePhase = this.dataset.phase;
        document.querySelectorAll('.phase-btn').forEach(function (b) { b.classList.remove('active'); });
        this.classList.add('active');
        if (reportData) renderCards();
      });
    });
  }

  // ── Drop zone drag events ──────────────────────────────────────────────────
  function bindDropZone() {
    var dz = document.getElementById('dropZone');
    if (!dz) return;

    dz.addEventListener('dragover', function (e) {
      e.preventDefault();
      e.stopPropagation();
      this.style.background    = 'var(--amber-glow)';
      this.style.borderColor   = 'var(--amber-400)';
    });

    dz.addEventListener('dragleave', function (e) {
      e.stopPropagation();
      this.style.background  = '';
      this.style.borderColor = '';
    });

    dz.addEventListener('drop', function (e) {
      e.preventDefault();
      e.stopPropagation();
      this.style.background  = '';
      this.style.borderColor = '';
      var file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (file) handleFile(file);
    });
  }

  // ── File handling ──────────────────────────────────────────────────────────
  function handleFile(file) {
    if (file.size > 5 * 1024 * 1024) {
      showStatus('error', 'File exceeds 5 MB limit.');
      return;
    }
    // Accept .json regardless of MIME type — Windows often sends text/plain
    if (!file.name.toLowerCase().endsWith('.json')) {
      showStatus('error', 'Please provide a .json file.');
      return;
    }
    var reader = new FileReader();
    reader.onerror = function () { showStatus('error', 'Could not read the file.'); };
    reader.onload = function (e) {
      var ta = document.getElementById('jsonPaste');
      if (ta) ta.value = e.target.result;
      showStatus('info', '&#128193; Loaded: ' + escHtml(file.name) +
        ' (' + (file.size / 1024).toFixed(1) + ' KB) — click Parse Report to continue.');
    };
    reader.readAsText(file);
  }

  // ── Parse & submit to server ───────────────────────────────────────────────
  function loadReport() {
    var ta  = document.getElementById('jsonPaste');
    var raw = ta ? ta.value.trim() : '';
    if (!raw) {
      showStatus('error', 'Nothing to parse. Drop a file or paste JSON above.');
      return;
    }

    var parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      showStatus('error', '&#10060; Invalid JSON: ' + escHtml(err.message));
      return;
    }

    showStatus('info', '&#9203; Validating report&#8230;');

    var meta   = document.querySelector('meta[name="csrf-token"]');
    var csrf   = meta ? meta.getAttribute('content') : '';

    fetch('/api/hunt/import', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
      body:    JSON.stringify(parsed)
    })
    .then(function (resp) {
      return resp.json().then(function (d) { return { ok: resp.ok, data: d }; });
    })
    .then(function (r) {
      if (!r.ok || !r.data.success) {
        showStatus('error', '&#10060; ' + escHtml(r.data.error || 'Server rejected the report.'));
        return;
      }
      reportData  = r.data;
      triageState = {};
      r.data.techniques.forEach(function (t) {
        triageState[t.technique_id] = { status: 'untriaged', notes: '' };
      });
      showStatus('success',
        '&#10003; Loaded ' + r.data.meta.technique_count +
        ' techniques for ' + escHtml(r.data.meta.actor_name));
      renderTriage();
    })
    .catch(function (err) {
      showStatus('error', '&#10060; Network error: ' + escHtml(err.message));
    });
  }

  // ── Render triage UI ───────────────────────────────────────────────────────
  function renderTriage() {
    var meta  = reportData.meta;
    var techs = reportData.techniques;

    var el;
    el = document.getElementById('actorTitle');
    if (el) el.textContent = meta.actor_name;

    el = document.getElementById('actorAliases');
    if (el) el.textContent = meta.actor_aliases ? 'Aliases: ' + meta.actor_aliases : '';

    el = document.getElementById('techCount');
    if (el) el.textContent = meta.technique_count + ' techniques';

    el = document.getElementById('reportMeta');
    if (el) el.textContent = meta.generated_at
      ? 'Generated: ' + new Date(meta.generated_at).toLocaleDateString() : '';

    // Build phase filter buttons
    var phases = [];
    techs.forEach(function (t) {
      if (t.kill_chain && phases.indexOf(t.kill_chain) === -1) phases.push(t.kill_chain);
    });
    phases.sort();

    var phDiv = document.getElementById('phaseButtons');
    if (phDiv) {
      phDiv.innerHTML = '';
      phases.forEach(function (p) {
        var btn = document.createElement('button');
        btn.className       = 'tab-btn phase-btn';
        btn.dataset.phase   = p;
        btn.dataset.bound   = '1';
        btn.style.cssText   = 'flex:unset;padding:5px 12px;';
        btn.textContent     = formatPhase(p);
        btn.addEventListener('click', function () {
          activePhase = this.dataset.phase;
          document.querySelectorAll('.phase-btn').forEach(function (b) { b.classList.remove('active'); });
          this.classList.add('active');
          renderCards();
        });
        phDiv.appendChild(btn);
      });
    }

    // Rebind the static "All" phase button (was bound at init but phase buttons are new)
    var allPhaseBtn = document.querySelector('.phase-btn[data-phase="all"]');
    if (allPhaseBtn) {
      allPhaseBtn.classList.add('active');
    }

    document.getElementById('triagePanel').style.display = '';
    renderCards();
    updateProgress();
  }

  // ── Render technique cards ─────────────────────────────────────────────────
  function renderCards() {
    var techs = reportData ? reportData.techniques.filter(function (t) {
      var pm = (activePhase  === 'all' || t.kill_chain === activePhase);
      var sm = (activeStatus === 'all' ||
                (triageState[t.technique_id] &&
                 triageState[t.technique_id].status === activeStatus));
      return pm && sm;
    }) : [];

    var grid = document.getElementById('techniqueGrid');
    var none = document.getElementById('noResults');
    if (!grid) return;

    if (techs.length === 0) {
      grid.innerHTML = '';
      if (none) none.style.display = '';
      return;
    }
    if (none) none.style.display = 'none';

    // Build cards as DOM nodes (not innerHTML strings) — safe by construction
    var frag = document.createDocumentFragment();
    techs.forEach(function (t) {
      frag.appendChild(buildCard(t));
    });
    grid.innerHTML = '';
    grid.appendChild(frag);

    // Bind card-level events after insertion
    bindCardEvents(grid);
  }

  // ── Build a single card as a DOM node ─────────────────────────────────────
  function buildCard(t) {
    var id    = t.technique_id;
    var state = triageState[id] || { status: 'untriaged', notes: '' };

    var wrap = document.createElement('div');
    wrap.className        = 'card technique-card';
    wrap.dataset.id       = id;
    wrap.dataset.phase    = t.kill_chain || '';
    wrap.dataset.status   = state.status;
    wrap.style.cssText    = 'border-left:3px solid ' + statusBorderColor(state.status) + ';padding:18px 20px;';

    // ── Header row ────────────────────────────────────────────────────────
    var header = el('div', 'display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap;');

    var code = el('code', 'color:var(--amber-400);font-weight:700;font-size:0.92rem;');
    code.textContent = id;
    header.appendChild(code);

    if (t.is_subtechnique) {
      var sub = el('span', 'margin-left:4px;');
      sub.className = 'badge badge-gray';
      sub.textContent = 'sub';
      header.appendChild(sub);
    }

    if (t.kill_chain) {
      var ph = el('span', 'margin-left:4px;');
      ph.className = 'badge badge-cyan';
      ph.textContent = formatPhase(t.kill_chain);
      header.appendChild(ph);
    }

    var statusBadge = el('span', 'margin-left:auto;');
    statusBadge.className = 'badge ' + statusBadgeClass(state.status);
    statusBadge.innerHTML = statusLabel(state.status);
    header.appendChild(statusBadge);
    wrap.appendChild(header);

    // ── Technique name + ATT&CK link ──────────────────────────────────────
    var h3 = document.createElement('h3');
    h3.style.cssText = 'font-size:0.97rem;font-weight:700;margin-bottom:10px;';
    var link = document.createElement('a');
    link.href             = sanitizeUrl(t.attack_url);
    link.target           = '_blank';
    link.rel              = 'noopener noreferrer';
    link.style.cssText    = 'color:var(--text-primary);text-decoration:none;';
    link.title            = 'Open in ATT&CK';
    link.textContent      = t.technique_name;
    var arrow = el('span', 'color:var(--text-muted);font-size:0.8rem;');
    arrow.innerHTML = ' &#8599;';
    link.appendChild(arrow);
    h3.appendChild(link);
    wrap.appendChild(h3);

    // ── Hunt hypothesis ───────────────────────────────────────────────────
    var hyp = el('div', 'background:rgba(245,158,11,0.06);border-left:3px solid var(--amber-500);border-radius:0 var(--r-sm) var(--r-sm) 0;padding:10px 14px;margin-bottom:12px;');
    var hypLabel = el('div', 'font-size:0.74rem;color:var(--amber-400);font-weight:700;text-transform:uppercase;letter-spacing:0.07em;margin-bottom:6px;');
    hypLabel.innerHTML = '&#128269; Hunt Hypothesis';
    var hypText = el('div', 'font-size:0.83rem;color:var(--text-secondary);line-height:1.55;');
    hypText.textContent = t.hunt_hypothesis || '—';
    hyp.appendChild(hypLabel);
    hyp.appendChild(hypText);
    wrap.appendChild(hyp);

    // ── Data sources ──────────────────────────────────────────────────────
    var dsWrap = el('div', 'margin-bottom:12px;');
    var dsLabel = el('div', 'font-size:0.74rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:6px;');
    dsLabel.innerHTML = '&#128225; Data Sources';
    dsWrap.appendChild(dsLabel);
    var dsPills = el('div', '');
    if (t.data_sources) {
      var ds = t.data_sources.split(';').map(function (s) { return s.trim(); }).filter(Boolean);
      ds.slice(0, 5).forEach(function (d) {
        var pill = el('span', 'margin:2px 3px 2px 0;');
        pill.className   = 'badge badge-gray';
        pill.textContent = d;
        dsPills.appendChild(pill);
      });
      if (ds.length > 5) {
        var more = el('span', 'font-size:0.74rem;color:var(--text-muted);');
        more.textContent = '+' + (ds.length - 5) + ' more';
        dsPills.appendChild(more);
      }
    } else {
      dsPills.innerHTML = '<span style="color:var(--text-muted);font-size:0.8rem;">—</span>';
    }
    dsWrap.appendChild(dsPills);
    wrap.appendChild(dsWrap);

    // ── MITRE detection (collapsible) ─────────────────────────────────────
    if (t.detection) {
      var detWrap   = el('div', 'margin-bottom:12px;');
      var detBtn    = document.createElement('button');
      detBtn.className  = 'btn btn-ghost btn-sm det-toggle';
      detBtn.style.cssText = 'font-size:0.78rem;padding:4px 10px;';
      detBtn.innerHTML  = '&#128737; MITRE Detection &#9660;';
      var detBody   = el('div', 'display:none;margin-top:8px;font-size:0.8rem;color:var(--text-muted);line-height:1.55;padding:10px 12px;background:var(--bg-code);border-radius:var(--r-sm);');
      detBody.textContent = t.detection.substring(0, 600) + (t.detection.length > 600 ? '…' : '');
      detBtn.dataset.target = 'det';   // used by delegated listener
      detWrap.appendChild(detBtn);
      detWrap.appendChild(detBody);
      wrap.appendChild(detWrap);
    }

    // ── Analyst notes ─────────────────────────────────────────────────────
    var notesWrap = el('div', 'margin-bottom:14px;');
    var notesTA   = document.createElement('textarea');
    notesTA.className    = 'notes-ta';
    notesTA.dataset.id   = id;
    notesTA.rows         = 2;
    notesTA.placeholder  = 'Analyst notes…';
    notesTA.value        = state.notes;
    notesTA.style.cssText = 'width:100%;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:var(--r-sm);padding:8px 10px;font-size:0.8rem;font-family:inherit;resize:none;outline:none;line-height:1.4;transition:border-color var(--t-fast);';
    notesWrap.appendChild(notesTA);
    wrap.appendChild(notesWrap);

    // ── Triage buttons ────────────────────────────────────────────────────
    var btnRow = el('div', 'display:flex;gap:6px;flex-wrap:wrap;');
    [
      ['hunt',    '&#127919;', 'Hunt',    'var(--amber-400)'],
      ['detect',  '&#9881;',   'Detect',  'var(--cyan-400)'],
      ['covered', '&#10003;',  'Covered', 'var(--green)'],
      ['na',      '&#215;',    'N/A',     'var(--text-muted)']
    ].forEach(function (def) {
      var s = def[0], icon = def[1], label = def[2], color = def[3];
      var b       = document.createElement('button');
      b.className = 'btn btn-ghost btn-sm triage-btn';
      b.dataset.techId = id;
      b.dataset.status = s;
      b.innerHTML      = icon + ' ' + label;
      if (state.status === s) {
        b.style.cssText = 'background:' + color + ';color:#0a0f1a;border-color:' + color + ';font-weight:700;';
      } else {
        b.style.color = color;
      }
      btnRow.appendChild(b);
    });
    wrap.appendChild(btnRow);

    return wrap;
  }

  // ── Delegated event binding for dynamically created cards ─────────────────
  function bindCardEvents(grid) {
    // Single delegated listener on the grid for all card interactions

    grid.addEventListener('click', function (e) {
      // Triage buttons
      var tb = e.target.closest('.triage-btn');
      if (tb) {
        var tid    = tb.dataset.techId;
        var status = tb.dataset.status;
        if (!triageState[tid]) triageState[tid] = { status: 'untriaged', notes: '' };
        triageState[tid].status = status;
        // Rebuild just this card
        var card = grid.querySelector('.technique-card[data-id="' + tid + '"]');
        if (card) {
          var tech = reportData.techniques.filter(function (x) { return x.technique_id === tid; })[0];
          if (tech) {
            var newCard = buildCard(tech);
            card.parentNode.replaceChild(newCard, card);
            // Re-bind events on the new subtree
            bindCardEvents(grid);
            // Restore focus-hint
            var saved = triageState[tid].notes;
            var newTA = grid.querySelector('.technique-card[data-id="' + tid + '"] .notes-ta');
            if (newTA) newTA.value = saved;
          }
        }
        updateProgress();
        if (activeStatus !== 'all') renderCards();
        return;
      }

      // Detection toggle
      var dt = e.target.closest('.det-toggle');
      if (dt) {
        var detBody = dt.nextElementSibling;
        if (!detBody) return;
        var hidden = detBody.style.display === 'none' || detBody.style.display === '';
        // On first render display is 'none' (set inline), after toggle it alternates
        var isHidden = detBody.style.display !== 'block';
        detBody.style.display = isHidden ? 'block' : 'none';
        dt.innerHTML = isHidden
          ? '&#128737; MITRE Detection &#9650;'
          : '&#128737; MITRE Detection &#9660;';
        return;
      }
    });

    // Notes textarea — save on blur via delegated focus-out
    grid.addEventListener('focusout', function (e) {
      if (e.target.classList.contains('notes-ta')) {
        var tid = e.target.dataset.id;
        if (!triageState[tid]) triageState[tid] = { status: 'untriaged', notes: '' };
        triageState[tid].notes = e.target.value;
      }
    });

    // Notes textarea — focus/blur styling
    grid.addEventListener('focusin', function (e) {
      if (e.target.classList.contains('notes-ta')) {
        e.target.style.borderColor = 'var(--border-focus)';
      }
    });
    grid.addEventListener('focusout', function (e) {
      if (e.target.classList.contains('notes-ta')) {
        e.target.style.borderColor = 'var(--border)';
      }
    });
  }

  // ── Progress bar ───────────────────────────────────────────────────────────
  function updateProgress() {
    if (!reportData) return;
    var total   = reportData.techniques.length;
    var triaged = Object.keys(triageState).filter(function (k) {
      return triageState[k].status !== 'untriaged';
    }).length;
    var pct = total > 0 ? Math.round((triaged / total) * 100) : 0;
    var lbl = document.getElementById('progressLabel');
    var bar = document.getElementById('progressBar');
    if (lbl) lbl.textContent  = triaged + ' / ' + total + ' triaged';
    if (bar) bar.style.width  = pct + '%';
  }

  // ── Export ─────────────────────────────────────────────────────────────────
  function exportTriage() {
    if (!reportData) return;
    var counts = { hunt: 0, detect: 0, covered: 0, na: 0, untriaged: 0 };
    Object.keys(triageState).forEach(function (k) {
      var s = triageState[k].status;
      counts[s] = (counts[s] || 0) + 1;
    });

    var out = {
      export_meta: {
        actor:       reportData.meta.actor_name,
        exported_at: new Date().toISOString(),
        tool:        'Phoenix CTI Forge — Hunt Import v2.1'
      },
      summary: {
        total:     reportData.techniques.length,
        hunt:      counts.hunt      || 0,
        detect:    counts.detect    || 0,
        covered:   counts.covered   || 0,
        na:        counts.na        || 0,
        untriaged: counts.untriaged || 0
      },
      techniques: reportData.techniques.map(function (t) {
        var s   = triageState[t.technique_id] || { status: 'untriaged', notes: '' };
        // Capture current textarea value if card is visible
        var taEl  = document.querySelector('.technique-card[data-id="' + t.technique_id + '"] .notes-ta');
        var notes = taEl ? taEl.value : s.notes;
        return {
          technique_id:    t.technique_id,
          technique_name:  t.technique_name,
          kill_chain:      t.kill_chain,
          platforms:       t.platforms,
          triage_status:   s.status,
          analyst_notes:   notes,
          hunt_hypothesis: t.hunt_hypothesis,
          data_sources:    t.data_sources,
          attack_url:      t.attack_url
        };
      })
    };

    var blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' });
    var a    = document.createElement('a');
    a.href   = URL.createObjectURL(blob);
    a.download = 'triage_' +
      (reportData.meta.actor_name || 'report').replace(/\s+/g, '_') +
      '_' + Date.now() + '.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  }

  // ── Clear ──────────────────────────────────────────────────────────────────
  function clearAll() {
    var ta = document.getElementById('jsonPaste');
    if (ta) ta.value = '';
    hideStatus();
    var tp = document.getElementById('triagePanel');
    if (tp) tp.style.display = 'none';
    var tg = document.getElementById('techniqueGrid');
    if (tg) tg.innerHTML = '';
    var nr = document.getElementById('noResults');
    if (nr) nr.style.display = 'none';

    // Reset phase buttons
    document.querySelectorAll('.phase-btn').forEach(function (b) { b.classList.remove('active'); });
    var allBtn = document.querySelector('.phase-btn[data-phase="all"]');
    if (allBtn) allBtn.classList.add('active');

    // Reset status buttons
    document.querySelectorAll('.status-btn').forEach(function (b) { b.classList.remove('active'); });
    var allStatus = document.querySelector('.status-btn[data-status="all"]');
    if (allStatus) allStatus.classList.add('active');

    reportData   = null;
    triageState  = {};
    activePhase  = 'all';
    activeStatus = 'all';
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // ── Status helpers ─────────────────────────────────────────────────────────
  function statusBorderColor(s) {
    return ({
      hunt:      'var(--amber-500)',
      detect:    'var(--cyan-500)',
      covered:   'var(--green)',
      na:        'var(--text-muted)',
      untriaged: 'var(--border)'
    })[s] || 'var(--border)';
  }

  function statusBadgeClass(s) {
    return ({
      hunt:      'badge-amber',
      detect:    'badge-cyan',
      covered:   'badge-green',
      na:        'badge-gray',
      untriaged: 'badge-gray'
    })[s] || 'badge-gray';
  }

  function statusLabel(s) {
    return ({
      hunt:      '&#127919; To Hunt',
      detect:    '&#9881; To Detect',
      covered:   '&#10003; Covered',
      na:        '&#215; N/A',
      untriaged: '&mdash; Untriaged'
    })[s] || '&mdash;';
  }

  // ── UI helpers ─────────────────────────────────────────────────────────────
  function showStatus(type, msg) {
    var statusEl = document.getElementById('importStatus');
    if (!statusEl) return;
    var colors = {
      error:   { border: 'var(--red)',      bg: 'rgba(239,68,68,0.08)',    text: 'var(--red)'      },
      success: { border: 'var(--green)',    bg: 'rgba(16,185,129,0.08)',   text: 'var(--green)'    },
      info:    { border: 'var(--cyan-400)', bg: 'rgba(6,182,212,0.06)',    text: 'var(--cyan-400)' }
    };
    var c = colors[type] || colors.info;
    var div = document.createElement('div');
    div.style.cssText = 'padding:10px 14px;border-radius:var(--r-md);' +
      'border:1px solid ' + c.border + ';background:' + c.bg + ';' +
      'font-size:0.85rem;color:' + c.text + ';';
    div.innerHTML = msg;   // msg is always our own static strings + escHtml() output
    statusEl.innerHTML = '';
    statusEl.appendChild(div);
    statusEl.style.display = '';
  }

  function hideStatus() {
    var statusEl = document.getElementById('importStatus');
    if (statusEl) { statusEl.style.display = 'none'; statusEl.innerHTML = ''; }
  }

  function formatPhase(p) {
    return p ? p.replace(/-/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); }) : '';
  }

  // Helper: create element with inline style
  function el(tag, style) {
    var e = document.createElement(tag);
    if (style) e.style.cssText = style;
    return e;
  }

  // Sanitise ATT&CK URLs — only allow https://attack.mitre.org/...
  function sanitizeUrl(url) {
    if (!url) return '#';
    if (/^https:\/\/attack\.mitre\.org\//.test(url)) return url;
    return '#';
  }

  // HTML escape for any user-derived content placed via innerHTML
  function escHtml(s) {
    if (!s) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

})();
