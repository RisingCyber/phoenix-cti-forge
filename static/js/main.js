/**
 * Phoenix CTI Forge v2.1 — Main JavaScript
 * Australian Phoenix CyberOps | Educational Platform
 * Single clean IIFE — no duplicates, no conflicts.
 */
(function () {
  'use strict';

  /* ── Helpers ─────────────────────────────────────────────────────── */
  function csrfToken() {
    const m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.content : '';
  }

  async function apiPost(url, data) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken() },
      body: JSON.stringify(data),
    });
    return r.json();
  }

  async function apiGet(url) {
    const r = await fetch(url, { headers: { 'X-CSRFToken': csrfToken() } });
    return r.json();
  }

  function el(id) { return document.getElementById(id); }

  function mk(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function esc(str) {
    const d = document.createElement('div');
    d.textContent = String(str || '');
    return d.innerHTML;
  }

  function show(e) { if (e) e.classList.remove('hidden'); }
  function hide(e) { if (e) e.classList.add('hidden'); }

  function copyBtn(btn, text) {
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.textContent;
      btn.textContent = '✓ Copied!';
      setTimeout(() => { btn.textContent = orig; }, 1800);
    });
  }

  /* ── Router ──────────────────────────────────────────────────────── */
  function init() {
    const page = document.body.dataset.page;
    if (page === 'ioc_analyzer')   initIOCAnalyzer();
    if (page === 'mitre_explorer') initMITREExplorer();
    if (page === 'training')       initTraining();
    if (page === 'report_builder') initReportBuilder();
    if (page === 'ttp_mapper')     initTTPMapper();
    if (page === 'defang')         initDefang();
    if (page === 'toolkit')        initToolkit();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  /* ══════════════════════════════════════════════════════════════════
     IOC ANALYZER
  ══════════════════════════════════════════════════════════════════ */
  function initIOCAnalyzer() {
    const analyzeBtn = el('analyze-btn');
    const clearBtn   = el('clear-btn');
    const inputArea  = el('ioc-input');
    const resultsArea= el('results-area');
    const statsBar   = el('stats-bar');
    const iocList    = el('ioc-list');
    const huntSection= el('hunt-queries');
    const queryCtrl  = el('query-controls');
    const queryOut   = el('query-output');

    if (!analyzeBtn) return;

    let allIOCs = [];

    analyzeBtn.addEventListener('click', async () => {
      const text = inputArea.value.trim();
      if (!text) { inputArea.focus(); return; }

      analyzeBtn.disabled = true;
      analyzeBtn.textContent = 'Analysing…';
      iocList.innerHTML = '';
      statsBar.innerHTML = '';
      hide(resultsArea);
      hide(huntSection);

      try {
        const data = await apiPost('/api/extract-iocs', { text });
        allIOCs = data.iocs || [];

        if (!data.count) {
          iocList.innerHTML = '<p class="text-muted" style="padding:16px">No indicators found. Try pasting a threat report or log file.</p>';
          show(resultsArea);
          return;
        }

        /* Stats chips */
        Object.entries(data.statistics || {}).forEach(([type, count]) => {
          const chip = mk('span', 'stat-chip');
          chip.innerHTML = `<strong>${count}</strong> ${type}`;
          statsBar.appendChild(chip);
        });

        /* Group by type */
        const byType = {};
        allIOCs.forEach(ioc => {
          (byType[ioc.type] = byType[ioc.type] || []).push(ioc);
        });

        Object.entries(byType).forEach(([type, iocs]) => {
          const section = mk('div', 'ioc-type-section');

          const hdr = mk('div', 'ioc-type-header');
          hdr.appendChild(mk('span', 'badge badge-cyan', type.toUpperCase()));
          hdr.appendChild(mk('span', 'ioc-count badge badge-amber', `${iocs.length} found`));
          section.appendChild(hdr);

          iocs.forEach(ioc => {
            const item = mk('div', 'ioc-item');

            const val = mk('div', 'ioc-value', ioc.value);
            item.appendChild(val);

            if (ioc.defanged && ioc.defanged !== ioc.value) {
              const df = mk('div', 'ioc-defanged', '↳ ' + ioc.defanged);
              item.appendChild(df);
            }

            if (ioc.educational_note) {
              const note = mk('div', 'ioc-note', ioc.educational_note);
              item.appendChild(note);
            }

            const meta = mk('div', 'ioc-meta');
            if (ioc.risk_context) {
              meta.appendChild(mk('span', 'badge badge-amber', ioc.risk_context));
            }

            /* Copy buttons */
            const cpRaw = mk('button', 'btn btn-ghost btn-sm', 'Copy');
            cpRaw.addEventListener('click', () => copyBtn(cpRaw, ioc.value));
            meta.appendChild(cpRaw);

            if (ioc.defanged && ioc.defanged !== ioc.value) {
              const cpDf = mk('button', 'btn btn-ghost btn-sm', 'Copy Defanged');
              cpDf.addEventListener('click', () => copyBtn(cpDf, ioc.defanged));
              meta.appendChild(cpDf);
            }

            item.appendChild(meta);
            section.appendChild(item);
          });

          iocList.appendChild(section);
        });

        /* Hunt query section */
        queryCtrl.innerHTML = '';
        queryOut.textContent = '';
        const uniqueTypes = Object.keys(byType);
        uniqueTypes.forEach(type => {
          const btn = mk('button', 'query-btn', type.toUpperCase());
          btn.addEventListener('click', async () => {
            document.querySelectorAll('.query-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            queryOut.textContent = 'Generating…';
            const typeIOCs = byType[type].map(i => i.value).slice(0, 20);
            try {
              const q = await apiPost('/api/generate-hunt', { ioc_type: type, iocs: typeIOCs });
              if (q.queries) {
                queryOut.textContent = Object.entries(q.queries)
                  .map(([k, v]) => `── ${k} ──\n${v}`)
                  .join('\n\n');
              } else {
                queryOut.textContent = JSON.stringify(q, null, 2);
              }
            } catch (e) {
              queryOut.textContent = 'Error: ' + e.message;
            }
          });
          queryCtrl.appendChild(btn);
        });

        show(resultsArea);
        show(huntSection);
      } catch (e) {
        iocList.innerHTML = `<p class="text-red" style="padding:16px">Error: ${esc(e.message)}</p>`;
        show(resultsArea);
      } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = 'Extract IOCs';
      }
    });

    clearBtn.addEventListener('click', () => {
      inputArea.value = '';
      iocList.innerHTML = '';
      statsBar.innerHTML = '';
      hide(resultsArea);
      hide(huntSection);
      inputArea.focus();
    });
  }

  /* ══════════════════════════════════════════════════════════════════
     MITRE ATT&CK EXPLORER
  ══════════════════════════════════════════════════════════════════ */
  function initMITREExplorer() {
    const searchInput  = el('mitre-search');
    const searchBtn    = el('search-btn');
    const searchRes    = el('search-results');
    const techPanel    = el('technique-panel');
    const tacticTitle  = el('tactic-title');
    const tacticPearl  = el('tactic-pearl');
    const techList     = el('technique-list');
    const techDetail   = el('technique-detail');
    const closeDetail  = el('close-detail');
    const detailCont   = el('detail-content');

    if (!searchBtn) return;

    /* Tactic explore buttons */
    document.querySelectorAll('.explore-tactic').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        await loadTactic(btn.dataset.tactic);
      });
    });

    document.querySelectorAll('.tactic-card').forEach(card => {
      card.addEventListener('click', async () => {
        await loadTactic(card.dataset.tacticId);
      });
    });

    async function loadTactic(tacticId) {
      techList.innerHTML = '<p class="text-muted" style="padding:16px">Loading…</p>';
      show(techPanel);
      hide(techDetail);
      techPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });

      try {
        const data = await apiGet('/api/mitre/techniques/' + tacticId);
        tacticTitle.textContent = `${data.tactic.id} — ${data.tactic.name}`;
        if (tacticPearl) tacticPearl.textContent = data.tactic.ctipearl || data.tactic.description || '';

        techList.innerHTML = '';
        if (!data.techniques.length) {
          techList.innerHTML = '<p class="text-muted" style="padding:16px">No techniques found for this tactic.</p>';
          return;
        }

        data.techniques.forEach(t => {
          const card = mk('div', 'technique-card');

          const tid = mk('div', 'technique-id', t.id);
          card.appendChild(tid);

          const name = mk('div', 'technique-name', t.name);
          card.appendChild(name);

          const desc = mk('div', 'technique-desc', (t.description || '').substring(0, 120) + '…');
          card.appendChild(desc);

          const footer = mk('div', 'technique-footer');
          if (t.difficulty) footer.appendChild(mk('span', `difficulty-badge ${t.difficulty}`, t.difficulty));
          if (t.apt_examples && t.apt_examples.length) {
            footer.appendChild(mk('span', 'badge badge-gray', t.apt_examples.slice(0, 2).join(', ')));
          }
          card.appendChild(footer);

          card.addEventListener('click', () => loadTechDetail(t.id));
          techList.appendChild(card);
        });
      } catch (err) {
        techList.innerHTML = `<p class="text-red">Error loading techniques: ${esc(err.message)}</p>`;
      }
    }

    async function loadTechDetail(techId) {
      detailCont.innerHTML = '<p class="text-muted" style="padding:16px">Loading…</p>';
      show(techDetail);
      hide(techPanel);
      techDetail.scrollIntoView({ behavior: 'smooth', block: 'start' });

      try {
        const t = await apiGet('/api/mitre/technique/' + techId);

        const wrap = mk('div', 'detail-content-inner');

        const h2 = mk('h2', '', '');
        h2.innerHTML = `<span style="font-family:monospace;font-size:0.85rem;color:var(--cyan-400)">${esc(t.id)}</span>  ${esc(t.name)}`;
        wrap.appendChild(h2);

        wrap.appendChild(mk('p', 'text-muted', `Tactic: ${t.tactic.id} — ${t.tactic.name}`));

        if (t.ctipearl) {
          const pearl = mk('div', 'cti-pearl mt-4', '');
          pearl.innerHTML = `<strong style="color:var(--amber-400)">CTI Insight</strong><br>${esc(t.ctipearl)}`;
          wrap.appendChild(pearl);
        }

        const descBox = mk('div', 'detail-section mt-4');
        descBox.appendChild(mk('h4', '', 'Description'));
        descBox.appendChild(mk('p', 'text-muted', t.description));
        wrap.appendChild(descBox);

        if (t.detection_tips && t.detection_tips.length) {
          const det = mk('div', 'detail-section');
          det.appendChild(mk('h4', '', 'Detection Tips'));
          t.detection_tips.forEach(tip => det.appendChild(mk('div', 'detection-tip', tip)));
          wrap.appendChild(det);
        }

        if (t.data_sources && t.data_sources.length) {
          const ds = mk('div', 'detail-section');
          ds.appendChild(mk('h4', '', 'Data Sources'));
          const row = mk('div');
          t.data_sources.forEach(s => row.appendChild(mk('span', 'data-source-tag', s)));
          ds.appendChild(row);
          wrap.appendChild(ds);
        }

        if (t.mitigations && t.mitigations.length) {
          const mit = mk('div', 'detail-section');
          mit.appendChild(mk('h4', '', 'Mitigations'));
          const row = mk('div');
          t.mitigations.forEach(m => row.appendChild(mk('span', 'mitigation-tag', m)));
          mit.appendChild(row);
          wrap.appendChild(mit);
        }

        if (t.apt_examples && t.apt_examples.length) {
          const apt = mk('div', 'detail-section');
          apt.appendChild(mk('h4', '', 'Threat Actors Using This Technique'));
          const row = mk('div');
          t.apt_examples.forEach(a => row.appendChild(mk('span', 'apt-tag', a)));
          apt.appendChild(row);
          wrap.appendChild(apt);
        }

        detailCont.innerHTML = '';
        detailCont.appendChild(wrap);
      } catch (err) {
        detailCont.innerHTML = `<p class="text-red">Error: ${esc(err.message)}</p>`;
      }
    }

    closeDetail.addEventListener('click', () => {
      hide(techDetail);
      show(techPanel);
    });

    /* Search */
    searchBtn.addEventListener('click', doSearch);
    searchInput.addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });

    async function doSearch() {
      const q = searchInput.value.trim();
      if (!q) return;
      searchRes.innerHTML = '<p class="text-muted">Searching…</p>';
      show(searchRes);
      try {
        const data = await apiGet('/api/mitre/search?q=' + encodeURIComponent(q));
        if (!data.results.length) {
          searchRes.innerHTML = '<p class="text-muted">No results found.</p>';
          return;
        }
        searchRes.innerHTML = `<h3 style="margin-bottom:12px;font-size:0.9rem">${data.count} result${data.count !== 1 ? 's' : ''} for "${esc(q)}"</h3>`;
        data.results.forEach(r => {
          const item = mk('div', 'search-result-item');
          item.innerHTML = `<span style="font-family:monospace;font-size:0.78rem;color:var(--cyan-400)">${esc(r.id)}</span>
<strong style="margin-left:8px">${esc(r.name)}</strong>
<span class="badge badge-gray" style="margin-left:8px">${esc(r.tactic)}</span>
<p style="font-size:0.8rem;color:var(--text-muted);margin-top:4px">${esc(r.description)}</p>`;
          item.addEventListener('click', () => loadTechDetail(r.id));
          searchRes.appendChild(item);
        });
      } catch (err) {
        searchRes.innerHTML = `<p class="text-red">Error: ${esc(err.message)}</p>`;
      }
    }
  }

  /* ══════════════════════════════════════════════════════════════════
     TRAINING
  ══════════════════════════════════════════════════════════════════ */
  function initTraining() {
    const startBtn    = el('start-quiz-btn');
    const quizWelcome = el('quiz-welcome');
    const quizArea    = el('quiz-area');
    const qCard       = el('question-card');
    const progressFill= el('progress-fill');
    const progressTxt = el('progress-text');
    const scoreLive   = el('score-live');
    const quizResults = el('quiz-results');
    const scoreDisp   = el('score-display');
    const reviewArea  = el('review-area');
    const restartBtn  = el('restart-quiz-btn');

    if (!startBtn) return;

    let questions = [], current = 0, score = 0, answered = false, history = [];

    startBtn.addEventListener('click', startQuiz);

    async function startQuiz() {
      const cat   = el('category-select').value;
      const diff  = el('difficulty-select').value;
      const count = parseInt(el('count-select').value) || 5;

      startBtn.disabled = true;
      startBtn.textContent = 'Loading…';

      try {
        const params = new URLSearchParams({ count });
        if (cat)  params.set('category', cat);
        if (diff) params.set('difficulty', diff);

        const data = await apiGet('/api/training/questions?' + params);
        questions = data.questions || [];

        if (!questions.length) {
          alert('No questions found for those filters. Try different settings.');
          startBtn.disabled = false;
          startBtn.textContent = '▶ Start Quiz';
          return;
        }

        current = 0; score = 0; answered = false; history = [];
        hide(quizWelcome);
        show(quizArea);
        hide(quizResults);
        renderQuestion();
      } catch (e) {
        alert('Could not load questions: ' + e.message);
      } finally {
        startBtn.disabled = false;
        startBtn.textContent = '▶ Start Quiz';
      }
    }

    function renderQuestion() {
      const q = questions[current];
      const opts = ['A', 'B', 'C', 'D'];
      answered = false;

      /* Progress */
      const pct = Math.round((current / questions.length) * 100);
      progressFill.style.width = pct + '%';
      progressTxt.textContent = `Question ${current + 1} of ${questions.length}`;
      scoreLive.textContent   = `Score: ${score}/${current}`;

      qCard.innerHTML = '';

      /* Meta */
      const meta = mk('div', 'question-meta');
      meta.appendChild(mk('span', 'question-category', q.category));
      meta.appendChild(mk('span', `difficulty-badge ${q.difficulty}`, q.difficulty));
      qCard.appendChild(meta);

      /* Question text */
      const qtxt = mk('p', 'question-text', q.question);
      qCard.appendChild(qtxt);

      /* Options */
      const optWrap = mk('div', 'answer-options');
      q.options.forEach((opt, idx) => {
        const btn = mk('button', 'answer-option', `${opts[idx]}. ${opt}`);
        btn.addEventListener('click', () => handleAnswer(btn, opts[idx], q));
        optWrap.appendChild(btn);
      });
      qCard.appendChild(optWrap);
    }

    async function handleAnswer(btn, letter, q) {
      if (answered) return;
      answered = true;

      /* Disable all options */
      btn.closest('.answer-options').querySelectorAll('.answer-option').forEach(b => b.disabled = true);

      try {
        const result = await apiPost('/api/training/check', {
          question: q.question,
          answer: letter,
        });

        const correct = result.correct;
        if (correct) {
          score++;
          btn.classList.add('correct');
        } else {
          btn.classList.add('incorrect');
          /* Highlight correct answer */
          const correctIdx = ['A','B','C','D'].indexOf(result.correct_answer.trim().toUpperCase());
          const allBtns = btn.closest('.answer-options').querySelectorAll('.answer-option');
          if (allBtns[correctIdx]) allBtns[correctIdx].classList.add('correct');
        }

        history.push({ question: q.question, correct, category: result.category });

        scoreLive.textContent = `Score: ${score}/${current + 1}`;

        /* Explanation */
        if (result.explanation) {
          const expBox = mk('div', 'explanation-box');
          expBox.appendChild(mk('h4', '', correct ? '✓ Correct!' : '✗ Incorrect'));
          expBox.appendChild(mk('p', '', result.explanation));
          qCard.appendChild(expBox);
        }

        /* Next button */
        setTimeout(() => {
          const nextBtn = mk('button', 'btn btn-primary', current + 1 < questions.length ? 'Next Question →' : 'See Results');
          nextBtn.style.marginTop = '16px';
          nextBtn.addEventListener('click', () => {
            current++;
            if (current < questions.length) {
              renderQuestion();
            } else {
              showResults();
            }
          });
          qCard.appendChild(nextBtn);
        }, 300);

      } catch (e) {
        const errBox = mk('p', 'text-red', 'Error checking answer: ' + e.message);
        qCard.appendChild(errBox);
      }
    }

    function showResults() {
      hide(qCard);
      progressFill.style.width = '100%';
      progressTxt.textContent = 'Complete!';

      const pct = Math.round((score / questions.length) * 100);
      scoreDisp.textContent = `${score} / ${questions.length} (${pct}%)`;
      scoreDisp.className = 'score-display ' + (pct >= 80 ? 'high' : pct >= 50 ? 'medium' : 'low');

      reviewArea.innerHTML = '';
      history.forEach((h, i) => {
        const item = mk('div', `review-item ${h.correct ? 'correct' : 'incorrect'}`);
        item.textContent = `${i + 1}. [${h.category}] ${h.correct ? '✓ Correct' : '✗ Incorrect'}`;
        reviewArea.appendChild(item);
      });

      show(quizResults);
    }

    restartBtn.addEventListener('click', () => {
      hide(quizResults);
      show(quizWelcome);
      qCard.innerHTML = '';
      progressFill.style.width = '0%';
      scoreLive.textContent = 'Score: 0/0';
    });
  }

  /* ══════════════════════════════════════════════════════════════════
     TTP MAPPER
  ══════════════════════════════════════════════════════════════════ */
  function initTTPMapper() {
    const mapBtn     = el('map-btn');
    const behaviorIn = el('behavior-input');
    const resultsDiv = el('mapping-results');
    const listDiv    = el('mapping-list');

    if (!mapBtn) return;

    mapBtn.addEventListener('click', async () => {
      const text = behaviorIn.value.trim();
      if (!text) { behaviorIn.focus(); return; }

      mapBtn.disabled = true;
      mapBtn.textContent = 'Mapping…';
      listDiv.innerHTML = '';
      hide(resultsDiv);

      try {
        const data = await apiPost('/api/ttp/analyze', { behavior: text });

        if (!data.count) {
          listDiv.innerHTML = '<p class="text-muted" style="padding:12px">No techniques matched. Try more specific keywords like: phishing, powershell, lateral, rdp, ransomware, exfil, c2, beacon, brute force, kerberoast, scheduled task.</p>';
          show(resultsDiv);
          return;
        }

        data.mapped_techniques.forEach(t => {
          const item = mk('div', 'mapping-item');

          const hdr = mk('div', 'mapping-item-header');
          hdr.appendChild(mk('span', 'badge badge-cyan', t.technique_id));
          hdr.appendChild(mk('strong', '', t.technique_name));
          hdr.appendChild(mk('span', 'badge badge-gray', t.tactic));
          item.appendChild(hdr);

          item.appendChild(mk('p', 'text-muted', `Keyword matched: "${t.keyword_matched}" | Confidence: ${t.confidence}`));
          listDiv.appendChild(item);
        });

        if (data.note) {
          const note = mk('div', 'alert alert-info', data.note);
          note.style.marginTop = '12px';
          listDiv.appendChild(note);
        }

        show(resultsDiv);
      } catch (e) {
        listDiv.innerHTML = `<p class="text-red">Error: ${esc(e.message)}</p>`;
        show(resultsDiv);
      } finally {
        mapBtn.disabled = false;
        mapBtn.textContent = 'Map to ATT&CK';
      }
    });
  }

  /* ══════════════════════════════════════════════════════════════════
     REPORT BUILDER
  ══════════════════════════════════════════════════════════════════ */
  function initReportBuilder() {
    const form       = el('report-form');
    const formTitle  = el('form-title');
    const dynFields  = el('dynamic-fields');
    const reportOut  = el('report-output');
    const reportCont = el('report-content');
    const copyMdBtn  = el('copy-md-btn');
    const newRptBtn  = el('new-report-btn');

    if (!form) return;

    let currentTemplate = 'incident_response';

    const TEMPLATES = {
      incident_response: {
        title: 'Incident Response Report',
        fields: [
          { id: 'incident_title',   label: 'Incident Title',          type: 'text',     hint: 'e.g. Ransomware Intrusion — Finance Dept' },
          { id: 'date',             label: 'Date Detected',           type: 'text',     hint: 'e.g. 2025-11-14' },
          { id: 'severity',         label: 'Severity',                type: 'text',     hint: 'Critical / High / Medium / Low' },
          { id: 'affected_systems', label: 'Affected Systems',        type: 'textarea', hint: 'List systems or subnets' },
          { id: 'tlp',              label: 'TLP Classification',      type: 'text',     hint: 'TLP:AMBER' },
          { id: 'iocs',             label: 'IOCs (one per line)',      type: 'textarea', hint: 'Paste indicators' },
          { id: 'ttps',             label: 'ATT&CK TTPs (T-IDs)',     type: 'textarea', hint: 'e.g. T1566.001, T1059.001' },
          { id: 'summary',          label: 'Executive Summary',       type: 'textarea', hint: 'Brief narrative of the incident' },
          { id: 'timeline',         label: 'Key Timeline Events',     type: 'textarea', hint: 'Chronological events' },
          { id: 'recommendations',  label: 'Recommendations',         type: 'textarea', hint: 'Immediate and long-term actions' },
        ],
      },
      threat_actor_profile: {
        title: 'Threat Actor Profile',
        fields: [
          { id: 'actor_name',       label: 'Actor Name / Alias',      type: 'text',     hint: 'e.g. APT29 / Cozy Bear' },
          { id: 'origin',           label: 'Suspected Origin',        type: 'text',     hint: 'e.g. Russia' },
          { id: 'motivation',       label: 'Motivation',              type: 'text',     hint: 'e.g. Espionage, Financial' },
          { id: 'tlp',              label: 'TLP Classification',      type: 'text',     hint: 'TLP:AMBER' },
          { id: 'description',      label: 'Actor Description',       type: 'textarea', hint: 'Summary of actor history and capabilities' },
          { id: 'ttps',             label: 'Known TTPs',              type: 'textarea', hint: 'ATT&CK technique IDs used by this actor' },
          { id: 'targeting',        label: 'Targeting',               type: 'textarea', hint: 'Industries and geographies targeted' },
          { id: 'iocs',             label: 'Known IOCs',              type: 'textarea', hint: 'Infrastructure or file indicators' },
        ],
      },
      ioc_bulletin: {
        title: 'IOC Bulletin',
        fields: [
          { id: 'bulletin_title',   label: 'Bulletin Title',          type: 'text',     hint: 'e.g. Campaign IOC Alert — Nov 2025' },
          { id: 'date',             label: 'Date',                    type: 'text',     hint: 'e.g. 2025-11-14' },
          { id: 'tlp',              label: 'TLP Classification',      type: 'text',     hint: 'TLP:AMBER' },
          { id: 'source',           label: 'Intelligence Source',     type: 'text',     hint: 'e.g. Australian Phoenix CyberOps' },
          { id: 'iocs',             label: 'IOC List (one per line)', type: 'textarea', hint: 'Paste defanged IOCs' },
          { id: 'context',          label: 'Campaign Context',        type: 'textarea', hint: 'Brief description of the campaign' },
          { id: 'action',           label: 'Recommended Action',      type: 'textarea', hint: 'What recipients should do with these IOCs' },
        ],
      },
      vulnerability_alert: {
        title: 'Vulnerability Alert',
        fields: [
          { id: 'cve',              label: 'CVE ID',                  type: 'text',     hint: 'e.g. CVE-2024-12345' },
          { id: 'cvss',             label: 'CVSS Score',              type: 'text',     hint: 'e.g. 9.8 Critical' },
          { id: 'date',             label: 'Date',                    type: 'text',     hint: 'e.g. 2025-11-14' },
          { id: 'tlp',              label: 'TLP Classification',      type: 'text',     hint: 'TLP:CLEAR' },
          { id: 'product',          label: 'Affected Product',        type: 'text',     hint: 'e.g. Apache Log4j 2.x' },
          { id: 'description',      label: 'Vulnerability Description', type: 'textarea', hint: 'Technical description' },
          { id: 'exploitation',     label: 'Exploitation Status',     type: 'text',     hint: 'e.g. Actively exploited in the wild' },
          { id: 'iocs',             label: 'Related IOCs',            type: 'textarea', hint: 'Exploitation indicators' },
          { id: 'remediation',      label: 'Remediation Steps',       type: 'textarea', hint: 'Patch, mitigate, or workaround steps' },
        ],
      },
    };

    function loadTemplate(templateKey) {
      currentTemplate = templateKey;
      const tmpl = TEMPLATES[templateKey];
      if (!tmpl) return;
      formTitle.textContent = tmpl.title;
      dynFields.innerHTML = '';
      tmpl.fields.forEach(f => {
        const wrap = mk('div', 'form-field');
        const lbl = mk('label', 'field-label', f.label);
        lbl.htmlFor = 'field-' + f.id;
        wrap.appendChild(lbl);
        let input;
        if (f.type === 'textarea') {
          input = mk('textarea', 'field-textarea');
          input.rows = 3;
        } else {
          input = mk('input', 'field-input');
          input.type = 'text';
        }
        input.id = 'field-' + f.id;
        input.placeholder = f.hint || '';
        wrap.appendChild(input);
        dynFields.appendChild(wrap);
      });
    }

    document.querySelectorAll('.template-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.template-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        loadTemplate(btn.dataset.template);
        hide(reportOut);
      });
    });

    document.querySelectorAll('.actor-item').forEach(item => {
      item.addEventListener('click', async () => {
        loadTemplate('threat_actor_profile');
        document.querySelectorAll('.template-btn').forEach(b => b.classList.remove('active'));
        document.querySelector('[data-template="threat_actor_profile"]')?.classList.add('active');
        try {
          const actor = await apiGet('/api/report/actor/' + item.dataset.actor);
          const setField = (id, val) => { const f = el('field-' + id); if (f) f.value = val || ''; };
          setField('actor_name', (actor.name || '') + (actor.aliases ? ' / ' + actor.aliases.join(', ') : ''));
          setField('origin', actor.origin);
          setField('motivation', actor.motivation);
          setField('description', actor.description);
          setField('ttps', (actor.ttps || []).join(', '));
          setField('targeting', (actor.targeting || []).join(', '));
        } catch (e) { console.error(e); }
      });
    });

    form.addEventListener('submit', e => {
      e.preventDefault();
      const tmpl = TEMPLATES[currentTemplate];
      const data = {};
      tmpl.fields.forEach(f => {
        const input = el('field-' + f.id);
        if (input) data[f.id] = input.value.trim();
      });

      /* Build markdown report */
      const lines = ['═'.repeat(60), `# ${tmpl.title}`, `**${data.tlp || 'TLP:AMBER'}** | ${data.date || new Date().toISOString().split('T')[0]}`, '', '---', ''];

      tmpl.fields.filter(f => f.id !== 'tlp' && f.id !== 'date').forEach(f => {
        if (data[f.id]) {
          lines.push(`## ${f.label}`);
          if (f.type === 'textarea') {
            data[f.id].split('\n').filter(Boolean).forEach(l => lines.push('- ' + l));
          } else {
            lines.push(data[f.id]);
          }
          lines.push('');
        }
      });
      lines.push('---');
      lines.push(`*Produced by Australian Phoenix CyberOps — ${data.tlp || 'TLP:AMBER'}*`);

      reportCont.textContent = lines.join('\n');
      hide(el('report-form-area'));
      show(reportOut);
    });

    copyMdBtn.addEventListener('click', () => copyBtn(copyMdBtn, reportCont.textContent));
    newRptBtn.addEventListener('click', () => {
      hide(reportOut);
      show(el('report-form-area'));
    });

    /* Load default template */
    loadTemplate('incident_response');
  }

  /* ══════════════════════════════════════════════════════════════════
     DEFANG TOOL
  ══════════════════════════════════════════════════════════════════ */
  function initDefang() {
    const quickInput    = el('quick-ioc-input');
    const quickResult   = el('quick-result');
    const quickTxt      = el('quick-result-text');
    const qDefangBtn    = el('quick-defang-btn');
    const qRefangBtn    = el('quick-refang-btn');
    const qCopyBtn      = el('quick-copy-btn');
    const bulkInput     = el('bulk-input');
    const bulkOutput    = el('bulk-output');
    const defangBtn     = el('defang-btn');
    const refangBtn     = el('refang-btn');
    const copyOutBtn    = el('copy-output-btn');
    const clearInBtn    = el('clear-input-btn');
    const clearOutBtn   = el('clear-output-btn');
    const charCount     = el('input-char-count');
    const loadSampleBtn = el('load-sample-btn');

    if (!qDefangBtn) return;

    /* EDR-safe sample using RFC 5737 documentation IPs */
    const SAMPLE = [
      'Threat Intelligence Report — TLP:AMBER',
      'Source: Australian Phoenix CyberOps | Date: 2025-11-15',
      '',
      'Campaign: Ransomware group targeting healthcare (educational example).',
      '',
      'C2 Infrastructure (FICTIONAL — RFC 5737 documentation range):',
      '  203.0.113.47',
      '  198.51.100.22',
      '  http://c2-example.test/loader.bin',
      '  https://exfil-example.test/upload',
      '',
      'Contact: actor@phish-example.test',
      '',
      'File hashes (FICTIONAL):',
      '  SHA256: 0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b',
      '',
      'CVEs referenced: CVE-2021-44228, CVE-2022-30190',
      '',
      'TLP:AMBER — Do not share beyond direct partners.',
    ].join('\n');

    /* Example quick buttons */
    document.querySelectorAll('.example-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        quickInput.value = btn.dataset.val;
        hide(quickResult);
      });
    });

    if (loadSampleBtn) loadSampleBtn.addEventListener('click', () => {
      bulkInput.value = SAMPLE;
      updateCount();
    });

    function updateCount() {
      if (charCount) charCount.textContent = bulkInput.value.length.toLocaleString() + ' characters';
    }
    if (bulkInput) bulkInput.addEventListener('input', updateCount);

    /* Client-side fallbacks */
    function clientDefang(t) {
      t = t.replace(/https?:\/\//gi, m => m.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://');
      t = t.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, '$1[.]$2[.]$3[.]$4');
      t = t.replace(/([a-zA-Z0-9._%+\-]+)@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/g, '$1[@]$2');
      t = t.replace(/(?<=[a-zA-Z0-9])\./g, '[.]');
      return t;
    }
    function clientRefang(t) {
      t = t.replace(/\[\.\]/g, '.').replace(/\[dot\]/gi, '.').replace(/\(dot\)/gi, '.');
      t = t.replace(/\[@\]/g, '@').replace(/\[at\]/gi, '@').replace(/\(at\)/gi, '@');
      t = t.replace(/hxxps?:\/\//gi, m => m.toLowerCase().includes('hxxps') ? 'https://' : 'http://');
      return t;
    }

    async function callAPI(route, text) {
      try {
        const d = await apiPost(route, { text });
        return d.success ? d.result : null;
      } catch { return null; }
    }

    /* Quick single */
    qDefangBtn.addEventListener('click', async () => {
      const v = quickInput.value.trim();
      if (!v) return;
      const r = await callAPI('/api/defang', v) || clientDefang(v);
      quickTxt.textContent = r;
      show(quickResult);
    });

    qRefangBtn.addEventListener('click', async () => {
      const v = quickInput.value.trim();
      if (!v) return;
      const r = await callAPI('/api/refang', v) || clientRefang(v);
      quickTxt.textContent = r;
      show(quickResult);
    });

    quickInput.addEventListener('keydown', e => { if (e.key === 'Enter') qDefangBtn.click(); });

    if (qCopyBtn) qCopyBtn.addEventListener('click', () => quickTxt.textContent && copyBtn(qCopyBtn, quickTxt.textContent));

    /* Bulk */
    function setOutput(text) {
      if (bulkOutput) bulkOutput.textContent = text;
    }

    if (defangBtn) defangBtn.addEventListener('click', async () => {
      const text = bulkInput.value;
      if (!text.trim()) return;
      defangBtn.disabled = true;
      defangBtn.textContent = 'Defanging…';
      const r = await callAPI('/api/defang', text) || clientDefang(text);
      setOutput(r);
      defangBtn.disabled = false;
      defangBtn.innerHTML = '🛡 Defang All IOCs<span class="btn-sub">Safe for sharing</span>';
    });

    if (refangBtn) refangBtn.addEventListener('click', async () => {
      const text = bulkInput.value;
      if (!text.trim()) return;
      refangBtn.disabled = true;
      refangBtn.textContent = 'Re-fanging…';
      const r = await callAPI('/api/refang', text) || clientRefang(text);
      setOutput(r);
      refangBtn.disabled = false;
      refangBtn.innerHTML = '🔍 Re-fang All IOCs<span class="btn-sub">Ready for analysis</span>';
    });

    if (copyOutBtn) copyOutBtn.addEventListener('click', () => copyBtn(copyOutBtn, bulkOutput ? bulkOutput.textContent : ''));
    if (clearInBtn)  clearInBtn.addEventListener('click',  () => { bulkInput.value = ''; updateCount(); });
    if (clearOutBtn) clearOutBtn.addEventListener('click', () => {
      if (bulkOutput) bulkOutput.innerHTML = '<div class="output-placeholder"><span class="output-placeholder-icon">⚙</span><p>Click Defang or Re-fang to process</p></div>';
    });
  }

  /* ══════════════════════════════════════════════════════════════════
     CTI TOOLKIT
  ══════════════════════════════════════════════════════════════════ */
  function initToolkit() {
    /* Nav switching */
    document.querySelectorAll('.toolkit-nav-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.toolkit-nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.toolkit-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const panel = el('tool-' + btn.dataset.tool);
        if (panel) panel.classList.add('active');
      });
    });

    initBase64(); initHex(); initUrlCodec(); initEntropy();
    initHashId(); initTimestamp(); initIPTools(); initDedup();
    initTLPStamper(); initHuntBuilder(); initYARA(); initSigma();
  }

  /* ─ Base64 ──────────────────────────────────────────────────────── */
  function initBase64() {
    const inp = el('b64-input'), out = el('b64-output');
    if (!inp) return;
    el('b64-encode-btn').addEventListener('click', () => {
      try { out.textContent = btoa(unescape(encodeURIComponent(inp.value))); }
      catch(e) { out.textContent = 'Error: ' + e.message; }
    });
    el('b64-decode-btn').addEventListener('click', () => {
      try { out.textContent = decodeURIComponent(escape(atob(inp.value.trim()))); }
      catch(e) { out.textContent = 'Error: Invalid Base64 — ' + e.message; }
    });
    el('b64-copy-btn').addEventListener('click', () => copyBtn(el('b64-copy-btn'), out.textContent));
    el('b64-clear-btn').addEventListener('click', () => { inp.value = ''; out.textContent = 'Result will appear here…'; });
  }

  /* ─ Hex ─────────────────────────────────────────────────────────── */
  function initHex() {
    const inp = el('hex-input'), out = el('hex-output');
    if (!inp) return;
    el('hex-encode-btn').addEventListener('click', () => {
      try { out.textContent = Array.from(new TextEncoder().encode(inp.value)).map(b=>b.toString(16).padStart(2,'0')).join(''); }
      catch(e) { out.textContent = 'Error: ' + e.message; }
    });
    el('hex-decode-btn').addEventListener('click', () => {
      try {
        const clean = inp.value.replace(/\s+/g,'').replace(/^0x/i,'');
        if (!clean || clean.length % 2 !== 0) throw new Error('Odd length hex string');
        const bytes = clean.match(/.{1,2}/g).map(b => parseInt(b,16));
        out.textContent = new TextDecoder().decode(new Uint8Array(bytes));
      } catch(e) { out.textContent = 'Error: ' + e.message; }
    });
    el('hex-bytes-btn').addEventListener('click', () => {
      try {
        const clean = inp.value.replace(/\s+/g,'').replace(/^0x/i,'');
        out.textContent = (clean.match(/.{1,2}/g)||[]).map((b,i)=>`0x${b} [${parseInt(b,16).toString().padStart(3)}]${(i+1)%8===0?'\n':' '}`).join('');
      } catch(e) { out.textContent = 'Error: ' + e.message; }
    });
    el('hex-copy-btn').addEventListener('click', () => copyBtn(el('hex-copy-btn'), out.textContent));
  }

  /* ─ URL Codec ───────────────────────────────────────────────────── */
  function initUrlCodec() {
    const inp = el('url-input'), out = el('url-output');
    if (!inp) return;
    el('url-encode-btn').addEventListener('click', () => { try { out.textContent = encodeURIComponent(inp.value); } catch(e) { out.textContent='Error: '+e.message; } });
    el('url-decode-btn').addEventListener('click', () => { try { out.textContent = decodeURIComponent(inp.value); } catch(e) { out.textContent='Error: '+e.message; } });
    el('url-full-encode-btn').addEventListener('click', () => {
      try { out.textContent = Array.from(inp.value).map(c=>'%'+c.charCodeAt(0).toString(16).padStart(2,'0').toUpperCase()).join(''); }
      catch(e) { out.textContent='Error: '+e.message; }
    });
    el('url-copy-btn').addEventListener('click', () => copyBtn(el('url-copy-btn'), out.textContent));
  }

  /* ─ Entropy ─────────────────────────────────────────────────────── */
  function initEntropy() {
    const btn = el('entropy-calc-btn');
    if (!btn) return;
    btn.addEventListener('click', () => {
      const text = el('entropy-input').value;
      if (!text) return;
      const freq = {};
      for (const ch of text) freq[ch] = (freq[ch]||0) + 1;
      let entropy = 0;
      for (const c of Object.values(freq)) { const p = c/text.length; if (p>0) entropy -= p*Math.log2(p); }
      const score = entropy.toFixed(4);
      el('entropy-score').textContent = score;
      el('entropy-len').textContent = text.length.toLocaleString();
      el('entropy-unique').textContent = Object.keys(freq).length;
      el('entropy-bar').style.width = Math.min(100,(entropy/8)*100)+'%';
      const v = el('entropy-verdict'), x = el('entropy-explanation');
      if (entropy < 3.5)      { v.className='badge badge-green';  v.textContent='Low'; x.className='alert alert-success mt-4'; x.textContent=`${score}: Natural language text — unlikely encrypted or packed.`; }
      else if (entropy < 4.5) { v.className='badge badge-gray';   v.textContent='Medium'; x.className='alert alert-info mt-4'; x.textContent=`${score}: Mixed content — code, URLs, or passwords. Review manually.`; }
      else if (entropy < 5.5) { v.className='badge badge-amber';  v.textContent='HIGH — Possible Encoding'; x.className='alert alert-warning mt-4'; x.textContent=`${score}: HIGH — likely Base64, hex, or compressed data. Attempt decode.`; }
      else                    { v.className='badge badge-red';    v.textContent='VERY HIGH — Encrypted?'; x.className='alert alert-danger mt-4'; x.textContent=`${score}: VERY HIGH — strong indicator of encryption or packing. Analyse in sandbox.`; }
      show(el('entropy-result'));
    });
  }

  /* ─ Hash Identifier ─────────────────────────────────────────────── */
  function initHashId() {
    const btn = el('hashid-btn');
    if (!btn) return;
    const TYPES = [
      {len:32,  name:'MD5',    note:'Weak — collisions known. Use SHA256 for verification.'},
      {len:40,  name:'SHA1',   note:'Deprecated for crypto. Still in many legacy CTI feeds.'},
      {len:56,  name:'SHA224', note:'SHA-2 family — rarely seen in CTI.'},
      {len:64,  name:'SHA256', note:'Current CTI standard for file identification.'},
      {len:96,  name:'SHA384', note:'SHA-2 family — uncommon.'},
      {len:128, name:'SHA512', note:'SHA-2 family — very rare in CTI feeds.'},
    ];
    btn.addEventListener('click', () => {
      const lines = el('hashid-input').value.split('\n').map(l=>l.trim()).filter(Boolean);
      if (!lines.length) return;
      const tbody = el('hashid-tbody');
      tbody.innerHTML = '';
      lines.slice(0,100).forEach(hash => {
        const isHex = /^[0-9a-fA-F]+$/.test(hash);
        const matches = isHex ? TYPES.filter(t=>t.len===hash.length) : [];
        const tr = document.createElement('tr');
        const disp = hash.length > 20 ? hash.substring(0,10)+'…'+hash.substring(hash.length-8) : hash;
        const typStr = matches.length ? matches.map(m=>`<span class="badge badge-amber">${m.name}</span>`).join(' ') : '<span class="badge badge-red">Unknown</span>';
        const note = matches.length ? matches[0].note : (!isHex ? 'Not a hex string' : 'Unusual length');
        tr.innerHTML = `<td style="font-family:monospace;font-size:0.78rem">${esc(disp)}</td><td>${typStr}</td><td>${hash.length}</td><td style="font-size:0.8rem;color:var(--text-secondary)">${esc(note)}</td>`;
        tbody.appendChild(tr);
      });
      show(el('hashid-results'));
    });
  }

  /* ─ Timestamp ───────────────────────────────────────────────────── */
  function initTimestamp() {
    const btn = el('ts-convert-btn');
    if (!btn) return;
    const FT_OFFSET = 11644473600000;

    function convert(ms) {
      const d = new Date(ms);
      el('ts-epoch').value    = Math.floor(ms/1000);
      el('ts-iso').value      = d.toISOString();
      el('ts-epoch-ms').value = ms;
      try { el('ts-filetime').value = (BigInt(Math.floor(ms)+FT_OFFSET)*10000n).toString(); } catch{}
      const body = el('ts-table-body');
      body.innerHTML = `<table class="data-table"><thead><tr><th>Format</th><th>Value</th><th>Notes</th></tr></thead><tbody>
<tr><td>Unix Epoch (s)</td><td class="mono">${Math.floor(ms/1000)}</td><td>Standard POSIX time</td></tr>
<tr><td>Unix Epoch (ms)</td><td class="mono">${ms}</td><td>JavaScript / Java</td></tr>
<tr><td>ISO 8601 UTC</td><td class="mono">${d.toISOString()}</td><td>Syslog, STIX, CTI reports</td></tr>
<tr><td>Human Readable</td><td class="mono">${d.toLocaleString()}</td><td>Local time</td></tr>
<tr><td>Windows FILETIME</td><td class="mono">${el('ts-filetime').value}</td><td>NTFS, Registry, Prefetch, ETW</td></tr>
<tr><td>RFC 2822</td><td class="mono">${d.toUTCString()}</td><td>Email Date: header</td></tr>
<tr><td>Day of Week</td><td class="mono">${d.toLocaleDateString('en-AU',{weekday:'long'})}</td><td>Threat actor working hours</td></tr>
</tbody></table>`;
      show(el('ts-results'));
    }

    btn.addEventListener('click', () => {
      try {
        const e=el('ts-epoch').value.trim(), m=el('ts-epoch-ms').value.trim(),
              i=el('ts-iso').value.trim(),   f=el('ts-filetime').value.trim();
        if (e)      convert(parseInt(e)*1000);
        else if (m) convert(parseInt(m));
        else if (i) convert(new Date(i).getTime());
        else if (f) { try { convert(Number(BigInt(f)/10000n)-FT_OFFSET); } catch(ex) { convert(Date.now()); } }
        else        convert(Date.now());
      } catch(ex) { el('ts-table-body').textContent='Error: '+ex.message; show(el('ts-results')); }
    });
    el('ts-now-btn').addEventListener('click', () => convert(Date.now()));
    el('ts-clear-btn').addEventListener('click', () => {
      ['ts-epoch','ts-iso','ts-epoch-ms','ts-filetime'].forEach(id=>{const e=el(id);if(e)e.value='';});
      hide(el('ts-results'));
    });
  }

  /* ─ IP Tools ────────────────────────────────────────────────────── */
  function initIPTools() {
    const anaBtn = el('ip-analyse-btn');
    if (!anaBtn) return;

    function parseIPv4(str) {
      const p = str.trim().split('.').map(Number);
      if (p.length!==4 || p.some(x=>isNaN(x)||x<0||x>255)) return null;
      return p;
    }
    function ipInt(p) { return ((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3])>>>0; }
    function classify(p) {
      const [a,b] = p;
      if (a===10) return {type:'Private (RFC1918)',note:'Internal — 10.0.0.0/8'};
      if (a===172&&b>=16&&b<=31) return {type:'Private (RFC1918)',note:'Internal — 172.16.0.0/12'};
      if (a===192&&b===168) return {type:'Private (RFC1918)',note:'Internal — 192.168.0.0/16'};
      if (a===127) return {type:'Loopback',note:'localhost'};
      if (a===169&&b===254) return {type:'Link-local (APIPA)',note:'Auto-assigned'};
      if (a===0) return {type:'Reserved',note:'Unspecified address'};
      if (a>=224&&a<=239) return {type:'Multicast',note:'RFC 5771'};
      if (a>=240) return {type:'Reserved',note:'RFC 1112'};
      if (a===100&&b>=64&&b<=127) return {type:'Shared Address (CGN)',note:'RFC 6598'};
      if (a===192&&b===0&&p[2]===2) return {type:'Documentation (RFC 5737)',note:'Not for production use'};
      if (a===198&&b===51&&p[2]===100) return {type:'Documentation (RFC 5737)',note:'Not for production use'};
      if (a===203&&b===0&&p[2]===113) return {type:'Documentation (RFC 5737)',note:'Not for production use'};
      return {type:'Public',note:'Routable — check threat intel feeds'};
    }

    anaBtn.addEventListener('click', () => {
      const inp = el('ip-input').value.trim();
      const p = parseIPv4(inp);
      const card = el('ip-result-card');
      if (!p) { card.innerHTML='<p class="text-red">Invalid IPv4 address.</p>'; show(el('ip-results')); return; }
      const cls = classify(p);
      card.innerHTML = `<h3 style="margin-bottom:14px">Analysis: <span class="mono text-amber">${esc(inp)}</span></h3>
<table class="data-table"><tbody>
<tr><td>Classification</td><td><span class="badge ${cls.type==='Public'?'badge-cyan':'badge-green'}">${esc(cls.type)}</span></td></tr>
<tr><td>Notes</td><td style="color:var(--text-secondary)">${esc(cls.note)}</td></tr>
<tr><td>Defanged</td><td class="mono text-amber">${esc(inp.replace(/\./g,'[.]'))}</td></tr>
<tr><td>Decimal</td><td class="mono">${ipInt(p)}</td></tr>
<tr><td>Hex</td><td class="mono">0x${p.map(x=>x.toString(16).padStart(2,'0')).join('')}</td></tr>
<tr><td>Reverse DNS</td><td class="mono">${[...p].reverse().join('.')}.in-addr.arpa</td></tr>
<tr><td>Threat Intel</td><td>${cls.type==='Public'?'<span class="badge badge-amber">Check VirusTotal, AbuseIPDB, Shodan</span>':'<span class="badge badge-gray">Private/Reserved — N/A</span>'}</td></tr>
</tbody></table>`;
      show(el('ip-results'));
    });

    el('ip-defang-btn').addEventListener('click', () => {
      const v = el('ip-input').value.trim();
      el('ip-result-card').innerHTML = `<p class="mono text-amber" style="padding:8px">${esc(v.replace(/\./g,'[.]'))}</p>`;
      show(el('ip-results'));
    });
    el('ip-clear-btn').addEventListener('click', () => { el('ip-input').value=''; hide(el('ip-results')); });

    const cidrBtn = el('cidr-check-btn');
    if (cidrBtn) cidrBtn.addEventListener('click', () => {
      const r = el('cidr-result');
      try {
        const ip = parseIPv4(el('cidr-ip').value.trim());
        const [rng,pfx] = el('cidr-range').value.trim().split('/');
        const rngP = parseIPv4(rng);
        if (!ip||!rngP||!pfx) throw new Error('Invalid input');
        const bits = parseInt(pfx);
        const mask = bits===0 ? 0 : (~0<<(32-bits))>>>0;
        const isIn = (ipInt(ip)&mask)===(ipInt(rngP)&mask);
        r.className = `alert ${isIn?'alert-success':'alert-danger'} mt-4`;
        r.textContent = isIn ? `✓ ${el('cidr-ip').value.trim()} IS within ${el('cidr-range').value.trim()}` : `✗ ${el('cidr-ip').value.trim()} is NOT in ${el('cidr-range').value.trim()}`;
        show(r);
      } catch(e) { r.className='alert alert-danger mt-4'; r.textContent='Error: '+e.message; show(r); }
    });
  }

  /* ─ IOC Deduplicator ────────────────────────────────────────────── */
  function initDedup() {
    const inp = el('dedup-input'), out = el('dedup-output'), btn = el('dedup-btn');
    if (!btn) return;
    function updIn() { const n=inp.value.split('\n').filter(l=>l.trim()).length; el('dedup-count-in').textContent=n+' entries'; }
    inp.addEventListener('input', updIn);
    btn.addEventListener('click', () => {
      let lines = inp.value.split('\n');
      if (el('dedup-ignore-blank').checked) lines=lines.filter(l=>l.trim());
      if (el('dedup-strip-quotes').checked) lines=lines.map(l=>l.replace(/["'`]/g,'').trim());
      if (el('dedup-lowercase').checked)    lines=lines.map(l=>l.toLowerCase());
      const total=lines.length, unique=[...new Set(lines.map(l=>l.trim()).filter(Boolean))].sort(), removed=total-unique.length;
      out.textContent = unique.join('\n');
      el('dedup-count-out').textContent = unique.length+' unique entries';
      el('dedup-stat-total').textContent  = 'Total: '+total;
      el('dedup-stat-unique').textContent = 'Unique: '+unique.length;
      el('dedup-stat-removed').textContent= 'Duplicates removed: '+removed;
      show(el('dedup-stats'));
    });
    el('dedup-copy-out').addEventListener('click', () => copyBtn(el('dedup-copy-out'), out.textContent));
    el('dedup-clear-in').addEventListener('click', () => { inp.value=''; updIn(); out.innerHTML='<div class="output-placeholder"><span class="output-placeholder-icon">⬡</span><p>Click Deduplicate to process</p></div>'; hide(el('dedup-stats')); });
  }

  /* ─ TLP Stamper ─────────────────────────────────────────────────── */
  function initTLPStamper() {
    const btn = el('tlp-stamp-btn');
    if (!btn) return;
    const DEFS = {
      'CLEAR':'Disclosure not limited.',
      'GREEN':'Share within community — not via public channels.',
      'AMBER':'Share within your organisation and direct partners.',
      'AMBER+STRICT':'Share within your organisation only.',
      'RED':'Named recipients only — no further disclosure.',
    };
    btn.addEventListener('click', () => {
      const tlp=el('tlp-select').value, src=el('tlp-source').value.trim(), txt=el('tlp-input').value, date=new Date().toISOString().split('T')[0];
      const line='═'.repeat(60);
      const out=`${line}\nTLP:${tlp}\n${DEFS[tlp]||''}\n${src?'Source: '+src:''}\nDate: ${date}\n${line}\n\n${txt}\n\n${line}\nTLP:${tlp} — Handle per FIRST TLP 2.0\n${src?'Produced by: '+src:'Produced by: Australian Phoenix CyberOps'}\n${line}`;
      el('tlp-output').textContent = out;
      show(el('tlp-output-wrap'));
    });
    el('tlp-copy-btn').addEventListener('click', () => copyBtn(el('tlp-copy-btn'), el('tlp-output').textContent));
    el('tlp-clear-btn').addEventListener('click', () => { el('tlp-input').value=''; hide(el('tlp-output-wrap')); });
  }

  /* ─ Hunt Query Builder ──────────────────────────────────────────── */
  function initHuntBuilder() {
    const btn = el('hb-generate-btn');
    if (!btn) return;

    btn.addEventListener('click', () => {
      const type=el('hb-type').value, ctx=el('hb-context').value;
      const name=(el('hb-rulename').value.trim()||'PhoenixCTI_Hunt').replace(/[^a-zA-Z0-9_]/g,'_');
      const iocs=[...new Set(el('hb-iocs').value.split('\n').map(l=>l.trim().replace(/["']/g,'')).filter(Boolean))].slice(0,50);
      if (!iocs.length) return;

      const fields = {
        ip:     {splunk:{network:'dest_ip',endpoint:'RemoteIP',dns:'query',email:'src_ip',proxy:'c-ip'},        kql:'RemoteIP',          sigma:'DestinationIp',   elastic:'destination.ip'},
        domain: {splunk:{network:'query',endpoint:'query',dns:'query',email:'sender_domain',proxy:'cs-host'}, kql:'RemoteUrl',         sigma:'QueryName',       elastic:'dns.question.name'},
        sha256: {splunk:{network:'sha256',endpoint:'sha256',dns:'sha256',email:'sha256',proxy:'sha256'},        kql:'SHA256',            sigma:'sha256',          elastic:'file.hash.sha256'},
        md5:    {splunk:{network:'md5',endpoint:'md5',dns:'md5',email:'md5',proxy:'md5'},                       kql:'MD5',               sigma:'md5',             elastic:'file.hash.md5'},
        url:    {splunk:{network:'url',endpoint:'url',dns:'url',email:'url',proxy:'cs-uri'},                    kql:'RemoteUrl',         sigma:'RequestURL',      elastic:'url.full'},
        email:  {splunk:{network:'sender',endpoint:'sender',dns:'sender',email:'sender',proxy:'sender'},        kql:'SenderFromAddress', sigma:'SenderAddress',   elastic:'email.from.address'},
      };
      const f = fields[type]||fields.ip;
      const sf = (f.splunk[ctx])||'dest';
      const date = new Date().toISOString().split('T')[0];
      const list = iocs.map(i=>`"${i}"`).join(', ');
      const listNQ= iocs.map(i=>`      - '${i}'`).join('\n');
      const listKQL=iocs.map(i=>`        "${i}"`).join(',\n');

      const queries = {
        'Splunk SPL': `/* ${name} | Australian Phoenix CyberOps | ${date} */\nindex=* ${sf} IN (${list})\n| stats count by ${sf}, src_ip, dest_ip, _time\n| sort - count`,
        'KQL (Sentinel)': `// ${name} | Australian Phoenix CyberOps | ${date}\nlet indicators = dynamic([\n${listKQL}\n]);\nDeviceNetworkEvents\n| where ${f.kql} in (indicators)\n| project Timestamp, DeviceName, InitiatingProcessFileName, ${f.kql}\n| order by Timestamp desc`,
        'Sigma YAML': `title: ${name}\nstatus: experimental\ndate: ${date}\nauthor: Australian Phoenix CyberOps\ndescription: 'CTI-generated detection rule'\nlogsource:\n  category: ${ctx.replace(/_/g,' ')}\ndetection:\n  selection:\n    ${f.sigma}:\n${listNQ}\n  condition: selection\nlevel: high`,
        'Elastic EQL': `// ${name} | Australian Phoenix CyberOps | ${date}\n[network where ${f.elastic} in (\n  ${iocs.map(i=>`"${i}"`).join(',\n  ')}\n)]`,
        'QRadar AQL': `/* ${name} | Australian Phoenix CyberOps | ${date} */\nSELECT sourceip, destinationip, starttime\nFROM events\nWHERE ${sf} IN (${list})\nLAST 7 DAYS ORDER BY starttime DESC`,
        'YARA Hash Rule': type==='sha256'||type==='md5'
          ? `rule ${name} {\n  meta:\n    author = "Australian Phoenix CyberOps"\n    date = "${date}"\n  strings:\n${iocs.slice(0,10).map((h,i)=>`    $h${i+1} = "${h}"`).join('\n')}\n  condition:\n    any of them\n}`
          : `/* YARA hash rules only apply to MD5 and SHA256 types */`,
      };

      const tabsEl=el('hb-tabs'), contsEl=el('hb-contents');
      tabsEl.innerHTML=''; contsEl.innerHTML='';

      Object.entries(queries).forEach(([label,query],i) => {
        const tab = mk('button','hunt-tab'+(i===0?' active':''), label);
        const uid = 'hq'+i;
        tab.addEventListener('click', () => {
          document.querySelectorAll('.hunt-tab').forEach(t=>t.classList.remove('active'));
          document.querySelectorAll('.hunt-content').forEach(c=>c.classList.remove('active'));
          tab.classList.add('active');
          el(uid+'c').classList.add('active');
        });
        tabsEl.appendChild(tab);

        const div = mk('div','hunt-content'+(i===0?' active':''));
        div.id=uid+'c';
        const cpb = mk('button','btn btn-ghost btn-sm','Copy');
        cpb.addEventListener('click', () => copyBtn(cpb, query));
        div.appendChild(cpb);
        const code = mk('div','code-block');
        code.id=uid; code.style.cssText='white-space:pre;overflow-x:auto;margin-top:8px';
        code.textContent=query;
        div.appendChild(code);
        contsEl.appendChild(div);
      });

      show(el('hb-output'));
    });
  }

  /* ─ YARA Generator ──────────────────────────────────────────────── */
  function initYARA() {
    const btn = el('yara-generate-btn');
    if (!btn) return;
    btn.addEventListener('click', () => {
      const name=(el('yara-name').value.trim()||'PhoenixCTI_Rule').replace(/[^a-zA-Z0-9_]/g,'_');
      const author=el('yara-author').value.trim()||'Australian Phoenix CyberOps';
      const hashes=el('yara-hashes').value.split('\n').map(l=>l.trim()).filter(l=>l&&/^[0-9a-fA-F]{32,128}$/.test(l));
      const strs  =el('yara-strings').value.split('\n').map(l=>l.trim()).filter(Boolean);
      const hexP  =el('yara-hex').value.split('\n').map(l=>l.trim()).filter(Boolean);
      const tlp   =el('yara-tlp').value;
      const date  =new Date().toISOString().split('T')[0];

      const defs=[];
      hashes.forEach((h,i)=>{ const t=h.length===32?'md5':h.length===40?'sha1':'sha256'; defs.push(`        $${t}_${i+1} = "${h}"`); });
      strs.forEach((s,i)=>  defs.push(`        $str_${i+1} = "${s.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}" ascii wide nocase`));
      hexP.forEach((h,i)=>  defs.push(`        $hex_${i+1} = { ${h} }`));

      const rule=`/*\n * ${name}\n * Author: ${author}\n * Date: ${date}\n * ${tlp}\n */\n\nrule ${name}\n{\n    meta:\n        author   = "${author}"\n        date     = "${date}"\n        tlp      = "${tlp}"\n        tool     = "Phoenix CTI Forge v2.1"\n\n    strings:\n${defs.join('\n') || '        // No strings defined'}\n\n    condition:\n        ${defs.length ? 'any of them' : 'false /* add indicators above */'}\n}\n`;

      el('yara-code').textContent=rule;
      show(el('yara-output'));
    });
    el('yara-copy-btn').addEventListener('click', () => copyBtn(el('yara-copy-btn'), el('yara-code').textContent));
  }

  /* ─ Sigma Generator ─────────────────────────────────────────────── */
  function initSigma() {
    const btn = el('sig-generate-btn');
    if (!btn) return;
    btn.addEventListener('click', () => {
      const title =el('sig-title').value.trim()||'Phoenix CTI Detection';
      const cat   =el('sig-category').value;
      const level =el('sig-level').value;
      const attack=el('sig-attack').value.trim();
      const desc  =el('sig-desc').value.trim()||'CTI-generated detection rule';
      const values=el('sig-values').value.split('\n').map(l=>l.trim().replace(/["']/g,'')).filter(Boolean);
      const date  =new Date().toISOString().split('T')[0];
      const fields={network_connection:'DestinationIp',dns_query:'QueryName',process_creation:'CommandLine',file_event:'TargetFilename',registry_event:'TargetObject',webserver:'cs-uri-query',firewall:'DestinationIp'};
      const field=fields[cat]||'value';
      const tags=attack?`\n  - attack.${attack.toLowerCase().replace('.','_')}`:'';
      const uid=()=>'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>{const r=Math.random()*16|0;return(c==='x'?r:(r&0x3|0x8)).toString(16);});

      const rule=`title: ${title}\nid: ${uid()}\nstatus: experimental\ndate: ${date}\nauthor: Australian Phoenix CyberOps\ndescription: '${desc}'\ntags:\n  - attack.command_and_control${tags}\nlogsource:\n  category: ${cat}\ndetection:\n  selection:\n    ${field}:\n${values.slice(0,50).map(v=>`      - '${v}'`).join('\n')}\n  condition: selection\nfalsepositives:\n  - Legitimate activity — verify before alerting\nlevel: ${level}\n`;

      el('sig-code').textContent=rule;
      show(el('sig-output'));
    });
    el('sig-copy-btn').addEventListener('click', () => copyBtn(el('sig-copy-btn'), el('sig-code').textContent));
  }

})();
