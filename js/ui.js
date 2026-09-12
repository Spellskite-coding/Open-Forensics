/* Open-Forensics — couche d'interface.
 * Le DOM est construit exclusivement par createElement et textContent :
 * aucune donnée, y compris la synthèse rédigée par l'analyste, n'est jamais
 * interprétée comme du balisage.
 */
(function (root) {
  'use strict';

  var UI = {};
  var u, REF, E;

  var app = {
    screen: 'home',
    view: 'brief',
    session: null,
    sel: { artifact: null },
    filters: { global: '', local: '', source: '' },
    timer: null,
    modalOpen: false
  };
  UI.app = app;

  function el(t, a, k) { return u.el(t, a, k); }

  /* ------------------------------------------------------------------ */
  /* Fabriques communes                                                  */
  /* ------------------------------------------------------------------ */

  function panel(title, body, headExtra, bodyClass) {
    var head = el('header', null, [el('span', { text: title })]);
    if (headExtra) u.append(head, headExtra);
    return el('section', { class: 'panel' }, [head, el('div', { class: 'panel-body ' + (bodyClass || '') }, body)]);
  }

  function kv(pairs) {
    var dl = el('dl', { class: 'kv' });
    pairs.forEach(function (p) {
      if (p[1] === undefined || p[1] === null || p[1] === '') return;
      dl.appendChild(el('dt', { text: p[0] }));
      dl.appendChild(el('dd', { text: String(p[1]) }));
    });
    return dl;
  }

  function table(headers, rows) {
    return el('div', { class: 'scroll-x' }, [
      el('table', null, [
        el('thead', null, [el('tr', null, headers.map(function (h) { return el('th', { text: h }); }))]),
        el('tbody', null, rows)
      ])
    ]);
  }

  function diffBadge(d) {
    var cls = d === 'facile' ? 'tag-ok' : (d === 'moyen' ? 'tag-neutral' : 'tag-bad');
    return el('span', { class: 'badge ' + cls, text: d });
  }

  function toast(msg, kind) {
    var box = u.byId('toasts');
    if (!box) return;
    var n = el('div', { class: 'toast ' + (kind || ''), text: msg });
    box.appendChild(n);
    root.setTimeout(function () { if (n.parentNode) n.parentNode.removeChild(n); }, 5200);
    while (box.childNodes.length > 4) box.removeChild(box.firstChild);
  }
  UI.toast = toast;

  /* Surlignage d'une occurrence sans jamais écrire de balisage. */
  function highlighted(text, q) {
    var span = el('span');
    if (!q) { span.appendChild(document.createTextNode(text)); return span; }
    var hay = text.toLowerCase(), needle = q.toLowerCase(), from = 0, idx;
    while ((idx = hay.indexOf(needle, from)) >= 0 && needle.length) {
      if (idx > from) span.appendChild(document.createTextNode(text.slice(from, idx)));
      span.appendChild(el('span', { class: 'hit-mark', text: text.slice(idx, idx + needle.length) }));
      from = idx + needle.length;
    }
    span.appendChild(document.createTextNode(text.slice(from)));
    return span;
  }

  /* ------------------------------------------------------------------ */
  /* Modale                                                              */
  /* ------------------------------------------------------------------ */

  function closeModal() {
    var m = u.byId('modal-root');
    u.clear(m);
    m.className = 'hidden';
    app.modalOpen = false;
  }

  function openModal(title, body, buttons) {
    var m = u.byId('modal-root');
    u.clear(m);
    m.className = 'overlay';
    app.modalOpen = true;
    var foot = el('div', { class: 'modal-foot' });
    (buttons || []).forEach(function (b) {
      var btn = el('button', { class: 'btn ' + (b.class || ''), type: 'button', text: b.label });
      u.on(btn, 'click', function () { b.action(); });
      foot.appendChild(btn);
    });
    var close = el('button', { class: 'btn btn-ghost btn-sm', type: 'button', text: 'Fermer' });
    u.on(close, 'click', closeModal);
    var dlg = el('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title }, [
      el('header', null, [el('h2', { text: title }), el('span', { class: 'grow' }), close]),
      el('div', { class: 'modal-body' }, body),
      foot
    ]);
    m.appendChild(dlg);
    var first = dlg.querySelector('input, select, textarea, button');
    if (first) first.focus();
  }

  /* ------------------------------------------------------------------ */
  /* Coque                                                               */
  /* ------------------------------------------------------------------ */

  UI.mount = function () {
    u = root.OpenForensics.util;
    REF = root.OpenForensics.ref;
    E = root.OpenForensics.engine;

    var rootEl = u.byId('app');
    u.clear(rootEl);
    rootEl.appendChild(el('div', { id: 'topbar', class: 'topbar' }));
    rootEl.appendChild(el('nav', { id: 'tabs', class: 'tabs hidden', role: 'tablist' }));
    rootEl.appendChild(el('main', { id: 'main' }));
    rootEl.appendChild(el('div', { class: 'footbar' }, [
      el('span', { text: 'Open-Forensics — reconstitution d\'incident. Environnement entièrement fictif.' }),
      el('span', { class: 'grow' }),
      el('span', { text: 'Hors ligne · aucune dépendance · aucune donnée transmise' })
    ]));
    document.body.appendChild(el('div', { id: 'toasts', class: 'toasts', 'aria-live': 'polite' }));
    document.body.appendChild(el('div', { id: 'modal-root', class: 'hidden' }));

    u.on(document, 'keydown', function (e) {
      if ((e.key === 'Escape' || e.key === 'Esc' || e.keyCode === 27) && app.modalOpen) closeModal();
    });

    app.timer = root.setInterval(tick, 1000);
    renderHome();
  };

  function tick() {
    if (app.screen !== 'case' || !app.session) return;
    E.tick(app.session);
    var c = u.byId('elapsed');
    if (c) c.textContent = u.mmss(app.session.elapsedSec);
  }

  function goHome() {
    if (app.screen === 'case' && app.session && !app.session.submitted) {
      openModal('Quitter le dossier ?', [
        el('p', { text: 'L\'investigation en cours sera abandonnée : les constatations établies, la chronologie et la synthèse seront perdues, et aucun débriefing ne sera produit.' }),
        el('p', { class: 'dim', text: 'Pour obtenir votre notation et le débriefing, utilisez « Clore l\'investigation » : il n\'est pas nécessaire d\'avoir tout trouvé.' })
      ], [
        { label: 'Rester sur le dossier', class: 'btn-ghost', action: closeModal },
        { label: 'Abandonner', class: 'btn-danger', action: function () { closeModal(); app.session = null; renderHome(); } }
      ]);
      return;
    }
    app.session = null;
    renderHome();
  }

  function renderTopbar() {
    var bar = u.byId('topbar');
    u.clear(bar);
    var brand = el('button', { class: 'brand', type: 'button', title: 'Retour aux dossiers', 'aria-label': 'Retour aux dossiers' }, [
      el('span', { class: 'brand-mark', 'aria-hidden': 'true' }),
      el('span', null, ['Open-Forensics ', el('small', { text: '· reconstitution d\'incident' })])
    ]);
    u.on(brand, 'click', goHome);
    bar.appendChild(brand);

    if (app.screen === 'case' && app.session) {
      var c = E.caseById(app.session.caseId);
      var solved = 0;
      c.questions.forEach(function (q) { if (app.session.flags[q.id].solved) solved += 1; });
      bar.appendChild(el('span', { class: 'clock', id: 'elapsed', text: u.mmss(app.session.elapsedSec) }));
      bar.appendChild(el('div', { class: 'metrics' }, [
        el('div', { class: 'metric' }, [el('span', { text: c.id }), el('b', { text: u.trunc(c.title, 34) })]),
        el('div', { class: 'metric' }, [el('span', { text: 'Constatations' }), el('b', { text: solved + ' / ' + c.questions.length })])
      ]));
      bar.appendChild(el('span', { class: 'grow' }));
      var close = el('button', { class: 'btn btn-sm btn-warn', type: 'button', text: 'Clore l\'investigation' });
      u.on(close, 'click', confirmSubmit);
      bar.appendChild(close);
    } else {
      bar.appendChild(el('span', { class: 'grow' }));
      bar.appendChild(el('span', { class: 'muted', text: REF.app.unit }));
    }
  }

  /* ------------------------------------------------------------------ */
  /* Accueil                                                             */
  /* ------------------------------------------------------------------ */

  function renderHome() {
    app.screen = 'home';
    renderTopbar();
    u.byId('tabs').className = 'tabs hidden';
    var main = u.byId('main');
    u.clear(main);
    var wrap = el('div', { class: 'home' });
    var progress = E.readProgress();

    wrap.appendChild(el('section', { class: 'hero' }, [
      el('h1', { text: 'Open-Forensics — investigation d\'incident' }),
      el('p', { class: 'muted', text: 'Vous êtes analyste au CERT. Un client vous remet ses journaux après incident : à vous d\'établir les faits, de reconstituer ce que l\'attaquant a fait, et de le démontrer. Tout est dans les journaux, rien d\'autre. Il n\'y a ni capture mémoire ni image disque : on travaille comme sur le terrain, avec ce que le client a su collecter.' }),
      el('p', { class: 'dim', text: root.OpenForensics.cases.length + ' dossiers · ' + REF.techniques.length + ' techniques ATT&CK au référentiel · aucune recherche externe nécessaire' })
    ]));

    wrap.appendChild(panel('Comment se déroule un dossier', [
      el('ul', { class: 'compact' }, [
        el('li', { text: 'Le briefing vous donne la saisine du client, le périmètre, ce qui a été collecté et surtout ce qui manque : un journal absent est une limite d\'investigation, pas une excuse.' }),
        el('li', { text: 'Les pièces sont des journaux, et uniquement des journaux. Ils contiennent l\'activité normale du client en plus des traces de l\'attaque : il faut filtrer, recouper, et remonter de proche en proche.' }),
        el('li', { text: 'Les constatations se valident une par une, comme des drapeaux. Une erreur coûte peu, un indice coûte davantage : cherchez avant de demander.' }),
        el('li', { text: 'La reconstitution de la chaîne d\'attaque est notée à part. Déclarer qu\'une tactique n\'a PAS été observée vaut autant de points que d\'en trouver une : conclure à l\'absence est un résultat.' }),
        el('li', { text: 'Vous pouvez clore à tout moment, même sans tout avoir trouvé. Le score sera partiel, le débriefing sera complet et vous dira où se trouvait chaque réponse.' })
      ])
    ]));

    var grid = el('div', { class: 'cards case-grid' });
    var order = { facile: 0, moyen: 1, difficile: 2 };
    root.OpenForensics.cases.slice().sort(function (a, b) {
      return (order[a.difficulty] - order[b.difficulty]) || (a.id < b.id ? -1 : 1);
    }).forEach(function (c) {
      var p = progress[c.id];
      var card = el('article', { class: 'card case-card diff-' + c.difficulty }, [
        el('div', { class: 'row' }, [
          el('span', { class: 'mono dim', text: c.id }),
          diffBadge(c.difficulty),
          el('span', { class: 'grow' }),
          p ? el('span', { class: 'badge ' + (p.best >= 78 ? 'tag-ok' : (p.best >= 50 ? 'tag-neutral' : 'tag-bad')), text: 'meilleur : ' + p.best + ' / 100' }) : el('span', { class: 'dim', text: 'non traité' })
        ]),
        el('h3', { text: c.title }),
        el('p', { class: 'dim', text: c.client }),
        el('div', { class: 'row' }, [
          el('span', { class: 'badge tag-neutral', text: '~ ' + c.estimatedMin + ' min' }),
          el('span', { class: 'badge tag-neutral', text: c.questions.length + ' constatations' }),
          el('span', { class: 'badge tag-neutral', text: c.evidence.length + ' journaux' })
        ]),
        el('div', { class: 'dim mono', text: (c.tags || []).join(' · ') })
      ]);
      var btn = el('button', { class: 'btn btn-primary btn-block', type: 'button', text: p ? 'Reprendre ce dossier' : 'Ouvrir le dossier' });
      u.on(btn, 'click', function () { openCase(c.id); });
      card.appendChild(btn);
      grid.appendChild(card);
    });
    wrap.appendChild(el('div', { class: 'stack' }, [panel('Dossiers', [grid])]));

    var keys = Object.keys(progress);
    if (keys.length) {
      var clear = el('button', { class: 'btn btn-sm btn-ghost', type: 'button', text: 'Effacer la progression' });
      u.on(clear, 'click', function () { E.clearProgress(); renderHome(); });
      var rows = keys.sort().map(function (k) {
        var p = progress[k];
        var c = E.caseById(k);
        return el('tr', null, [
          el('td', { class: 'mono', text: k }),
          el('td', { text: c ? c.title : '—' }),
          el('td', { class: 'mono', text: p.best + ' / 100' }),
          el('td', null, [el('span', { class: 'badge tag-neutral', text: p.grade })]),
          el('td', { class: 'mono dim', text: String(p.runs) }),
          el('td', { class: 'mono dim', text: p.date })
        ]);
      });
      wrap.appendChild(el('div', { class: 'stack' }, [
        panel('Progression (stockée uniquement dans ce navigateur)',
          [table(['Dossier', 'Intitulé', 'Meilleur score', 'Mention', 'Passages', 'Dernier'], rows), clear])
      ]));
    }

    main.appendChild(wrap);
    root.scrollTo(0, 0);
  }
  UI.renderHome = renderHome;

  /* ------------------------------------------------------------------ */
  /* Dossier : onglets                                                   */
  /* ------------------------------------------------------------------ */

  var VIEWS = [
    { id: 'brief', label: 'Briefing' },
    { id: 'logs', label: 'Journaux' },
    { id: 'chain', label: 'Chaîne d\'attaque' },
    { id: 'report', label: 'Constatations et rapport' }
  ];

  function openCase(id) {
    app.session = E.createSession(id);
    app.screen = 'case';
    app.view = 'brief';
    app.sel.artifact = null;
    app.filters = { global: '', local: '', source: '' };
    renderTopbar();
    renderTabs();
    switchView('brief');
    toast('Dossier ' + id + ' ouvert. Le chronomètre tourne, sans limite de temps.', 'good');
  }

  function renderTabs() {
    var nav = u.byId('tabs');
    nav.className = 'tabs';
    u.clear(nav);
    VIEWS.forEach(function (v) {
      var b = el('button', { class: 'tab', type: 'button', role: 'tab', id: 'tab-' + v.id, 'aria-selected': app.view === v.id ? 'true' : 'false' }, [el('span', { text: v.label })]);
      if (v.id === 'report') b.appendChild(el('span', { class: 'pill', id: 'tab-badge' }));
      u.on(b, 'click', function () { switchView(v.id); });
      nav.appendChild(b);
    });
    updateTabBadge();
  }

  function updateTabBadge() {
    var b = u.byId('tab-badge');
    if (!b || !app.session) return;
    var c = E.caseById(app.session.caseId), left = 0;
    c.questions.forEach(function (q) { if (!app.session.flags[q.id].solved) left += 1; });
    b.textContent = String(left);
    b.className = left ? 'pill' : 'pill hidden';
  }

  function switchView(id) {
    app.view = id;
    VIEWS.forEach(function (v) {
      var t = u.byId('tab-' + v.id);
      if (t) t.setAttribute('aria-selected', v.id === id ? 'true' : 'false');
    });
    var main = u.byId('main');
    u.clear(main);
    if (id === 'brief') renderBrief(main);
    else if (id === 'logs') renderLogs(main);
    else if (id === 'chain') renderChain(main);
    else if (id === 'report') renderReport(main);
    root.scrollTo(0, 0);
  }

  /* ------------------------------------------------------------------ */
  /* Briefing                                                            */
  /* ------------------------------------------------------------------ */

  function renderBrief(main) {
    var c = E.caseById(app.session.caseId);
    var vol = E.logVolume(app.session);
    var wrap = el('div', { class: 'home' });

    wrap.appendChild(el('section', { class: 'hero' }, [
      el('div', { class: 'row' }, [el('span', { class: 'mono dim', text: c.id }), diffBadge(c.difficulty), el('span', { class: 'badge tag-neutral', text: '~ ' + c.estimatedMin + ' min' })]),
      el('h1', { text: c.title }),
      el('p', { class: 'muted', text: c.client })
    ]));

    wrap.appendChild(el('div', { class: 'grid-2' }, [
      panel('Saisine', [el('p', { text: c.brief.saisine })]),
      panel('Mission confiée au CERT', [el('p', { text: c.brief.mission })])
    ]));

    wrap.appendChild(el('div', { class: 'grid-2' }, [
      panel('Périmètre technique', [el('p', { text: c.brief.perimetre })]),
      panel('Conditions de collecte', [el('p', { text: c.brief.collecte })])
    ]));

    wrap.appendChild(panel('Limites de l\'investigation', [
      el('div', { class: 'note warn' }, [el('span', { text: c.brief.limites })]),
      el('p', { class: 'dim', text: 'Ces limites font partie du dossier : si une question ne peut pas être tranchée avec les pièces disponibles, il faut le dire dans la synthèse plutôt que d\'extrapoler. À l\'inverse, un journal présent et couvrant la période permet de conclure à une absence.' })
    ]));

    wrap.appendChild(panel('Pièces remises', [
      table(['Pièce', 'Nature', 'Système', 'Lignes'], c.evidence.map(function (a) {
        var tr = el('tr', { class: 'clickable', tabindex: '0' }, [
          el('td', { class: 'mono nowrap', text: a.id }),
          el('td', null, [el('div', { text: a.title }), el('div', { class: 'dim', text: REF.sourceLabel(a.source) })]),
          el('td', { class: 'mono', text: a.system }),
          el('td', { class: 'mono right', text: String(E.logOf(app.session, a.id).length) })
        ]);
        function go() { app.sel.artifact = a.id; switchView('logs'); }
        u.on(tr, 'click', go);
        u.on(tr, 'keydown', function (e) { if (e.key === 'Enter') go(); });
        return tr;
      })),
      el('p', { class: 'dim', text: vol + ' lignes de journal au total. L\'activité normale du client y figure : c\'est à vous de séparer le bruit du signal.' })
    ]));

    main.appendChild(wrap);
  }

  /* ------------------------------------------------------------------ */
  /* Journaux                                                            */
  /* ------------------------------------------------------------------ */

  function renderLogs(main) {
    var c = E.caseById(app.session.caseId);
    if (!app.sel.artifact) app.sel.artifact = c.evidence[0].id;

    /* Colonne gauche : recherche transverse et liste des pièces. */
    var gq = el('input', { type: 'text', id: 'g-query', placeholder: 'Recherche dans tous les journaux…' });
    gq.value = app.filters.global;
    var gres = el('div', { id: 'g-results', class: 'scroll-y' });
    u.on(gq, 'input', function () { app.filters.global = gq.value; updateGlobalSearch(gres); });

    var list = el('div', { id: 'ev-list' });
    REF.sources.forEach(function (src) {
      var items = c.evidence.filter(function (a) { return a.source === src.id; });
      if (!items.length) return;
      list.appendChild(el('h4', { text: src.label }));
      items.forEach(function (a) {
        var n = E.logOf(app.session, a.id).length;
        var b = el('button', { class: 'ev-item' + (app.sel.artifact === a.id ? ' on' : ''), type: 'button' }, [
          el('div', { class: 'mono', text: a.id + ' · ' + a.system }),
          el('div', { text: a.title }),
          el('div', { class: 'dim mono', text: n + ' lignes' })
        ]);
        u.on(b, 'click', function () {
          app.sel.artifact = a.id;
          app.filters.local = '';
          switchView('logs');
        });
        list.appendChild(b);
      });
    });

    var left = el('div', { class: 'stack' }, [
      panel('Recherche transverse', [gq, el('p', { class: 'dim', text: 'Cherche la même chaîne dans toutes les pièces du dossier : c\'est ainsi qu\'on suit une adresse, un compte ou un nom de fichier d\'un journal à l\'autre.' }), gres]),
      panel('Pièces du dossier', [list], null, 'tight')
    ]);

    var right = el('div', { id: 'log-pane', class: 'stack' });
    main.appendChild(el('div', { class: 'split split-wide' }, [left, right]));
    renderArtifact();
    if (app.filters.global) updateGlobalSearch(gres);
  }

  function updateGlobalSearch(box) {
    u.clear(box);
    var q = app.filters.global.replace(/^\s+|\s+$/g, '');
    if (q.length < 2) {
      box.appendChild(el('p', { class: 'dim', text: 'Saisissez au moins deux caractères.' }));
      return;
    }
    var res = E.searchEvidence(app.session, q);
    if (!res.length) {
      box.appendChild(el('p', { class: 'dim', text: 'Aucune occurrence dans les pièces du dossier.' }));
      return;
    }
    var byArt = {};
    res.forEach(function (r) {
      byArt[r.artifact.id] = (byArt[r.artifact.id] || 0) + 1;
    });
    box.appendChild(el('p', { class: 'dim', text: res.length + ' occurrences dans ' + Object.keys(byArt).length + ' pièce(s).' }));
    Object.keys(byArt).forEach(function (id) {
      var a = E.artifactById(E.caseById(app.session.caseId), id);
      var b = el('button', { class: 'ev-item', type: 'button' }, [
        el('div', { class: 'mono', text: id + ' · ' + a.system }),
        el('div', { text: a.title }),
        el('div', { class: 'dim mono', text: byArt[id] + ' occurrence(s)' })
      ]);
      u.on(b, 'click', function () {
        app.sel.artifact = id;
        app.filters.local = app.filters.global;
        switchView('logs');
      });
      box.appendChild(b);
    });
  }

  function renderArtifact() {
    var pane = u.byId('log-pane');
    if (!pane) return;
    u.clear(pane);
    var c = E.caseById(app.session.caseId);
    var a = E.artifactById(c, app.sel.artifact);
    if (!a) return;
    var lines = E.logOf(app.session, a.id);

    var lq = el('input', { type: 'text', id: 'l-query', placeholder: 'Filtrer ce journal (compte, adresse, code d\'évènement…)' });
    lq.value = app.filters.local;
    var body = el('div', { id: 'log-body', class: 'log-list scroll-y' });
    var count = el('span', { id: 'log-count', class: 'dim' });

    function draw() {
      var q = app.filters.local.replace(/^\s+|\s+$/g, '');
      u.clear(body);
      var shown = 0;
      for (var i = 0; i < lines.length; i++) {
        var l = lines[i];
        if (q && !u.has(l.m, q) && !u.has(l.t, q)) continue;
        shown += 1;
        body.appendChild(el('div', { class: 'log-line' }, [
          el('span', { class: 'lt', text: l.t }),
          highlighted(l.m, q)
        ]));
        if (shown >= 1200) break;
      }
      if (!shown) body.appendChild(el('p', { class: 'dim center', text: 'Aucune ligne ne correspond à ce filtre dans cette pièce.' }));
      count.textContent = shown + ' lignes affichées sur ' + lines.length;
    }
    u.on(lq, 'input', function () { app.filters.local = lq.value; draw(); });

    pane.appendChild(el('section', { class: 'panel' }, [
      el('header', null, [el('span', { text: a.id + ' — ' + a.title }), el('span', { class: 'grow' }), count]),
      el('div', { class: 'panel-body' }, [
        kv([['Système', a.system], ['Nature', REF.sourceLabel(a.source)]]),
        a.note ? el('div', { class: 'note' }, [el('span', { text: a.note })]) : null,
        lq
      ]),
      body
    ]));
    draw();
  }

  /* ------------------------------------------------------------------ */
  /* Chaîne d'attaque                                                    */
  /* ------------------------------------------------------------------ */

  function renderChain(main) {
    var c = E.caseById(app.session.caseId);
    var wrap = el('div', { class: 'stack' });

    wrap.appendChild(panel('Reconstitution de la chaîne d\'attaque', [
      el('p', { text: 'Pour chaque tactique, désignez l\'évènement du dossier qui la démontre, et la technique correspondante. Le vivier d\'évènements contient aussi de l\'activité légitime : tout n\'est pas à placer.' }),
      el('div', { class: 'note' }, [el('span', { text: 'Une tactique que l\'attaquant n\'a pas employée se déclare « Non observé ». C\'est une conclusion à part entière, notée comme telle : un rapport qui invente une exfiltration inexistante est plus dangereux qu\'un rapport incomplet.' })])
    ]));

    var rows = c.chain.map(function (row) {
      var slot = app.session.chain[row.tactic];

      var evSel = el('select', { 'aria-label': 'Évènement pour ' + row.tactic });
      evSel.appendChild(el('option', { value: '', text: '— à déterminer —' }));
      evSel.appendChild(el('option', { value: 'NONE', text: 'Non observé dans ce dossier' }));
      c.events.forEach(function (ev) {
        evSel.appendChild(el('option', { value: ev.id, text: ev.t + ' — ' + ev.label }));
      });
      evSel.value = slot.event;
      u.on(evSel, 'change', function () { E.setChain(app.session, row.tactic, 'event', evSel.value); });

      var tqSel = el('select', { 'aria-label': 'Technique pour ' + row.tactic });
      tqSel.appendChild(el('option', { value: '', text: '— à déterminer —' }));
      tqSel.appendChild(el('option', { value: 'NONE', text: 'Aucune (tactique non observée)' }));
      REF.techniquesByTactic(row.tactic).forEach(function (t) {
        tqSel.appendChild(el('option', { value: t.id, text: t.name }));
      });
      tqSel.value = slot.technique;
      u.on(tqSel, 'change', function () { E.setChain(app.session, row.tactic, 'technique', tqSel.value); });

      return el('tr', null, [
        el('td', { class: 'nowrap' }, [el('b', { text: row.tactic })]),
        el('td', null, [evSel]),
        el('td', null, [tqSel])
      ]);
    });

    wrap.appendChild(panel('Tactiques', [table(['Tactique', 'Évènement qui la démontre', 'Technique retenue'], rows)]));
    main.appendChild(el('div', { class: 'home wide' }, [wrap]));
  }

  /* ------------------------------------------------------------------ */
  /* Constatations et rapport                                            */
  /* ------------------------------------------------------------------ */

  function renderReport(main) {
    var c = E.caseById(app.session.caseId);
    var st = app.session;
    var wrap = el('div', { class: 'stack' });

    wrap.appendChild(panel('Constatations', [
      el('p', { class: 'dim', text: 'Chaque constatation se valide indépendamment. Une réponse fausse coûte ' + REF.weights.flagWrongAttempt + ' point (plafonné à ' + REF.weights.flagWrongAttemptCap + '), un indice en coûte ' + REF.weights.hint + '. Les valeurs « défanguées » (hxxp, [.]) et les variantes de casse sont acceptées.' })
    ]));

    var qbox = el('div', { class: 'stack' });
    c.questions.forEach(function (q) {
      qbox.appendChild(questionRow(c, q));
    });
    wrap.appendChild(qbox);

    /* Bloc-notes de l'analyste */
    var notes = el('textarea', { id: 'notes', placeholder: 'Bloc-notes : hypothèses, indicateurs relevés, pistes à vérifier. Non noté, non transmis.' });
    notes.value = st.notes;
    u.on(notes, 'input', function () { st.notes = notes.value.slice(0, 4000); });
    wrap.appendChild(panel('Bloc-notes', [notes]));

    /* Synthèse */
    var syn = el('textarea', { id: 'syn', class: 'tall', maxlength: String(REF.weights.synthesisMax), placeholder: 'Ce qui s\'est passé, par quel point d\'entrée, ce que l\'attaquant a fait, ce qui est prouvé et ce qui ne l\'est pas. Citez vos indicateurs.' });
    syn.value = st.synthesis;
    var scount = el('div', { class: 'counter' });
    function updCount() {
      var n = syn.value.trim().length;
      scount.textContent = n + ' / ' + REF.weights.synthesisMax + ' caractères (minimum ' + REF.weights.synthesisMin + ')';
      scount.className = 'counter' + (n < REF.weights.synthesisMin ? ' bad' : '');
    }
    u.on(syn, 'input', function () { st.synthesis = syn.value; updCount(); });
    updCount();
    wrap.appendChild(panel('Synthèse d\'investigation', [
      el('p', { class: 'dim', text: 'Le livrable du CERT. Il est noté sur sa longueur et sur les indicateurs du dossier qu\'il cite : un rapport qui n\'apporte aucune preuve à l\'appui de ses affirmations n\'est pas exploitable.' }),
      syn, scount
    ]));

    var submit = el('button', { class: 'btn btn-primary', type: 'button', text: 'Clore l\'investigation et obtenir le débriefing' });
    u.on(submit, 'click', confirmSubmit);
    wrap.appendChild(el('div', { class: 'row' }, [submit]));

    main.appendChild(el('div', { class: 'home wide' }, [wrap]));
  }

  function questionRow(c, q) {
    var st = app.session;
    var slot = st.flags[q.id];
    var box = el('section', { class: 'panel q-card' + (slot.solved ? ' solved' : '') });
    var head = el('header', null, [
      el('span', { class: 'mono', text: q.id }),
      el('span', { class: 'grow' }),
      slot.solved ? el('span', { class: 'badge tag-ok', text: 'Établie' }) : el('span', { class: 'badge tag-neutral', text: REF.weights.flag + ' pts' })
    ]);
    box.appendChild(head);

    var input;
    if (q.type === 'choice') {
      input = el('select', { 'aria-label': q.label });
      input.appendChild(el('option', { value: '', text: '— choisir —' }));
      (q.options || []).forEach(function (o) { input.appendChild(el('option', { value: o, text: o })); });
      input.value = slot.value;
    } else if (q.type === 'technique') {
      input = el('select', { 'aria-label': q.label });
      input.appendChild(el('option', { value: '', text: '— choisir —' }));
      REF.techniques.forEach(function (t) { input.appendChild(el('option', { value: t.id, text: t.name })); });
      input.value = slot.value;
    } else {
      input = el('input', { type: 'text', maxlength: '200', 'aria-label': q.label, placeholder: placeholderFor(q.type) });
      input.value = slot.value;
    }
    input.disabled = slot.solved || st.submitted;

    var feedback = el('div', { class: 'dim' });
    var validate = el('button', { class: 'btn btn-primary btn-sm', type: 'button', text: 'Valider' });
    validate.disabled = slot.solved || st.submitted;
    function doValidate() {
      var r = E.answerFlag(st, q.id, input.value);
      if (r.ok) {
        toast(q.id + ' établie.', 'good');
        switchView('report');
        renderTopbar();
        updateTabBadge();
      } else {
        u.clear(feedback);
        feedback.className = 'note bad';
        feedback.appendChild(el('span', { text: r.msg + (slot.wrong ? ' — ' + slot.wrong + ' tentative(s) infructueuse(s).' : '') }));
      }
    }
    u.on(validate, 'click', doValidate);
    u.on(input, 'keydown', function (e) { if (e.key === 'Enter' && !slot.solved) { e.preventDefault(); doValidate(); } });

    var hintBtn = el('button', { class: 'btn btn-sm', type: 'button', text: slot.hint ? 'Indice utilisé' : 'Indice (−' + REF.weights.hint + ')' });
    hintBtn.disabled = slot.solved || slot.hint || st.submitted;
    u.on(hintBtn, 'click', function () {
      var h = E.useHint(st, q.id);
      if (h) { switchView('report'); toast('Indice affiché — ' + REF.weights.hint + ' points.', 'warn'); }
    });

    box.appendChild(el('div', { class: 'panel-body' }, [
      el('p', null, [el('b', { text: q.label })]),
      el('div', { class: 'row' }, [el('div', { class: 'grow' }, [input]), validate, hintBtn]),
      slot.hint ? el('div', { class: 'note warn' }, [el('b', { text: 'Indice : ' }), el('span', { text: q.hint })]) : null,
      slot.solved ? el('div', { class: 'note good' }, [el('span', { text: 'Confirmé : ' + slot.value })]) : feedback,
      (!slot.solved && slot.wrong) ? el('div', { class: 'dim', text: slot.wrong + ' tentative(s) infructueuse(s).' }) : null
    ]));
    return box;
  }

  function placeholderFor(type) {
    switch (type) {
      case 'ip': return 'ex. 203.0.113.10';
      case 'hash': return 'empreinte SHA-256';
      case 'datetime': return 'ex. 2026-03-04 01:27';
      case 'number': return 'nombre entier';
      case 'domain': return 'ex. domaine.test';
      case 'path': return 'chemin complet';
      default: return 'réponse';
    }
  }

  /* ------------------------------------------------------------------ */
  /* Clôture                                                             */
  /* ------------------------------------------------------------------ */

  function confirmSubmit() {
    var st = app.session;
    if (!st || st.submitted) return;
    var c = E.caseById(st.caseId);
    var unsolved = 0, chainLeft = 0;
    c.questions.forEach(function (q) { if (!st.flags[q.id].solved) unsolved += 1; });
    c.chain.forEach(function (row) {
      var s = st.chain[row.tactic];
      if (!s.event || !s.technique) chainLeft += 1;
    });
    var body = [
      el('p', { text: 'La clôture fige vos réponses et produit le débriefing complet : ce qui s\'est réellement passé, où se trouvait chaque réponse, et pourquoi elle comptait.' })
    ];
    if (unsolved || chainLeft || st.synthesis.trim().length < REF.weights.synthesisMin) {
      var warn = [];
      if (unsolved) warn.push(unsolved + ' constatation(s) non établie(s)');
      if (chainLeft) warn.push(chainLeft + ' tactique(s) sans réponse complète');
      if (st.synthesis.trim().length < REF.weights.synthesisMin) warn.push('synthèse trop courte');
      body.push(el('div', { class: 'note warn' }, [
        el('b', { text: 'Dossier incomplet : ' }),
        el('span', { text: warn.join(', ') + '. Vous pouvez clore quand même — le score sera partiel, le débriefing sera entier.' })
      ]));
    }
    openModal('Clore l\'investigation ?', body, [
      { label: 'Continuer à investiguer', class: 'btn-ghost', action: closeModal },
      { label: 'Clore et voir le débriefing', class: 'btn-primary', action: function () { closeModal(); doSubmit(); } }
    ]);
  }

  function doSubmit() {
    var st = app.session;
    var report = E.submit(st);
    E.saveProgress(st.caseId, report);
    renderDebrief(report);
  }

  /* ------------------------------------------------------------------ */
  /* Débriefing                                                          */
  /* ------------------------------------------------------------------ */

  function bar(label, value) {
    var fill = el('i');
    var b = el('div', { class: 'bar' + (value < 50 ? ' b-bad' : (value < 78 ? ' b-mid' : '')) }, [fill]);
    u.setWidthPct(fill, value);
    return el('div', { class: 'bar-row' }, [el('span', { text: label }), b, el('span', { class: 'mono right', text: value + ' %' })]);
  }

  function renderDebrief(r) {
    app.screen = 'debrief';
    var st = app.session;
    var c = E.caseById(st.caseId);
    renderTopbar();
    u.byId('tabs').className = 'tabs hidden';
    var main = u.byId('main');
    u.clear(main);
    var wrap = el('div', { class: 'home wide' });

    var ring = el('div', { class: 'score-ring' }, [el('div', null, [
      el('b', { text: String(r.score) }), el('span', { class: 'dim', text: 'sur 100' })
    ])]);
    u.setVarPct(ring, '--pct', r.score);

    wrap.appendChild(el('section', { class: 'hero' }, [
      el('div', { class: 'score-hero' }, [
        ring,
        el('div', null, [
          el('div', { class: 'grade', text: r.grade }),
          el('h1', { text: r.label }),
          el('p', { class: 'muted', text: c.id + ' — ' + c.title + ' · durée : ' + u.dur(r.stats.elapsedSec) + ' (estimée : ' + c.estimatedMin + ' min)' })
        ]),
        el('div', { class: 'grow' }),
        el('div', { class: 'bars' }, [
          bar('Établissement des faits', r.dims.etablissement),
          bar('Reconstitution de la chaîne', r.dims.reconstitution),
          bar('Restitution écrite', r.dims.restitution),
          bar('Autonomie (indices, tâtonnements)', r.dims.autonomie)
        ])
      ])
    ]));

    wrap.appendChild(panel('Chiffres du dossier', [
      el('div', { class: 'cards' }, [
        el('div', { class: 'card' }, [el('h3', { text: r.stats.flagsSolved + ' / ' + r.stats.flagsTotal }), el('div', { class: 'dim', text: 'constatations établies' })]),
        el('div', { class: 'card' }, [el('h3', { text: r.stats.chainOk + ' / ' + r.stats.chainTotal }), el('div', { class: 'dim', text: 'tactiques entièrement correctes' })]),
        el('div', { class: 'card' }, [el('h3', { text: String(r.stats.hints) }), el('div', { class: 'dim', text: 'indices utilisés' })]),
        el('div', { class: 'card' }, [el('h3', { text: String(r.stats.wrongAttempts) }), el('div', { class: 'dim', text: 'réponses erronées' })]),
        el('div', { class: 'card' }, [el('h3', { text: u.dur(r.stats.elapsedSec) }), el('div', { class: 'dim', text: 'temps passé' })])
      ])
    ]));

    wrap.appendChild(panel('Ce qui s\'est réellement passé', [
      el('p', { text: c.debrief.story }),
      el('h4', { text: 'Ce que ce dossier apprend' }),
      el('ul', { class: 'compact' }, c.debrief.lessons.map(function (l) { return el('li', { text: l }); })),
      el('h4', { text: 'Pièges du dossier' }),
      el('ul', { class: 'compact' }, c.debrief.pitfalls.map(function (l) { return el('li', { text: l }); }))
    ]));

    /* Correction des constatations */
    var qcards = el('div', { class: 'stack' });
    r.flags.forEach(function (f) {
      qcards.appendChild(el('section', { class: 'panel q-card ' + (f.solved ? 'solved' : 'missed') }, [
        el('header', null, [
          el('span', { class: 'mono', text: f.id }),
          el('span', { class: 'grow' }),
          el('span', { class: 'badge ' + (f.solved ? 'tag-ok' : 'tag-bad'), text: f.points + ' / ' + f.max + ' pts' })
        ]),
        el('div', { class: 'panel-body' }, [
          el('p', null, [el('b', { text: f.label })]),
          el('div', { class: 'row' }, [
            el('span', { class: 'badge tag-neutral', text: 'Attendu : ' + f.expected }),
            f.given ? el('span', { class: 'badge ' + (f.solved ? 'tag-ok' : 'tag-bad'), text: 'Votre réponse : ' + f.given }) : el('span', { class: 'badge tag-bad', text: 'Aucune réponse' }),
            f.hint ? el('span', { class: 'badge tag-neutral', text: 'indice utilisé' }) : null,
            f.wrong ? el('span', { class: 'badge tag-neutral', text: f.wrong + ' essai(s) manqué(s)' }) : null
          ]),
          f.where ? el('div', { class: 'note' }, [el('b', { text: 'Où la trouver : ' }), el('span', { text: f.where })]) : null,
          f.why ? el('div', { class: 'note good' }, [el('b', { text: 'Pourquoi elle compte : ' }), el('span', { text: f.why })]) : null
        ])
      ]));
    });
    wrap.appendChild(el('div', { class: 'stack' }, [el('h2', { text: 'Correction des constatations' }), qcards]));

    /* Correction de la chaîne */
    var crows = r.chain.map(function (x) {
      return el('tr', null, [
        el('td', { class: 'nowrap' }, [el('b', { text: x.tactic })]),
        el('td', null, [
          el('div', null, [el('span', { class: 'badge ' + (x.eventOk ? 'tag-ok' : 'tag-bad'), text: x.eventOk ? 'correct' : 'manqué' })]),
          el('div', { class: 'dim', text: 'attendu : ' + x.expectedEvent }),
          el('div', { class: 'dim', text: 'votre réponse : ' + x.givenEvent })
        ]),
        el('td', null, [
          el('div', null, [el('span', { class: 'badge ' + (x.techniqueOk ? 'tag-ok' : 'tag-bad'), text: x.techniqueOk ? 'correcte' : 'manquée' })]),
          el('div', { class: 'dim', text: 'attendue : ' + x.expectedTechnique }),
          el('div', { class: 'dim', text: 'votre réponse : ' + x.givenTechnique })
        ]),
        el('td', null, [
          x.where ? el('div', { class: 'dim', text: x.where }) : null,
          x.why ? el('div', null, [el('span', { text: x.why })]) : null
        ])
      ]);
    });
    wrap.appendChild(panel('Correction de la chaîne d\'attaque', [
      table(['Tactique', 'Évènement', 'Technique', 'Ce qu\'il fallait voir'], crows)
    ]));

    /* Synthèse */
    wrap.appendChild(panel('Votre synthèse', [
      el('div', { class: 'row' }, [el('span', { class: 'badge tag-neutral', text: r.synthesis.points + ' / ' + r.synthesis.max + ' pts' })]),
      el('ul', { class: 'compact' }, r.synthesis.detail.map(function (d) {
        return el('li', { class: d.ok ? '' : 'flag-suspect' }, [el('span', { text: d.t })]);
      })),
      r.synthesis.cited.length ? el('p', { class: 'dim', text: 'Indicateurs cités : ' + r.synthesis.cited.join(', ') }) : null,
      r.synthesis.text ? el('div', { class: 'note' }, [el('span', { text: r.synthesis.text })]) : el('p', { class: 'dim', text: 'Aucune synthèse rédigée.' })
    ]));

    /* Fiche IOC */
    wrap.appendChild(panel('Fiche d\'indicateurs à transmettre au SOC', [
      table(['Type', 'Valeur', 'Contexte'], E.iocSheet(c).map(function (i) {
        return el('tr', null, [
          el('td', { text: i.type }),
          el('td', { class: 'mono', text: i.value }),
          el('td', { class: 'dim', text: i.context })
        ]);
      }))
    ]));

    var json = JSON.stringify(E.exportReport(st), null, 2);
    var pre = el('pre', { class: 'export', text: json });
    var selBtn = el('button', { class: 'btn btn-sm', type: 'button', text: 'Sélectionner le rapport' });
    u.on(selBtn, 'click', function () {
      var range = document.createRange();
      range.selectNodeContents(pre);
      var s = root.getSelection();
      s.removeAllRanges();
      s.addRange(range);
      toast('Rapport sélectionné — copiez-le avec Ctrl+C.');
    });
    wrap.appendChild(panel('Rapport exportable (JSON)', [
      el('p', { class: 'dim', text: 'Aucune donnée n\'est transmise : le rapport ne quitte pas ce navigateur.' }),
      selBtn, pre
    ]));

    var again = el('button', { class: 'btn btn-primary', type: 'button', text: 'Rejouer ce dossier' });
    u.on(again, 'click', function () { openCase(c.id); });
    var back = el('button', { class: 'btn', type: 'button', text: 'Retour aux dossiers' });
    u.on(back, 'click', function () { app.session = null; renderHome(); });
    wrap.appendChild(el('div', { class: 'row' }, [again, back]));

    main.appendChild(wrap);
    root.scrollTo(0, 0);
  }

  root.OpenForensics = root.OpenForensics || {};
  root.OpenForensics.ui = UI;
})(typeof globalThis !== 'undefined' ? globalThis : this);
