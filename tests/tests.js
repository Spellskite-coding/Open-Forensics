/* Open-Forensics — suite de tests.
 * Ouvrir tests/run.html dans un navigateur : chaque ligne indique OK ou ÉCHEC.
 * Aucun outil externe, aucune installation.
 */
(function (root) {
  'use strict';

  var out = document.getElementById('out');
  var pass = 0, fail = 0, failures = [];

  function line(ok, label, extra) {
    pass += ok ? 1 : 0;
    fail += ok ? 0 : 1;
    if (!ok) failures.push(label + ' — ' + (extra === undefined ? '' : String(extra)));
    var d = document.createElement('div');
    d.className = 'log-line';
    var a = document.createElement('span');
    a.className = 'lt';
    a.textContent = ok ? 'OK' : 'ÉCHEC';
    a.style.color = ok ? '#3ddc97' : '#ff4d6d';
    var b = document.createElement('span');
    b.textContent = label + (extra === undefined ? '' : '  ' + extra);
    d.appendChild(a); d.appendChild(b);
    out.appendChild(d);
  }
  function eq(l, got, want) { line(got === want, l, 'obtenu=' + got + ' attendu=' + want); }
  function ok(l, cond, extra) { line(!!cond, l, extra); }

  var U = root.OpenForensics.util, REF = root.OpenForensics.ref,
      E = root.OpenForensics.engine, CASES = root.OpenForensics.cases;

  /* --- 1. Normalisation des réponses ----------------------------------- */
  eq('normalisation : casse et accents', E.normalize('text', '  Adm_Marcelin '), 'adm_marcelin');
  eq('normalisation : accents français', E.normalize('text', 'Élévation'), 'elevation');
  eq('normalisation : adresse défanguée', E.normalize('ip', 'hxxp://198[.]51[.]100[.]77'), '198.51.100.77');
  eq('normalisation : domaine avec protocole', E.normalize('domain', 'https://Exemple.TEST/page'), 'exemple.test');
  eq('normalisation : empreinte en majuscules', E.normalize('hash', ' 5719370CEA15F355 '), '5719370cea15f355');
  eq('normalisation : nombre avec séparateurs', E.normalize('number', '81 240'), '81240');
  eq('normalisation : horodatage ISO', E.normalize('datetime', '2026-03-04T01:27:14'), '202603040127');
  eq('normalisation : horodatage à la française', E.normalize('datetime', '04/03/2026 01:27'), '202603040127');
  eq('normalisation : chemin Windows', E.normalize('path', 'C:\\Windows\\Temp\\X'), 'c:/windows/temp/x');

  /* --- 2. Intégrité des dossiers --------------------------------------- */
  eq('la bibliothèque contient dix dossiers', CASES.length, 10);
  (function () {
    var ids = {}, byDiff = { facile: 0, moyen: 0, difficile: 0 };
    CASES.forEach(function (c) {
      ok('  ' + c.id + ' est structurellement complet',
        !!(c.title && c.client && c.brief && c.brief.saisine && c.brief.limites && c.brief.mission &&
           c.evidence.length && c.questions.length && c.chain.length && c.events.length &&
           c.debrief && c.debrief.story && c.debrief.lessons.length && c.debrief.pitfalls.length &&
           c.iocs.length && c.keyIndicators.length && c.env),
        c.questions.length + ' constatations, ' + c.evidence.length + ' journaux');
      ok(c.id + ' : identifiant unique', !ids[c.id], c.id);
      ids[c.id] = 1;
      byDiff[c.difficulty] = (byDiff[c.difficulty] || 0) + 1;
    });
    ok('les trois niveaux de difficulté sont peuplés', byDiff.facile > 0 && byDiff.moyen > 0 && byDiff.difficile > 0, JSON.stringify(byDiff));
  })();

  (function () {
    /* Un dossier difficile doit être plus long qu'un dossier facile. */
    var bad = [];
    CASES.forEach(function (c) {
      var mini = { facile: 8, moyen: 11, difficile: 13 }[c.difficulty];
      if (c.questions.length < mini) bad.push(c.id + ' ' + c.questions.length + '<' + mini);
      var dur = { facile: 30, moyen: 50, difficile: 80 }[c.difficulty];
      if (c.estimatedMin < dur) bad.push(c.id + ' durée ' + c.estimatedMin + '<' + dur);
    });
    ok('la difficulté se traduit en volume et en durée', bad.length === 0, bad.join(', '));
  })();

  (function () {
    var bad = [];
    CASES.forEach(function (c) {
      c.evidence.forEach(function (a) {
        if (!a.id || !a.source || !a.system || !a.title) bad.push(c.id + '/' + a.id + ' incomplet');
        if (!REF.sources.some(function (s) { return s.id === a.source; })) bad.push(c.id + '/' + a.id + ' source inconnue: ' + a.source);
        (a.lines || []).forEach(function (l) {
          if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(l.t)) bad.push(c.id + '/' + a.id + ' horodatage invalide: ' + l.t);
          if (!l.m) bad.push(c.id + '/' + a.id + ' ligne vide');
        });
        var specs = a.noise ? (Array.isArray(a.noise) ? a.noise : [a.noise]) : [];
        specs.forEach(function (s) {
          if (!REF.noise[s.family]) bad.push(c.id + '/' + a.id + ' famille de bruit inconnue: ' + s.family);
          if (E.parseTs(s.to) <= E.parseTs(s.from)) bad.push(c.id + '/' + a.id + ' fenêtre de bruit invalide');
        });
      });
    });
    ok('toutes les pièces sont des journaux bien formés', bad.length === 0, bad.slice(0, 4).join(' | '));
  })();

  (function () {
    var bad = [];
    CASES.forEach(function (c) {
      var qids = {};
      c.questions.forEach(function (q) {
        if (qids[q.id]) bad.push(c.id + ' question en double ' + q.id);
        qids[q.id] = 1;
        if (!q.label || !q.hint || !q.where || !q.why) bad.push(c.id + '/' + q.id + ' feedback incomplet');
        if (q.answer === undefined || q.answer === '') bad.push(c.id + '/' + q.id + ' sans réponse');
        if (q.type === 'choice') {
          if (!q.options || q.options.length < 3) bad.push(c.id + '/' + q.id + ' moins de trois options');
          if (q.options && q.options.indexOf(q.answer) < 0) bad.push(c.id + '/' + q.id + ' réponse absente des options');
        }
        /* La réponse doit se valider elle-même après normalisation. */
        if (!E.checkFlag(q, q.answer)) bad.push(c.id + '/' + q.id + ' réponse non auto-validante');
        (q.alt || []).forEach(function (a) {
          if (!E.checkFlag(q, a)) bad.push(c.id + '/' + q.id + ' variante refusée: ' + a);
        });
      });
    });
    ok('les constatations sont complètes et auto-validantes', bad.length === 0, bad.slice(0, 4).join(' | '));
  })();

  (function () {
    var bad = [];
    CASES.forEach(function (c) {
      var evids = {};
      c.events.forEach(function (e) {
        if (evids[e.id]) bad.push(c.id + ' évènement en double ' + e.id);
        evids[e.id] = 1;
        if (!e.label || !e.t) bad.push(c.id + '/' + e.id + ' incomplet');
      });
      var seen = {};
      c.chain.forEach(function (row) {
        if (REF.chainTactics.indexOf(row.tactic) < 0) bad.push(c.id + ' tactique hors référentiel: ' + row.tactic);
        if (seen[row.tactic]) bad.push(c.id + ' tactique en double: ' + row.tactic);
        seen[row.tactic] = 1;
        if (row.event !== 'NONE' && !evids[row.event]) bad.push(c.id + ' évènement attendu inconnu: ' + row.event);
        if (row.technique !== 'NONE' && !REF.techniques.some(function (t) { return t.id === row.technique; })) bad.push(c.id + ' technique inconnue: ' + row.technique);
        if (row.technique !== 'NONE') {
          var t = REF.techniques.filter(function (x) { return x.id === row.technique; })[0];
          if (t && t.tactic !== row.tactic) bad.push(c.id + ' ' + row.technique + ' n\'appartient pas à ' + row.tactic + ' mais à ' + t.tactic);
        }
        if ((row.event === 'NONE') !== (row.technique === 'NONE')) bad.push(c.id + ' incohérence non-observé sur ' + row.tactic);
        if (!row.why || !row.where) bad.push(c.id + ' feedback de chaîne incomplet sur ' + row.tactic);
      });
      if (c.chain.length !== REF.chainTactics.length) bad.push(c.id + ' chaîne incomplète (' + c.chain.length + ')');
    });
    ok('les chaînes d\'attaque sont cohérentes avec le référentiel', bad.length === 0, bad.slice(0, 4).join(' | '));
  })();

  (function () {
    /* Chaque dossier doit contenir des tactiques non observées : conclure à
     * l'absence fait partie de l'exercice. */
    var bad = [];
    CASES.forEach(function (c) {
      var none = c.chain.filter(function (r) { return r.event === 'NONE'; }).length;
      if (none < 2) bad.push(c.id + ' seulement ' + none + ' tactique(s) non observée(s)');
      if (none > 9) bad.push(c.id + ' ' + none + ' tactiques non observées, dossier trop creux');
    });
    ok('chaque dossier comporte des tactiques non observées', bad.length === 0, bad.join(', '));
  })();

  (function () {
    /* Les indicateurs cités dans la synthèse doivent exister dans les pièces. */
    var bad = [];
    CASES.forEach(function (c) {
      var st = E.createSession(c.id);
      var all = '';
      c.evidence.forEach(function (a) {
        E.logOf(st, a.id).forEach(function (l) { all += l.m + '\n'; });
      });
      c.keyIndicators.forEach(function (k) {
        if (all.toLowerCase().indexOf(String(k).toLowerCase()) < 0) bad.push(c.id + ' indicateur introuvable dans les journaux: ' + k);
      });
    });
    ok('les indicateurs clés apparaissent réellement dans les journaux', bad.length === 0, bad.slice(0, 4).join(' | '));
  })();

  /* --- 3. Volumétrie des journaux -------------------------------------- */
  (function () {
    var bad = [], total = 0;
    CASES.forEach(function (c) {
      var st = E.createSession(c.id);
      var vol = E.logVolume(st);
      total += vol;
      var mini = { facile: 600, moyen: 1000, difficile: 1400 }[c.difficulty];
      if (vol < mini) bad.push(c.id + ' ' + vol + ' lignes < ' + mini);
      /* Les lignes utiles doivent rester minoritaires, sinon il n'y a rien à chercher. */
      var signal = 0;
      c.evidence.forEach(function (a) {
        E.logOf(st, a.id).forEach(function (l) { if (l.signal) signal += 1; });
      });
      if (signal / vol > 0.12) bad.push(c.id + ' signal trop dense (' + Math.round(signal / vol * 100) + ' %)');
    });
    ok('le volume de journaux impose une vraie recherche', bad.length === 0, bad.join(', ') + ' — ' + total + ' lignes au total');
  })();

  (function () {
    var c = CASES[0];
    var a = E.buildLog(c, c.evidence[0]);
    var b = E.buildLog(c, c.evidence[0]);
    eq('les journaux sont reproductibles à l\'identique',
      a.map(function (x) { return x.t + x.m; }).join('|') === b.map(function (x) { return x.t + x.m; }).join('|'), true);
    var sorted = true;
    for (var i = 1; i < a.length; i++) if (a[i].ms < a[i - 1].ms) sorted = false;
    ok('les lignes sont triées chronologiquement', sorted);
  })();

  (function () {
    var st = E.createSession('CAS-01');
    var res = E.searchEvidence(st, '198.51.100.77');
    ok('la recherche transverse retrouve un indicateur dans plusieurs pièces',
      res.length >= 2 && U.uniq(res.map(function (r) { return r.artifact.id; })).length >= 2,
      res.length + ' occurrences dans ' + U.uniq(res.map(function (r) { return r.artifact.id; })).length + ' pièces');
    eq('une recherche vide ne retourne rien', E.searchEvidence(st, '').length, 0);
  })();

  /* --- 4. Session et notation ------------------------------------------ */
  (function () {
    var st = E.createSession('CAS-01');
    var c = E.caseById('CAS-01');
    var q = c.questions[0];
    eq('une réponse fausse est refusée', E.answerFlag(st, q.id, 'pas la bonne').ok, false);
    eq('la tentative est comptabilisée', st.flags[q.id].wrong, 1);
    eq('une réponse juste est acceptée', E.answerFlag(st, q.id, q.answer).ok, true);
    eq('la constatation est marquée établie', st.flags[q.id].solved, true);
    ok('l\'indice n\'est plus proposé une fois la réponse trouvée', E.useHint(st, q.id) === null);
  })();

  function solve(caseId, mode) {
    var c = E.caseById(caseId);
    var st = E.createSession(caseId);
    if (mode !== 'idle') {
      c.questions.forEach(function (q) { E.answerFlag(st, q.id, q.answer); });
      c.chain.forEach(function (row) {
        E.setChain(st, row.tactic, 'event', row.event);
        E.setChain(st, row.tactic, 'technique', row.technique);
      });
      st.synthesis = 'Synthese complete de l investigation. ' + c.keyIndicators.slice(0, 4).join(', ') +
        '. La chronologie est etablie de bout en bout, les preuves proviennent de plusieurs journaux concordants, ' +
        'et les conclusions sur la portee reelle de la compromission sont documentees piece par piece dans le present rapport.';
    }
    return { st: st, report: E.submit(st) };
  }

  (function () {
    var bad = [];
    CASES.forEach(function (c) {
      var r = solve(c.id, 'perfect').report;
      if (r.score < 100) bad.push(c.id + ' score=' + r.score);
      if (r.stats.flagsSolved !== c.questions.length) bad.push(c.id + ' constatations ' + r.stats.flagsSolved);
      if (r.stats.chainOk !== c.chain.length) bad.push(c.id + ' chaîne ' + r.stats.chainOk);
    });
    ok('une investigation parfaite atteint 100 sur chaque dossier', bad.length === 0, bad.join(', '));
  })();

  (function () {
    var r = solve('CAS-01', 'idle').report;
    eq('une investigation vide obtient zéro', r.score, 0);
    eq('aucune constatation établie', r.stats.flagsSolved, 0);
    ok('le débriefing reste complet malgré l\'abandon', r.flags.length > 0 && r.chain.length > 0 && !!r.flags[0].where);
  })();

  (function () {
    /* Clore sans tout trouver doit rester possible et donner un score partiel. */
    var c = E.caseById('CAS-04');
    var st = E.createSession('CAS-04');
    c.questions.slice(0, 5).forEach(function (q) { E.answerFlag(st, q.id, q.answer); });
    c.chain.slice(0, 6).forEach(function (row) {
      E.setChain(st, row.tactic, 'event', row.event);
      E.setChain(st, row.tactic, 'technique', row.technique);
    });
    st.synthesis = 'Investigation partielle : ' + c.keyIndicators[0] + ' identifie comme source, le webshell est localise, mais la portee exacte de l extraction reste a confirmer avec les journaux manquants du serveur de base de donnees.';
    var r = E.submit(st);
    ok('une clôture partielle donne un score intermédiaire', r.score > 25 && r.score < 75, 'score=' + r.score);
    ok('le débriefing indique où trouver ce qui a été manqué',
      r.flags.filter(function (f) { return !f.solved && f.where; }).length > 0);
  })();

  (function () {
    /* Indices et tâtonnements pèsent sur l'autonomie. */
    var c = E.caseById('CAS-02');
    var st = E.createSession('CAS-02');
    c.questions.forEach(function (q) {
      E.useHint(st, q.id);
      E.answerFlag(st, q.id, 'faux');
      E.answerFlag(st, q.id, q.answer);
    });
    c.chain.forEach(function (row) {
      E.setChain(st, row.tactic, 'event', row.event);
      E.setChain(st, row.tactic, 'technique', row.technique);
    });
    st.synthesis = 'Synthese redigee apres usage systematique des indices. ' + c.keyIndicators.slice(0, 3).join(', ') + '. La chronologie est etablie mais l autonomie de l analyste reste a construire sur ce type de dossier.';
    var r = E.submit(st);
    ok('les indices et erreurs réduisent le score', r.score < 90 && r.score > 50, 'score=' + r.score);
    eq('l\'autonomie s\'effondre', r.dims.autonomie, 0);
    eq('l\'établissement des faits reste complet', r.stats.flagsSolved, c.questions.length);
  })();

  (function () {
    var st = E.createSession('CAS-03');
    var c = E.caseById('CAS-03');
    c.questions.forEach(function (q) { E.answerFlag(st, q.id, q.answer); });
    c.chain.forEach(function (row) {
      E.setChain(st, row.tactic, 'event', row.event);
      E.setChain(st, row.tactic, 'technique', row.technique);
    });
    st.synthesis = 'Trop court.';
    var r = E.submit(st);
    ok('une synthèse indigente est sanctionnée', r.synthesis.points === 0, r.synthesis.points + ' pts');
    ok('le reste du dossier reste crédité', r.score > 80, 'score=' + r.score);
    ok('le rapport exportable est sérialisable', JSON.stringify(E.exportReport(st)).length > 400);
  })();

  /* --- Résultat --------------------------------------------------------- */
  var head = document.createElement('h2');
  head.textContent = (fail === 0 ? 'TOUS LES TESTS PASSENT — ' : 'ÉCHECS DÉTECTÉS — ') + pass + ' réussis, ' + fail + ' échoués';
  head.style.color = fail === 0 ? '#3ddc97' : '#ff4d6d';
  out.parentNode.insertBefore(head, out);
  if (failures.length) {
    var ul = document.createElement('ul');
    ul.className = 'compact';
    failures.forEach(function (f) {
      var li = document.createElement('li');
      li.style.color = '#ff9f43';
      li.textContent = f;
      ul.appendChild(li);
    });
    out.parentNode.insertBefore(ul, out);
  }
  document.title = (fail === 0 ? 'OK ' : 'FAIL ') + pass + '/' + (pass + fail);
})(typeof globalThis !== 'undefined' ? globalThis : this);
