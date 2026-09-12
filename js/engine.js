/* Open-Forensics — moteur d'investigation et de notation.
 *
 * Ce module ne touche jamais au DOM : il est testable seul, et c'est ce qui
 * permet à la suite de tests de rejouer des investigations complètes.
 */
(function (root) {
  'use strict';

  var E = {};

  function REF() { return root.OpenForensics.ref; }
  function CASES() { return root.OpenForensics.cases; }
  function U() { return root.OpenForensics.util; }

  /* ------------------------------------------------------------------ */
  /* Normalisation des réponses                                          */
  /* ------------------------------------------------------------------ */

  var ACCENTS = { 'à': 'a', 'â': 'a', 'ä': 'a', 'á': 'a', 'ã': 'a', 'å': 'a', 'ç': 'c', 'è': 'e', 'é': 'e',
    'ê': 'e', 'ë': 'e', 'î': 'i', 'ï': 'i', 'í': 'i', 'ì': 'i', 'ô': 'o', 'ö': 'o', 'ó': 'o', 'ò': 'o',
    'õ': 'o', 'ù': 'u', 'û': 'u', 'ü': 'u', 'ú': 'u', 'ÿ': 'y', 'ñ': 'n', 'œ': 'oe', 'æ': 'ae' };

  function stripAccents(s) {
    var out = '', i, c;
    for (i = 0; i < s.length; i++) {
      c = s.charAt(i);
      out += ACCENTS[c] || c;
    }
    return out;
  }

  /* Les indicateurs sont souvent recopiés sous forme « défanguée » depuis un
   * rapport : on accepte hxxp://, [.] et (.) comme s'ils étaient normaux. */
  function refang(s) {
    return s
      .replace(/hxxps?:\/\//gi, '')
      .replace(/https?:\/\//gi, '')
      .replace(/\[\.\]/g, '.')
      .replace(/\(\.\)/g, '.')
      .replace(/\[:\]/g, ':')
      .replace(/\[at\]/gi, '@');
  }

  E.normalize = function (type, value) {
    var s = String(value === undefined || value === null ? '' : value);
    s = s.replace(/^\s+|\s+$/g, '');
    if (!s) return '';
    switch (type) {
      case 'hash':
        return s.toLowerCase().replace(/[^0-9a-f]/g, '');
      case 'ip':
        return refang(s).replace(/[\[\]\s]/g, '').replace(/\/$/, '');
      case 'domain':
        s = refang(s).toLowerCase().replace(/\s/g, '');
        s = s.replace(/^www\./, '').replace(/\/.*$/, '').replace(/\.$/, '');
        return s;
      case 'number':
        return s.replace(/[^0-9]/g, '').replace(/^0+(?=\d)/, '');
      case 'datetime':
        /* On compare à la minute : 2026-03-04 08:12, 2026-03-04T08:12:33,
         * 04/03/2026 08:12 sont équivalents. */
        var d = s.replace(/[^0-9]/g, '');
        if (/^\d{2}\d{2}\d{4}/.test(s.replace(/[^0-9]/g, '')) && /^\d{2}[\/.]\d{2}[\/.]\d{4}/.test(s)) {
          d = d.slice(4, 8) + d.slice(2, 4) + d.slice(0, 2) + d.slice(8);
        }
        return d.slice(0, 12);
      case 'path':
        return stripAccents(s.toLowerCase()).replace(/\\/g, '/').replace(/\/+$/, '').replace(/\s+/g, ' ');
      case 'choice':
      case 'technique':
        return s;
      default:
        return stripAccents(s.toLowerCase()).replace(/["'«»]/g, '').replace(/\s+/g, ' ');
    }
  };

  E.checkFlag = function (question, value) {
    var given = E.normalize(question.type, value);
    if (!given) return false;
    var accepted = [question.answer].concat(question.alt || []);
    for (var i = 0; i < accepted.length; i++) {
      if (E.normalize(question.type, accepted[i]) === given) return true;
    }
    return false;
  };

  /* ------------------------------------------------------------------ */
  /* Accès aux dossiers                                                  */
  /* ------------------------------------------------------------------ */

  E.caseById = function (id) {
    var list = CASES();
    for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    return null;
  };

  E.artifactById = function (c, id) {
    for (var i = 0; i < c.evidence.length; i++) if (c.evidence[i].id === id) return c.evidence[i];
    return null;
  };

  E.eventById = function (c, id) {
    for (var i = 0; i < c.events.length; i++) if (c.events[i].id === id) return c.events[i];
    return null;
  };

  E.maxScoreParts = function (c) {
    var W = REF().weights;
    return {
      flags: c.questions.length * W.flag,
      chain: c.chain.length * (W.chainEvent + W.chainTechnique),
      synthesis: W.synthesis
    };
  };

  /* ------------------------------------------------------------------ */
  /* Session d'investigation                                             */
  /* ------------------------------------------------------------------ */

  E.createSession = function (caseId) {
    var c = E.caseById(caseId);
    if (!c) return null;
    var st = {
      caseId: caseId,
      startedWall: Date.now(),
      elapsedSec: 0,
      flags: {},
      chain: {},
      synthesis: '',
      notes: '',
      logs: {},
      submitted: false,
      report: null
    };
    c.questions.forEach(function (q) {
      st.flags[q.id] = { solved: false, wrong: 0, hint: false, value: '' };
    });
    c.chain.forEach(function (row) {
      st.chain[row.tactic] = { event: '', technique: '' };
    });
    return st;
  };

  E.tick = function (st) {
    if (!st || st.submitted) return;
    st.elapsedSec = Math.round((Date.now() - st.startedWall) / 1000);
  };

  E.answerFlag = function (st, qid, value) {
    if (st.submitted) return { ok: false, msg: 'L\'investigation est close.' };
    var c = E.caseById(st.caseId);
    var q = null, i;
    for (i = 0; i < c.questions.length; i++) if (c.questions[i].id === qid) q = c.questions[i];
    if (!q) return { ok: false, msg: 'Question inconnue.' };
    var slot = st.flags[qid];
    if (slot.solved) return { ok: true, msg: 'Déjà validé.' };
    slot.value = String(value || '').slice(0, 200);
    if (!E.normalize(q.type, value)) return { ok: false, msg: 'Saisissez une valeur.' };
    if (E.checkFlag(q, value)) {
      slot.solved = true;
      return { ok: true, msg: 'Confirmé par les pièces.' };
    }
    slot.wrong += 1;
    return { ok: false, msg: 'Ne correspond à aucune trace du dossier.' };
  };

  E.useHint = function (st, qid) {
    if (st.submitted) return null;
    var c = E.caseById(st.caseId), q = null, i;
    for (i = 0; i < c.questions.length; i++) if (c.questions[i].id === qid) q = c.questions[i];
    if (!q || !st.flags[qid] || st.flags[qid].solved) return null;
    st.flags[qid].hint = true;
    return q.hint;
  };

  E.setChain = function (st, tactic, field, value) {
    if (st.submitted || !st.chain[tactic]) return;
    st.chain[tactic][field] = String(value || '');
  };

  /* ------------------------------------------------------------------ */
  /* Construction des journaux                                           */
  /* ------------------------------------------------------------------ */

  /* Les pièces sont exclusivement des journaux. Les lignes utiles sont
   * écrites à la main dans le dossier ; le trafic de fond est engendré de
   * façon déterministe puis fusionné par horodatage. C'est ce mélange qui
   * oblige à filtrer, recouper et remonter une piste au lieu de lire une
   * liste de preuves. */

  function parseTs(s) {
    var m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/.exec(String(s));
    if (!m) return 0;
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], m[6] ? +m[6] : 0);
  }
  E.parseTs = parseTs;

  function pad(n, w) {
    var s = String(Math.floor(Math.abs(n)));
    while (s.length < w) s = '0' + s;
    return s;
  }

  function fmtTs(ms) {
    var d = new Date(ms);
    return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1, 2) + '-' + pad(d.getUTCDate(), 2) + ' ' +
      pad(d.getUTCHours(), 2) + ':' + pad(d.getUTCMinutes(), 2) + ':' + pad(d.getUTCSeconds(), 2);
  }
  E.fmtTs = fmtTs;

  E.buildLog = function (c, artifact) {
    var u = U();
    var rnd = u.prng(u.seedFromString(c.id + '|' + artifact.id));
    var out = [];
    (artifact.lines || []).forEach(function (l) {
      out.push({ ms: parseTs(l.t), t: l.t, m: l.m, signal: true });
    });
    var specs = artifact.noise ? (Array.isArray(artifact.noise) ? artifact.noise : [artifact.noise]) : [];
    var env = c.env || {};
    specs.forEach(function (spec) {
      var gen = REF().noise[spec.family];
      if (!gen) return;
      var a = parseTs(spec.from), b = parseTs(spec.to);
      if (b <= a) return;
      var vars = { users: env.users || ['utilisateur'], admins: env.admins || env.users || ['admin'],
        hosts: env.hosts || ['POSTE-01'], vms: env.vms || null, domain: env.domain || 'DOMAINE',
        dns: env.dns || 'interne.test', mail: env.mail || 'client.example',
        lan: env.lan || '10.0.0', edge: env.edge || '198.51.100.10' };
      if (spec.vars) {
        for (var k in spec.vars) if (Object.prototype.hasOwnProperty.call(spec.vars, k)) vars[k] = spec.vars[k];
      }
      for (var i = 0; i < spec.count; i++) {
        var ms = a + Math.floor(rnd() * (b - a));
        out.push({ ms: ms, t: fmtTs(ms), m: gen(rnd, vars), signal: false });
      }
    });
    out.sort(function (x, y) { return x.ms - y.ms; });
    return out;
  };

  /* Les journaux construits sont mis en cache dans la session : la graine
   * étant fixe, deux ouvertures donnent exactement le même journal. */
  E.logOf = function (st, artifactId) {
    var c = E.caseById(st.caseId);
    if (!st.logs) st.logs = {};
    if (!st.logs[artifactId]) {
      var a = E.artifactById(c, artifactId);
      st.logs[artifactId] = a ? E.buildLog(c, a) : [];
    }
    return st.logs[artifactId];
  };

  E.logVolume = function (st) {
    var c = E.caseById(st.caseId), total = 0;
    c.evidence.forEach(function (a) { total += E.logOf(st, a.id).length; });
    return total;
  };

  /* ------------------------------------------------------------------ */
  /* Recherche transverse dans les journaux                              */
  /* ------------------------------------------------------------------ */

  E.searchEvidence = function (st, query, sourceFilter) {
    var u = U(), out = [];
    var c = E.caseById(st.caseId);
    var q = String(query || '').replace(/^\s+|\s+$/g, '');
    if (!q) return out;
    c.evidence.forEach(function (a) {
      if (sourceFilter && a.source !== sourceFilter) return;
      var lines = E.logOf(st, a.id);
      for (var i = 0; i < lines.length && out.length < 600; i++) {
        if (u.has(lines[i].m, q) || u.has(lines[i].t, q)) {
          out.push({ artifact: a, line: lines[i] });
        }
      }
    });
    return out;
  };

  /* ------------------------------------------------------------------ */
  /* Notation                                                            */
  /* ------------------------------------------------------------------ */

  E.grade = function (st) {
    var W = REF().weights, c = E.caseById(st.caseId), u = U();
    var res = {
      caseId: c.id, title: c.title, client: c.client, difficulty: c.difficulty,
      flags: [], chain: [], synthesis: null,
      earned: 0, max: 0, score: 0, grade: 'E', label: '',
      stats: {}
    };

    /* --- Flags ---------------------------------------------------------- */
    var solved = 0, hints = 0, wrong = 0, flagEarned = 0;
    c.questions.forEach(function (q) {
      var slot = st.flags[q.id];
      var pts = 0;
      if (slot.solved) {
        solved += 1;
        pts = W.flag;
        if (slot.hint) pts -= W.hint;
        pts -= Math.min(W.flagWrongAttemptCap, slot.wrong * W.flagWrongAttempt);
        pts = Math.max(0, pts);
      }
      hints += slot.hint ? 1 : 0;
      wrong += slot.wrong;
      flagEarned += pts;
      res.flags.push({
        id: q.id, label: q.label, expected: q.answer, given: slot.value,
        solved: slot.solved, hint: slot.hint, wrong: slot.wrong,
        points: Math.round(pts * 10) / 10, max: W.flag,
        why: q.why || '', where: q.where || ''
      });
    });

    /* --- Reconstitution de la chaîne ------------------------------------ */
    var chainEarned = 0, chainOk = 0;
    c.chain.forEach(function (row) {
      var given = st.chain[row.tactic] || { event: '', technique: '' };
      var evOk = given.event === row.event;
      var tqOk = given.technique === row.technique;
      var pts = (evOk ? W.chainEvent : 0) + (tqOk ? W.chainTechnique : 0);
      chainEarned += pts;
      if (evOk && tqOk) chainOk += 1;
      var ev = row.event === 'NONE' ? null : E.eventById(c, row.event);
      var gEv = given.event === 'NONE' ? null : E.eventById(c, given.event);
      res.chain.push({
        tactic: row.tactic,
        expectedEvent: row.event === 'NONE' ? 'Non observé' : (ev ? ev.label : row.event),
        givenEvent: !given.event ? 'Rien indiqué' : (given.event === 'NONE' ? 'Non observé' : (gEv ? gEv.label : given.event)),
        expectedTechnique: row.technique === 'NONE' ? 'Aucune' : REF().techniqueName(row.technique),
        givenTechnique: !given.technique ? 'Rien indiqué' : (given.technique === 'NONE' ? 'Aucune' : REF().techniqueName(given.technique)),
        eventOk: evOk, techniqueOk: tqOk,
        points: pts, max: W.chainEvent + W.chainTechnique,
        why: row.why || '', where: row.where || ''
      });
    });

    /* --- Synthèse -------------------------------------------------------- */
    var text = String(st.synthesis || '').replace(/^\s+|\s+$/g, '');
    var low = stripAccents(text.toLowerCase());
    var cited = (c.keyIndicators || []).filter(function (k) {
      return low.indexOf(stripAccents(String(k).toLowerCase())) >= 0;
    });
    var sPts = 0, sDetail = [];
    if (text.length >= W.synthesisMin) { sPts += 2; sDetail.push({ ok: true, t: 'Longueur suffisante' }); }
    else sDetail.push({ ok: false, t: 'Trop courte (' + text.length + ' caractères sur ' + W.synthesisMin + ' attendus)' });
    if (cited.length >= 1) { sPts += 3; sDetail.push({ ok: true, t: 'Au moins un indicateur cité' }); }
    else sDetail.push({ ok: false, t: 'Aucun indicateur du dossier cité' });
    if (cited.length >= 3) { sPts += 3; sDetail.push({ ok: true, t: 'Trois indicateurs ou plus cités' }); }
    else sDetail.push({ ok: false, t: 'Moins de trois indicateurs cités (' + cited.length + ')' });
    res.synthesis = { points: sPts, max: W.synthesis, cited: cited, detail: sDetail, text: text };

    /* --- Agrégation ------------------------------------------------------ */
    var parts = E.maxScoreParts(c);
    res.max = parts.flags + parts.chain + parts.synthesis;
    res.earned = flagEarned + chainEarned + sPts;
    res.score = Math.round(u.clamp(res.max > 0 ? (res.earned / res.max) * 100 : 0, 0, 100));
    res.parts = {
      flags: { earned: Math.round(flagEarned * 10) / 10, max: parts.flags },
      chain: { earned: chainEarned, max: parts.chain },
      synthesis: { earned: sPts, max: parts.synthesis }
    };
    res.dims = {
      etablissement: parts.flags ? Math.round((flagEarned / parts.flags) * 100) : 100,
      reconstitution: parts.chain ? Math.round((chainEarned / parts.chain) * 100) : 100,
      restitution: Math.round((sPts / W.synthesis) * 100),
      autonomie: Math.round(u.clamp(100 - (hints * 12) - (wrong * 3), 0, 100))
    };
    res.stats = {
      flagsSolved: solved, flagsTotal: c.questions.length,
      hints: hints, wrongAttempts: wrong,
      chainOk: chainOk, chainTotal: c.chain.length,
      elapsedSec: st.elapsedSec
    };

    var grades = REF().grades;
    for (var i = 0; i < grades.length; i++) {
      if (res.score >= grades[i].min) { res.grade = grades[i].letter; res.label = grades[i].label; break; }
    }
    return res;
  };

  E.submit = function (st) {
    if (st.submitted) return st.report;
    st.submitted = true;
    E.tick(st);
    st.report = E.grade(st);
    return st.report;
  };

  /* Fiche d'indicateurs : le livrable qu'un CERT transmet au SOC. */
  E.iocSheet = function (c) {
    return (c.iocs || []).slice();
  };

  E.exportReport = function (st) {
    var c = E.caseById(st.caseId);
    var r = st.report || E.grade(st);
    return {
      application: 'Open-Forensics',
      dossier: c.id,
      intitule: c.title,
      client: c.client,
      difficulte: c.difficulty,
      duree_s: st.elapsedSec,
      score: r.score,
      mention: r.grade,
      dimensions: r.dims,
      statistiques: r.stats,
      constatations: r.flags.map(function (f) {
        return { question: f.label, reponse_attendue: f.expected, reponse_donnee: f.given, etablie: f.solved, points: f.points };
      }),
      chaine_attaque: r.chain.map(function (x) {
        return { tactique: x.tactic, evenement_attendu: x.expectedEvent, evenement_retenu: x.givenEvent, technique_attendue: x.expectedTechnique, technique_retenue: x.givenTechnique };
      }),
      indicateurs: E.iocSheet(c),
      synthese: r.synthesis.text
    };
  };

  /* ------------------------------------------------------------------ */
  /* Progression locale                                                  */
  /* ------------------------------------------------------------------ */

  var KEY = 'openforensics.progress.v1';

  E.readProgress = function () {
    try {
      var raw = root.localStorage.getItem(KEY);
      if (!raw || raw.length > 20000) return {};
      var o = JSON.parse(raw);
      if (!o || typeof o !== 'object' || Array.isArray(o)) return {};
      var out = {}, u = U();
      Object.keys(o).slice(0, 60).forEach(function (k) {
        var v = o[k];
        if (!v || typeof v !== 'object') return;
        out[String(k).slice(0, 12)] = {
          best: u.clamp(Math.round(Number(v.best) || 0), 0, 100),
          grade: String(v.grade || '?').slice(0, 2),
          date: String(v.date || '').slice(0, 16),
          runs: u.clamp(Math.round(Number(v.runs) || 1), 1, 999)
        };
      });
      return out;
    } catch (e) { return {}; }
  };

  E.saveProgress = function (caseId, report) {
    try {
      var all = E.readProgress();
      var prev = all[caseId];
      all[caseId] = {
        best: Math.max(prev ? prev.best : 0, report.score),
        grade: (prev && prev.best > report.score) ? prev.grade : report.grade,
        date: new Date().toISOString().slice(0, 16).replace('T', ' '),
        runs: (prev ? prev.runs : 0) + 1
      };
      root.localStorage.setItem(KEY, JSON.stringify(all));
    } catch (e) { /* stockage indisponible : sans conséquence */ }
  };

  E.clearProgress = function () {
    try { root.localStorage.removeItem(KEY); } catch (e) { /* ignoré */ }
  };

  root.OpenForensics = root.OpenForensics || {};
  root.OpenForensics.engine = E;
})(typeof globalThis !== 'undefined' ? globalThis : this);
