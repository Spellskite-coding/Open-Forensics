/* Open-Forensics — amorçage. */
(function (root) {
  'use strict';

  function showFatal(message) {
    try {
      var app = document.getElementById('app');
      if (!app) return;
      var box = document.createElement('div');
      box.className = 'note bad';
      var b = document.createElement('b');
      b.textContent = 'Erreur interne — ';
      var s = document.createElement('span');
      s.textContent = String(message).slice(0, 500);
      box.appendChild(b);
      box.appendChild(s);
      app.insertBefore(box, app.firstChild);
    } catch (e) { /* rien de plus à tenter */ }
  }

  root.addEventListener('error', function (e) {
    showFatal((e && e.message ? e.message : 'inconnue') + ' (' + (e && e.filename ? e.filename : '?') + ':' + (e && e.lineno ? e.lineno : '?') + ')');
  });

  function boot() {
    var ns = root.OpenForensics;
    var missing = ['util', 'ref', 'engine', 'ui'].filter(function (k) { return !ns || !ns[k]; });
    if (missing.length) {
      showFatal('Modules manquants : ' + missing.join(', ') + '. Vérifiez que tous les fichiers du dossier js/ sont présents.');
      return;
    }
    if (!ns.cases.length) {
      showFatal('Aucun dossier chargé : vérifiez les fichiers js/data/cas-*.js.');
      return;
    }
    ns.util.deepFreeze(ns.cases);
    ns.ui.mount();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})(typeof globalThis !== 'undefined' ? globalThis : this);
