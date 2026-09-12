/* Open-Forensics — utilitaires bas niveau (DOM sûr, PRNG déterministe, formatage).
 * Aucune dépendance, aucun accès réseau, aucune évaluation dynamique de code.
 */
(function (root) {
  'use strict';

  var U = {};

  /* --- DOM ------------------------------------------------------------- */

  /* Attributs interdits par construction : tout gestionnaire on*, et les
   * attributs porteurs d'URL ou de style que l'application n'utilise pas.
   * Aucune donnée n'est jamais interprétée comme du balisage. */
  var BANNED_ATTRS = { style: 1, href: 1, src: 1, srcdoc: 1, formaction: 1, action: 1, background: 1, ping: 1 };

  U.el = function (tag, attrs, kids) {
    var node = document.createElement(String(tag));
    if (attrs) {
      for (var k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
        var v = attrs[k];
        if (v === null || v === undefined || v === false) continue;
        var key = String(k);
        if (key.length > 1 && key.slice(0, 2).toLowerCase() === 'on') continue;
        if (BANNED_ATTRS[key.toLowerCase()] === 1) continue;
        if (key === 'class') node.className = String(v);
        else if (key === 'text') node.textContent = String(v);
        else if (key === 'value') node.value = String(v);
        else if (key === 'checked' || key === 'disabled' || key === 'selected') { node[key] = !!v; }
        else if (key === 'data') { for (var d in v) { if (Object.prototype.hasOwnProperty.call(v, d)) node.setAttribute('data-' + d, String(v[d])); } }
        else node.setAttribute(key, String(v));
      }
    }
    U.append(node, kids);
    return node;
  };

  U.append = function (node, kids) {
    if (kids === null || kids === undefined || kids === false) return node;
    if (Array.isArray(kids)) {
      for (var i = 0; i < kids.length; i++) U.append(node, kids[i]);
      return node;
    }
    if (typeof kids === 'object' && kids.nodeType) node.appendChild(kids);
    else node.appendChild(document.createTextNode(String(kids)));
    return node;
  };

  U.clear = function (node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
    return node;
  };

  U.on = function (node, evt, fn) {
    node.addEventListener(evt, fn, false);
    return node;
  };

  U.byId = function (id) { return document.getElementById(id); };

  /* Largeur de barre : passe par le CSSOM avec une valeur numerique bornee. */
  U.setWidthPct = function (node, pct) {
    var p = U.clamp(Number(pct) || 0, 0, 100);
    node.style.width = p.toFixed(1) + '%';
    return node;
  };

  U.setVarPct = function (node, name, pct) {
    var p = U.clamp(Number(pct) || 0, 0, 100);
    node.style.setProperty(name, p.toFixed(1));
    return node;
  };

  /* --- Nombres / temps -------------------------------------------------- */

  U.clamp = function (n, lo, hi) { return n < lo ? lo : (n > hi ? hi : n); };

  U.pad2 = function (n) { n = Math.floor(Math.abs(n)); return (n < 10 ? '0' : '') + n; };

  /* mm:ss */
  U.mmss = function (sec) {
    var s = Math.max(0, Math.floor(sec));
    return U.pad2(Math.floor(s / 60)) + ':' + U.pad2(s % 60);
  };

  /* Duree lisible : "4 min 12 s" */
  U.dur = function (sec) {
    var s = Math.max(0, Math.round(sec));
    if (s < 60) return s + ' s';
    var m = Math.floor(s / 60);
    var r = s % 60;
    return m + ' min' + (r ? ' ' + U.pad2(r) + ' s' : '');
  };

  /* Horodatage fictif de la journee simulee : "09:14:22" */
  U.stamp = function (baseSec, offsetSec) {
    var t = Math.round(baseSec + offsetSec);
    var neg = t < 0;
    if (neg) t += 86400;
    t = ((t % 86400) + 86400) % 86400;
    return U.pad2(Math.floor(t / 3600)) + ':' + U.pad2(Math.floor((t % 3600) / 60)) + ':' + U.pad2(t % 60);
  };

  U.stampFull = function (day, baseSec, offsetSec) {
    return day + ' ' + U.stamp(baseSec, offsetSec);
  };

  /* --- Aleatoire deterministe (mulberry32) ------------------------------ */

  /* Multiplication 32 bits. Math.imul existe partout depuis 2013, mais le
   * repli garantit un résultat identique sur un moteur ancien. */
  var imul = Math.imul || function (a, b) {
    var aH = (a >>> 16) & 0xffff, aL = a & 0xffff;
    var bH = (b >>> 16) & 0xffff, bL = b & 0xffff;
    return ((aL * bL) + ((((aH * bL) + (aL * bH)) << 16) >>> 0)) | 0;
  };
  U.imul = imul;

  U.prng = function (seed) {
    var a = (seed >>> 0) || 0x9e3779b9;
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      var t = imul(a ^ (a >>> 15), 1 | a);
      t = (t + imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  };

  U.seedFromString = function (str) {
    var h = 2166136261;
    str = String(str);
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = imul(h, 16777619);
    }
    return h >>> 0;
  };

  U.randomSeed = function () {
    try {
      if (root.crypto && root.crypto.getRandomValues) {
        var a = new Uint32Array(1);
        root.crypto.getRandomValues(a);
        return a[0] >>> 0;
      }
    } catch (e) { /* environnement sans crypto : repli deterministe */ }
    return (Date.now() ^ 0x5f3759df) >>> 0;
  };

  U.randInt = function (rnd, lo, hi) { return lo + Math.floor(rnd() * (hi - lo + 1)); };

  U.pick = function (rnd, arr) { return arr[Math.floor(rnd() * arr.length) % arr.length]; };

  U.shuffle = function (rnd, arr) {
    var a = arr.slice();
    for (var i = a.length - 1; i > 0; i--) {
      var j = Math.floor(rnd() * (i + 1));
      var t = a[i]; a[i] = a[j]; a[j] = t;
    }
    return a;
  };

  /* --- Chaines ---------------------------------------------------------- */

  U.has = function (hay, needle) {
    if (!hay || !needle) return false;
    return String(hay).toLowerCase().indexOf(String(needle).toLowerCase()) !== -1;
  };

  U.trunc = function (s, n) {
    s = String(s);
    return s.length <= n ? s : s.slice(0, n - 1) + '…';
  };

  U.uniq = function (arr) {
    var seen = {}, out = [];
    for (var i = 0; i < arr.length; i++) {
      var k = String(arr[i]);
      if (!seen[k]) { seen[k] = 1; out.push(arr[i]); }
    }
    return out;
  };

  /* --- Divers ------------------------------------------------------------ */

  U.deepFreeze = function (obj) {
    if (!obj || (typeof obj !== 'object')) return obj;
    Object.getOwnPropertyNames(obj).forEach(function (k) {
      var v = obj[k];
      if (v && typeof v === 'object' && !Object.isFrozen(v)) U.deepFreeze(v);
    });
    return Object.freeze(obj);
  };

  U.sortBy = function (arr, key, desc) {
    return arr.slice().sort(function (a, b) {
      var x = a[key], y = b[key];
      if (x === y) return 0;
      return (x < y ? -1 : 1) * (desc ? -1 : 1);
    });
  };

  root.OpenForensics = root.OpenForensics || {};
  root.OpenForensics.util = U;
})(typeof globalThis !== 'undefined' ? globalThis : this);
