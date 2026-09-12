/* Open-Forensics — trafic de fond.
 *
 * Un journal réel n'est pas une liste de preuves : c'est un fleuve d'activité
 * banale dans lequel trois lignes comptent. Ces générateurs produisent ce
 * fleuve de façon déterministe (graine du dossier), ce qui rend la recherche,
 * le filtrage et le recoupement obligatoires — et l'investigation longue,
 * comme dans la vraie vie.
 *
 * Chaque famille reçoit un générateur pseudo-aléatoire et les variables du
 * journal concerné (hôtes, comptes, adresses internes du client), et rend une
 * ligne de message. L'horodatage est ajouté par le moteur.
 */
(function (root) {
  'use strict';

  var OF = root.OpenForensics.ref;
  var N = {};

  function pick(rnd, a) { return a[Math.floor(rnd() * a.length) % a.length]; }
  function int(rnd, a, b) { return a + Math.floor(rnd() * (b - a + 1)); }
  function ip(rnd, base) { return base + '.' + int(rnd, 2, 250); }

  var WEB = ['intranet', 'portail-rh', 'wiki', 'crm', 'facturation', 'support', 'planning'];
  var EXT = ['actualites-metier.example', 'fournisseur-logistique.example', 'banque-entreprise.example',
    'documentation-editeur.example', 'meteo-locale.example', 'formation-continue.example'];
  var DOCS = ['compte_rendu_hebdo.docx', 'budget_T2.xlsx', 'procedure_qualite.pdf', 'planning_equipe.xlsx',
    'contrat_cadre.pdf', 'note_de_service.docx', 'inventaire.csv'];
  var WINPROC = ['EXCEL.EXE', 'WINWORD.EXE', 'OUTLOOK.EXE', 'chrome.exe', 'Teams.exe', 'explorer.exe',
    'svchost.exe', 'MsMpEng.exe', 'SearchIndexer.exe'];

  /* --- Journaux de sécurité Windows ------------------------------------- */
  N['win-security'] = function (rnd, v) {
    var u = pick(rnd, v.users), h = pick(rnd, v.hosts);
    return pick(rnd, [
      'EventCode=4624 Logon_Type=3 Account_Name=' + u + ' Computer=' + h + ' Source_Network_Address=' + ip(rnd, v.lan) + ' Authentication_Package=Kerberos Logon_ID=0x' + int(rnd, 100000, 999999).toString(16).toUpperCase(),
      'EventCode=4634 Logon_Type=3 Account_Name=' + u + ' Computer=' + h + ' Logon_ID=0x' + int(rnd, 100000, 999999).toString(16).toUpperCase(),
      'EventCode=4624 Logon_Type=2 Account_Name=' + u + ' Computer=' + h + ' Logon_Process=User32 Authentication_Package=Negotiate',
      'EventCode=4768 Account_Name=' + u + ' Client_Address=' + ip(rnd, v.lan) + ' Ticket_Encryption_Type=0x12 Result=Success',
      'EventCode=4769 Account_Name=' + u + ' Service_Name=' + pick(rnd, v.hosts) + '$ Client_Address=' + ip(rnd, v.lan) + ' Ticket_Encryption_Type=0x12',
      'EventCode=4625 Logon_Type=2 Account_Name=' + u + ' Computer=' + h + ' Failure_Reason=Bad_Password Attempt=1',
      'EventCode=5140 Share_Name=\\\\*\\' + pick(rnd, ['Partage', 'Commun', 'Projets', 'Comptabilite']) + ' Account_Name=' + u + ' Source_Address=' + ip(rnd, v.lan) + ' Access=ReadData',
      'EventCode=4672 Account_Name=' + pick(rnd, v.admins || v.users) + ' Computer=' + h + ' Privileges=SeSecurityPrivilege,SeBackupPrivilege',
      'EventCode=4688 New_Process_Name=C:\\Windows\\System32\\' + pick(rnd, ['taskhostw.exe', 'sihost.exe', 'RuntimeBroker.exe']) + ' Creator_Process=svchost.exe Account_Name=' + u + ' Computer=' + h,
      'EventCode=4776 Account_Name=' + u + ' Workstation=' + h + ' Error_Code=0x0'
    ]);
  };

  /* --- Télémétrie de processus (Sysmon) --------------------------------- */
  N['sysmon'] = function (rnd, v) {
    var u = pick(rnd, v.users), h = pick(rnd, v.hosts), p = pick(rnd, WINPROC);
    return pick(rnd, [
      'EventCode=1 Computer=' + h + ' Image=C:\\Program Files\\' + pick(rnd, ['Microsoft Office\\root\\Office16', 'Google\\Chrome\\Application', 'Teams']) + '\\' + p + ' ParentImage=C:\\Windows\\explorer.exe User=' + v.domain + '\\' + u + ' ProcessId=' + int(rnd, 1200, 9800),
      'EventCode=3 Computer=' + h + ' Image=' + p + ' User=' + v.domain + '\\' + u + ' DestinationIp=' + ip(rnd, v.lan) + ' DestinationPort=' + pick(rnd, [443, 445, 88, 389, 135]),
      'EventCode=11 Computer=' + h + ' TargetFilename=C:\\Users\\' + u + '\\AppData\\Local\\Temp\\~DF' + int(rnd, 100000, 999999).toString(16) + '.tmp Image=' + p,
      'EventCode=22 Computer=' + h + ' QueryName=' + pick(rnd, WEB) + '.' + v.dns + ' QueryResults=' + ip(rnd, v.lan) + ' Image=chrome.exe',
      'EventCode=13 Computer=' + h + ' TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\State Details=' + int(rnd, 1, 9) + ' Image=svchost.exe',
      'EventCode=1 Computer=' + h + ' Image=C:\\Windows\\System32\\wbem\\WmiPrvSE.exe ParentImage=C:\\Windows\\System32\\svchost.exe User=AUTORITE NT\\Système ProcessId=' + int(rnd, 1200, 9800)
    ]);
  };

  /* --- Agent de sécurité (EDR) ------------------------------------------ */
  N['edr'] = function (rnd, v) {
    var h = pick(rnd, v.hosts);
    return pick(rnd, [
      'agent_heartbeat host=' + h + ' version=' + pick(rnd, ['7.4.2', '7.4.3']) + ' policy=Standard status=healthy',
      'scan_scheduled host=' + h + ' type=quick files=' + int(rnd, 8000, 42000) + ' result=clean',
      'policy_update host=' + h + ' revision=' + int(rnd, 400, 460) + ' applied=true',
      'detection name="PUA/ToolbarInstaller" host=' + h + ' path=C:\\Users\\' + pick(rnd, v.users) + '\\Downloads\\setup_' + int(rnd, 10, 99) + '.exe action=QUARANTINED severity=low',
      'usb_device host=' + h + ' action=connected vendor=' + pick(rnd, ['Kingston', 'SanDisk', 'Generic']) + ' serial=' + int(rnd, 100000, 999999),
      'agent_update host=' + h + ' from=7.4.2 to=7.4.3 result=success'
    ]);
  };

  /* --- Pare-feu ---------------------------------------------------------- */
  N['firewall'] = function (rnd, v) {
    var s = ip(rnd, v.lan);
    return pick(rnd, [
      'src=' + s + ' dst=' + ip(rnd, v.lan) + ' dport=' + pick(rnd, [445, 88, 389, 3268, 1433]) + ' proto=tcp action=ALLOW bytes=' + int(rnd, 400, 90000),
      'src=' + s + ' dst=' + pick(rnd, ['203.0.113.', '198.51.100.']) + int(rnd, 2, 250) + ' dport=443 proto=tcp action=ALLOW bytes_out=' + int(rnd, 800, 60000) + ' bytes_in=' + int(rnd, 900, 400000) + ' app=web',
      'src=' + pick(rnd, ['203.0.113.', '198.51.100.', '192.0.2.']) + int(rnd, 2, 250) + ' dst=' + v.edge + ' dport=' + pick(rnd, [22, 23, 3389, 445, 8080]) + ' proto=tcp action=DENY reason=policy_default',
      'src=' + s + ' dst=' + ip(rnd, v.lan) + ' dport=53 proto=udp action=ALLOW bytes=' + int(rnd, 80, 400),
      'src=' + s + ' dst=203.0.113.' + int(rnd, 2, 250) + ' dport=123 proto=udp action=ALLOW app=ntp'
    ]);
  };

  /* --- Mandataire web ---------------------------------------------------- */
  N['proxy'] = function (rnd, v) {
    var u = pick(rnd, v.users);
    return pick(rnd, [
      'user=' + u + ' src=' + ip(rnd, v.lan) + ' action=ALLOW method=GET url=https://' + pick(rnd, EXT) + '/' + pick(rnd, ['accueil', 'articles/2026', 'catalogue', 'connexion']) + ' status=200 bytes=' + int(rnd, 2000, 90000) + ' category=business',
      'user=' + u + ' src=' + ip(rnd, v.lan) + ' action=ALLOW method=POST url=https://' + pick(rnd, WEB) + '.' + v.dns + '/api/' + pick(rnd, ['save', 'search', 'sync']) + ' status=' + pick(rnd, [200, 201, 204]) + ' bytes=' + int(rnd, 300, 9000),
      'user=' + u + ' src=' + ip(rnd, v.lan) + ' action=BLOCK method=GET url=https://' + pick(rnd, ['streaming-video.example', 'jeux-en-ligne.example', 'reseau-social.example']) + '/ status=403 category=' + pick(rnd, ['streaming', 'jeux', 'reseaux_sociaux']) + ' policy=usage_interne',
      'user=' + u + ' src=' + ip(rnd, v.lan) + ' action=ALLOW method=GET url=https://update.' + pick(rnd, ['editeur-bureautique.example', 'editeur-navigateur.example']) + '/check status=200 bytes=' + int(rnd, 200, 4000) + ' category=updates'
    ]);
  };

  /* --- Résolutions DNS ---------------------------------------------------- */
  N['dns'] = function (rnd, v) {
    return pick(rnd, [
      'client=' + ip(rnd, v.lan) + ' query=' + pick(rnd, WEB) + '.' + v.dns + ' type=A answer=' + ip(rnd, v.lan) + ' rcode=NOERROR',
      'client=' + ip(rnd, v.lan) + ' query=' + pick(rnd, EXT) + ' type=A answer=203.0.113.' + int(rnd, 2, 250) + ' rcode=NOERROR',
      'client=' + ip(rnd, v.lan) + ' query=' + pick(rnd, v.hosts).toLowerCase() + '.' + v.dns + ' type=A answer=' + ip(rnd, v.lan) + ' rcode=NOERROR',
      'client=' + ip(rnd, v.lan) + ' query=' + pick(rnd, ['_ldap._tcp.dc._msdcs', '_kerberos._tcp']) + '.' + v.dns + ' type=SRV rcode=NOERROR',
      'client=' + ip(rnd, v.lan) + ' query=' + pick(rnd, ['telemetrie', 'ocsp', 'crl']) + '.' + pick(rnd, EXT) + ' type=A rcode=NOERROR'
    ]);
  };

  /* --- Fédération d'identité --------------------------------------------- */
  N['idp'] = function (rnd, v) {
    var u = pick(rnd, v.users);
    return pick(rnd, [
      'event=auth_success user=' + u + '@' + v.mail + ' src_ip=' + ip(rnd, v.lan) + ' device=' + pick(rnd, v.hosts) + ' mfa=device_compliant app=' + pick(rnd, ['Bureau', 'Messagerie', 'Intranet', 'Documents']),
      'event=token_refresh user=' + u + '@' + v.mail + ' src_ip=' + ip(rnd, v.lan) + ' app=Messagerie result=Succeeded',
      'event=auth_failure user=' + u + '@' + v.mail + ' src_ip=' + ip(rnd, v.lan) + ' reason=invalid_password attempt=1',
      'event=mfa_challenge user=' + u + '@' + v.mail + ' src_ip=' + ip(rnd, v.lan) + ' result=approved method=push',
      'event=session_created user=' + u + '@' + v.mail + ' src_ip=' + ip(rnd, v.lan) + ' app=Documents protocol=web'
    ]);
  };

  /* --- Messagerie -------------------------------------------------------- */
  N['mta'] = function (rnd, v) {
    var u = pick(rnd, v.users);
    return pick(rnd, [
      'queue=' + int(rnd, 100000, 999999).toString(16) + ' from=' + pick(rnd, ['contact', 'facturation', 'no-reply', 'rh']) + '@' + pick(rnd, EXT) + ' to=' + u + '@' + v.mail + ' subject="' + pick(rnd, ['Votre commande', 'Relance facture', 'Lettre d information', 'Convocation reunion']) + '" spf=pass dkim=pass verdict=delivered',
      'queue=' + int(rnd, 100000, 999999).toString(16) + ' from=' + u + '@' + v.mail + ' to=' + pick(rnd, ['contact', 'service.client']) + '@' + pick(rnd, EXT) + ' subject="' + pick(rnd, ['Re: devis', 'Documents joints', 'Point hebdomadaire']) + '" verdict=sent',
      'queue=' + int(rnd, 100000, 999999).toString(16) + ' from=' + pick(rnd, ['promo', 'newsletter']) + '@' + pick(rnd, EXT) + ' to=' + u + '@' + v.mail + ' spf=fail verdict=quarantined reason=spam_score_' + int(rnd, 6, 9),
      'queue=' + int(rnd, 100000, 999999).toString(16) + ' from=' + u + '@' + v.mail + ' to=' + pick(rnd, v.users) + '@' + v.mail + ' subject="' + pick(rnd, ['Compte rendu', 'Pour validation', 'Planning']) + '" verdict=delivered'
    ]);
  };

  /* --- Journaux Unix ----------------------------------------------------- */
  N['auditd'] = function (rnd, v) {
    var h = pick(rnd, v.hosts);
    return pick(rnd, [
      'host=' + h + ' type=SYSCALL syscall=execve exe=/usr/sbin/cron args="run-parts /etc/cron.hourly" uid=0',
      'host=' + h + ' type=SYSCALL syscall=execve exe=/usr/bin/find args="/var/log -mtime +30 -delete" uid=0',
      'host=' + h + ' type=USER_AUTH acct=' + pick(rnd, v.users) + ' exe=/usr/sbin/sshd hostname=' + ip(rnd, v.lan) + ' res=success',
      'host=' + h + ' type=SERVICE_START unit=' + pick(rnd, ['logrotate', 'apt-daily', 'systemd-tmpfiles-clean', 'man-db']) + '.service result=done',
      'host=' + h + ' type=SYSCALL syscall=execve exe=/usr/bin/python3 args="/opt/app/tasks/sync.py" uid=' + int(rnd, 1000, 1010),
      'host=' + h + ' type=CRED_ACQ acct=' + pick(rnd, v.users) + ' exe=/usr/bin/sudo res=success'
    ]);
  };

  /* --- Serveur web ------------------------------------------------------- */
  N['nginx'] = function (rnd, v) {
    var ua = pick(rnd, ['Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)']);
    return pick(rnd, [
      pick(rnd, ['203.0.113.', '198.51.100.']) + int(rnd, 2, 250) + ' - - "GET /' + pick(rnd, ['', 'catalogue', 'contact', 'panier', 'compte/connexion', 'assets/app.css']) + ' HTTP/1.1" 200 ' + int(rnd, 400, 48000) + ' "-" "' + ua + '"',
      pick(rnd, ['203.0.113.', '198.51.100.']) + int(rnd, 2, 250) + ' - - "POST /compte/connexion HTTP/1.1" ' + pick(rnd, [200, 302]) + ' ' + int(rnd, 200, 900) + ' "-" "' + ua + '"',
      pick(rnd, ['203.0.113.', '198.51.100.']) + int(rnd, 2, 250) + ' - - "GET /' + pick(rnd, ['wp-login.php', 'admin', '.env', 'phpmyadmin']) + ' HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; scanner)"',
      pick(rnd, ['203.0.113.', '198.51.100.']) + int(rnd, 2, 250) + ' - - "GET /robots.txt HTTP/1.1" 200 68 "-" "Googlebot/2.1"'
    ]);
  };

  /* --- Accès distant ----------------------------------------------------- */
  N['vpn'] = function (rnd, v) {
    var u = pick(rnd, v.users);
    return pick(rnd, [
      'event=tunnel_up user=' + u + ' assigned_ip=10.99.' + int(rnd, 1, 4) + '.' + int(rnd, 10, 240) + ' src_ip=' + pick(rnd, ['203.0.113.', '198.51.100.']) + int(rnd, 2, 250) + ' client=6.1.4 mfa=ok',
      'event=tunnel_down user=' + u + ' duration_s=' + int(rnd, 400, 28000) + ' bytes_in=' + int(rnd, 100000, 9000000) + ' bytes_out=' + int(rnd, 40000, 3000000),
      'event=auth_failure user=' + u + ' src_ip=' + pick(rnd, ['203.0.113.', '198.51.100.']) + int(rnd, 2, 250) + ' reason=bad_password',
      'event=posture_check user=' + u + ' device=' + pick(rnd, v.hosts) + ' antivirus=ok patch=ok result=allow'
    ]);
  };

  /* --- Espace documentaire et messagerie en ligne ------------------------ */
  N['saas'] = function (rnd, v) {
    var u = pick(rnd, v.users);
    return pick(rnd, [
      'operation=FileAccessed user=' + u + ' site=' + pick(rnd, ['Equipe', 'Direction', 'Projets']) + ' file="' + pick(rnd, DOCS) + '" client=Web src_ip=' + ip(rnd, v.lan),
      'operation=FileModified user=' + u + ' site=Equipe file="' + pick(rnd, DOCS) + '" client=Bureau src_ip=' + ip(rnd, v.lan),
      'operation=MailItemsAccessed user=' + u + ' item_count=' + int(rnd, 3, 60) + ' client=Bureau src_ip=' + ip(rnd, v.lan),
      'operation=FileUploaded user=' + u + ' site=Projets file="' + pick(rnd, DOCS) + '" size=' + int(rnd, 40000, 4000000) + ' src_ip=' + ip(rnd, v.lan),
      'operation=UserLoggedIn user=' + u + ' src_ip=' + ip(rnd, v.lan) + ' result=Succeeded'
    ]);
  };

  /* --- Base de données ---------------------------------------------------- */
  N['bdd'] = function (rnd, v) {
    return pick(rnd, [
      'login succeeded user=' + pick(rnd, ['app_web', 'app_reporting', 'svc_sauvegarde']) + ' src=' + ip(rnd, v.lan) + ' database=' + pick(rnd, ['boutique', 'referentiel']),
      'query duration=' + int(rnd, 2, 400) + 'ms user=app_web statement="SELECT id, libelle FROM produits WHERE actif = 1 LIMIT ' + int(rnd, 10, 200) + '"',
      'query duration=' + int(rnd, 2, 90) + 'ms user=app_web statement="UPDATE paniers SET maj = now() WHERE id = ' + int(rnd, 1000, 99000) + '"',
      'backup started database=' + pick(rnd, ['boutique', 'referentiel']) + ' type=incremental',
      'checkpoint complete write=' + int(rnd, 100, 9000) + ' sync=' + int(rnd, 1, 40) + 'ms'
    ]);
  };

  /* --- Chaîne d'intégration continue -------------------------------------- */
  N['cicd'] = function (rnd, v) {
    return pick(rnd, [
      'pipeline=' + int(rnd, 4000, 4900) + ' projet=' + pick(rnd, ['api-clients', 'front-web', 'infra-tf']) + ' etape=build statut=success duree=' + int(rnd, 40, 400) + 's declencheur=' + pick(rnd, v.users),
      'pipeline=' + int(rnd, 4000, 4900) + ' projet=' + pick(rnd, ['api-clients', 'front-web']) + ' etape=tests statut=' + pick(rnd, ['success', 'success', 'failed']) + ' duree=' + int(rnd, 60, 900) + 's',
      'runner=' + pick(rnd, ['runner-01', 'runner-02', 'runner-03']) + ' etat=idle jobs_traites=' + int(rnd, 1, 40),
      'pipeline=' + int(rnd, 4000, 4900) + ' projet=infra-tf etape=plan statut=success ressources_modifiees=' + int(rnd, 0, 6)
    ]);
  };

  /* --- Hyperviseur -------------------------------------------------------- */
  N['hyperviseur'] = function (rnd, v) {
    var vm = pick(rnd, v.vms || ['VM-APP-01', 'VM-BDD-01', 'VM-FS-01']);
    return pick(rnd, [
      'task=Refresh entity=' + vm + ' user=svc_supervision result=success',
      'task=CreateSnapshot entity=' + vm + ' user=svc_sauvegarde result=success duree=' + int(rnd, 4, 90) + 's',
      'task=RemoveSnapshot entity=' + vm + ' user=svc_sauvegarde result=success',
      'event=VmPoweredOn entity=' + vm + ' user=' + pick(rnd, v.users),
      'event=HostSyncState host=' + pick(rnd, v.hosts) + ' state=connected'
    ]);
  };

  OF.noise = N;
  OF.noiseFamilies = Object.keys(N);
})(typeof globalThis !== 'undefined' ? globalThis : this);
