/* Open-Forensics — CAS-01.
 *
 * ======================= AVERTISSEMENT FORMATEUR =========================
 * Ce fichier contient les réponses attendues, la chaîne d'attaque réelle et
 * le débriefing. Ne pas l'ouvrir avant d'avoir traité le dossier.
 * =========================================================================
 */
(function (root) {
  'use strict';

  root.OpenForensics.cases.push({
    id: 'CAS-01',
    title: 'Rançongiciel nocturne chez un transporteur',
    client: 'Transports Marcelin — transport routier, 120 salariés',
    difficulty: 'facile',
    estimatedMin: 35,
    tags: ['rançongiciel', 'RDP exposé', 'Windows'],

    env: {
      domain: 'MARCELIN', dns: 'marcelin.lan', mail: 'transports-marcelin.example',
      lan: '10.12.4', edge: '198.51.100.23',
      hosts: ['SRV-FS-01', 'SRV-AD-01', 'SRV-BKP-01', 'PC-EXPL-04', 'PC-COMPTA-02', 'PC-ATELIER-07'],
      users: ['c.perrin', 'm.leroy', 'a.diallo', 's.bertin', 'j.marchand'],
      admins: ['adm_marcelin', 'svc_sauvegarde']
    },

    brief: {
      saisine: 'Mercredi 4 mars 2026, 07h40. Le responsable informatique constate à son arrivée que les fichiers du serveur bureautique sont illisibles et qu\'une note de rançon est déposée dans chaque dossier. L\'activité d\'exploitation est à l\'arrêt : les lettres de voiture ne sont plus accessibles.',
      perimetre: 'Six machines Windows, un domaine Active Directory, une sauvegarde locale sur SRV-BKP-01. Pas de solution de sauvegarde externalisée.',
      collecte: 'Les journaux ont été exportés depuis les machines encore démarrées et depuis le pare-feu périmétrique, dans la nuit du 4 au 5 mars, avant toute réinstallation. Horodatages en UTC.',
      limites: 'Aucune capture mémoire : les postes touchés ont été éteints par les utilisateurs avant l\'intervention. Aucun journal de mandataire web : le client n\'en dispose pas. Le journal de sécurité de PC-ATELIER-07 est absent, la machine était hors tension depuis le 28 février.',
      mission: 'Établir le point d\'entrée, la chronologie complète, l\'étendue de la compromission, et déterminer si des données ont quitté le réseau — le client doit savoir s\'il a une obligation de notification.'
    },

    evidence: [
      {
        id: 'PJ-01', source: 'journaux', system: 'SRV-FS-01',
        title: 'Journal de sécurité Windows — SRV-FS-01',
        note: 'Serveur de fichiers. Export EVTX converti en texte, fuseau UTC. C\'est la machine qui porte le partage bureautique.',
        lines: [
          { t: '2026-03-03 21:04:11', m: 'EventCode=4625 Logon_Type=10 Account_Name=administrateur Computer=SRV-FS-01 Source_Network_Address=198.51.100.77 Failure_Reason=Unknown_user_name_or_bad_password' },
          { t: '2026-03-03 21:04:19', m: 'EventCode=4625 Logon_Type=10 Account_Name=admin Computer=SRV-FS-01 Source_Network_Address=198.51.100.77 Failure_Reason=Unknown_user_name_or_bad_password' },
          { t: '2026-03-03 22:16:52', m: 'EventCode=4625 Logon_Type=10 Account_Name=backup Computer=SRV-FS-01 Source_Network_Address=198.51.100.77 Failure_Reason=Unknown_user_name_or_bad_password' },
          { t: '2026-03-03 23:41:07', m: 'EventCode=4625 Logon_Type=10 Account_Name=adm_marcelin Computer=SRV-FS-01 Source_Network_Address=198.51.100.77 Failure_Reason=Unknown_user_name_or_bad_password' },
          { t: '2026-03-04 00:52:44', m: 'EventCode=4625 Logon_Type=10 Account_Name=adm_marcelin Computer=SRV-FS-01 Source_Network_Address=198.51.100.77 Failure_Reason=Unknown_user_name_or_bad_password' },
          { t: '2026-03-04 01:26:58', m: 'EventCode=4625 Logon_Type=10 Account_Name=adm_marcelin Computer=SRV-FS-01 Source_Network_Address=198.51.100.77 Failure_Reason=Unknown_user_name_or_bad_password' },
          { t: '2026-03-04 01:27:14', m: 'EventCode=4624 Logon_Type=10 Account_Name=adm_marcelin Computer=SRV-FS-01 Source_Network_Address=198.51.100.77 Authentication_Package=Negotiate Logon_ID=0x5A11C4' },
          { t: '2026-03-04 01:27:15', m: 'EventCode=4672 Account_Name=adm_marcelin Computer=SRV-FS-01 Privileges=SeDebugPrivilege,SeBackupPrivilege,SeTakeOwnershipPrivilege,SeLoadDriverPrivilege' },
          { t: '2026-03-04 01:31:02', m: 'EventCode=4720 New_Account_Name=svc_help Computer=SRV-FS-01 Creator_Account=adm_marcelin' },
          { t: '2026-03-04 01:31:03', m: 'EventCode=4732 Group=Administrateurs Member=svc_help Computer=SRV-FS-01 Creator_Account=adm_marcelin' },
          { t: '2026-03-04 01:31:44', m: 'EventCode=4738 Account_Name=svc_help Computer=SRV-FS-01 Changes="PasswordNeverExpires enabled"' },
          { t: '2026-03-04 02:03:31', m: 'EventCode=7045 Service_Name=PSEXESVC Service_File_Name=C:\\Windows\\PSEXESVC.exe Service_Account=LocalSystem Computer=PC-EXPL-04 Source_Address=10.12.4.21' },
          { t: '2026-03-04 02:03:52', m: 'EventCode=7045 Service_Name=PSEXESVC Service_File_Name=C:\\Windows\\PSEXESVC.exe Service_Account=LocalSystem Computer=PC-COMPTA-02 Source_Address=10.12.4.21' },
          { t: '2026-03-04 02:04:18', m: 'EventCode=7045 Service_Name=PSEXESVC Service_File_Name=C:\\Windows\\PSEXESVC.exe Service_Account=LocalSystem Computer=SRV-BKP-01 Source_Address=10.12.4.21' },
          { t: '2026-03-04 02:41:09', m: 'EventCode=4634 Logon_Type=10 Account_Name=adm_marcelin Computer=SRV-FS-01 Logon_ID=0x5A11C4' }
        ],
        noise: [
          { family: 'win-security', count: 230, from: '2026-03-03 06:00:00', to: '2026-03-04 07:30:00' }
        ]
      },
      {
        id: 'PJ-02', source: 'journaux', system: 'SRV-FS-01',
        title: 'Télémétrie de processus (Sysmon) — SRV-FS-01',
        note: 'Sysmon était déployé sur les serveurs uniquement, pas sur les postes. Configuration standard SwiftOnSecurity.',
        lines: [
          { t: '2026-03-04 01:29:40', m: 'EventCode=1 Computer=SRV-FS-01 Image=C:\\Windows\\System32\\cmd.exe ParentImage=C:\\Windows\\explorer.exe CommandLine="cmd.exe" User=MARCELIN\\adm_marcelin ProcessId=4180' },
          { t: '2026-03-04 01:30:12', m: 'EventCode=1 Computer=SRV-FS-01 Image=C:\\Windows\\System32\\net.exe ParentImage=C:\\Windows\\System32\\cmd.exe CommandLine="net view /domain" User=MARCELIN\\adm_marcelin ProcessId=4212' },
          { t: '2026-03-04 01:30:28', m: 'EventCode=1 Computer=SRV-FS-01 Image=C:\\Windows\\System32\\net.exe ParentImage=C:\\Windows\\System32\\cmd.exe CommandLine="net view \\\\SRV-BKP-01" User=MARCELIN\\adm_marcelin ProcessId=4233' },
          { t: '2026-03-04 01:31:01', m: 'EventCode=1 Computer=SRV-FS-01 Image=C:\\Windows\\System32\\net.exe ParentImage=C:\\Windows\\System32\\cmd.exe CommandLine="net user svc_help Tr4nsp0rt! /add" User=MARCELIN\\adm_marcelin ProcessId=4251' },
          { t: '2026-03-04 01:38:55', m: 'EventCode=1 Computer=SRV-FS-01 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe ParentImage=C:\\Windows\\System32\\cmd.exe CommandLine="powershell -c Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true" User=MARCELIN\\adm_marcelin ProcessId=4388' },
          { t: '2026-03-04 01:44:26', m: 'EventCode=11 Computer=SRV-FS-01 TargetFilename=C:\\Users\\adm_marcelin\\Desktop\\mkill.exe Image=C:\\Windows\\explorer.exe SHA256=5719370cea15f355537b8867c5d129056a362f869b1ade6a3221bf47d37f4473' },
          { t: '2026-03-04 01:52:03', m: 'EventCode=1 Computer=SRV-FS-01 Image=C:\\Windows\\System32\\vssadmin.exe ParentImage=C:\\Windows\\System32\\cmd.exe CommandLine="vssadmin delete shadows /all /quiet" User=MARCELIN\\adm_marcelin ProcessId=4502' },
          { t: '2026-03-04 01:52:47', m: 'EventCode=1 Computer=SRV-FS-01 Image=C:\\Windows\\System32\\wbadmin.exe ParentImage=C:\\Windows\\System32\\cmd.exe CommandLine="wbadmin delete catalog -quiet" User=MARCELIN\\adm_marcelin ProcessId=4517' },
          { t: '2026-03-04 01:58:14', m: 'EventCode=1 Computer=SRV-FS-01 Image=C:\\Windows\\System32\\bcdedit.exe ParentImage=C:\\Windows\\System32\\cmd.exe CommandLine="bcdedit /set {default} recoveryenabled No" User=MARCELIN\\adm_marcelin ProcessId=4561' },
          { t: '2026-03-04 02:02:55', m: 'EventCode=1 Computer=SRV-FS-01 Image=C:\\Users\\adm_marcelin\\Desktop\\PsExec64.exe ParentImage=C:\\Windows\\System32\\cmd.exe CommandLine="PsExec64.exe @cibles.txt -s -c mkill.exe" User=MARCELIN\\adm_marcelin ProcessId=4620' },
          { t: '2026-03-04 02:11:38', m: 'EventCode=1 Computer=SRV-FS-01 Image=C:\\Users\\adm_marcelin\\Desktop\\mkill.exe ParentImage=C:\\Windows\\System32\\cmd.exe CommandLine="mkill.exe -path D:\\Partage -ext vryx" User=MARCELIN\\adm_marcelin ProcessId=4688' },
          { t: '2026-03-04 02:11:52', m: 'EventCode=11 Computer=SRV-FS-01 TargetFilename=D:\\Partage\\Exploitation\\lettre_voiture_2026_02.xlsx.vryx Image=C:\\Users\\adm_marcelin\\Desktop\\mkill.exe' },
          { t: '2026-03-04 02:12:03', m: 'EventCode=11 Computer=SRV-FS-01 TargetFilename=D:\\Partage\\RESTAURER-VOS-FICHIERS.txt Image=C:\\Users\\adm_marcelin\\Desktop\\mkill.exe' },
          { t: '2026-03-04 02:39:47', m: 'EventCode=5 Computer=SRV-FS-01 Image=C:\\Users\\adm_marcelin\\Desktop\\mkill.exe ProcessId=4688 State=terminated files_processed=48211' }
        ],
        noise: [
          { family: 'sysmon', count: 210, from: '2026-03-03 06:00:00', to: '2026-03-04 07:30:00' }
        ]
      },
      {
        id: 'PJ-03', source: 'journaux', system: 'Console EDR',
        title: 'Journal de l\'agent de sécurité — parc',
        note: 'Console centralisée. L\'agent est en mode détection seule sur les serveurs à la demande de l\'exploitation, pour éviter les faux positifs sur les traitements de nuit.',
        lines: [
          { t: '2026-03-04 01:39:02', m: 'tamper_protection host=SRV-FS-01 action=realtime_monitoring_disabled actor=MARCELIN\\adm_marcelin result=applied severity=high' },
          { t: '2026-03-04 01:44:31', m: 'file_reputation host=SRV-FS-01 path=C:\\Users\\adm_marcelin\\Desktop\\mkill.exe sha256=5719370cea15f355537b8867c5d129056a362f869b1ade6a3221bf47d37f4473 prevalence=global_count_2 signer=none verdict=unknown' },
          { t: '2026-03-04 01:52:10', m: 'detection name="Shadow Copy Deletion" host=SRV-FS-01 process=vssadmin.exe severity=critical action=DETECTED_ONLY policy=serveurs_detection_seule' },
          { t: '2026-03-04 02:12:44', m: 'detection name="Mass File Rename" host=SRV-FS-01 process=mkill.exe files_per_minute=1840 severity=critical action=DETECTED_ONLY' },
          { t: '2026-03-04 02:14:09', m: 'detection name="Mass File Rename" host=PC-EXPL-04 process=mkill.exe files_per_minute=920 severity=critical action=DETECTED_ONLY' },
          { t: '2026-03-04 02:16:33', m: 'detection name="Mass File Rename" host=PC-COMPTA-02 process=mkill.exe files_per_minute=610 severity=critical action=DETECTED_ONLY' },
          { t: '2026-03-04 02:22:51', m: 'detection name="Mass File Rename" host=SRV-BKP-01 process=mkill.exe files_per_minute=2210 severity=critical action=DETECTED_ONLY' }
        ],
        noise: [
          { family: 'edr', count: 140, from: '2026-03-01 06:00:00', to: '2026-03-04 07:30:00' }
        ]
      },
      {
        id: 'PJ-04', source: 'reseau', system: 'Pare-feu périmétrique',
        title: 'Journal du pare-feu périmétrique',
        note: 'Équipement de bordure. Conservation de sept jours. La traduction d\'adresses expose certains services internes.',
        lines: [
          { t: '2026-03-03 21:03:58', m: 'policy=NAT-RDP-TEMP src=198.51.100.77 dst=10.12.4.21 dport=3389 proto=tcp action=ALLOW comment="regle temporaire teletravail 2023, non revoquee"' },
          { t: '2026-03-03 23:40:12', m: 'policy=NAT-RDP-TEMP src=198.51.100.77 dst=10.12.4.21 dport=3389 proto=tcp action=ALLOW sessions=1842 note="volume anormal"' },
          { t: '2026-03-04 01:27:14', m: 'policy=NAT-RDP-TEMP src=198.51.100.77 dst=10.12.4.21 dport=3389 proto=tcp action=ALLOW session_established=true duration_s=4435' },
          { t: '2026-03-04 02:41:12', m: 'policy=NAT-RDP-TEMP src=198.51.100.77 dst=10.12.4.21 dport=3389 proto=tcp action=CLOSE bytes_in=18422100 bytes_out=41220' },
          { t: '2026-03-04 07:12:00', m: 'egress_summary window=2026-03-03T20:00Z/2026-03-04T07:00Z total_bytes_out=48211334 top_talker=10.12.4.9 note="volumetrie sortante conforme a la moyenne des 30 jours (moy. 51 Mo)"' }
        ],
        noise: [
          { family: 'firewall', count: 300, from: '2026-03-03 06:00:00', to: '2026-03-04 07:30:00' }
        ]
      },
      {
        id: 'PJ-05', source: 'journaux', system: 'SRV-AD-01',
        title: 'Journal de sécurité Windows — contrôleur de domaine',
        note: 'Contrôleur de domaine. Permet de voir les authentifications réseau vers les autres machines du parc.',
        lines: [
          { t: '2026-03-04 02:03:29', m: 'EventCode=4624 Logon_Type=3 Account_Name=adm_marcelin Computer=PC-EXPL-04 Source_Network_Address=10.12.4.21 Authentication_Package=NTLM' },
          { t: '2026-03-04 02:03:50', m: 'EventCode=4624 Logon_Type=3 Account_Name=adm_marcelin Computer=PC-COMPTA-02 Source_Network_Address=10.12.4.21 Authentication_Package=NTLM' },
          { t: '2026-03-04 02:04:16', m: 'EventCode=4624 Logon_Type=3 Account_Name=adm_marcelin Computer=SRV-BKP-01 Source_Network_Address=10.12.4.21 Authentication_Package=NTLM' },
          { t: '2026-03-04 02:04:22', m: 'EventCode=4648 Account_Name=adm_marcelin Target_Server=SRV-BKP-01 Process=PsExec64.exe Source_Network_Address=10.12.4.21' }
        ],
        noise: [
          { family: 'win-security', count: 200, from: '2026-03-03 06:00:00', to: '2026-03-04 07:30:00' }
        ]
      },
      {
        id: 'PJ-06', source: 'journaux', system: 'SRV-BKP-01',
        title: 'Journal applicatif de la sauvegarde',
        note: 'Logiciel de sauvegarde local. Les sauvegardes étaient écrites sur un volume monté en permanence.',
        lines: [
          { t: '2026-03-03 22:00:04', m: 'job=nightly-full status=started volume=E:\\Sauvegardes sets=14' },
          { t: '2026-03-03 23:47:51', m: 'job=nightly-full status=completed duration=6467s written_gb=212 sets=14 result=OK' },
          { t: '2026-03-04 02:22:48', m: 'volume=E:\\Sauvegardes event=mass_rename detected_files=31204 extension=.vryx' },
          { t: '2026-03-04 02:31:10', m: 'job=catalog status=error message="catalogue introuvable ou corrompu" note="wbadmin delete catalog execute depuis SRV-FS-01"' },
          { t: '2026-03-04 02:44:02', m: 'agent=backup status=stopped reason="volume inaccessible"' }
        ],
        noise: [
          { family: 'win-security', count: 90, from: '2026-03-03 06:00:00', to: '2026-03-04 07:30:00' }
        ]
      }
    ],

    questions: [
      { id: 'Q1', type: 'ip', label: 'Adresse IP source de l\'attaque',
        answer: '198.51.100.77',
        hint: 'Le pare-feu et le journal de sécurité de SRV-FS-01 pointent la même adresse : cherchez les échecs d\'ouverture de session de type 10.',
        where: 'PJ-01, filtrer sur 4625 — puis PJ-04, règle NAT-RDP-TEMP.',
        why: 'C\'est le premier indicateur à remonter au SOC pour blocage, et il date l\'ensemble de la campagne.' },

      { id: 'Q2', type: 'text', label: 'Service exposé sur Internet ayant servi de point d\'entrée (protocole)',
        answer: 'RDP', alt: ['bureau à distance', 'remote desktop', '3389', 'rdp/3389'],
        hint: 'Regardez le port de destination de la règle de pare-feu restée ouverte.',
        where: 'PJ-04, première ligne : policy=NAT-RDP-TEMP, dport=3389.',
        why: 'Le point d\'entrée détermine la mesure corrective immédiate : fermer la règle, pas réinstaller les postes.' },

      { id: 'Q3', type: 'text', label: 'Compte compromis lors de l\'authentification réussie',
        answer: 'adm_marcelin', alt: ['marcelin\\adm_marcelin'],
        hint: 'Dans la rafale d\'échecs, un seul compte finit par produire un EventCode=4624.',
        where: 'PJ-01, le 4624 de type 10 à 01:27:14.',
        why: 'C\'est le compte à réinitialiser en priorité, et celui dont il faut auditer toutes les actions.' },

      { id: 'Q4', type: 'datetime', label: 'Horodatage de la première authentification réussie (UTC)',
        answer: '2026-03-04 01:27',
        hint: 'C\'est l\'unique 4624 de type 10 provenant de l\'adresse externe.',
        where: 'PJ-01, ligne 4624 Logon_ID=0x5A11C4.',
        why: 'Ce point fixe borne le début de la compromission : tout ce qui précède est hors périmètre d\'incident.' },

      { id: 'Q5', type: 'text', label: 'Nom du compte local créé par l\'attaquant',
        answer: 'svc_help',
        hint: 'Un EventCode=4720 signale une création de compte ; regardez ensuite le 4732 qui suit d\'une seconde.',
        where: 'PJ-01, 4720 à 01:31:02, confirmé par la ligne net user de PJ-02.',
        why: 'Ce compte est la porte de secours : réinitialiser adm_marcelin sans le supprimer laisse l\'accès ouvert.' },

      { id: 'Q6', type: 'text', label: 'Utilitaire employé pour détruire les clichés instantanés',
        answer: 'vssadmin', alt: ['vssadmin.exe', 'vssadmin delete shadows'],
        hint: 'Cherchez dans la télémétrie de processus une commande contenant « delete shadows ».',
        where: 'PJ-02 à 01:52:03, et la détection correspondante dans PJ-03.',
        why: 'La destruction des clichés est le geste qui rend la restauration impossible : il précède toujours le chiffrement.' },

      { id: 'Q7', type: 'text', label: 'Extension ajoutée aux fichiers chiffrés',
        answer: 'vryx', alt: ['.vryx'],
        hint: 'Les lignes de création de fichiers du chiffreur montrent le nom complet des fichiers produits.',
        where: 'PJ-02, EventCode=11 sur D:\\Partage, et PJ-06 (mass_rename).',
        why: 'L\'extension et le nom de la note permettent d\'identifier la famille de rançongiciel et de chercher un déchiffreur public.' },

      { id: 'Q8', type: 'text', label: 'Nom du fichier de demande de rançon',
        answer: 'RESTAURER-VOS-FICHIERS.txt', alt: ['restaurer-vos-fichiers.txt', 'restaurer-vos-fichiers'],
        hint: 'Le chiffreur écrit un fichier texte à la racine du partage juste après les premiers chiffrements.',
        where: 'PJ-02, EventCode=11 à 02:12:03.',
        why: 'C\'est une pièce à conserver : elle porte l\'identifiant de victime et le moyen de contact des attaquants.' },

      { id: 'Q9', type: 'hash', label: 'Empreinte SHA-256 du binaire de chiffrement',
        answer: '5719370cea15f355537b8867c5d129056a362f869b1ade6a3221bf47d37f4473',
        hint: 'Deux pièces donnent la même empreinte : la télémétrie de processus à l\'écriture du fichier, et la console de l\'agent de sécurité.',
        where: 'PJ-02 (EventCode=11 sur mkill.exe) et PJ-03 (file_reputation).',
        why: 'L\'empreinte alimente la fiche d\'indicateurs et permet de chercher le même binaire sur le reste du parc.' },

      { id: 'Q10', type: 'number', label: 'Nombre de machines sur lesquelles le chiffreur s\'est exécuté',
        answer: '4',
        hint: 'Comptez les détections « Mass File Rename » distinctes dans la console de l\'agent, sans oublier la machine d\'origine.',
        where: 'PJ-03 : SRV-FS-01, PC-EXPL-04, PC-COMPTA-02, SRV-BKP-01.',
        why: 'L\'étendue conditionne le plan de remise en service et le chiffrage du sinistre.' },

      { id: 'Q11', type: 'choice', label: 'Des données ont-elles quitté le réseau ?',
        answer: 'Non — aucun volume sortant anormal',
        options: ['Oui — exfiltration massive avant chiffrement', 'Oui — exfiltration limitée à quelques fichiers', 'Non — aucun volume sortant anormal', 'Indéterminable avec les pièces disponibles'],
        hint: 'Le pare-feu produit une synthèse de volumétrie sortante sur la fenêtre de l\'incident : comparez-la à la moyenne.',
        where: 'PJ-04, ligne egress_summary : 48 Mo sortants contre 51 Mo de moyenne, et la session RDP montre 18 Mo entrants pour 41 Ko sortants.',
        why: 'Sans exfiltration, il n\'y a pas de violation de données à notifier : cette réponse a des conséquences juridiques directes pour le client. Répondre « indéterminable » par prudence serait ici une facilité : les pièces permettent de trancher.' }
    ],

    events: [
      { id: 'EV-01', t: '2026-03-03 21:04', label: 'Début de la force brute RDP depuis 198.51.100.77' },
      { id: 'EV-02', t: '2026-03-04 01:27', label: 'Authentification RDP réussie du compte adm_marcelin depuis Internet' },
      { id: 'EV-03', t: '2026-03-04 01:30', label: 'Énumération du domaine et des partages (net view /domain)' },
      { id: 'EV-04', t: '2026-03-04 01:31', label: 'Création du compte local svc_help et ajout aux administrateurs' },
      { id: 'EV-05', t: '2026-03-04 01:38', label: 'Désactivation de la protection en temps réel de l\'antivirus' },
      { id: 'EV-06', t: '2026-03-04 01:44', label: 'Dépôt du binaire mkill.exe sur le bureau du compte compromis' },
      { id: 'EV-07', t: '2026-03-04 01:52', label: 'Destruction des clichés instantanés et du catalogue de sauvegarde' },
      { id: 'EV-08', t: '2026-03-04 02:03', label: 'Déploiement du chiffreur par PsExec vers trois machines' },
      { id: 'EV-09', t: '2026-03-04 02:11', label: 'Exécution du chiffreur sur le partage bureautique' },
      { id: 'EV-10', t: '2026-03-03 22:00', label: 'Sauvegarde complète nocturne planifiée, terminée avec succès' },
      { id: 'EV-11', t: '2026-03-03 19:02', label: 'Mise à jour de l\'agent de sécurité en 7.4.3 sur le parc' },
      { id: 'EV-12', t: '2026-03-04 07:12', label: 'Synthèse de volumétrie sortante conforme à la moyenne mensuelle' }
    ],

    chain: [
      { tactic: 'Accès initial', event: 'EV-02', technique: 'T1133', techniqueAlt: ['T1078.002', 'T1078'],
        where: 'PJ-01 (4624 type 10) et PJ-04 (règle NAT-RDP-TEMP).',
        why: 'Le service distant exposé est la cause racine : sans cette règle laissée ouverte depuis 2023, la force brute n\'aurait jamais abouti.' },
      { tactic: 'Exécution', event: 'EV-09', technique: 'T1059.003', techniqueAlt: ['T1204.002'],
        where: 'PJ-02, exécution de mkill.exe depuis cmd.exe à 02:11:38.',
        why: 'L\'exécution est ici manuelle, au clavier, dans une session interactive : il n\'y a ni macro ni utilisateur piégé.' },
      { tactic: 'Persistance', event: 'EV-04', technique: 'T1136.001',
        where: 'PJ-01, 4720 puis 4732 à 01:31.',
        why: 'Le compte local créé survit à la réinitialisation du compte d\'origine : c\'est l\'élément que les remédiations pressées oublient.' },
      { tactic: 'Élévation de privilèges', event: 'NONE', technique: 'NONE',
        where: 'Aucune trace : le compte compromis était déjà administrateur (4672 dès l\'ouverture de session).',
        why: 'Savoir qu\'il n\'y a pas eu d\'élévation est une conclusion à part entière : l\'attaquant n\'a exploité aucune vulnérabilité locale.' },
      { tactic: 'Contournement des défenses', event: 'EV-05', technique: 'T1562.001',
        where: 'PJ-02 (Set-MpPreference) et PJ-03 (tamper_protection).',
        why: 'La désactivation de l\'antivirus est le signal d\'alerte le plus précoce exploitable : elle précède le chiffrement de trente minutes.' },
      { tactic: 'Accès aux identifiants', event: 'NONE', technique: 'NONE',
        where: 'Aucun accès à LSASS, aucun export de ruche, aucun outil de collecte d\'identifiants dans la télémétrie.',
        why: 'L\'attaquant n\'avait pas besoin de voler d\'identifiants : la force brute lui avait déjà donné un compte administrateur.' },
      { tactic: 'Découverte', event: 'EV-03', technique: 'T1018', techniqueAlt: ['T1135'],
        where: 'PJ-02, net view /domain puis net view \\\\SRV-BKP-01 à 01:30.',
        why: 'Trois minutes de reconnaissance ont suffi à identifier le serveur de sauvegarde — qui sera chiffré en priorité.' },
      { tactic: 'Déplacement latéral', event: 'EV-08', technique: 'T1021.002', techniqueAlt: ['T1570'],
        where: 'PJ-02 (PsExec64.exe @cibles.txt), PJ-01 et PJ-05 (services PSEXESVC, 4624 NTLM).',
        why: 'Le déplacement se lit deux fois : côté source dans la télémétrie, côté cible dans la création du service. Recouper les deux évite de conclure trop vite sur l\'étendue.' },
      { tactic: 'Collecte', event: 'NONE', technique: 'NONE',
        where: 'Aucun archivage, aucune copie massive vers un répertoire de regroupement.',
        why: 'L\'absence de collecte est cohérente avec l\'absence d\'exfiltration : ce groupe ne pratique pas la double extorsion.' },
      { tactic: 'Commande et contrôle', event: 'NONE', technique: 'NONE',
        where: 'Aucune connexion sortante anormale dans PJ-04 : l\'opérateur travaillait directement dans la session RDP.',
        why: 'Chercher un canal de commande et contrôle qui n\'existe pas fait perdre des heures. La session interactive EST le canal.' },
      { tactic: 'Exfiltration', event: 'NONE', technique: 'NONE',
        where: 'PJ-04, egress_summary : 48 Mo sortants sur la fenêtre, contre 51 Mo de moyenne.',
        why: 'C\'est la conclusion la plus lourde de conséquences du dossier : elle détermine l\'obligation de notification du client.' },
      { tactic: 'Impact', event: 'EV-07', technique: 'T1490', techniqueAlt: ['T1486', 'T1485'],
        where: 'PJ-02 (vssadmin, wbadmin, bcdedit), PJ-06 (catalogue corrompu).',
        why: 'L\'impact commence avant le chiffrement : c\'est la destruction des moyens de restauration qui transforme un incident en crise.' }
    ],

    keyIndicators: ['198.51.100.77', 'adm_marcelin', 'svc_help', 'mkill.exe', 'vryx', 'vssadmin', 'SRV-FS-01', 'RESTAURER-VOS-FICHIERS.txt'],

    iocs: [
      { type: 'Adresse IP', value: '198.51.100.77', context: 'Source de la force brute RDP et de la session interactive de l\'attaquant.' },
      { type: 'Empreinte SHA-256', value: '5719370cea15f355537b8867c5d129056a362f869b1ade6a3221bf47d37f4473', context: 'Binaire de chiffrement mkill.exe.' },
      { type: 'Nom de fichier', value: 'mkill.exe', context: 'Chiffreur déposé sur le bureau du compte compromis.' },
      { type: 'Extension', value: '.vryx', context: 'Extension ajoutée aux fichiers chiffrés.' },
      { type: 'Nom de fichier', value: 'RESTAURER-VOS-FICHIERS.txt', context: 'Note de rançon déposée dans chaque répertoire.' },
      { type: 'Compte', value: 'svc_help', context: 'Compte local créé par l\'attaquant, membre des administrateurs.' },
      { type: 'Comportement', value: 'vssadmin delete shadows /all /quiet', context: 'Destruction des clichés instantanés, à détecter et bloquer en priorité.' }
    ],

    debrief: {
      story: 'Une règle de traduction d\'adresses créée en 2023 pour du télétravail exposait le port 3389 de SRV-FS-01 sur Internet. Un opérateur a lancé une force brute depuis 198.51.100.77 pendant quatre heures et demie, jusqu\'à obtenir le mot de passe du compte administrateur adm_marcelin à 01:27. En une heure quinze, il a reconnu le domaine, créé un compte de secours, désactivé l\'antivirus, détruit les clichés instantanés, le catalogue de sauvegarde et l\'environnement de récupération Windows, puis déployé son chiffreur par PsExec sur trois machines supplémentaires, dont le serveur de sauvegarde. Le chiffrement s\'est terminé à 02:39 sur 48 211 fichiers. Aucune donnée n\'est sortie du réseau.',
      lessons: [
        'La chronologie se construit toujours depuis un point fixe. Ici, le 4624 de type 10 à 01:27 : tout ce qui précède est de la tentative, tout ce qui suit est de la compromission.',
        'Une même action laisse des traces dans plusieurs journaux. Le déploiement latéral apparaît côté source (PsExec dans Sysmon), côté annuaire (4624 NTLM) et côté cible (service PSEXESVC 7045). Un seul de ces journaux aurait donné une étendue fausse.',
        'L\'absence de preuve, quand le journal existe et couvre la période, est une preuve d\'absence exploitable. La synthèse de volumétrie sortante permet d\'affirmer qu\'il n\'y a pas eu d\'exfiltration, et donc pas d\'obligation de notification.',
        'Le mode « détection seule » configuré sur les serveurs pour éviter les faux positifs nocturnes a laissé passer trois alertes critiques. C\'est une recommandation à porter dans le rapport, au même titre que la règle de pare-feu.'
      ],
      pitfalls: [
        'Conclure que l\'attaque commence à 02:11 avec le chiffrement, en oubliant les quatre heures de force brute et l\'heure et quart de préparation.',
        'Oublier le compte svc_help et laisser au client un accès administrateur résiduel après réinitialisation d\'adm_marcelin.',
        'Répondre « indéterminable » sur l\'exfiltration alors que la volumétrie sortante est journalisée et sans anomalie : le doute de confort a un coût pour le client.',
        'Compter trois machines chiffrées au lieu de quatre en oubliant la machine d\'origine, ou cinq en comptant PC-ATELIER-07, éteint depuis le 28 février.'
      ]
    }
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
