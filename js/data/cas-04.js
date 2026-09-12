/* Open-Forensics — CAS-04. AVERTISSEMENT : contient les réponses attendues. */
(function (root) {
  'use strict';

  root.OpenForensics.cases.push({
    id: 'CAS-04',
    title: 'Vol de la base clients d\'une boutique en ligne',
    client: 'Boutique Lorent — vente en ligne d\'équipement sportif',
    difficulty: 'moyen',
    estimatedMin: 60,
    tags: ['webshell', 'exfiltration', 'application exposée'],

    env: {
      domain: 'LORENT', dns: 'lorent.lan', mail: 'boutique-lorent.example',
      lan: '10.44.3', edge: '198.51.100.60',
      hosts: ['SRV-WEB-01', 'SRV-BDD-01', 'SRV-ADM-01', 'PC-DSI-01'],
      users: ['t.lorent', 'e.vidal', 'g.sanchez', 'deploy'],
      admins: ['adm_web']
    },

    brief: {
      saisine: 'Mardi 12 mai 2026. Un lot de 81 000 comptes clients attribué à la boutique est mis en vente sur un forum. Les échantillons publiés contiennent des adresses de courriel, des empreintes de mots de passe et des historiques de commande authentiques. La boutique n\'a détecté aucune alerte.',
      perimetre: 'Un serveur web exposé (nginx + PHP), un serveur de base de données en réseau interne, un serveur d\'administration. Pas de pare-feu applicatif. Sauvegardes quotidiennes.',
      collecte: 'Journaux d\'accès et d\'erreur du serveur web, journal d\'audit système du serveur web, journal du moteur de base de données et journal du pare-feu, du 1er au 12 mai. Horodatages en UTC.',
      limites: 'Le journal d\'accès nginx ne conserve pas le corps des requêtes : le contenu des requêtes POST est perdu. Les fichiers du serveur web ont été modifiés depuis l\'incident par l\'hébergeur. Le journal d\'audit système ne couvre que les sept derniers jours.',
      mission: 'Déterminer le point d\'entrée, la date de première compromission, ce qui a été extrait exactement, par quel canal, et si l\'accès de l\'attaquant est encore ouvert aujourd\'hui.'
    },

    evidence: [
      {
        id: 'PJ-01', source: 'journaux', system: 'SRV-WEB-01',
        title: 'Journal d\'accès du serveur web',
        note: 'Format combiné. Le corps des requêtes POST n\'est pas journalisé : seules l\'URI, la méthode, le code de retour et la taille de réponse sont disponibles.',
        lines: [
          { t: '2026-05-04 02:11:44', m: '198.51.100.203 - - "GET /index.php?route=common/home HTTP/1.1" 200 24118 "-" "Mozilla/5.0 (X11; Linux x86_64)"' },
          { t: '2026-05-04 02:14:07', m: '198.51.100.203 - - "GET /index.php?route=extension/module/gallery&file=../../../../etc/passwd HTTP/1.1" 200 1842 "-" "Mozilla/5.0 (X11; Linux x86_64)"' },
          { t: '2026-05-04 02:17:31', m: '198.51.100.203 - - "POST /index.php?route=extension/module/gallery/upload HTTP/1.1" 200 74 "-" "Mozilla/5.0 (X11; Linux x86_64)"' },
          { t: '2026-05-04 02:17:52', m: '198.51.100.203 - - "GET /media/cache/th.php?c=id HTTP/1.1" 200 62 "-" "Mozilla/5.0 (X11; Linux x86_64)"' },
          { t: '2026-05-04 02:18:40', m: '198.51.100.203 - - "GET /media/cache/th.php?c=uname%20-a HTTP/1.1" 200 118 "-" "Mozilla/5.0 (X11; Linux x86_64)"' },
          { t: '2026-05-04 02:31:09', m: '198.51.100.203 - - "GET /media/cache/th.php?c=cat%20/var/www/boutique/config.php HTTP/1.1" 200 2214 "-" "Mozilla/5.0 (X11; Linux x86_64)"' },
          { t: '2026-05-07 23:02:18', m: '198.51.100.203 - - "GET /media/cache/th.php?c=mysqldump%20-u%20boutique_ro%20-p...%20boutique%20clients%20commandes%20-r%20/tmp/.c.sql HTTP/1.1" 200 46 "-" "curl/8.4.0"' },
          { t: '2026-05-07 23:14:55', m: '198.51.100.203 - - "GET /media/cache/th.php?c=gzip%20/tmp/.c.sql HTTP/1.1" 200 44 "-" "curl/8.4.0"' },
          { t: '2026-05-07 23:16:02', m: '198.51.100.203 - - "GET /media/cache/th.php?d=/tmp/.c.sql.gz HTTP/1.1" 200 214884352 "-" "curl/8.4.0"' },
          { t: '2026-05-07 23:41:20', m: '198.51.100.203 - - "GET /media/cache/th.php?c=rm%20-f%20/tmp/.c.sql.gz%20/media/cache/th.php HTTP/1.1" 200 41 "-" "curl/8.4.0"' },
          { t: '2026-05-08 01:12:33', m: '198.51.100.203 - - "GET /media/cache/th.php HTTP/1.1" 404 162 "-" "curl/8.4.0"' }
        ],
        noise: [{ family: 'nginx', count: 420, from: '2026-05-01 00:00:00', to: '2026-05-12 12:00:00' }]
      },
      {
        id: 'PJ-02', source: 'journaux', system: 'SRV-WEB-01',
        title: 'Journal d\'erreur PHP',
        note: 'Les avertissements de l\'interpréteur PHP y sont consignés, y compris pour les scripts déposés par un tiers.',
        lines: [
          { t: '2026-05-04 02:14:07', m: 'PHP Warning: include(): Failed opening \'../../../../etc/passwd\' for inclusion in /var/www/boutique/extension/module/gallery.php on line 118' },
          { t: '2026-05-04 02:17:31', m: 'PHP Notice: move_uploaded_file(): file moved to /var/www/boutique/media/cache/th.php in /var/www/boutique/extension/module/gallery.php on line 204 note="extension non verifiee par le controle de type"' },
          { t: '2026-05-04 02:17:52', m: 'PHP Notice: shell_exec() called in /var/www/boutique/media/cache/th.php on line 3' },
          { t: '2026-05-07 23:02:18', m: 'PHP Notice: shell_exec() called in /var/www/boutique/media/cache/th.php on line 3' },
          { t: '2026-05-09 04:02:11', m: 'PHP Warning: require_once(): Failed opening \'/var/www/boutique/media/cache/th.php\' in /var/www/boutique/index.php on line 12 note="tentative d appel depuis une tache planifiee du module"' }
        ],
        noise: [{ family: 'nginx', count: 90, from: '2026-05-01 00:00:00', to: '2026-05-12 12:00:00' }]
      },
      {
        id: 'PJ-03', source: 'journaux', system: 'SRV-WEB-01',
        title: 'Journal d\'audit système — serveur web',
        note: 'auditd, règles standard sur execve. Ne couvre que les sept derniers jours : rien avant le 5 mai.',
        lines: [
          { t: '2026-05-07 23:02:19', m: 'host=SRV-WEB-01 type=SYSCALL syscall=execve exe=/usr/bin/mysqldump args="-u boutique_ro -h 10.44.3.20 boutique clients commandes -r /tmp/.c.sql" uid=www-data ppid=1102 pcomm=php-fpm8.2' },
          { t: '2026-05-07 23:13:58', m: 'host=SRV-WEB-01 type=PATH name=/tmp/.c.sql nametype=CREATE mode=0644 ouid=www-data size=1204871168' },
          { t: '2026-05-07 23:14:55', m: 'host=SRV-WEB-01 type=SYSCALL syscall=execve exe=/usr/bin/gzip args="/tmp/.c.sql" uid=www-data ppid=1102 pcomm=php-fpm8.2' },
          { t: '2026-05-07 23:15:51', m: 'host=SRV-WEB-01 type=PATH name=/tmp/.c.sql.gz nametype=CREATE mode=0644 ouid=www-data size=214884352' },
          { t: '2026-05-07 23:41:20', m: 'host=SRV-WEB-01 type=SYSCALL syscall=unlink exe=/bin/rm args="-f /tmp/.c.sql.gz /media/cache/th.php" uid=www-data ppid=1102 pcomm=php-fpm8.2' },
          { t: '2026-05-10 03:00:02', m: 'host=SRV-WEB-01 type=SERVICE_START unit=sauvegarde-quotidienne.service result=done' }
        ],
        noise: [{ family: 'auditd', count: 260, from: '2026-05-05 00:00:00', to: '2026-05-12 12:00:00' }]
      },
      {
        id: 'PJ-04', source: 'journaux', system: 'SRV-BDD-01',
        title: 'Journal du moteur de base de données',
        note: 'Journalisation des connexions et des requêtes longues. Le compte boutique_ro est en lecture seule sur la base boutique.',
        lines: [
          { t: '2026-05-07 23:02:20', m: 'login succeeded user=boutique_ro src=10.44.3.11 database=boutique note="compte applicatif en lecture seule"' },
          { t: '2026-05-07 23:02:21', m: 'query duration=671412ms user=boutique_ro statement="SELECT /*!40001 SQL_NO_CACHE */ * FROM clients" rows_sent=81240' },
          { t: '2026-05-07 23:13:44', m: 'query duration=68211ms user=boutique_ro statement="SELECT /*!40001 SQL_NO_CACHE */ * FROM commandes" rows_sent=214902' },
          { t: '2026-05-07 23:13:57', m: 'connection closed user=boutique_ro src=10.44.3.11 duration_s=657 bytes_sent=1204871168' },
          { t: '2026-05-09 03:00:11', m: 'login succeeded user=svc_sauvegarde src=10.44.3.30 database=boutique note="sauvegarde planifiee"' }
        ],
        noise: [{ family: 'bdd', count: 280, from: '2026-05-01 00:00:00', to: '2026-05-12 12:00:00' }]
      },
      {
        id: 'PJ-05', source: 'reseau', system: 'Pare-feu périmétrique',
        title: 'Journal du pare-feu périmétrique',
        note: 'Compteurs de volume par session. La sortie du serveur web vers Internet n\'est pas filtrée.',
        lines: [
          { t: '2026-05-04 02:11:40', m: 'src=198.51.100.203 dst=10.44.3.11 dport=443 proto=tcp action=ALLOW policy=WEB-PUBLIC bytes_in=18422 bytes_out=214880' },
          { t: '2026-05-07 23:16:02', m: 'src=10.44.3.11 dst=198.51.100.203 dport=443 proto=tcp action=ALLOW direction=egress bytes_out=214884352 duration_s=1488 note="volume sortant le plus eleve de la periode"' },
          { t: '2026-05-07 23:02:19', m: 'src=10.44.3.11 dst=10.44.3.20 dport=3306 proto=tcp action=ALLOW policy=WEB-TO-DB bytes=1204871168' },
          { t: '2026-05-12 09:41:00', m: 'egress_summary window=2026-05-01/2026-05-12 top_talker=10.44.3.11 total_bytes_out=286114220 note="dont 214 Mo sur une seule session le 7 mai"' }
        ],
        noise: [{ family: 'firewall', count: 340, from: '2026-05-01 00:00:00', to: '2026-05-12 12:00:00' }]
      }
    ],

    questions: [
      { id: 'Q1', type: 'ip', label: 'Adresse IP de l\'attaquant',
        answer: '198.51.100.203',
        hint: 'Une même adresse revient du premier balayage jusqu\'au nettoyage final, dans trois journaux différents.',
        where: 'PJ-01 de bout en bout, PJ-05 pour la session sortante.',
        why: 'Le fil rouge du dossier : c\'est sur cette adresse que se construit toute la chronologie.' },

      { id: 'Q2', type: 'path', label: 'Chemin du webshell déposé sur le serveur',
        answer: '/media/cache/th.php', alt: ['media/cache/th.php', '/var/www/boutique/media/cache/th.php'],
        hint: 'Juste après une requête POST vers un module de téléversement, une nouvelle URI apparaît dans le journal d\'accès.',
        where: 'PJ-01 à 02:17:52, et PJ-02 qui donne le chemin absolu à la ligne move_uploaded_file.',
        why: 'Le chemin exact permet de vérifier la présence du fichier sur les sauvegardes et d\'identifier le répertoire inscriptible à corriger.' },

      { id: 'Q3', type: 'text', label: 'Module applicatif vulnérable ayant permis le dépôt',
        answer: 'gallery', alt: ['extension/module/gallery', 'module gallery', 'gallery.php'],
        hint: 'Le journal d\'erreur PHP nomme le fichier source dans lequel le téléversement a été traité.',
        where: 'PJ-02 : /var/www/boutique/extension/module/gallery.php, ligne 204, contrôle de type absent.',
        why: 'Sans identification du composant vulnérable, la remise en service réintroduit la faille : c\'est la recommandation centrale du rapport.' },

      { id: 'Q4', type: 'datetime', label: 'Horodatage du dépôt du webshell (UTC)',
        answer: '2026-05-04 02:17',
        hint: 'Le POST vers le module de téléversement et le premier appel au webshell sont séparés de vingt et une secondes.',
        where: 'PJ-01, POST à 02:17:31 puis premier appel à 02:17:52.',
        why: 'Cette date fixe le début de la compromission : les sauvegardes antérieures au 4 mai sont saines, celles d\'après ne le sont pas.' },

      { id: 'Q5', type: 'text', label: 'Paramètre HTTP par lequel les commandes étaient passées au webshell',
        answer: 'c',
        hint: 'Regardez la chaîne de requête des appels au webshell : un paramètre porte systématiquement la commande.',
        where: 'PJ-01, th.php?c=id, th.php?c=uname -a, etc. Un second paramètre, d, sert au téléchargement.',
        why: 'Connaître le paramètre permet d\'écrire une règle de détection rétroactive et de chercher les mêmes appels sur d\'autres serveurs du client.' },

      { id: 'Q6', type: 'text', label: 'Compte de base de données utilisé pour l\'extraction',
        answer: 'boutique_ro',
        hint: 'La commande d\'export et le journal du moteur de base de données nomment le même compte.',
        where: 'PJ-01 (commande mysqldump), PJ-03 (execve) et PJ-04 (login succeeded).',
        why: 'Un compte en lecture seule a suffi : la leçon est que la restriction d\'écriture ne protège pas de l\'extraction. Les identifiants étaient en clair dans config.php, lu trois jours plus tôt.' },

      { id: 'Q7', type: 'number', label: 'Nombre d\'enregistrements clients extraits',
        answer: '81240',
        hint: 'Le journal du moteur de base de données indique le nombre de lignes renvoyées par la requête sur la table clients.',
        where: 'PJ-04, rows_sent=81240.',
        why: 'C\'est le chiffre à faire figurer dans la notification à l\'autorité de contrôle et dans l\'information des personnes concernées.' },

      { id: 'Q8', type: 'datetime', label: 'Horodatage de l\'extraction de la base (UTC)',
        answer: '2026-05-07 23:02',
        hint: 'Trois jours séparent le dépôt du webshell de l\'extraction. Cherchez l\'exécution de mysqldump.',
        where: 'PJ-01, PJ-03 et PJ-04 donnent la même minute.',
        why: 'Le délai de trois jours entre l\'accès et l\'extraction est typique : l\'accès est souvent revendu ou exploité plus tard par un autre opérateur.' },

      { id: 'Q9', type: 'number', label: 'Volume exfiltré en octets',
        answer: '214884352',
        hint: 'L\'archive compressée a été téléchargée en une seule requête ; sa taille figure dans le journal d\'accès et dans celui du pare-feu.',
        where: 'PJ-01 (taille de réponse), PJ-03 (taille du fichier .gz) et PJ-05 (session sortante).',
        why: 'La concordance de trois journaux sur le même volume rend la constatation incontestable — et distingue l\'extraction (1,2 Go) de l\'exfiltration (215 Mo compressés).' },

      { id: 'Q10', type: 'text', label: 'Chemin du fichier d\'export créé sur le serveur',
        answer: '/tmp/.c.sql', alt: ['/tmp/.c.sql.gz', 'tmp/.c.sql'],
        hint: 'Le nom commence par un point : c\'est un fichier caché sous Unix.',
        where: 'PJ-03, type=PATH nametype=CREATE.',
        why: 'Le point initial n\'est pas anodin : il fait disparaître le fichier d\'un simple ls, et c\'est une habitude constante de ce type d\'opérateur.' },

      { id: 'Q11', type: 'choice', label: 'L\'accès de l\'attaquant est-il encore ouvert aujourd\'hui ?',
        answer: 'Non : le webshell a été supprimé par l\'attaquant lui-même après l\'exfiltration',
        options: [
          'Oui : le webshell répond toujours',
          'Non : le webshell a été supprimé par l\'attaquant lui-même après l\'exfiltration',
          'Non : le webshell a été supprimé par l\'hébergeur lors de la remise en service',
          'Indéterminable avec les pièces disponibles'
        ],
        hint: 'Une commande de suppression apparaît juste après le téléchargement, et un appel ultérieur au webshell renvoie un code différent.',
        where: 'PJ-01 : rm à 23:41:20 puis un 404 sur th.php le 8 mai à 01:12. PJ-03 confirme l\'appel système unlink.',
        why: 'La réponse a une conséquence directe : il n\'y a pas d\'urgence à couper le serveur, mais la vulnérabilité de téléversement, elle, reste ouverte. Confondre les deux conduit à un plan de remédiation faux.' },

      { id: 'Q12', type: 'choice', label: 'La vulnérabilité exploitée est-elle corrigée ?',
        answer: 'Non : rien n\'indique une correction, le module reste en place',
        options: [
          'Oui : le module a été retiré le 9 mai',
          'Non : rien n\'indique une correction, le module reste en place',
          'Sans objet : la faille venait du système, pas de l\'application',
          'Indéterminable : les journaux applicatifs manquent'
        ],
        hint: 'Regardez la dernière ligne du journal d\'erreur PHP : que tente encore d\'appeler l\'application le 9 mai ?',
        where: 'PJ-02, le 9 mai à 04:02 : une tâche du module gallery tente toujours d\'inclure th.php. Le module est donc toujours actif et non corrigé.',
        why: 'C\'est la distinction entre éradication et remédiation. Le webshell est parti, la porte par laquelle il est entré est toujours ouverte : sans cette précision, le client se croit tiré d\'affaire.' }
    ],

    events: [
      { id: 'EV-01', t: '2026-05-04 02:14', label: 'Tentative de traversée de répertoire sur le module gallery' },
      { id: 'EV-02', t: '2026-05-04 02:17', label: 'Téléversement puis premier appel du webshell th.php' },
      { id: 'EV-03', t: '2026-05-04 02:31', label: 'Lecture du fichier de configuration applicatif (identifiants de base)' },
      { id: 'EV-04', t: '2026-05-07 23:02', label: 'Export des tables clients et commandes par mysqldump' },
      { id: 'EV-05', t: '2026-05-07 23:14', label: 'Compression de l\'export en archive cachée' },
      { id: 'EV-06', t: '2026-05-07 23:16', label: 'Téléchargement de l\'archive de 215 Mo par le webshell' },
      { id: 'EV-07', t: '2026-05-07 23:41', label: 'Suppression de l\'archive et du webshell par l\'attaquant' },
      { id: 'EV-08', t: '2026-05-09 03:00', label: 'Sauvegarde quotidienne planifiée du serveur' },
      { id: 'EV-09', t: '2026-05-09 04:02', label: 'Tâche du module gallery tentant d\'inclure un fichier absent' },
      { id: 'EV-10', t: '2026-05-10 03:00', label: 'Démarrage du service de sauvegarde quotidienne' }
    ],

    chain: [
      { tactic: 'Accès initial', event: 'EV-02', technique: 'T1190',
        where: 'PJ-01 (POST sur le module de téléversement) et PJ-02 (move_uploaded_file sans contrôle de type).',
        why: 'Le contrôle d\'extension absent sur un module tiers est la cause racine. La traversée de répertoire qui précède n\'est que de la reconnaissance.' },
      { tactic: 'Exécution', event: 'EV-04', technique: 'T1059.004',
        where: 'PJ-03, execve de mysqldump sous l\'identité www-data avec pour parent php-fpm.',
        why: 'Le couple « processus de serveur web parent d\'un binaire système » est la signature la plus fiable d\'un webshell actif.' },
      { tactic: 'Persistance', event: 'EV-02', technique: 'T1505.003',
        where: 'PJ-01, le webshell reste joignable du 4 au 7 mai.',
        why: 'Le webshell EST la persistance : trois jours d\'accès sans aucun autre mécanisme, jusqu\'à ce que l\'attaquant le supprime lui-même.' },
      { tactic: 'Élévation de privilèges', event: 'NONE', technique: 'NONE',
        where: 'Toutes les actions restent sous l\'identité www-data : aucun passage à root.',
        why: 'L\'attaquant n\'en avait pas besoin, le compte du serveur web ayant accès à la base. Le signaler évite de facturer une reconstruction système complète.' },
      { tactic: 'Contournement des défenses', event: 'EV-07', technique: 'T1070.004',
        where: 'PJ-01 et PJ-03 : rm -f sur l\'archive et sur le webshell, puis 404 le lendemain.',
        why: 'Le nettoyage est ici ce qui a retardé la détection de cinq jours : plus aucun fichier suspect sur le disque, seuls les journaux témoignent.' },
      { tactic: 'Accès aux identifiants', event: 'EV-03', technique: 'T1552.001',
        where: 'PJ-01, lecture de config.php le 4 mai à 02:31.',
        why: 'Les identifiants de base en clair dans un fichier de configuration sont le maillon qui transforme un accès web en vol de données.' },
      { tactic: 'Découverte', event: 'EV-01', technique: 'T1083', techniqueAlt: ['T1082'],
        where: 'PJ-01, traversée vers /etc/passwd, puis id et uname -a.',
        why: 'Reconnaissance minimale : l\'attaquant vérifie sous quelle identité il s\'exécute et sur quel système, rien de plus.' },
      { tactic: 'Déplacement latéral', event: 'NONE', technique: 'NONE',
        where: 'Aucune connexion vers SRV-ADM-01 ni vers un poste : seule la liaison applicative vers la base a été utilisée.',
        why: 'L\'accès à la base via le port 3306 depuis le serveur web est un flux légitime et attendu : ce n\'est pas un déplacement latéral, c\'est l\'usage normal de l\'application détourné.' },
      { tactic: 'Collecte', event: 'EV-05', technique: 'T1560.001',
        where: 'PJ-03, gzip sur /tmp/.c.sql produisant une archive de 215 Mo.',
        why: 'La compression avant sortie réduit le volume d\'un facteur six : c\'est aussi ce qui rend l\'exfiltration discrète dans un journal de pare-feu.' },
      { tactic: 'Commande et contrôle', event: 'NONE', technique: 'NONE',
        where: 'Aucune connexion sortante initiée par le serveur en dehors du transfert du 7 mai : l\'attaquant pilote en HTTP entrant.',
        why: 'Un webshell n\'a pas besoin de canal sortant : c\'est le client qui vient chercher. Chercher une balise sortante ici ne donne rien.' },
      { tactic: 'Exfiltration', event: 'EV-06', technique: 'T1041', techniqueAlt: ['T1048.003'],
        where: 'PJ-01 (réponse de 214 884 352 octets) et PJ-05 (session sortante de même volume).',
        why: 'L\'exfiltration emprunte exactement le même canal que le contrôle : une simple requête GET sur le webshell.' },
      { tactic: 'Impact', event: 'NONE', technique: 'NONE',
        where: 'Aucune destruction, aucun chiffrement, aucune altération des données de production.',
        why: 'L\'impact est réglementaire et réputationnel, pas opérationnel. La boutique fonctionnait normalement pendant toute la compromission, ce qui explique l\'absence de détection.' }
    ],

    keyIndicators: ['198.51.100.203', 'th.php', 'gallery', 'boutique_ro', '81240', '/tmp/.c.sql', '214884352'],

    iocs: [
      { type: 'Adresse IP', value: '198.51.100.203', context: 'Source unique de la compromission, du 4 au 8 mai.' },
      { type: 'Chemin', value: '/media/cache/th.php', context: 'Webshell déposé via le module gallery, supprimé par l\'attaquant le 7 mai.' },
      { type: 'Motif de requête', value: 'th.php?c= et th.php?d=', context: 'Paramètres de commande et de téléchargement du webshell.' },
      { type: 'Chemin', value: '/tmp/.c.sql.gz', context: 'Archive de l\'export de base, 215 Mo, supprimée après exfiltration.' },
      { type: 'Compte', value: 'boutique_ro', context: 'Compte applicatif en lecture seule utilisé pour l\'export, identifiants lus dans config.php.' },
      { type: 'Agent utilisateur', value: 'curl/8.4.0', context: 'Employé pour les requêtes d\'exfiltration, distinct du navigateur simulé lors de la phase initiale.' }
    ],

    debrief: {
      story: 'Dans la nuit du 4 mai, un opérateur balaie la boutique depuis 198.51.100.203 et découvre qu\'un module de galerie accepte un téléversement sans vérifier le type de fichier. À 02h17 il dépose th.php dans /media/cache et l\'appelle vingt et une secondes plus tard. Il vérifie son identité (www-data), le système, puis lit le fichier de configuration de l\'application, qui contient en clair les identifiants de la base. Puis plus rien pendant trois jours. Le 7 mai à 23h02, il revient — avec un autre outil, curl au lieu du navigateur — et exporte les tables clients et commandes : 81 240 clients et 214 902 commandes, soit 1,2 Go. Il compresse en 215 Mo, télécharge l\'archive par le webshell en vingt-cinq minutes, puis efface l\'archive et le webshell. Le 8 mai, le webshell ne répond plus. Rien n\'a été chiffré, rien n\'a cessé de fonctionner : la boutique n\'a rien vu.',
      lessons: [
        'Le trou de trois jours entre l\'accès et l\'extraction, et le changement d\'agent utilisateur, racontent quelque chose : ce ne sont probablement pas les mêmes mains. L\'accès initial et son exploitation sont deux métiers distincts, et les journaux le montrent.',
        'Trois journaux donnent le même volume de 214 884 352 octets. Quand une constatation doit tenir devant une autorité de contrôle, on ne cite pas une source, on en cite trois qui concordent.',
        'Distinguer extraction et exfiltration : 1,2 Go sont sortis de la base, 215 Mo sont sortis du réseau. Les deux chiffres sont justes et ne décrivent pas la même chose.',
        'Le webshell a disparu, la vulnérabilité est restée. L\'éradication de l\'implant n\'est pas la remédiation de la cause — et ici, c\'est l\'attaquant lui-même qui a fait le ménage, ce qui a failli faire conclure à un incident clos.'
      ],
      pitfalls: [
        'Conclure que l\'accès est toujours ouvert parce qu\'un webshell a existé : les journaux montrent sa suppression et un 404 le lendemain.',
        'Conclure à l\'inverse que l\'affaire est close parce que le webshell est parti, alors que le module vulnérable est toujours actif le 9 mai.',
        'Annoncer 1,2 Go exfiltrés en confondant la taille de l\'export et celle de l\'archive réellement transférée.',
        'Chercher une élévation de privilèges ou un canal de commande sortant : ni l\'une ni l\'autre n\'existent, et les chercher coûte des heures.'
      ]
    }
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
