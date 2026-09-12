/* Open-Forensics — CAS-05. AVERTISSEMENT : contient les réponses attendues. */
(function (root) {
  'use strict';

  root.OpenForensics.cases.push({
    id: 'CAS-05',
    title: 'Mise à jour logicielle téléchargée sur un faux miroir',
    client: 'Fonderie Haussmann — métallurgie, site de production continu',
    difficulty: 'moyen',
    estimatedMin: 55,
    tags: ['faux miroir', 'chargement latéral de DLL', 'balise'],

    env: {
      domain: 'HAUSSMANN', dns: 'haussmann.lan', mail: 'fonderie-haussmann.example',
      lan: '10.20.5', edge: '198.51.100.44',
      hosts: ['PC-SUPERV-01', 'PC-SUPERV-02', 'PC-METHODE-03', 'PC-QUAL-07', 'SRV-SCADA-01', 'SRV-AD-03'],
      users: ['b.nguyen', 'o.karam', 'v.petit', 's.lefranc'],
      admins: ['adm_indus']
    },

    brief: {
      saisine: 'Lundi 16 février 2026. L\'agent de sécurité a déclenché une alerte après une mise à jour de signatures : un service inconnu communique régulièrement vers Internet depuis deux postes de supervision de production. Aucun ralentissement n\'a été constaté, aucune donnée ne semble manquer.',
      perimetre: 'Deux postes de supervision reliés à l\'automate de production, trois postes bureautiques, un serveur de supervision et un contrôleur de domaine. Le réseau de production est théoriquement séparé du réseau bureautique.',
      collecte: 'Journaux du mandataire web, de l\'agent de sécurité, de télémétrie de processus, du pare-feu et du serveur DNS interne, du 1er au 17 février. Horodatages en UTC.',
      limites: 'La télémétrie de processus n\'est déployée que sur les postes de supervision, pas sur les postes bureautiques. Le mandataire web ne journalise pas le corps des réponses : impossible de récupérer le fichier réellement téléchargé, seulement son URL et sa taille.',
      mission: 'Déterminer comment le code est entré, ce qu\'il fait, depuis combien de temps, combien de machines sont touchées, et si le réseau de production a été atteint. La direction industrielle veut savoir si elle doit arrêter la ligne.'
    },

    evidence: [
      {
        id: 'PJ-01', source: 'reseau', system: 'Mandataire web',
        title: 'Journal du mandataire web',
        note: 'Catégorisation et âge de domaine évalués à la volée. Les téléchargements de plus de 1 Mo sont journalisés avec leur taille.',
        lines: [
          { t: '2026-02-09 08:41:12', m: 'user=o.karam src=10.20.5.31 action=ALLOW method=GET url=https://www.moteur-recherche.example/search?q=plantwatch+4.2+telechargement status=200 bytes=44120 category=moteur_de_recherche' },
          { t: '2026-02-09 08:42:50', m: 'user=o.karam src=10.20.5.31 action=ALLOW method=GET url=https://updates-plantwatch.test/download/PlantWatch_4.2.1_setup.msi status=200 bytes=48211456 category=uncategorized domain_age_days=17' },
          { t: '2026-02-09 08:44:02', m: 'user=o.karam src=10.20.5.31 action=ALLOW method=GET url=https://updates-plantwatch.test/notes-de-version status=200 bytes=8820 category=uncategorized' },
          { t: '2026-02-03 14:10:33', m: 'user=v.petit src=10.20.5.44 action=ALLOW method=GET url=https://plantwatch-updates.example/support/faq status=200 bytes=21044 category=logiciels note="site officiel de l editeur"' },
          { t: '2026-02-09 09:22:41', m: 'user=o.karam src=10.20.5.31 action=ALLOW method=POST url=https://cdn-telemetry-eu.test/api/v1/collect status=200 bytes_out=842 bytes_in=311 category=uncategorized domain_age_days=22' },
          { t: '2026-02-09 09:27:44', m: 'user=o.karam src=10.20.5.31 action=ALLOW method=POST url=https://cdn-telemetry-eu.test/api/v1/collect status=200 bytes_out=804 bytes_in=298 category=uncategorized' },
          { t: '2026-02-10 07:02:19', m: 'user=b.nguyen src=10.20.5.32 action=ALLOW method=POST url=https://cdn-telemetry-eu.test/api/v1/collect status=200 bytes_out=811 bytes_in=305 category=uncategorized' }
        ],
        noise: [{ family: 'proxy', count: 340, from: '2026-02-01 06:00:00', to: '2026-02-17 19:00:00' }]
      },
      {
        id: 'PJ-02', source: 'journaux', system: 'PC-SUPERV-01 et PC-SUPERV-02',
        title: 'Télémétrie de processus — postes de supervision',
        note: 'Sysmon, configuration industrielle allégée : créations de processus, chargements de modules signés inconnus, créations de fichiers exécutables.',
        lines: [
          { t: '2026-02-09 08:47:31', m: 'EventCode=1 Computer=PC-SUPERV-01 Image=C:\\Windows\\System32\\msiexec.exe CommandLine="msiexec.exe /i C:\\Users\\o.karam\\Downloads\\PlantWatch_4.2.1_setup.msi" User=HAUSSMANN\\o.karam Signature="Norvik Systems AB" SignatureStatus=Valid SHA256=5608c0368c3e19e5f1c88c419c16adf5b47c72093bfb9960bbf63935fac163f4' },
          { t: '2026-02-09 08:48:02', m: 'EventCode=11 Computer=PC-SUPERV-01 TargetFilename=C:\\Program Files\\PlantWatch\\PlantWatch.exe Image=msiexec.exe Signature="PlantWatch Industrial AB" note="binaire legitime de l editeur"' },
          { t: '2026-02-09 08:48:03', m: 'EventCode=11 Computer=PC-SUPERV-01 TargetFilename=C:\\Program Files\\PlantWatch\\mscoree.dll Image=msiexec.exe Signature=none SHA256=d1924b371887a63c024ffb04d13717b4da76c5e2ccf6d47ffbffc3a9b5c159eb' },
          { t: '2026-02-09 08:48:44', m: 'EventCode=7 Computer=PC-SUPERV-01 Image=C:\\Program Files\\PlantWatch\\PlantWatch.exe ImageLoaded=C:\\Program Files\\PlantWatch\\mscoree.dll Signed=false note="module non signe charge par un binaire signe"' },
          { t: '2026-02-09 08:49:10', m: 'EventCode=1 Computer=PC-SUPERV-01 Image=C:\\Windows\\System32\\sc.exe CommandLine="sc create PlantWatchSync binPath= \\"C:\\Program Files\\PlantWatch\\PlantWatch.exe -svc\\" start= auto" User=HAUSSMANN\\o.karam' },
          { t: '2026-02-09 09:21:03', m: 'EventCode=1 Computer=PC-SUPERV-01 Image=C:\\Windows\\System32\\whoami.exe ParentImage=C:\\Program Files\\PlantWatch\\PlantWatch.exe CommandLine="whoami /groups"' },
          { t: '2026-02-09 09:21:40', m: 'EventCode=1 Computer=PC-SUPERV-01 Image=C:\\Windows\\System32\\net.exe ParentImage=C:\\Program Files\\PlantWatch\\PlantWatch.exe CommandLine="net group \\"Domain Admins\\" /domain"' },
          { t: '2026-02-09 09:22:15', m: 'EventCode=1 Computer=PC-SUPERV-01 Image=C:\\Windows\\System32\\nltest.exe ParentImage=C:\\Program Files\\PlantWatch\\PlantWatch.exe CommandLine="nltest /domain_trusts"' },
          { t: '2026-02-10 06:58:22', m: 'EventCode=1 Computer=PC-SUPERV-02 Image=C:\\Windows\\System32\\msiexec.exe CommandLine="msiexec.exe /i \\\\PC-SUPERV-01\\Partage\\PlantWatch_4.2.1_setup.msi" User=HAUSSMANN\\b.nguyen SHA256=5608c0368c3e19e5f1c88c419c16adf5b47c72093bfb9960bbf63935fac163f4' },
          { t: '2026-02-10 06:59:41', m: 'EventCode=7 Computer=PC-SUPERV-02 Image=C:\\Program Files\\PlantWatch\\PlantWatch.exe ImageLoaded=C:\\Program Files\\PlantWatch\\mscoree.dll Signed=false' },
          { t: '2026-02-12 11:04:58', m: 'EventCode=3 Computer=PC-SUPERV-01 Image=C:\\Program Files\\PlantWatch\\PlantWatch.exe DestinationIp=10.20.5.90 DestinationPort=445 Result=connection_refused note="SRV-SCADA-01, filtrage reseau de production"' }
        ],
        noise: [{ family: 'sysmon', count: 320, from: '2026-02-01 06:00:00', to: '2026-02-17 19:00:00', vars: { hosts: ['PC-SUPERV-01', 'PC-SUPERV-02'] } }]
      },
      {
        id: 'PJ-03', source: 'journaux', system: 'Console EDR',
        title: 'Journal de l\'agent de sécurité',
        note: 'La détection du 16 février fait suite à une mise à jour de signatures : le comportement était présent depuis une semaine sans être reconnu.',
        lines: [
          { t: '2026-02-09 08:47:35', m: 'file_reputation host=PC-SUPERV-01 path=C:\\Users\\o.karam\\Downloads\\PlantWatch_4.2.1_setup.msi sha256=5608c0368c3e19e5f1c88c419c16adf5b47c72093bfb9960bbf63935fac163f4 signer="Norvik Systems AB" prevalence=global_count_6 verdict=unknown action=allowed note="signature valide, editeur inconnu du parc"' },
          { t: '2026-02-16 05:12:44', m: 'signature_update host=* version=2026.02.16 new_rules=1142' },
          { t: '2026-02-16 05:31:08', m: 'detection name="Suspicious DLL Sideload (mscoree.dll)" host=PC-SUPERV-01 process=PlantWatch.exe severity=high action=DETECTED' },
          { t: '2026-02-16 05:31:12', m: 'detection name="Suspicious DLL Sideload (mscoree.dll)" host=PC-SUPERV-02 process=PlantWatch.exe severity=high action=DETECTED' },
          { t: '2026-02-16 05:33:20', m: 'detection name="Periodic Beacon To Rare Domain" host=PC-SUPERV-01 destination=cdn-telemetry-eu.test interval_avg_s=300 jitter_pct=9 severity=high action=DETECTED' },
          { t: '2026-02-16 05:40:02', m: 'inventory_query scope=parc rule="fichier mscoree.dll non signe dans Program Files" results=2 hosts=PC-SUPERV-01,PC-SUPERV-02' }
        ],
        noise: [{ family: 'edr', count: 200, from: '2026-02-01 06:00:00', to: '2026-02-17 19:00:00' }]
      },
      {
        id: 'PJ-04', source: 'reseau', system: 'Serveur DNS interne',
        title: 'Journal des résolutions DNS',
        note: 'Toutes les requêtes des postes passent par ce résolveur. Utile pour dater la première résolution d\'un domaine.',
        lines: [
          { t: '2026-02-09 08:42:48', m: 'client=10.20.5.31 query=updates-plantwatch.test type=A answer=203.0.113.201 rcode=NOERROR note="premiere resolution de ce domaine sur le parc"' },
          { t: '2026-02-09 09:22:39', m: 'client=10.20.5.31 query=cdn-telemetry-eu.test type=A answer=203.0.113.88 rcode=NOERROR note="premiere resolution de ce domaine sur le parc"' },
          { t: '2026-02-10 07:02:17', m: 'client=10.20.5.32 query=cdn-telemetry-eu.test type=A answer=203.0.113.88 rcode=NOERROR' },
          { t: '2026-02-16 05:33:18', m: 'client=10.20.5.31 query=cdn-telemetry-eu.test type=A answer=203.0.113.88 rcode=NOERROR count_since_first=1904' }
        ],
        noise: [{ family: 'dns', count: 360, from: '2026-02-01 06:00:00', to: '2026-02-17 19:00:00' }]
      },
      {
        id: 'PJ-05', source: 'reseau', system: 'Pare-feu périmétrique',
        title: 'Journal du pare-feu et synthèse de volumétrie',
        note: 'Le réseau de production est filtré depuis le réseau bureautique : les refus sont journalisés.',
        lines: [
          { t: '2026-02-12 11:04:58', m: 'src=10.20.5.31 dst=10.20.5.90 dport=445 proto=tcp action=DENY policy=BUREAU-VERS-PRODUCTION note="cloisonnement respecte"' },
          { t: '2026-02-12 11:05:31', m: 'src=10.20.5.31 dst=10.20.5.90 dport=3389 proto=tcp action=DENY policy=BUREAU-VERS-PRODUCTION' },
          { t: '2026-02-16 06:00:00', m: 'egress_summary window=2026-02-09/2026-02-16 host=10.20.5.31 sessions=1904 total_bytes_out=1602144 total_bytes_in=589220 note="trafic regulier de faible volume, aucun transfert massif"' },
          { t: '2026-02-16 06:00:01', m: 'egress_summary window=2026-02-10/2026-02-16 host=10.20.5.32 sessions=1687 total_bytes_out=1368210 total_bytes_in=512004' }
        ],
        noise: [{ family: 'firewall', count: 320, from: '2026-02-01 06:00:00', to: '2026-02-17 19:00:00' }]
      }
    ],

    questions: [
      { id: 'Q1', type: 'domain', label: 'Domaine depuis lequel l\'installeur a été téléchargé',
        answer: 'updates-plantwatch.test',
        hint: 'Le mandataire journalise le téléchargement d\'un fichier de 48 Mo le 9 février au matin.',
        where: 'PJ-01 à 08:42:50, et PJ-04 qui date la première résolution du domaine sur le parc.',
        why: 'C\'est le point d\'entrée. Sa date de création — dix-sept jours — suffisait à le rendre suspect pour un mandataire correctement réglé.' },

      { id: 'Q2', type: 'domain', label: 'Domaine officiel de l\'éditeur, à ne pas confondre avec le précédent',
        answer: 'plantwatch-updates.example',
        hint: 'Un autre utilisateur a consulté le site du vrai éditeur quelques jours plus tôt.',
        where: 'PJ-01, ligne du 3 février : v.petit consulte plantwatch-updates.example, catégorisé « logiciels ».',
        why: 'Les deux domaines emploient les mêmes mots dans l\'ordre inverse. C\'est l\'essentiel du piège, et c\'est ce qui doit figurer dans la sensibilisation qui suivra.' },

      { id: 'Q3', type: 'text', label: 'Éditeur figurant sur la signature numérique de l\'installeur',
        answer: 'Norvik Systems AB', alt: ['norvik systems', 'norvik'],
        hint: 'La télémétrie de processus et la console de l\'agent donnent le nom du signataire.',
        where: 'PJ-02 (Signature=) et PJ-03 (file_reputation signer=).',
        why: 'La signature est valide, mais elle n\'est pas celle de l\'éditeur attendu. Une signature valide ne prouve que l\'intégrité du fichier, pas l\'identité de qui aurait dû le produire.' },

      { id: 'Q4', type: 'hash', label: 'Empreinte SHA-256 de l\'installeur',
        answer: '5608c0368c3e19e5f1c88c419c16adf5b47c72093bfb9960bbf63935fac163f4',
        hint: 'Elle apparaît à l\'identique sur les deux postes touchés.',
        where: 'PJ-02 (lignes msiexec des 9 et 10 février) et PJ-03.',
        why: 'La même empreinte sur les deux postes prouve que le second a installé le fichier recopié du premier, et non un téléchargement distinct.' },

      { id: 'Q5', type: 'text', label: 'Nom de la bibliothèque chargée latéralement par le binaire légitime',
        answer: 'mscoree.dll',
        hint: 'Un module non signé est chargé par un exécutable signé de l\'éditeur.',
        where: 'PJ-02, EventCode=7 à 08:48:44 ; la détection de PJ-03 le nomme aussi.',
        why: 'Le chargement latéral est la raison pour laquelle le code s\'exécute sous l\'identité d\'un programme légitime, ce qui explique une semaine d\'invisibilité.' },

      { id: 'Q6', type: 'text', label: 'Nom du service créé pour la persistance',
        answer: 'PlantWatchSync',
        hint: 'Une commande sc.exe est exécutée trente secondes après l\'installation.',
        where: 'PJ-02, ligne sc create du 9 février 08:49:10.',
        why: 'Le nom imite celui du produit légitime : lors de l\'éradication, il faut le distinguer du vrai service PlantWatch, qui doit rester.' },

      { id: 'Q7', type: 'domain', label: 'Domaine de commande et contrôle',
        answer: 'cdn-telemetry-eu.test',
        hint: 'Un domaine récent reçoit des requêtes POST de petite taille à intervalle régulier.',
        where: 'PJ-01 (POST /api/v1/collect), PJ-03 (détection de balise) et PJ-04 (résolution).',
        why: 'Le nom est choisi pour ressembler à de la télémétrie logicielle : sans le caractère périodique, il passerait pour du trafic d\'éditeur.' },

      { id: 'Q8', type: 'ip', label: 'Adresse IP résolue pour le domaine de commande et contrôle',
        answer: '203.0.113.88',
        hint: 'Le résolveur interne journalise la réponse.',
        where: 'PJ-04, 9 février 09:22:39.',
        why: 'C\'est l\'indicateur réseau à bloquer immédiatement, plus robuste que le nom de domaine si celui-ci change.' },

      { id: 'Q9', type: 'number', label: 'Intervalle moyen entre deux balises, en secondes',
        answer: '300',
        hint: 'La détection comportementale de l\'agent donne l\'intervalle moyen et la variation appliquée.',
        where: 'PJ-03, detection « Periodic Beacon To Rare Domain », interval_avg_s.',
        why: 'Cinq minutes avec 9 % de variation : la régularité est ce qui distingue une balise d\'un trafic applicatif, et c\'est détectable sans connaître le domaine.' },

      { id: 'Q10', type: 'number', label: 'Nombre de machines sur lesquelles la bibliothèque malveillante est présente',
        answer: '2',
        hint: 'L\'agent a lancé une recherche sur tout le parc après la détection.',
        where: 'PJ-03, inventory_query du 16 février : results=2.',
        why: 'La recherche rétroactive sur l\'ensemble du parc, à partir d\'un indicateur, est le réflexe qui borne réellement l\'incident.' },

      { id: 'Q11', type: 'datetime', label: 'Horodatage de l\'installation sur le second poste (UTC)',
        answer: '2026-02-10 06:58',
        hint: 'Le second poste n\'a pas téléchargé depuis Internet : regardez d\'où vient le fichier.',
        where: 'PJ-02, msiexec sur PC-SUPERV-02 lancé depuis un partage réseau de PC-SUPERV-01.',
        why: 'La propagation s\'est faite par un partage de fichiers entre collègues, sans aucune action de l\'attaquant : c\'est un mode de diffusion qu\'aucun indicateur réseau n\'aurait révélé.' },

      { id: 'Q12', type: 'choice', label: 'Le réseau de production a-t-il été atteint ?',
        answer: 'Non : les tentatives vers SRV-SCADA-01 ont été refusées par le cloisonnement',
        options: [
          'Oui : le serveur de supervision a été compromis le 12 février',
          'Non : les tentatives vers SRV-SCADA-01 ont été refusées par le cloisonnement',
          'Non : aucune tentative n\'a été faite vers le réseau de production',
          'Indéterminable : le réseau de production n\'est pas journalisé'
        ],
        hint: 'Deux journaux indépendants décrivent la même tentative du 12 février et son issue.',
        where: 'PJ-02 (connection_refused) et PJ-05 (action=DENY policy=BUREAU-VERS-PRODUCTION).',
        why: 'La nuance est décisive pour la direction industrielle : il y a bien eu tentative — donc intention — mais le cloisonnement a tenu. Répondre « aucune tentative » minimiserait le risque et ferait rater la recommandation la plus importante : le cloisonnement est ce qui a évité l\'arrêt de la ligne.' }
    ],

    events: [
      { id: 'EV-01', t: '2026-02-09 08:42', label: 'Téléchargement de l\'installeur depuis un faux miroir' },
      { id: 'EV-02', t: '2026-02-09 08:47', label: 'Installation du paquet signé par un éditeur inattendu' },
      { id: 'EV-03', t: '2026-02-09 08:48', label: 'Chargement latéral d\'une bibliothèque non signée par le binaire légitime' },
      { id: 'EV-04', t: '2026-02-09 08:49', label: 'Création du service PlantWatchSync' },
      { id: 'EV-05', t: '2026-02-09 09:21', label: 'Énumération des groupes du domaine et des approbations' },
      { id: 'EV-06', t: '2026-02-09 09:22', label: 'Première balise vers cdn-telemetry-eu.test' },
      { id: 'EV-07', t: '2026-02-10 06:58', label: 'Installation du même paquet sur le second poste depuis un partage' },
      { id: 'EV-08', t: '2026-02-12 11:04', label: 'Tentative de connexion vers le réseau de production, refusée' },
      { id: 'EV-09', t: '2026-02-16 05:12', label: 'Mise à jour des signatures de l\'agent de sécurité' },
      { id: 'EV-10', t: '2026-02-03 14:10', label: 'Consultation du site officiel de l\'éditeur par un autre utilisateur' },
      { id: 'EV-11', t: '2026-02-16 05:40', label: 'Recherche rétroactive de l\'indicateur sur l\'ensemble du parc' }
    ],

    chain: [
      { tactic: 'Accès initial', event: 'EV-01', technique: 'T1189',
        where: 'PJ-01 (téléchargement) et PJ-04 (première résolution du domaine).',
        why: 'Ce n\'est pas une compromission de la chaîne logicielle de l\'éditeur : l\'éditeur n\'a rien livré de malveillant. C\'est un faux site atteint par un moteur de recherche, donc une compromission par navigation.' },
      { tactic: 'Exécution', event: 'EV-02', technique: 'T1204.002',
        where: 'PJ-02, msiexec lancé par o.karam sur un fichier de son dossier Téléchargements.',
        why: 'L\'exécution est le fait d\'un technicien de bonne foi qui croyait installer une mise à jour attendue.' },
      { tactic: 'Persistance', event: 'EV-04', technique: 'T1543.003',
        where: 'PJ-02, sc create PlantWatchSync start=auto.',
        why: 'Le service redémarre le code à chaque amorçage et porte un nom volontairement proche du produit légitime.' },
      { tactic: 'Élévation de privilèges', event: 'NONE', technique: 'NONE',
        where: 'Aucune : l\'installation a été lancée par un compte disposant déjà des droits d\'installation sur son poste.',
        why: 'Sur un poste de supervision industrielle, les techniciens sont souvent administrateurs locaux. L\'attaquant n\'a eu aucun effort à fournir.' },
      { tactic: 'Contournement des défenses', event: 'EV-03', technique: 'T1553.002', techniqueAlt: ['T1036.005'],
        where: 'PJ-03, verdict « unknown » mais action « allowed » grâce à une signature valide ; PJ-02, module non signé chargé par un binaire signé.',
        why: 'Deux contournements se combinent : une signature valide qui rassure l\'agent de sécurité, et un chargement latéral qui fait porter l\'exécution par un programme légitime.' },
      { tactic: 'Accès aux identifiants', event: 'NONE', technique: 'NONE',
        where: 'Aucun accès à la mémoire du processus d\'authentification, aucun export de ruche, aucun outil de collecte.',
        why: 'L\'opérateur en était encore à la phase de reconnaissance quand la détection est tombée.' },
      { tactic: 'Découverte', event: 'EV-05', technique: 'T1069.002', techniqueAlt: ['T1482', 'T1087.002'],
        where: 'PJ-02, whoami /groups, net group "Domain Admins", nltest /domain_trusts.',
        why: 'Trois commandes en une minute, lancées par le binaire de supervision : c\'est la signature d\'un opérateur humain qui prend ses repères.' },
      { tactic: 'Déplacement latéral', event: 'NONE', technique: 'NONE',
        where: 'PJ-02 et PJ-05 : les deux tentatives vers SRV-SCADA-01 sont refusées, aucune session n\'est ouverte.',
        why: 'Une tentative échouée n\'est pas un déplacement. La distinction est ce qui permet de dire à la direction que la production n\'a pas été atteinte — et l\'installation du second poste est le fait d\'un collègue, pas de l\'attaquant.' },
      { tactic: 'Collecte', event: 'NONE', technique: 'NONE',
        where: 'Aucun archivage, aucune lecture massive de fichiers.',
        why: 'Cohérent avec la chronologie : sept jours de présence, dont l\'essentiel en attente.' },
      { tactic: 'Commande et contrôle', event: 'EV-06', technique: 'T1071.001', techniqueAlt: ['T1102'],
        where: 'PJ-01, PJ-03 et PJ-04 : POST réguliers vers cdn-telemetry-eu.test, intervalle moyen de 300 secondes.',
        why: 'Le canal est en HTTPS vers un domaine d\'apparence anodine : seule la régularité le trahit.' },
      { tactic: 'Exfiltration', event: 'NONE', technique: 'NONE',
        where: 'PJ-05, synthèse de volumétrie : 1,6 Mo sortants en sept jours sur 1 904 sessions, soit la taille des balises elles-mêmes.',
        why: 'Le calcul est à faire explicitement : 1 904 sessions pour 1,6 Mo donnent 840 octets par session. Il n\'y a pas la place pour un document dans ce volume.' },
      { tactic: 'Impact', event: 'NONE', technique: 'NONE',
        where: 'Aucune altération, aucun chiffrement, aucun arrêt de service.',
        why: 'L\'incident a été traité avant toute conséquence : c\'est le résultat d\'une mise à jour de signatures, pas d\'une détection comportementale. Cette nuance mérite de figurer au rapport.' }
    ],

    keyIndicators: ['updates-plantwatch.test', 'cdn-telemetry-eu.test', '203.0.113.88', 'mscoree.dll', 'PlantWatchSync', 'Norvik Systems AB', 'o.karam'],

    iocs: [
      { type: 'Domaine', value: 'updates-plantwatch.test', context: 'Faux miroir de téléchargement, enregistré dix-sept jours avant l\'incident.' },
      { type: 'Domaine', value: 'cdn-telemetry-eu.test', context: 'Commande et contrôle, balise toutes les 300 secondes avec 9 % de variation.' },
      { type: 'Adresse IP', value: '203.0.113.88', context: 'Résolution du domaine de commande et contrôle.' },
      { type: 'Empreinte SHA-256', value: '5608c0368c3e19e5f1c88c419c16adf5b47c72093bfb9960bbf63935fac163f4', context: 'Installeur PlantWatch_4.2.1_setup.msi signé « Norvik Systems AB ».' },
      { type: 'Empreinte SHA-256', value: 'd1924b371887a63c024ffb04d13717b4da76c5e2ccf6d47ffbffc3a9b5c159eb', context: 'Bibliothèque mscoree.dll chargée latéralement, non signée.' },
      { type: 'Service', value: 'PlantWatchSync', context: 'Service de persistance imitant le nom du produit légitime.' },
      { type: 'Certificat', value: 'Norvik Systems AB', context: 'Signataire du paquet, sans lien avec l\'éditeur PlantWatch Industrial AB.' }
    ],

    debrief: {
      story: 'Le 9 février à 08h41, un technicien de supervision cherche la mise à jour 4.2 de son outil dans un moteur de recherche. Il atterrit sur updates-plantwatch.test — inversion des deux mots du domaine officiel plantwatch-updates.example — enregistré dix-sept jours plus tôt, et télécharge un installeur de 48 Mo. Le paquet est signé, la signature est valide, mais au nom de « Norvik Systems AB ». L\'agent de sécurité relève un éditeur inconnu du parc et laisse passer. L\'installation dépose le vrai binaire PlantWatch et une bibliothèque mscoree.dll non signée, chargée latéralement par le binaire légitime. Un service PlantWatchSync est créé. Trente minutes plus tard, une reconnaissance d\'annuaire est lancée, puis une balise part toutes les cinq minutes vers cdn-telemetry-eu.test. Le lendemain, un collègue installe le même paquet depuis un partage réseau : deuxième poste touché, sans intervention de l\'attaquant. Le 12 février, deux tentatives vers le serveur de supervision de production sont refusées par le cloisonnement réseau. Le 16, une mise à jour de signatures reconnaît enfin le chargement latéral, sept jours après les faits.',
      lessons: [
        'Une signature numérique valide ne dit pas que le logiciel est légitime : elle dit que le fichier n\'a pas été altéré depuis sa signature. Comparer le signataire à l\'éditeur attendu est le contrôle qui manquait.',
        'Le calcul de volumétrie tranche la question de l\'exfiltration : 1 904 sessions pour 1,6 Mo sortants, soit 840 octets par échange. Aucun document n\'est passé. C\'est une démonstration arithmétique, pas une impression.',
        'La propagation au second poste n\'est pas un déplacement latéral : c\'est un collègue qui a recopié un installeur depuis un partage. Les incidents se propagent aussi par entraide, et aucun indicateur réseau ne le montre.',
        'La détection est venue d\'une mise à jour de signatures, sept jours après. Le comportement — balise régulière vers un domaine récent, module non signé chargé par un binaire signé — était pourtant journalisé dès le premier jour. C\'est la recommandation centrale du rapport.'
      ],
      pitfalls: [
        'Qualifier l\'incident de compromission de la chaîne logicielle : l\'éditeur n\'est pas en cause, c\'est un faux site atteint par un moteur de recherche.',
        'Conclure à une compromission du réseau de production parce que des connexions vers SRV-SCADA-01 apparaissent : elles sont toutes refusées, dans deux journaux distincts.',
        'Compter un seul poste touché en s\'arrêtant au poste d\'origine, ou trois en confondant la tentative vers le serveur de production avec une installation.',
        'Annoncer une exfiltration parce qu\'il y a du trafic sortant régulier, sans regarder le volume.'
      ]
    }
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
