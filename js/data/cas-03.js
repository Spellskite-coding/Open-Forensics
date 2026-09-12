/* Open-Forensics — CAS-03. AVERTISSEMENT : contient les réponses attendues. */
(function (root) {
  'use strict';

  root.OpenForensics.cases.push({
    id: 'CAS-03',
    title: 'Fuite de plans avant un départ',
    client: 'Atelier Roncier — bureau d\'études mécaniques, 58 salariés',
    difficulty: 'facile',
    estimatedMin: 40,
    tags: ['menace interne', 'exfiltration', 'média amovible'],

    env: {
      domain: 'RONCIER', dns: 'roncier.lan', mail: 'atelier-roncier.example',
      lan: '10.8.1', edge: '198.51.100.31',
      hosts: ['PC-BE-11', 'PC-BE-14', 'PC-RH-02', 'PC-ADV-05', 'SRV-FIC-02', 'SRV-AD-02'],
      users: ['c.brevet', 'm.tissot', 'l.fabre', 'y.nadal', 'r.jomier'],
      admins: ['adm_roncier']
    },

    brief: {
      saisine: 'Lundi 8 juin 2026. Un concurrent a répondu à un appel d\'offres avec une solution techniquement identique à un projet confidentiel du bureau d\'études. Un ingénieur, c.brevet, a démissionné le 2 juin et rejoint ce concurrent. La direction demande si des documents sont sortis, lesquels, et par quel moyen.',
      perimetre: 'Serveur de fichiers avec audit d\'accès aux objets activé depuis deux ans, agent de sécurité sur tous les postes avec journalisation des médias amovibles, mandataire web avec inspection et catégorisation.',
      collecte: 'Journaux du serveur de fichiers, de l\'agent de sécurité, du mandataire web et de la fédération d\'identité, du 25 mai au 8 juin. Horodatages en UTC.',
      limites: 'La clé USB elle-même n\'a pas été saisie : on ne pourra pas dire ce qu\'elle contient aujourd\'hui, seulement ce qui y a été écrit. Les journaux du poste PC-BE-11 antérieurs au 25 mai ont été purgés par la rotation locale.',
      mission: 'Établir ce qui est sorti, par quels canaux, et à quelles dates. La direction envisage une action prud\'homale : les constatations doivent être factuelles, datées et rattachées à un compte, sans surinterprétation.'
    },

    evidence: [
      {
        id: 'PJ-01', source: 'journaux', system: 'SRV-FIC-02',
        title: 'Audit d\'accès aux fichiers — serveur de fichiers',
        note: 'Audit d\'objet Windows (5145 et 4663) sur le partage Projets. Volumineux par nature : filtrez par compte ou par partage.',
        lines: [
          { t: '2026-05-29 09:14:22', m: 'EventCode=5145 Share_Name=\\\\*\\Projets Relative_Target=Aubade\\plans\\ Account_Name=c.brevet Source_Address=10.8.1.61 Access=ReadData note="acces habituel en journee"' },
          { t: '2026-06-01 18:52:10', m: 'EventCode=5145 Share_Name=\\\\*\\Projets Relative_Target=Aubade\\plans\\ Account_Name=c.brevet Source_Address=10.8.1.61 Access=ReadData,ListDirectory' },
          { t: '2026-06-01 19:41:58', m: 'EventCode=4663 Object_Name=E:\\Projets\\Aubade\\plans\\ENS-AUBADE-001.step Account_Name=c.brevet Accesses=ReadData Process=explorer.exe Source_Address=10.8.1.61' },
          { t: '2026-06-01 19:42:03', m: 'EventCode=4663 Object_Name=E:\\Projets\\Aubade\\plans\\ENS-AUBADE-002.step Account_Name=c.brevet Accesses=ReadData Process=explorer.exe Source_Address=10.8.1.61' },
          { t: '2026-06-01 19:42:09', m: 'EventCode=4663 Object_Name=E:\\Projets\\Aubade\\calculs\\note_dimensionnement_v7.xlsx Account_Name=c.brevet Accesses=ReadData Process=explorer.exe Source_Address=10.8.1.61' },
          { t: '2026-06-01 20:07:44', m: 'EventCode=5145 Share_Name=\\\\*\\Projets Relative_Target=Aubade\\ Account_Name=c.brevet Source_Address=10.8.1.61 Access=ReadData files_read_session=412 bytes_read=1932744192 note="compteur de session agrege par le collecteur"' },
          { t: '2026-06-02 08:31:19', m: 'EventCode=5145 Share_Name=\\\\*\\RH Relative_Target=Dossiers\\m.tissot\\ Account_Name=m.tissot Source_Address=10.8.1.74 Access=ReadData files_read_session=11 bytes_read=4210221' },
          { t: '2026-06-03 10:02:55', m: 'EventCode=5145 Share_Name=\\\\*\\Projets Relative_Target=Aubade\\ Account_Name=l.fabre Source_Address=10.8.1.58 Access=ReadData files_read_session=27 bytes_read=88210331 note="revue de conception planifiee"' }
        ],
        noise: [{ family: 'win-security', count: 260, from: '2026-05-25 06:00:00', to: '2026-06-08 19:00:00' }]
      },
      {
        id: 'PJ-02', source: 'journaux', system: 'Console EDR',
        title: 'Journal de l\'agent de sécurité — médias amovibles et processus',
        note: 'La journalisation des médias amovibles enregistre le numéro de série du volume et le volume de données écrites.',
        lines: [
          { t: '2026-06-01 19:38:41', m: 'usb_device host=PC-BE-11 user=RONCIER\\c.brevet action=connected vendor=SanDisk product="Ultra Fit" serial=4C530001120607118203 capacity_gb=128' },
          { t: '2026-06-01 19:41:55', m: 'usb_write host=PC-BE-11 user=RONCIER\\c.brevet serial=4C530001120607118203 files=412 bytes=1932744192 source_path=E:\\Projets\\Aubade top_extensions=.step,.xlsx,.pdf,.dwg' },
          { t: '2026-06-01 20:09:12', m: 'usb_device host=PC-BE-11 user=RONCIER\\c.brevet action=disconnected serial=4C530001120607118203 session_duration_s=1831' },
          { t: '2026-06-02 08:29:03', m: 'usb_device host=PC-RH-02 user=RONCIER\\m.tissot action=connected vendor=Kingston product="DataTraveler" serial=0016CD8B2A19F3 capacity_gb=32' },
          { t: '2026-06-02 08:33:40', m: 'usb_write host=PC-RH-02 user=RONCIER\\m.tissot serial=0016CD8B2A19F3 files=11 bytes=4210221 source_path=E:\\RH\\Dossiers\\m.tissot top_extensions=.pdf note="documents personnels de l agent"' },
          { t: '2026-06-02 08:41:02', m: 'usb_device host=PC-RH-02 user=RONCIER\\m.tissot action=disconnected serial=0016CD8B2A19F3' },
          { t: '2026-06-01 21:14:30', m: 'process host=PC-BE-11 user=RONCIER\\c.brevet image=C:\\Program Files\\7-Zip\\7z.exe cmdline="7z a -tzip -mx1 C:\\Users\\c.brevet\\Documents\\archive_perso.zip E:\\Projets\\Aubade" result=completed output_bytes=1711276032' }
        ],
        noise: [{ family: 'edr', count: 180, from: '2026-05-25 06:00:00', to: '2026-06-08 19:00:00' }]
      },
      {
        id: 'PJ-03', source: 'reseau', system: 'Mandataire web',
        title: 'Journal du mandataire web',
        note: 'Inspection et catégorisation actives. Le volume téléversé est journalisé séparément du volume téléchargé.',
        lines: [
          { t: '2026-06-01 21:22:08', m: 'user=c.brevet src=10.8.1.61 action=ALLOW method=GET url=https://partage-fichiers-perso.test/ status=200 bytes_in=18402 category=stockage_en_ligne note="categorie autorisee par la politique actuelle"' },
          { t: '2026-06-01 21:26:41', m: 'user=c.brevet src=10.8.1.61 action=ALLOW method=POST url=https://partage-fichiers-perso.test/api/upload status=201 bytes_out=1711276032 bytes_in=412 duration_s=742 filename="archive_perso.zip"' },
          { t: '2026-06-01 21:39:55', m: 'user=c.brevet src=10.8.1.61 action=ALLOW method=GET url=https://partage-fichiers-perso.test/l/9f2ac1 status=200 bytes_in=8210 note="consultation du lien de partage genere"' },
          { t: '2026-06-04 12:11:02', m: 'user=l.fabre src=10.8.1.58 action=BLOCK method=POST url=https://transfert-gros-fichiers.example/upload status=403 category=stockage_en_ligne policy=volume_max_depasse' }
        ],
        noise: [{ family: 'proxy', count: 300, from: '2026-05-25 06:00:00', to: '2026-06-08 19:00:00' }]
      },
      {
        id: 'PJ-04', source: 'cloud', system: 'Fédération d\'identité',
        title: 'Journal d\'authentification et d\'accès applicatif',
        note: 'Permet de situer les personnes : poste utilisé, horaires de connexion, applications ouvertes.',
        lines: [
          { t: '2026-06-01 18:44:12', m: 'event=auth_success user=c.brevet@atelier-roncier.example src_ip=10.8.1.61 device=PC-BE-11 mfa=device_compliant app=Bureau note="connexion un dimanche soir"' },
          { t: '2026-06-01 21:45:30', m: 'event=session_end user=c.brevet@atelier-roncier.example device=PC-BE-11 duration_s=11238' },
          { t: '2026-06-02 07:58:44', m: 'event=auth_success user=c.brevet@atelier-roncier.example src_ip=10.8.1.61 device=PC-BE-11 mfa=device_compliant app=Messagerie' },
          { t: '2026-06-02 09:12:00', m: 'event=account_disabled user=c.brevet@atelier-roncier.example actor=adm_roncier reason="depart de l entreprise"' }
        ],
        noise: [{ family: 'idp', count: 240, from: '2026-05-25 06:00:00', to: '2026-06-08 19:00:00' }]
      }
    ],

    questions: [
      { id: 'Q1', type: 'text', label: 'Compte à l\'origine de la copie massive de documents projet',
        answer: 'c.brevet',
        hint: 'Cherchez dans l\'audit du serveur de fichiers une session dont le compteur de fichiers lus dépasse la centaine.',
        where: 'PJ-01, ligne du 1er juin 20:07 (412 fichiers), confirmée par PJ-02.',
        why: 'Le rattachement à un compte nommé, daté et horodaté est la base de toute suite disciplinaire ou judiciaire.' },

      { id: 'Q2', type: 'number', label: 'Nombre de fichiers copiés sur le média amovible',
        answer: '412',
        hint: 'Le journal de l\'agent de sécurité donne un décompte exact lors de l\'écriture sur la clé.',
        where: 'PJ-02, ligne usb_write du 1er juin 19:41:55 — le même nombre apparaît dans PJ-01.',
        why: 'Le décompte issu de deux journaux indépendants qui concordent vaut bien mieux qu\'une estimation : c\'est ce qui rend la constatation opposable.' },

      { id: 'Q3', type: 'text', label: 'Numéro de série du média amovible utilisé',
        answer: '4C530001120607118203',
        hint: 'Deux clés apparaissent dans la période. Retenez celle branchée sur PC-BE-11.',
        where: 'PJ-02, évènement usb_device connected du 1er juin 19:38.',
        why: 'Le numéro de série permet de demander la restitution d\'un objet précis et de le rattacher aux écritures constatées.' },

      { id: 'Q4', type: 'datetime', label: 'Horodatage du branchement de cette clé (UTC)',
        answer: '2026-06-01 19:38',
        hint: 'L\'évènement « connected » précède de trois minutes l\'écriture.',
        where: 'PJ-02, première ligne du dossier.',
        why: 'Un dimanche soir à 19h38 : le contexte horaire pèse autant que le volume dans la démonstration de l\'intention.' },

      { id: 'Q5', type: 'text', label: 'Nom du projet dont les documents ont été copiés',
        answer: 'Aubade',
        hint: 'Le chemin source de la copie et les accès fichiers désignent le même répertoire.',
        where: 'PJ-01 (Relative_Target=Aubade) et PJ-02 (source_path=E:\\Projets\\Aubade).',
        why: 'Identifier précisément le périmètre des documents sortis conditionne l\'évaluation du préjudice.' },

      { id: 'Q6', type: 'domain', label: 'Service en ligne utilisé pour le second canal de sortie',
        answer: 'partage-fichiers-perso.test',
        hint: 'Le mandataire journalise un volume sortant très supérieur à la normale le même soir.',
        where: 'PJ-03, POST du 1er juin à 21:26 avec bytes_out=1711276032.',
        why: 'Deux canaux ont été utilisés le même soir. S\'arrêter au premier aurait sous-estimé la fuite et raté la preuve la plus facile à obtenir auprès d\'un hébergeur.' },

      { id: 'Q7', type: 'text', label: 'Nom de l\'archive téléversée',
        answer: 'archive_perso.zip',
        hint: 'Le nom apparaît deux fois : à la création de l\'archive et lors du téléversement.',
        where: 'PJ-02 (commande 7z) et PJ-03 (paramètre filename).',
        why: 'Le nom choisi — « perso » — sera opposé à l\'intéressé : il désigne des documents de l\'entreprise.' },

      { id: 'Q8', type: 'text', label: 'Utilitaire employé pour compresser les documents avant envoi',
        answer: '7z', alt: ['7z.exe', '7-zip', '7zip'],
        hint: 'Un processus a produit une sortie de 1,7 Go à 21h14.',
        where: 'PJ-02, ligne process du 1er juin 21:14:30.',
        why: 'La compression préalable est l\'étape qui distingue une copie de travail d\'une préparation d\'exfiltration.' },

      { id: 'Q9', type: 'choice', label: 'Le second utilisateur ayant branché une clé USB est-il impliqué ?',
        answer: 'Non : les fichiers copiés sont ses propres documents administratifs',
        options: [
          'Oui : il a copié des documents du projet Aubade',
          'Non : les fichiers copiés sont ses propres documents administratifs',
          'Indéterminable : le journal ne dit pas ce qui a été copié',
          'Oui : il a téléversé une archive vers le même service'
        ],
        hint: 'Comparez le chemin source et le volume des deux écritures sur clé.',
        where: 'PJ-02 : m.tissot écrit 11 fichiers PDF depuis E:\\RH\\Dossiers\\m.tissot, soit 4 Mo, confirmé par l\'audit du partage RH dans PJ-01.',
        why: 'Un dossier de menace interne produit toujours des faux positifs de contexte. Mettre en cause un salarié qui récupérait ses bulletins de paie détruirait la crédibilité du rapport et exposerait le client.' },

      { id: 'Q10', type: 'choice', label: 'Quel canal a fait sortir le plus grand volume de données ?',
        answer: 'La clé USB, avec environ 1,93 Go contre 1,71 Go téléversés',
        options: [
          'Le téléversement en ligne, avec 1,71 Go',
          'La clé USB, avec environ 1,93 Go contre 1,71 Go téléversés',
          'Les deux canaux ont transporté exactement le même volume',
          'La messagerie, en pièces jointes'
        ],
        hint: 'Comparez bytes de l\'écriture USB et bytes_out du téléversement.',
        where: 'PJ-02 (1 932 744 192 octets) et PJ-03 (1 711 276 032 octets).',
        why: 'L\'écart s\'explique par la compression : ce sont les mêmes documents, sortis deux fois. Le dire évite de doubler artificiellement l\'estimation du préjudice.' }
    ],

    events: [
      { id: 'EV-01', t: '2026-06-01 18:44', label: 'Connexion de c.brevet un dimanche soir depuis son poste' },
      { id: 'EV-02', t: '2026-06-01 19:38', label: 'Branchement d\'une clé USB de 128 Go sur PC-BE-11' },
      { id: 'EV-03', t: '2026-06-01 19:41', label: 'Copie de 412 fichiers du projet Aubade vers la clé' },
      { id: 'EV-04', t: '2026-06-01 21:14', label: 'Compression du répertoire projet en archive_perso.zip' },
      { id: 'EV-05', t: '2026-06-01 21:26', label: 'Téléversement de 1,71 Go vers un service de partage personnel' },
      { id: 'EV-06', t: '2026-06-02 08:29', label: 'Branchement d\'une clé USB sur le poste des ressources humaines' },
      { id: 'EV-07', t: '2026-06-02 09:12', label: 'Désactivation du compte de c.brevet à son départ' },
      { id: 'EV-08', t: '2026-06-03 10:02', label: 'Consultation du projet Aubade par l.fabre en revue de conception' },
      { id: 'EV-09', t: '2026-06-04 12:11', label: 'Téléversement bloqué par la politique du mandataire' },
      { id: 'EV-10', t: '2026-06-01 18:52', label: 'Listage du répertoire du projet Aubade sur le partage' }
    ],

    chain: [
      { tactic: 'Accès initial', event: 'NONE', technique: 'NONE',
        where: 'Aucun accès frauduleux : l\'intéressé disposait légitimement de ses habilitations sur le partage Projets.',
        why: 'C\'est la caractéristique de la menace interne : il n\'y a rien à trouver côté accès initial, et chercher une intrusion fait perdre le fil. Ce qui est fautif, c\'est l\'usage, pas l\'accès.' },
      { tactic: 'Exécution', event: 'NONE', technique: 'NONE',
        where: 'Aucun code de l\'attaquant : le seul binaire lancé est 7-Zip, un outil légitime installé par l\'entreprise.',
        why: 'Piège de mappage classique : compresser des fichiers avant de les sortir relève de la Collecte, pas de l\'Exécution. Aucun code étranger n\'a tourné sur ce poste.' },
      { tactic: 'Persistance', event: 'NONE', technique: 'NONE',
        where: 'Aucun mécanisme : l\'intéressé savait qu\'il partait le lendemain.',
        why: 'Le calendrier remplace la persistance. La veille d\'un départ est une fenêtre de risque connue, et rarement surveillée.' },
      { tactic: 'Élévation de privilèges', event: 'NONE', technique: 'NONE',
        where: 'Aucune : les droits en lecture sur le projet faisaient partie de ses fonctions.',
        why: 'Un rapport qui invoquerait une élévation de privilèges serait démonté en une question à l\'audience.' },
      { tactic: 'Contournement des défenses', event: 'NONE', technique: 'NONE',
        where: 'Aucune tentative de dissimulation : ni effacement de journaux, ni contournement du mandataire, ni renommage.',
        why: 'L\'absence de dissimulation est un fait à consigner : elle traduit la conviction d\'agir sans être observé, ce qui renseigne autant sur le climat interne que sur l\'intention.' },
      { tactic: 'Accès aux identifiants', event: 'NONE', technique: 'NONE',
        where: 'Aucune trace.',
        why: 'Rien à démontrer ici : c\'est une conclusion en soi.' },
      { tactic: 'Découverte', event: 'EV-10', technique: 'T1083',
        where: 'PJ-01, listage du répertoire Aubade à 18:52, soit quarante-six minutes avant la copie.',
        why: 'Une reconnaissance minimale subsiste malgré tout : l\'intéressé a parcouru l\'arborescence avant de copier, ce qui situe le moment où la décision est prise.' },
      { tactic: 'Déplacement latéral', event: 'NONE', technique: 'NONE',
        where: 'Aucun accès à une autre machine que son poste.',
        why: 'Le périmètre est resté strictement celui de son poste de travail et du partage projet.' },
      { tactic: 'Collecte', event: 'EV-04', technique: 'T1560.001', techniqueAlt: ['T1039', 'T1005'],
        where: 'PJ-02, compression du répertoire projet à 21:14, précédée de la lecture de 412 fichiers sur le partage (PJ-01).',
        why: 'La collecte se lit dans l\'audit du serveur de fichiers, la sortie dans le journal de l\'agent : deux sources, deux moments, une même action.' },
      { tactic: 'Commande et contrôle', event: 'NONE', technique: 'NONE',
        where: 'Aucun canal : il n\'y a pas d\'attaquant distant dans ce dossier.',
        why: 'Rappel salutaire : toutes les compromissions n\'ont pas d\'opérateur extérieur.' },
      { tactic: 'Exfiltration', event: 'EV-05', technique: 'T1567.002', techniqueAlt: ['T1052.001'],
        where: 'PJ-03, POST de 1,71 Go vers partage-fichiers-perso.test à 21:26.',
        why: 'Deux canaux coexistent — média amovible et service en ligne. Retenir l\'un des deux est acceptable, ignorer le second ne l\'est pas : c\'est celui sur lequel une réquisition auprès de l\'hébergeur est possible.' },
      { tactic: 'Impact', event: 'NONE', technique: 'NONE',
        where: 'Aucune destruction, aucun chiffrement, aucune altération : les documents sont intacts sur le serveur.',
        why: 'Le préjudice est concurrentiel, pas technique. Le distinguer évite de facturer au client une remise en service qui n\'a pas lieu d\'être.' }
    ],

    keyIndicators: ['c.brevet', '4C530001120607118203', 'partage-fichiers-perso.test', 'archive_perso.zip', 'Aubade', '412'],

    iocs: [
      { type: 'Compte', value: 'c.brevet', context: 'Auteur des copies, compte désactivé le 2 juin à son départ.' },
      { type: 'Numéro de série', value: '4C530001120607118203', context: 'Clé USB SanDisk 128 Go ayant reçu 412 fichiers du projet Aubade.' },
      { type: 'Domaine', value: 'partage-fichiers-perso.test', context: 'Service de partage personnel ayant reçu une archive de 1,71 Go.' },
      { type: 'Nom de fichier', value: 'archive_perso.zip', context: 'Archive du répertoire projet, téléversée le 1er juin à 21:26.' },
      { type: 'Comportement', value: 'Écriture massive sur média amovible hors heures ouvrées', context: 'Motif de détection à mettre en place : plus de 100 fichiers projet écrits sur un média amovible.' }
    ],

    debrief: {
      story: 'Le dimanche 1er juin, veille de sa démission, c.brevet se connecte à 18h44 depuis son poste. À 19h38 il branche une clé USB SanDisk de 128 Go, et copie en vingt-cinq minutes 412 fichiers du projet confidentiel Aubade, soit 1,93 Go de plans, de calculs et de notes. À 21h14 il compresse le même répertoire avec 7-Zip sous le nom archive_perso.zip, puis téléverse les 1,71 Go obtenus vers un service de partage personnel à 21h26. Il se déconnecte à 21h45. Le lendemain matin il vient travailler normalement, et son compte est désactivé à 09h12 lors de son départ. Aucune intrusion, aucun code malveillant, aucune élévation de privilèges : un salarié habilité a utilisé ses accès légitimes, la veille de son départ, sur deux canaux successifs.',
      lessons: [
        'La menace interne ne se lit pas dans les mêmes journaux qu\'une intrusion. Ici, tout tient dans trois sources : l\'audit d\'accès aux fichiers, la journalisation des médias amovibles et le volume sortant du mandataire. Aucune n\'aurait suffi seule.',
        'Deux journaux indépendants qui donnent le même chiffre — 412 fichiers, 1,93 Go — valent infiniment mieux qu\'une estimation. Dans un dossier destiné à une juridiction, la concordance est la démonstration.',
        'Le second canal est celui qu\'on oublie. La clé USB saute aux yeux, le téléversement de 21h26 passe inaperçu dans un journal de mandataire. C\'est pourtant sur l\'hébergeur qu\'une réquisition judiciaire est possible.',
        'Un dossier de menace interne produit toujours un faux positif de contexte : ici, une salariée qui récupère ses propres documents administratifs sur une clé. Le rapport doit l\'écarter explicitement, sans quoi c\'est la crédibilité de l\'ensemble qui tombe.'
      ],
      pitfalls: [
        'Mettre en cause m.tissot parce qu\'elle a branché une clé le lendemain : le chemin source et le volume la disculpent en une ligne.',
        'Additionner 1,93 Go et 1,71 Go pour annoncer 3,6 Go sortis : ce sont les mêmes documents, sortis deux fois, l\'un compressé.',
        'Conclure à un accès initial ou à une élévation de privilèges alors que l\'intéressé était habilité : c\'est l\'usage qui est fautif, pas l\'accès.',
        'Oublier de dater précisément le branchement de la clé : sans horodatage, la constatation perd sa valeur probante.'
      ]
    }
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
