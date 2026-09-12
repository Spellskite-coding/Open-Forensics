/* Open-Forensics — CAS-02. AVERTISSEMENT : contient les réponses attendues. */
(function (root) {
  'use strict';

  root.OpenForensics.cases.push({
    id: 'CAS-02',
    title: 'Virement détourné après vol de session',
    client: 'Vasseur & Associés — cabinet d\'avocats, 34 collaborateurs',
    difficulty: 'facile',
    estimatedMin: 45,
    tags: ['fraude au virement', 'hameçonnage', 'messagerie'],

    env: {
      domain: 'VASSEUR', dns: 'vasseur.lan', mail: 'cabinet-vasseur.example',
      lan: '10.30.2', edge: '198.51.100.12',
      hosts: ['PC-SECR-01', 'PC-ASSOC-03', 'PC-COMPTA-01', 'PC-JUR-05', 'SRV-FIC-01'],
      users: ['p.vasseur', 'n.rouault', 'k.amrani', 'f.leduc', 'c.morin'],
      admins: ['adm_cabinet']
    },

    brief: {
      saisine: 'Vendredi 17 avril 2026. Le cabinet a viré 48 200 € sur le compte d\'un fournisseur habituel. Le fournisseur réclame son paiement dix jours plus tard : l\'argent n\'est jamais arrivé. La banque confirme que le virement est parti vers un IBAN qui n\'est pas celui du fournisseur.',
      perimetre: 'Messagerie hébergée chez un prestataire, authentification fédérée avec notification sur téléphone. Cinq postes bureautiques, un serveur de fichiers.',
      collecte: 'Journaux de la passerelle de messagerie, de la fédération d\'identité et de l\'audit de la plateforme collaborative, sur trente jours. Journaux du mandataire web sur quinze jours. Horodatages en UTC.',
      limites: 'Aucun journal côté poste de travail : le client ne dispose ni de Sysmon ni d\'agent de sécurité. Impossible donc d\'affirmer qu\'un code a été exécuté sur une machine — il faudra déterminer si l\'attaque en avait besoin.',
      mission: 'Déterminer par où l\'attaquant est entré, depuis quand il était présent, ce qu\'il a vu, et si d\'autres comptes du cabinet sont concernés. Le cabinet doit aussi savoir s\'il y a eu accès à des données couvertes par le secret professionnel.'
    },

    evidence: [
      {
        id: 'PJ-01', source: 'messagerie', system: 'Passerelle de messagerie',
        title: 'Journal de la passerelle de messagerie',
        note: 'Trente jours de conservation. Les verdicts antipourriel et les résultats SPF/DKIM figurent sur chaque ligne.',
        lines: [
          { t: '2026-04-07 07:12:40', m: 'queue=8f21ac from=notifications@portail-vasseur-connexion.test to=n.rouault@cabinet-vasseur.example subject="Action requise : votre espace de signature expire" spf=pass dkim=none dmarc=none verdict=delivered_to_inbox note="domaine enregistre il y a 3 jours"' },
          { t: '2026-04-07 07:12:41', m: 'queue=8f21ad from=notifications@portail-vasseur-connexion.test to=p.vasseur@cabinet-vasseur.example subject="Action requise : votre espace de signature expire" spf=pass dkim=none dmarc=none verdict=quarantined reason=newly_seen_domain' },
          { t: '2026-04-07 07:12:41', m: 'queue=8f21ae from=notifications@portail-vasseur-connexion.test to=c.morin@cabinet-vasseur.example subject="Action requise : votre espace de signature expire" spf=pass dkim=none dmarc=none verdict=quarantined reason=newly_seen_domain' },
          { t: '2026-04-16 15:41:02', m: 'queue=b7e004 from=n.rouault@cabinet-vasseur.example to=k.amrani@cabinet-vasseur.example subject="RE: Facture FA-2026-0412 - coordonnees bancaires" client_ip=203.0.113.44 verdict=delivered note="reponse dans un fil existant"' },
          { t: '2026-04-16 15:41:03', m: 'queue=b7e004 attachment="FA-2026-0412-rectificatif.pdf" size=184220 sha256=eecf3832ae53a792101106b0b09849a2c3cfab83d727a2083c742826587c314d scan=clean note="document bureautique sans macro"' },
          { t: '2026-04-16 16:02:55', m: 'queue=b7e0f1 from=k.amrani@cabinet-vasseur.example to=n.rouault@cabinet-vasseur.example subject="RE: Facture FA-2026-0412 - coordonnees bancaires" client_ip=10.30.2.41 verdict=delivered' },
          { t: '2026-04-16 16:19:30', m: 'queue=b7e13a from=n.rouault@cabinet-vasseur.example to=k.amrani@cabinet-vasseur.example subject="RE: Facture FA-2026-0412 - coordonnees bancaires" client_ip=203.0.113.44 verdict=delivered' },
          { t: '2026-04-27 09:04:12', m: 'queue=c9a201 from=comptabilite@fournisseur-papeterie.example to=k.amrani@cabinet-vasseur.example subject="Relance impayee FA-2026-0412" spf=pass dkim=pass verdict=delivered' }
        ],
        noise: [{ family: 'mta', count: 220, from: '2026-04-01 06:00:00', to: '2026-04-28 19:00:00' }]
      },
      {
        id: 'PJ-02', source: 'cloud', system: 'Fédération d\'identité',
        title: 'Journal d\'authentification de la fédération',
        note: 'Toutes les authentifications aux services du cabinet passent par cette fédération. Le champ « session_id » suit une session jusqu\'à sa révocation.',
        lines: [
          { t: '2026-04-07 07:19:58', m: 'event=auth_success user=n.rouault@cabinet-vasseur.example src_ip=10.30.2.18 device=PC-SECR-01 mfa=push_approved app=Messagerie session_id=7c19aa' },
          { t: '2026-04-07 07:20:44', m: 'event=auth_success user=n.rouault@cabinet-vasseur.example src_ip=203.0.113.44 asn=AS64520 geo=NL device=unknown user_agent="Mozilla/5.0 (X11; Linux x86_64)" mfa=not_required reason=existing_session_token session_id=7c19aa note="meme identifiant de session que la connexion interne"' },
          { t: '2026-04-08 06:52:11', m: 'event=token_refresh user=n.rouault@cabinet-vasseur.example src_ip=203.0.113.44 session_id=7c19aa result=Succeeded' },
          { t: '2026-04-11 21:33:07', m: 'event=token_refresh user=n.rouault@cabinet-vasseur.example src_ip=203.0.113.44 session_id=7c19aa result=Succeeded' },
          { t: '2026-04-16 15:38:20', m: 'event=token_refresh user=n.rouault@cabinet-vasseur.example src_ip=203.0.113.44 session_id=7c19aa result=Succeeded' },
          { t: '2026-04-21 08:10:02', m: 'event=token_expired user=n.rouault@cabinet-vasseur.example session_id=7c19aa reason=max_lifetime' },
          { t: '2026-04-21 08:11:44', m: 'event=auth_failure user=n.rouault@cabinet-vasseur.example src_ip=203.0.113.44 reason=mfa_denied_by_user attempt=1' },
          { t: '2026-04-21 08:12:09', m: 'event=auth_failure user=p.vasseur@cabinet-vasseur.example src_ip=203.0.113.44 reason=invalid_password attempt=1' }
        ],
        noise: [{ family: 'idp', count: 260, from: '2026-04-01 06:00:00', to: '2026-04-28 19:00:00' }]
      },
      {
        id: 'PJ-03', source: 'cloud', system: 'Plateforme collaborative',
        title: 'Journal d\'audit de la plateforme collaborative',
        note: 'Audit unifié : opérations sur les boîtes aux lettres et sur les espaces documentaires.',
        lines: [
          { t: '2026-04-07 07:23:16', m: 'operation=New-InboxRule user=n.rouault client_ip=203.0.113.44 rule_name="Archive-Sync" conditions="subject or body contains: facture, RIB, IBAN, virement" actions="MoveToFolder: Flux RSS; MarkAsRead: true" result=Succeeded' },
          { t: '2026-04-07 07:24:02', m: 'operation=MailItemsAccessed user=n.rouault client_ip=203.0.113.44 folder=Boite de reception item_count=418 client=REST' },
          { t: '2026-04-09 11:40:19', m: 'operation=MailItemsAccessed user=n.rouault client_ip=203.0.113.44 folder="Dossiers clients" item_count=96 client=REST' },
          { t: '2026-04-14 19:22:38', m: 'operation=FileAccessed user=n.rouault client_ip=203.0.113.44 site=Comptabilite file="echeancier_fournisseurs_2026.xlsx" client=REST' },
          { t: '2026-04-16 15:36:51', m: 'operation=FileAccessed user=n.rouault client_ip=203.0.113.44 site=Comptabilite file="FA-2026-0412.pdf" client=REST' },
          { t: '2026-04-16 15:44:07', m: 'operation=MailItemsAccessed user=n.rouault client_ip=203.0.113.44 folder="Flux RSS" item_count=11 client=REST' },
          { t: '2026-04-28 10:02:00', m: 'operation=Remove-InboxRule user=adm_cabinet client_ip=10.30.2.9 rule_name="Archive-Sync" result=Succeeded note="suppression par l equipe informatique apres decouverte"' }
        ],
        noise: [{ family: 'saas', count: 240, from: '2026-04-01 06:00:00', to: '2026-04-28 19:00:00' }]
      },
      {
        id: 'PJ-04', source: 'reseau', system: 'Mandataire web',
        title: 'Journal du mandataire web',
        note: 'Quinze jours de conservation seulement : les journaux antérieurs au 13 avril ont été écrasés par rotation. La navigation du 7 avril n\'est donc PAS couverte.',
        lines: [
          { t: '2026-04-16 15:35:12', m: 'user=k.amrani src=10.30.2.41 action=ALLOW method=GET url=https://banque-entreprise.example/virements/nouveau status=200 bytes=18422 category=finance' },
          { t: '2026-04-16 16:31:48', m: 'user=k.amrani src=10.30.2.41 action=ALLOW method=POST url=https://banque-entreprise.example/virements/valider status=200 bytes=2214 category=finance' },
          { t: '2026-04-21 08:09:55', m: 'user=- src=203.0.113.44 action=BLOCK method=GET url=https://portail-vasseur-connexion.test/session status=403 category=phishing note="domaine ajoute a la liste de blocage le 20 avril"' }
        ],
        noise: [{ family: 'proxy', count: 280, from: '2026-04-13 06:00:00', to: '2026-04-28 19:00:00' }]
      },
      {
        id: 'PJ-05', source: 'journaux', system: 'Outil comptable',
        title: 'Journal applicatif de l\'outil comptable',
        note: 'Trace les créations et modifications de tiers et de règlements. Le champ « iban » est journalisé en clair.',
        lines: [
          { t: '2026-04-16 16:24:11', m: 'action=tiers_modifie utilisateur=k.amrani tiers="Papeterie Renard" champ=iban ancienne_valeur=FR7630004000031234567890143 nouvelle_valeur=FR7612739000401234567890215 source="piece jointe FA-2026-0412-rectificatif.pdf"' },
          { t: '2026-04-16 16:29:03', m: 'action=reglement_cree utilisateur=k.amrani tiers="Papeterie Renard" montant=48200.00 devise=EUR iban=FR7612739000401234567890215 reference=FA-2026-0412' },
          { t: '2026-04-16 16:31:47', m: 'action=reglement_transmis utilisateur=k.amrani lot=VIR-2026-0416-02 montant_total=48200.00 statut=transmis_banque' },
          { t: '2026-04-27 09:20:14', m: 'action=consultation utilisateur=k.amrani tiers="Papeterie Renard" note="verification suite relance fournisseur"' }
        ],
        noise: [{ family: 'saas', count: 120, from: '2026-04-01 06:00:00', to: '2026-04-28 19:00:00', vars: { users: ['k.amrani', 'c.morin', 'f.leduc'] } }]
      }
    ],

    questions: [
      { id: 'Q1', type: 'domain', label: 'Domaine utilisé pour la page d\'hameçonnage',
        answer: 'portail-vasseur-connexion.test',
        hint: 'Le message d\'origine figure dans le journal de la passerelle : regardez l\'expéditeur du courriel du 7 avril.',
        where: 'PJ-01, première ligne (7 avril, 07:12:40), et PJ-04 au 21 avril quand le domaine est bloqué.',
        why: 'C\'est l\'indicateur à transmettre pour blocage, et il date l\'ouverture de la fenêtre de compromission.' },

      { id: 'Q2', type: 'text', label: 'Compte compromis',
        answer: 'n.rouault',
        hint: 'Trois personnes ont reçu le message, mais deux l\'ont vu partir en quarantaine.',
        where: 'PJ-01 : seul le message vers n.rouault est « delivered_to_inbox ». PJ-02 confirme la connexion externe sur ce compte.',
        why: 'Deux destinataires sur trois étaient protégés par la quarantaine : la compromission tient à une seule boîte, ce qui limite le périmètre à notifier.' },

      { id: 'Q3', type: 'ip', label: 'Adresse IP utilisée par l\'attaquant',
        answer: '203.0.113.44',
        hint: 'Cherchez dans le journal de fédération une authentification réussie avec un agent utilisateur qui ne ressemble pas à ceux du cabinet.',
        where: 'PJ-02 au 7 avril 07:20:44, puis dans toutes les opérations de PJ-03.',
        why: 'Cette adresse permet de recouper toutes les actions de l\'attaquant à travers trois journaux différents.' },

      { id: 'Q4', type: 'choice', label: 'Qu\'est-ce que l\'attaquant a réellement volé lors de l\'hameçonnage ?',
        answer: 'Le jeton de session, ce qui lui a évité l\'authentification forte',
        options: [
          'Le mot de passe, qu\'il a ensuite réutilisé avec succès',
          'Le jeton de session, ce qui lui a évité l\'authentification forte',
          'Le second facteur, en interceptant la notification',
          'Rien : il a exploité une vulnérabilité du serveur de messagerie'
        ],
        hint: 'Comparez les champs « mfa » et « session_id » des deux connexions du 7 avril matin.',
        where: 'PJ-02 : la connexion externe porte le même session_id=7c19aa que la connexion interne, avec mfa=not_required et reason=existing_session_token.',
        why: 'C\'est toute la différence entre une attaque par hameçonnage classique et une interception de session : réinitialiser le mot de passe ne coupe rien tant que la session n\'est pas révoquée. C\'est d\'ailleurs pour cela que l\'accès dure quatorze jours, jusqu\'à l\'expiration naturelle du jeton.' },

      { id: 'Q5', type: 'datetime', label: 'Horodatage de la première connexion illégitime (UTC)',
        answer: '2026-04-07 07:20',
        hint: 'Elle suit de moins d\'une minute la connexion légitime de l\'utilisatrice depuis son poste.',
        where: 'PJ-02, ligne auth_success depuis 203.0.113.44.',
        why: 'Le délai de quarante-six secondes entre la connexion légitime et la connexion externe est la signature d\'une interception en temps réel : l\'utilisatrice s\'est authentifiée sur la fausse page, qui a relayé vers la vraie.' },

      { id: 'Q6', type: 'text', label: 'Nom de la règle de boîte aux lettres créée par l\'attaquant',
        answer: 'Archive-Sync',
        hint: 'Une opération New-InboxRule apparaît dans le journal d\'audit, trois minutes après la première connexion.',
        where: 'PJ-03, 7 avril 07:23:16.',
        why: 'La règle masque les échanges financiers à la véritable titulaire de la boîte : sans elle, l\'utilisatrice aurait vu la réponse de sa collègue et l\'arnaque se serait arrêtée là.' },

      { id: 'Q7', type: 'text', label: 'Dossier vers lequel la règle déplaçait les messages',
        answer: 'Flux RSS', alt: ['flux rss', 'rss'],
        hint: 'La règle précise une action MoveToFolder.',
        where: 'PJ-03, paramètres de la règle Archive-Sync.',
        why: 'Les dossiers rarement consultés — flux RSS, éléments de conversation, archives — sont le choix constant de ce mode opératoire.' },

      { id: 'Q8', type: 'text', label: 'IBAN frauduleux sur lequel le virement est parti',
        answer: 'FR7612739000401234567890215',
        hint: 'L\'outil comptable journalise les modifications de coordonnées bancaires des tiers.',
        where: 'PJ-05, action=tiers_modifie le 16 avril à 16:24, puis le règlement créé cinq minutes plus tard.',
        why: 'C\'est la pièce qui permet le dépôt de plainte et la demande de rappel de fonds auprès de la banque : plus elle est produite tôt, plus la chance de récupération est réelle.' },

      { id: 'Q9', type: 'number', label: 'Montant du virement détourné, en euros',
        answer: '48200',
        hint: 'Le règlement créé dans l\'outil comptable porte le montant.',
        where: 'PJ-05, action=reglement_cree.',
        why: 'Le montant conditionne la qualification pénale et la déclaration à l\'assureur.' },

      { id: 'Q10', type: 'text', label: 'Compte de la collaboratrice qui a exécuté le virement de bonne foi',
        answer: 'k.amrani',
        hint: 'L\'outil comptable et le mandataire web désignent la même personne le 16 avril après-midi.',
        where: 'PJ-05 et PJ-04 (accès à la banque en ligne depuis 10.30.2.41).',
        why: 'Distinguer la victime de l\'auteur est une obligation de l\'analyste : cette collaboratrice a suivi une instruction qui paraissait venir d\'une collègue, dans un fil de discussion authentique.' },

      { id: 'Q11', type: 'choice', label: 'Un code malveillant a-t-il été exécuté sur un poste du cabinet ?',
        answer: 'Non, et l\'attaque n\'en avait pas besoin',
        options: [
          'Oui, la pièce jointe du 16 avril contenait une charge active',
          'Non, et l\'attaque n\'en avait pas besoin',
          'Indéterminable : aucun journal ne couvre les postes',
          'Oui, mais uniquement sur le poste de n.rouault'
        ],
        hint: 'Croisez deux éléments : ce que la passerelle dit de la pièce jointe, et ce que l\'attaquant a eu besoin de faire pour agir.',
        where: 'PJ-01 : la pièce jointe est analysée « clean », sans macro. Toutes les actions de l\'attaquant (PJ-03) passent par l\'interface web avec le jeton volé.',
        why: 'La tentation est de répondre « indéterminable » puisque les postes ne sont pas journalisés. Mais la question n\'est pas seulement « y a-t-il une trace » : c\'est aussi « l\'attaque en avait-elle besoin ». Ici, tout a été fait depuis le navigateur de l\'attaquant, avec une session valide. Conclure à tort à une compromission de poste aurait conduit le cabinet à réinstaller cinq machines pour rien.' }
    ],

    events: [
      { id: 'EV-01', t: '2026-04-07 07:12', label: 'Réception du courriel d\'hameçonnage (une boîte sur trois atteinte)' },
      { id: 'EV-02', t: '2026-04-07 07:20', label: 'Connexion externe réutilisant le jeton de session de l\'utilisatrice' },
      { id: 'EV-03', t: '2026-04-07 07:23', label: 'Création de la règle de boîte « Archive-Sync »' },
      { id: 'EV-04', t: '2026-04-07 07:24', label: 'Lecture de 418 éléments de la boîte de réception' },
      { id: 'EV-05', t: '2026-04-14 19:22', label: 'Consultation de l\'échéancier fournisseurs' },
      { id: 'EV-06', t: '2026-04-16 15:41', label: 'Réponse frauduleuse envoyée dans un fil existant avec un RIB modifié' },
      { id: 'EV-07', t: '2026-04-16 16:29', label: 'Création du règlement de 48 200 € vers l\'IBAN frauduleux' },
      { id: 'EV-08', t: '2026-04-21 08:11', label: 'Notification d\'authentification refusée par l\'utilisatrice' },
      { id: 'EV-09', t: '2026-04-16 15:35', label: 'Connexion de la comptable à la banque en ligne' },
      { id: 'EV-10', t: '2026-04-28 10:02', label: 'Suppression de la règle de boîte par l\'équipe informatique' },
      { id: 'EV-11', t: '2026-04-27 09:04', label: 'Relance du fournisseur pour impayé' }
    ],

    chain: [
      { tactic: 'Accès initial', event: 'EV-01', technique: 'T1566.002',
        where: 'PJ-01, courriel du 7 avril depuis portail-vasseur-connexion.test.',
        why: 'Le vecteur est un lien, pas une pièce jointe : c\'est une distinction opérationnelle, car les défenses et les traces ne sont pas les mêmes.' },
      { tactic: 'Exécution', event: 'NONE', technique: 'NONE',
        where: 'Aucune exécution : la pièce jointe du 16 avril est un document sans macro, et l\'attaquant opère depuis son propre navigateur.',
        why: 'Une compromission peut être totale sans qu\'aucun code ne tourne chez la victime. Chercher un implant ici, c\'est perdre une semaine.' },
      { tactic: 'Persistance', event: 'NONE', technique: 'NONE',
        where: 'Aucun mécanisme de persistance : l\'accès cesse le 21 avril à l\'expiration naturelle du jeton.',
        why: 'L\'attaquant a tenu quatorze jours sans rien installer. La persistance, ici, c\'est la durée de vie du jeton — un paramètre de configuration, pas un implant.' },
      { tactic: 'Élévation de privilèges', event: 'NONE', technique: 'NONE',
        where: 'Aucune tentative : le compte d\'une assistante suffisait au projet de l\'attaquant.',
        why: 'Rappel utile : la valeur d\'un compte ne se mesure pas à ses privilèges techniques mais à ce qu\'il permet de faire croire.' },
      { tactic: 'Contournement des défenses', event: 'EV-03', technique: 'T1564.008', techniqueAlt: ['T1562.001'],
        where: 'PJ-03, règle Archive-Sync qui déplace et marque comme lus les messages financiers.',
        why: 'La règle ne trompe pas un antivirus : elle trompe l\'utilisatrice légitime, qui est ici le meilleur capteur du cabinet.' },
      { tactic: 'Accès aux identifiants', event: 'EV-02', technique: 'T1539',
        where: 'PJ-02, même session_id que la connexion légitime, mfa=not_required.',
        why: 'Le vol de cookie de session est la réponse de l\'écosystème criminel au déploiement de l\'authentification forte : il faut savoir le reconnaître dans un journal.' },
      { tactic: 'Découverte', event: 'EV-05', technique: 'T1083', techniqueAlt: ['T1082'],
        where: 'PJ-03, consultation de l\'échéancier fournisseurs le 14 avril.',
        why: 'Neuf jours d\'observation avant d\'agir : l\'attaquant a appris les usages du cabinet, le nom du fournisseur, le format des factures et le ton des échanges.' },
      { tactic: 'Déplacement latéral', event: 'NONE', technique: 'NONE',
        where: 'Aucune connexion vers un autre compte ou une autre machine.',
        why: 'La tentative du 21 avril sur le compte p.vasseur a échoué, et elle est postérieure à la fraude : elle ne constitue pas un déplacement réussi.' },
      { tactic: 'Collecte', event: 'EV-04', technique: 'T1114.002',
        where: 'PJ-03, MailItemsAccessed : 418 éléments puis 96 dans les dossiers clients.',
        why: 'Ce point détermine l\'atteinte au secret professionnel : des dossiers clients ont été lus, et le cabinet a une obligation d\'information.' },
      { tactic: 'Commande et contrôle', event: 'NONE', technique: 'NONE',
        where: 'Aucun canal : l\'attaquant utilise l\'interface web légitime du prestataire de messagerie.',
        why: 'Quand l\'outil de l\'attaquant est le navigateur, il n\'y a pas de canal à détecter — seulement des sessions à surveiller.' },
      { tactic: 'Exfiltration', event: 'NONE', technique: 'NONE',
        where: 'Aucun téléchargement de masse dans PJ-03 : les messages sont lus, pas extraits en volume.',
        why: 'Lecture n\'est pas exfiltration. La nuance a des conséquences directes sur la qualification de la violation de données.' },
      { tactic: 'Impact', event: 'EV-07', technique: 'T1657',
        where: 'PJ-05, règlement de 48 200 € transmis à la banque le 16 avril à 16:31.',
        why: 'L\'impact est financier et immédiat. Le délai entre le virement et la découverte — onze jours — est ce qui rend le rappel de fonds très difficile.' }
    ],

    keyIndicators: ['portail-vasseur-connexion.test', '203.0.113.44', 'n.rouault', 'Archive-Sync', 'FR7612739000401234567890215', '7c19aa', '48200'],

    iocs: [
      { type: 'Domaine', value: 'portail-vasseur-connexion.test', context: 'Page d\'hameçonnage interceptant les sessions, enregistrée trois jours avant la campagne.' },
      { type: 'Adresse IP', value: '203.0.113.44', context: 'Source de toutes les actions de l\'attaquant, du 7 au 21 avril.' },
      { type: 'Règle de messagerie', value: 'Archive-Sync', context: 'Règle masquant les messages contenant facture, RIB, IBAN ou virement.' },
      { type: 'IBAN', value: 'FR7612739000401234567890215', context: 'Compte destinataire du virement frauduleux.' },
      { type: 'Empreinte SHA-256', value: 'eecf3832ae53a792101106b0b09849a2c3cfab83d727a2083c742826587c314d', context: 'Faux rectificatif de facture, document sans code actif.' }
    ],

    debrief: {
      story: 'Le 7 avril à 07h12, trois collaborateurs reçoivent un courriel imitant le portail de signature du cabinet. Deux exemplaires partent en quarantaine, celui de l\'assistante n.rouault arrive en boîte de réception. À 07h19 elle s\'authentifie sur la fausse page, qui relaie ses identifiants et sa validation d\'authentification forte vers le vrai service et récupère le jeton de session. Quarante-six secondes plus tard, l\'attaquant est connecté avec ce même jeton depuis 203.0.113.44, sans avoir eu à passer l\'authentification forte. Il pose immédiatement une règle de boîte qui masque tout ce qui parle d\'argent, puis observe le cabinet pendant neuf jours : 418 messages lus, les dossiers clients, l\'échéancier fournisseurs. Le 16 avril, il répond dans un fil de discussion authentique avec un faux rectificatif de facture. La comptable modifie l\'IBAN du fournisseur et exécute un virement de 48 200 €. La fraude n\'est découverte que le 27 avril, à la relance du vrai fournisseur.',
      lessons: [
        'Le champ qui résout ce dossier tient en deux mots : même session_id. Quand une connexion externe réutilise l\'identifiant de session d\'une connexion interne, il ne s\'agit pas d\'un vol de mot de passe mais d\'une interception de session, et la réponse est la révocation des jetons, pas la réinitialisation du mot de passe.',
        'Aucun code n\'a été exécuté chez le client. Une compromission peut être complète, durable et coûteuse sans le moindre implant : l\'absence d\'agent de sécurité sur les postes n\'empêchait pas de conclure.',
        'La rotation des journaux fait partie du dossier. Le mandataire ne conserve que quinze jours : impossible de voir la navigation du 7 avril. On documente la limite, on ne l\'ignore pas, et on recommande un allongement de la conservation.',
        'Neuf jours séparent l\'accès de la fraude. C\'est la fenêtre pendant laquelle une revue des règles de boîte aux lettres, ou une alerte sur la création d\'une règle masquant des messages financiers, aurait tout arrêté.'
      ],
      pitfalls: [
        'Conclure à un vol de mot de passe et se contenter d\'une réinitialisation : la session volée serait restée valide jusqu\'au 21 avril.',
        'Accuser la comptable k.amrani, qui a exécuté le virement : elle répondait dans un fil authentique, à une collègue, sur une facture réelle.',
        'Répondre « indéterminable » à la question de l\'exécution de code parce que les postes ne sont pas journalisés, alors que la chaîne complète s\'explique sans aucune exécution.',
        'Oublier la lecture des dossiers clients, qui engage le secret professionnel et l\'obligation d\'information, alors même qu\'il n\'y a pas eu d\'exfiltration au sens strict.'
      ]
    }
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
