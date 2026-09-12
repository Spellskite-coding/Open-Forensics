/* Open-Forensics — CAS-07. AVERTISSEMENT : contient les réponses attendues. */
(function (root) {
  'use strict';

  root.OpenForensics.cases.push({
    id: 'CAS-07',
    title: 'Fournisseur fictif dans le logiciel comptable',
    client: 'Fiduciaire Beaumont — cabinet d\'expertise comptable, 45 salariés',
    difficulty: 'moyen',
    estimatedMin: 60,
    tags: ['fraude interne', 'abus de privilèges', 'ERP'],

    env: {
      domain: 'BEAUMONT', dns: 'beaumont.lan', mail: 'fiduciaire-beaumont.example',
      lan: '10.70.4', edge: '198.51.100.71',
      hosts: ['PC-COMPTA-11', 'PC-COMPTA-12', 'PC-DIR-01', 'PC-IT-01', 'SRV-ERP-01', 'SRV-AD-04'],
      users: ['n.delaunay', 'f.perrot', 'a.zerbib', 'm.carre'],
      admins: ['adm_beaumont', 'h.bracq']
    },

    brief: {
      saisine: 'Lundi 8 juin 2026. Le commissaire aux comptes relève, lors de la revue annuelle, six règlements totalisant 28 800 € versés à un prestataire « Consultis Digital » dont aucun contrat, aucun devis et aucun livrable ne figurent au dossier. Le prestataire n\'est connu de personne dans le cabinet.',
      perimetre: 'Un progiciel de gestion hébergé en interne, un annuaire Active Directory, un outil de billetterie pour le support, un mandataire web. Le cabinet compte quatre comptables et deux administrateurs informatiques.',
      collecte: 'Journal d\'audit métier du progiciel, journal d\'authentification applicative, journal de sécurité du contrôleur de domaine, journal de la billetterie et journal du mandataire, du 1er janvier au 8 juin. Horodatages en UTC.',
      limites: 'Le progiciel purge son journal d\'audit métier au bout de six mois : les écritures antérieures au 8 décembre sont perdues. Les postes ne sont pas journalisés individuellement. Le cabinet n\'a pas de vidéosurveillance des locaux.',
      mission: 'Établir qui a créé le tiers et saisi les règlements, avec quel compte et depuis quelle machine, et distinguer sans ambiguïté l\'auteur des faits des personnes dont le compte a servi. Le dossier sera remis à l\'avocat du cabinet.'
    },

    evidence: [
      {
        id: 'PJ-01', source: 'journaux', system: 'SRV-ERP-01',
        title: 'Journal d\'audit métier du progiciel',
        note: 'Trace les créations et modifications de tiers, les écritures et les règlements, avec le compte applicatif à l\'origine. Le champ « session » permet de faire le lien avec le journal d\'authentification.',
        lines: [
          { t: '2026-01-12 05:21:40', m: 'action=tiers_cree utilisateur=f.perrot session=S-44120 tiers="Consultis Digital" siret=00000000000000 iban=FR7630788001000123456789021 categorie=prestataire_conseil' },
          { t: '2026-01-12 05:24:18', m: 'action=facture_saisie utilisateur=f.perrot session=S-44120 tiers="Consultis Digital" numero=CD-2026-01 montant=4800.00 libelle="Prestation de conseil - janvier"' },
          { t: '2026-01-12 05:26:02', m: 'action=reglement_valide utilisateur=f.perrot session=S-44120 tiers="Consultis Digital" montant=4800.00 iban=FR7630788001000123456789021' },
          { t: '2026-02-09 05:18:55', m: 'action=facture_saisie utilisateur=f.perrot session=S-49702 tiers="Consultis Digital" numero=CD-2026-02 montant=4800.00 libelle="Prestation de conseil - fevrier"' },
          { t: '2026-03-09 05:31:12', m: 'action=facture_saisie utilisateur=f.perrot session=S-55310 tiers="Consultis Digital" numero=CD-2026-03 montant=4800.00' },
          { t: '2026-04-13 05:27:44', m: 'action=facture_saisie utilisateur=f.perrot session=S-61044 tiers="Consultis Digital" numero=CD-2026-04 montant=4800.00' },
          { t: '2026-05-11 05:22:30', m: 'action=facture_saisie utilisateur=f.perrot session=S-66820 tiers="Consultis Digital" numero=CD-2026-05 montant=4800.00' },
          { t: '2026-06-08 05:19:08', m: 'action=facture_saisie utilisateur=f.perrot session=S-72411 tiers="Consultis Digital" numero=CD-2026-06 montant=4800.00' },
          { t: '2026-03-31 14:02:11', m: 'action=tiers_cree utilisateur=n.delaunay session=S-57880 tiers="Imprimerie Valmont" siret=48210033700025 iban=FR7610107001010012345678901 categorie=fournisseur note="creation en periode de cloture, dossier complet"' },
          { t: '2026-03-31 14:40:52', m: 'action=facture_saisie utilisateur=n.delaunay session=S-57880 tiers="Imprimerie Valmont" numero=IV-1188 montant=2140.00 piece_jointe=devis_IV-1188.pdf' },
          { t: '2026-01-12 05:19:02', m: 'action=audit_desactive utilisateur=svc_erp_admin session=S-44119 duree_prevue_min=10 motif="maintenance planifiee" note="aucune demande de maintenance correspondante dans la billetterie"' },
          { t: '2026-01-12 05:29:11', m: 'action=audit_reactive utilisateur=svc_erp_admin session=S-44119 duree_reelle_min=10' }
        ],
        noise: [{ family: 'saas', count: 300, from: '2026-01-02 05:00:00', to: '2026-06-08 19:00:00', vars: { users: ['n.delaunay', 'f.perrot', 'a.zerbib', 'm.carre'] } }]
      },
      {
        id: 'PJ-02', source: 'journaux', system: 'SRV-ERP-01',
        title: 'Journal d\'authentification du progiciel',
        note: 'Chaque session applicative est horodatée avec l\'adresse IP source. C\'est la seule pièce qui relie une session métier à une machine.',
        lines: [
          { t: '2026-01-12 05:20:55', m: 'session=S-44120 utilisateur=f.perrot src_ip=10.70.4.51 agent="Mozilla/5.0 (Windows NT 10.0)" resultat=succes note="poste PC-IT-01"' },
          { t: '2026-01-12 05:18:40', m: 'session=S-44119 utilisateur=svc_erp_admin src_ip=10.70.4.51 agent="Mozilla/5.0 (Windows NT 10.0)" resultat=succes' },
          { t: '2026-02-09 05:18:10', m: 'session=S-49702 utilisateur=f.perrot src_ip=10.70.4.51 resultat=succes' },
          { t: '2026-03-09 05:30:44', m: 'session=S-55310 utilisateur=f.perrot src_ip=10.70.4.51 resultat=succes' },
          { t: '2026-04-13 05:27:02', m: 'session=S-61044 utilisateur=f.perrot src_ip=10.70.4.51 resultat=succes' },
          { t: '2026-05-11 05:21:58', m: 'session=S-66820 utilisateur=f.perrot src_ip=10.70.4.51 resultat=succes' },
          { t: '2026-06-08 05:18:40', m: 'session=S-72411 utilisateur=f.perrot src_ip=10.70.4.51 resultat=succes' },
          { t: '2026-01-12 08:41:22', m: 'session=S-44160 utilisateur=f.perrot src_ip=10.70.4.22 resultat=succes note="poste habituel de l utilisatrice"' },
          { t: '2026-03-31 14:01:40', m: 'session=S-57880 utilisateur=n.delaunay src_ip=10.70.4.24 resultat=succes' }
        ],
        noise: [{ family: 'idp', count: 280, from: '2026-01-02 05:00:00', to: '2026-06-08 19:00:00', vars: { users: ['n.delaunay', 'f.perrot', 'a.zerbib', 'm.carre'] } }]
      },
      {
        id: 'PJ-03', source: 'journaux', system: 'SRV-AD-04',
        title: 'Journal de sécurité du contrôleur de domaine',
        note: 'Événements d\'authentification et d\'administration de comptes. Le code 4724 correspond à une réinitialisation de mot de passe par un administrateur.',
        lines: [
          { t: '2026-01-12 05:14:33', m: 'EventCode=4724 Target_Account=f.perrot Subject_Account=h.bracq Computer=SRV-AD-04 note="reinitialisation du mot de passe par un administrateur"' },
          { t: '2026-01-12 05:14:35', m: 'EventCode=4738 Target_Account=f.perrot Subject_Account=h.bracq Changes="PasswordLastSet updated"' },
          { t: '2026-01-12 05:12:01', m: 'EventCode=4624 Logon_Type=2 Account_Name=h.bracq Computer=PC-IT-01 Source_Network_Address=10.70.4.51' },
          { t: '2026-02-09 05:15:20', m: 'EventCode=4724 Target_Account=f.perrot Subject_Account=h.bracq Computer=SRV-AD-04' },
          { t: '2026-03-09 05:28:04', m: 'EventCode=4724 Target_Account=f.perrot Subject_Account=h.bracq Computer=SRV-AD-04' },
          { t: '2026-04-13 05:24:51', m: 'EventCode=4724 Target_Account=f.perrot Subject_Account=h.bracq Computer=SRV-AD-04' },
          { t: '2026-05-11 05:19:33', m: 'EventCode=4724 Target_Account=f.perrot Subject_Account=h.bracq Computer=SRV-AD-04' },
          { t: '2026-06-08 05:16:12', m: 'EventCode=4724 Target_Account=f.perrot Subject_Account=h.bracq Computer=SRV-AD-04' },
          { t: '2026-01-12 08:40:02', m: 'EventCode=4624 Logon_Type=2 Account_Name=f.perrot Computer=PC-COMPTA-11 Source_Network_Address=10.70.4.22' }
        ],
        noise: [{ family: 'win-security', count: 320, from: '2026-01-02 05:00:00', to: '2026-06-08 19:00:00' }]
      },
      {
        id: 'PJ-04', source: 'journaux', system: 'Billetterie du support',
        title: 'Journal de la billetterie interne',
        note: 'Toute demande d\'assistance et toute maintenance planifiée y figurent. Utile pour confronter une justification à une trace indépendante.',
        lines: [
          { t: '2026-01-12 08:44:10', m: 'ticket=T-2201 demandeur=f.perrot objet="Mon mot de passe ne fonctionne plus ce matin" assigne=h.bracq statut=resolu note="mot de passe reinitialise par le support"' },
          { t: '2026-02-09 08:51:33', m: 'ticket=T-2318 demandeur=f.perrot objet="Encore un probleme de mot de passe" assigne=h.bracq statut=resolu' },
          { t: '2026-03-09 09:02:14', m: 'ticket=T-2455 demandeur=f.perrot objet="Mot de passe refuse au demarrage" assigne=h.bracq statut=resolu' },
          { t: '2026-04-13 08:47:50', m: 'ticket=T-2610 demandeur=f.perrot objet="Probleme de connexion recurrent" assigne=h.bracq statut=resolu note="l utilisatrice signale que cela arrive une fois par mois"' },
          { t: '2026-05-11 08:55:02', m: 'ticket=T-2744 demandeur=f.perrot objet="Mot de passe a nouveau invalide" assigne=h.bracq statut=resolu' },
          { t: '2026-06-08 08:49:31', m: 'ticket=T-2902 demandeur=f.perrot objet="Connexion impossible" assigne=h.bracq statut=resolu' },
          { t: '2026-03-25 10:12:00', m: 'ticket=T-2501 demandeur=n.delaunay objet="Creation du fournisseur Imprimerie Valmont pour la cloture" assigne=a.zerbib statut=resolu note="validation hierarchique jointe"' }
        ],
        noise: [{ family: 'saas', count: 200, from: '2026-01-02 05:00:00', to: '2026-06-08 19:00:00', vars: { users: ['n.delaunay', 'f.perrot', 'a.zerbib', 'm.carre'] } }]
      },
      {
        id: 'PJ-05', source: 'reseau', system: 'Mandataire web',
        title: 'Journal du mandataire web',
        note: 'Navigation des postes du cabinet. Le poste PC-IT-01 est celui de l\'administrateur h.bracq.',
        lines: [
          { t: '2026-01-11 21:04:12', m: 'user=h.bracq src=10.70.4.51 action=ALLOW method=GET url=https://creation-societe-express.example/statuts-auto-entrepreneur status=200 bytes=22140 category=services_aux_entreprises' },
          { t: '2026-01-12 05:10:44', m: 'user=h.bracq src=10.70.4.51 action=ALLOW method=GET url=https://banque-en-ligne-pro.example/connexion status=200 bytes=18820 category=finance' },
          { t: '2026-06-08 05:15:02', m: 'user=h.bracq src=10.70.4.51 action=ALLOW method=GET url=https://banque-en-ligne-pro.example/comptes status=200 bytes=31204 category=finance' },
          { t: '2026-03-31 13:58:20', m: 'user=n.delaunay src=10.70.4.24 action=ALLOW method=GET url=https://annuaire-entreprises.example/recherche?q=imprimerie+valmont status=200 bytes=14402 category=services_aux_entreprises note="verification du SIRET du fournisseur"' }
        ],
        noise: [{ family: 'proxy', count: 300, from: '2026-01-02 05:00:00', to: '2026-06-08 19:00:00' }]
      }
    ],

    questions: [
      { id: 'Q1', type: 'text', label: 'Nom du tiers fictif créé dans le progiciel',
        answer: 'Consultis Digital', alt: ['consultis'],
        hint: 'Deux tiers ont été créés dans la période : l\'un est accompagné d\'un devis et d\'un SIRET valide, l\'autre non.',
        where: 'PJ-01, action=tiers_cree du 12 janvier à 05:21:40, avec un SIRET composé uniquement de zéros.',
        why: 'Un SIRET nul et l\'absence de pièce jointe sont deux anomalies qui auraient pu être détectées par un contrôle automatique à la création.' },

      { id: 'Q2', type: 'text', label: 'Compte applicatif sous lequel les écritures ont été saisies',
        answer: 'f.perrot',
        hint: 'Le journal d\'audit métier nomme un utilisateur pour chaque écriture.',
        where: 'PJ-01, champ utilisateur des six factures.',
        why: 'C\'est le compte apparent, et c\'est précisément le piège du dossier : le compte utilisé n\'est pas l\'auteur.' },

      { id: 'Q3', type: 'ip', label: 'Adresse IP depuis laquelle ces sessions ont été ouvertes',
        answer: '10.70.4.51',
        hint: 'Le journal d\'authentification du progiciel donne l\'adresse source de chaque session métier.',
        where: 'PJ-02, sessions S-44120, S-49702, S-55310, S-61044, S-66820 et S-72411 — toutes depuis la même adresse.',
        why: 'C\'est le pivot du dossier : la même utilisatrice se connecte depuis 10.70.4.22 le reste du temps. L\'adresse trahit la machine réellement employée.' },

      { id: 'Q4', type: 'text', label: 'Machine correspondant à cette adresse',
        answer: 'PC-IT-01', alt: ['pc-it-01'],
        hint: 'Le journal d\'authentification annote la première session, et le contrôleur de domaine montre qui ouvre une session sur cette machine.',
        where: 'PJ-02 (note « poste PC-IT-01 ») et PJ-03 (4624 de h.bracq sur PC-IT-01 depuis 10.70.4.51).',
        why: 'Rattacher l\'adresse à une machine, puis la machine à une personne, est la chaîne de démonstration qui tiendra devant un conseil de prud\'hommes.' },

      { id: 'Q5', type: 'text', label: 'Compte de l\'auteur réel des faits',
        answer: 'h.bracq',
        hint: 'Qui ouvre une session sur cette machine, et qui réinitialise le mot de passe de la comptable quelques minutes avant chaque saisie ?',
        where: 'PJ-03, EventCode=4724 avec Subject_Account=h.bracq, sept minutes avant chaque session frauduleuse.',
        why: 'La démonstration repose sur trois faits concordants : la réinitialisation du mot de passe, l\'ouverture de session sur PC-IT-01, et l\'adresse source des sessions applicatives.' },

      { id: 'Q6', type: 'datetime', label: 'Horodatage de la première réinitialisation du mot de passe de la comptable (UTC)',
        answer: '2026-01-12 05:14',
        hint: 'Le code d\'évènement 4724 signale une réinitialisation par un administrateur.',
        where: 'PJ-03, première ligne du dossier.',
        why: 'Sept minutes séparent la réinitialisation de la création du tiers fictif : c\'est ce délai qui rend la coïncidence intenable.' },

      { id: 'Q7', type: 'text', label: 'IBAN sur lequel les règlements ont été versés',
        answer: 'FR7630788001000123456789021',
        hint: 'Il figure à la création du tiers et sur le premier règlement validé.',
        where: 'PJ-01, action=tiers_cree et action=reglement_valide du 12 janvier.',
        why: 'C\'est la pièce qui permettra d\'identifier le bénéficiaire réel auprès de l\'établissement bancaire.' },

      { id: 'Q8', type: 'number', label: 'Nombre de factures fictives saisies',
        answer: '6',
        hint: 'Elles portent des numéros séquentiels et un montant identique.',
        where: 'PJ-01, factures CD-2026-01 à CD-2026-06.',
        why: 'La régularité mensuelle et le montant constant caractérisent une fraude installée dans la durée, pas un geste isolé.' },

      { id: 'Q9', type: 'number', label: 'Montant total détourné, en euros',
        answer: '28800',
        hint: 'Six factures d\'un même montant.',
        where: 'PJ-01, six écritures à 4 800 €.',
        why: 'Le montant, la durée et la régularité conditionnent la qualification pénale et l\'action civile.' },

      { id: 'Q10', type: 'text', label: 'Compte utilisé pour désactiver temporairement l\'audit du progiciel',
        answer: 'svc_erp_admin',
        hint: 'Une action technique précède de deux minutes la création du tiers, et son motif ne correspond à aucune demande.',
        where: 'PJ-01, action=audit_desactive du 12 janvier à 05:19:02, motif « maintenance planifiée ».',
        why: 'Aucun ticket de maintenance n\'existe pour cette fenêtre dans PJ-04 : le motif déclaré est faux, et c\'est cette contradiction qui transforme une anomalie en élément intentionnel.' },

      { id: 'Q11', type: 'choice', label: 'La comptable f.perrot est-elle impliquée ?',
        answer: 'Non : son compte a été utilisé à son insu, et elle a signalé chaque incident au support',
        options: [
          'Oui : les écritures sont saisies sous son compte',
          'Non : son compte a été utilisé à son insu, et elle a signalé chaque incident au support',
          'Indéterminable : rien ne permet de distinguer l\'usage du compte de son titulaire',
          'Oui : elle a créé le tiers puis a tenté de le dissimuler'
        ],
        hint: 'Confrontez les heures des sessions frauduleuses à l\'activité normale de l\'utilisatrice, et regardez la billetterie les matins concernés.',
        where: 'PJ-02 (sessions à 05h depuis 10.70.4.51, alors qu\'elle se connecte depuis 10.70.4.22 en journée), PJ-04 (six tickets « mot de passe » déposés par elle, les mêmes matins).',
        why: 'C\'est le cœur déontologique du dossier. Les six tickets déposés par la comptable sont la preuve que son mot de passe changeait à son insu : loin de la charger, ils la disculpent. Un rapport qui se serait arrêté au champ « utilisateur » du progiciel aurait accusé une innocente.' },

      { id: 'Q12', type: 'choice', label: 'La création du tiers « Imprimerie Valmont » par n.delaunay relève-t-elle des mêmes faits ?',
        answer: 'Non : opération justifiée, documentée et vérifiée, sans lien avec la fraude',
        options: [
          'Oui : c\'est le même mode opératoire',
          'Non : opération justifiée, documentée et vérifiée, sans lien avec la fraude',
          'Indéterminable : les deux créations sont identiques dans les journaux',
          'Oui, mais pour un montant moindre'
        ],
        hint: 'Comparez l\'heure, la machine, le SIRET, la présence de pièce jointe et l\'existence d\'un ticket de validation.',
        where: 'PJ-01 (SIRET valide, devis joint), PJ-02 (session depuis son poste habituel en journée), PJ-04 (ticket T-2501 avec validation hiérarchique), PJ-05 (vérification du SIRET sur l\'annuaire des entreprises).',
        why: 'Tout dossier de fraude interne contient une opération légitime qui lui ressemble. L\'écarter explicitement, avec ses cinq points de différence, est ce qui donne au rapport sa crédibilité — et ce qui protège une salariée d\'un soupçon injustifié.' }
    ],

    events: [
      { id: 'EV-01', t: '2026-01-11 21:04', label: 'Consultation d\'un service de création de société depuis le poste de l\'administrateur' },
      { id: 'EV-02', t: '2026-01-12 05:14', label: 'Réinitialisation du mot de passe de la comptable par l\'administrateur' },
      { id: 'EV-03', t: '2026-01-12 05:19', label: 'Désactivation de l\'audit du progiciel sous un motif de maintenance inexistant' },
      { id: 'EV-04', t: '2026-01-12 05:21', label: 'Création du tiers fictif Consultis Digital' },
      { id: 'EV-05', t: '2026-01-12 05:26', label: 'Validation du premier règlement de 4 800 €' },
      { id: 'EV-06', t: '2026-01-12 08:44', label: 'Ticket de la comptable signalant que son mot de passe ne fonctionne plus' },
      { id: 'EV-07', t: '2026-03-31 14:02', label: 'Création documentée du fournisseur Imprimerie Valmont en période de clôture' },
      { id: 'EV-08', t: '2026-06-08 05:19', label: 'Saisie de la sixième et dernière facture fictive' },
      { id: 'EV-09', t: '2026-01-12 05:29', label: 'Réactivation de l\'audit du progiciel après dix minutes' },
      { id: 'EV-10', t: '2026-03-25 10:12', label: 'Demande de création de fournisseur validée hiérarchiquement' }
    ],

    chain: [
      { tactic: 'Accès initial', event: 'NONE', technique: 'NONE',
        where: 'Aucun accès frauduleux : l\'auteur est administrateur du système, ses droits sont ceux de sa fonction.',
        why: 'Comme dans toute fraude interne, il n\'y a pas d\'entrée à trouver. Chercher une intrusion revient à passer à côté du dossier.' },
      { tactic: 'Exécution', event: 'NONE', technique: 'NONE',
        where: 'Aucun code exécuté : tout se fait dans les interfaces normales du progiciel et de l\'annuaire.',
        why: 'Une fraude peut ne laisser aucune trace technique au sens habituel : seulement des actions métier parfaitement valides, mais illégitimes.' },
      { tactic: 'Persistance', event: 'EV-02', technique: 'T1098',
        where: 'PJ-03, six réinitialisations de mot de passe en 4724, une par mois, toutes par le même administrateur.',
        why: 'La manipulation répétée du compte d\'un tiers est le mécanisme qui permet de recommencer chaque mois. C\'est aussi la trace la plus régulière, donc la plus détectable, du dossier.' },
      { tactic: 'Élévation de privilèges', event: 'NONE', technique: 'NONE',
        where: 'Inutile : l\'auteur dispose déjà des droits d\'administration de l\'annuaire et du progiciel.',
        why: 'Le cumul des droits d\'administration système et d\'administration applicative est la vulnérabilité organisationnelle de fond.' },
      { tactic: 'Contournement des défenses', event: 'EV-03', technique: 'T1562.001',
        where: 'PJ-01, audit désactivé dix minutes sous un motif de maintenance, sans ticket correspondant dans PJ-04.',
        why: 'La désactivation elle-même est journalisée : vouloir effacer sa trace en laisse une autre, et celle-là est datée à la seconde.' },
      { tactic: 'Accès aux identifiants', event: 'NONE', technique: 'NONE',
        where: 'Aucun vol de mot de passe : il a été réinitialisé, pas dérobé.',
        why: 'Distinction importante pour la qualification : l\'administrateur n\'a pas eu besoin de connaître le mot de passe de la comptable, il l\'a remplacé.' },
      { tactic: 'Découverte', event: 'NONE', technique: 'NONE',
        where: 'Aucune reconnaissance : l\'auteur administre ces systèmes au quotidien.',
        why: 'La connaissance intime du système est ce qui a permis une fraude propre pendant six mois.' },
      { tactic: 'Déplacement latéral', event: 'NONE', technique: 'NONE',
        where: 'Toutes les actions proviennent du poste d\'administration PC-IT-01.',
        why: 'Une seule machine, une seule adresse, six mois durant : la constance de l\'adresse source est ce qui a permis de remonter à l\'auteur.' },
      { tactic: 'Collecte', event: 'NONE', technique: 'NONE',
        where: 'Aucune donnée collectée : le dossier porte sur des mouvements financiers, pas sur de l\'information.',
        why: 'Rien n\'a été volé au sens des données : il est important de le dire, le cabinet n\'a pas d\'obligation de notification.' },
      { tactic: 'Commande et contrôle', event: 'NONE', technique: 'NONE',
        where: 'Aucun canal, aucun tiers extérieur.',
        why: 'Le bénéficiaire du compte bancaire reste à identifier par la voie judiciaire : ce n\'est pas du ressort de l\'analyse technique.' },
      { tactic: 'Exfiltration', event: 'NONE', technique: 'NONE',
        where: 'Aucun transfert de fichiers vers l\'extérieur dans le journal du mandataire.',
        why: 'Le préjudice est entièrement financier. Le confirmer évite au cabinet une déclaration de violation de données injustifiée.' },
      { tactic: 'Impact', event: 'EV-05', technique: 'T1657',
        where: 'PJ-01, six règlements de 4 800 € validés entre janvier et juin.',
        why: 'Vingt-huit mille huit cents euros sur six mois, avec un rythme mensuel : la régularité est ce qui a fini par la rendre visible en revue annuelle.' }
    ],

    keyIndicators: ['Consultis Digital', 'h.bracq', 'f.perrot', '10.70.4.51', 'FR7630788001000123456789021', 'svc_erp_admin', 'PC-IT-01'],

    iocs: [
      { type: 'Compte', value: 'h.bracq', context: 'Administrateur auteur des réinitialisations et des sessions frauduleuses depuis PC-IT-01.' },
      { type: 'Adresse IP', value: '10.70.4.51', context: 'Poste d\'administration, source des six sessions applicatives frauduleuses.' },
      { type: 'Tiers', value: 'Consultis Digital', context: 'Fournisseur fictif, SIRET nul, sans pièce jointe ni contrat.' },
      { type: 'IBAN', value: 'FR7630788001000123456789021', context: 'Destinataire des six règlements, total 28 800 €.' },
      { type: 'Compte technique', value: 'svc_erp_admin', context: 'Employé pour désactiver l\'audit du progiciel avant chaque série d\'écritures.' },
      { type: 'Motif de détection', value: 'EventCode 4724 suivi d\'une session applicative du compte cible dans les dix minutes', context: 'Règle de corrélation à mettre en place : une réinitialisation administrative suivie d\'un usage immédiat du compte.' }
    ],

    debrief: {
      story: 'Le 11 janvier au soir, l\'administrateur systèmes h.bracq consulte depuis son poste un service de création de société. Le lendemain à 05h12 il ouvre une session sur PC-IT-01. À 05h14 il réinitialise le mot de passe de la comptable f.perrot depuis le contrôleur de domaine. À 05h19 il désactive l\'audit du progiciel pour dix minutes, sous un motif de maintenance qui ne correspond à aucun ticket. À 05h21 il crée, sous l\'identité de la comptable, un tiers « Consultis Digital » au SIRET composé de zéros, saisit une facture de 4 800 € et valide le règlement. À 08h44, la comptable dépose un ticket : son mot de passe ne fonctionne plus. Le scénario se répète six fois, une fois par mois, jusqu\'au 8 juin. Vingt-huit mille huit cents euros ont été versés. La fraude n\'est découverte qu\'à la revue annuelle du commissaire aux comptes.',
      lessons: [
        'Le champ « utilisateur » d\'un journal applicatif ne désigne pas une personne : il désigne un compte. C\'est l\'adresse source, croisée avec les journaux d\'annuaire, qui désigne une machine, et la machine qui désigne une personne. Sauter cette chaîne, c\'est accuser un innocent.',
        'Les six tickets de la comptable, qui pouvaient passer pour de la négligence, sont en réalité la preuve de son innocence : son mot de passe changeait à son insu, et elle l\'a signalé chaque fois.',
        'Effacer sa trace en produit une autre. La désactivation de l\'audit est elle-même journalisée, avec son motif — et le motif est démenti par la billetterie. La contradiction entre deux systèmes indépendants est ce qui établit l\'intention.',
        'Le cumul des droits d\'administration de l\'annuaire et du progiciel, chez une même personne, sans séparation des tâches ni revue croisée, est la cause organisationnelle. Elle doit figurer dans le rapport au même rang que les faits.'
      ],
      pitfalls: [
        'Conclure que f.perrot est l\'auteur parce que son compte figure sur toutes les écritures.',
        'Traiter la création du fournisseur Imprimerie Valmont comme un fait connexe : SIRET valide, devis joint, ticket de validation, poste habituel, heure ouvrée — cinq différences.',
        'Chercher une intrusion, un code malveillant ou une exfiltration : il n\'y en a aucun, et les chercher fait manquer le rythme mensuel des réinitialisations.',
        'Omettre la désactivation de l\'audit, qui est le seul élément prouvant que l\'auteur savait mal faire et cherchait à le cacher.'
      ]
    }
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
