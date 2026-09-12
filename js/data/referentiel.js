/* Open-Forensics — référentiel commun aux dix dossiers.
 *
 * Tout est fictif : clients, personnes, machines, adresses et empreintes.
 * Les adresses IP appartiennent aux plages réservées à la documentation
 * (RFC 5737) et les domaines aux TLD réservés .test, .invalid et .example
 * (RFC 2606), afin qu'aucun indicateur de ce simulateur ne puisse désigner
 * une ressource réelle.
 */
(function (root) {
  'use strict';

  var OF = {};

  OF.app = {
    name: 'Open-Forensics',
    unit: 'CERT Vigie — unité d\'investigation numérique',
    tagline: 'reconstitution d\'incident'
  };

  /* Nature des pièces remises à l'analyste. L'ordre est celui du volet
   * gauche du navigateur de pièces. */
  OF.sources = [
    { id: 'journaux', label: 'Journaux', hint: 'Événements système, applicatifs et de sécurité' },
    { id: 'disque', label: 'Disque', hint: 'Triage de poste : registre, fichiers, artefacts d\'exécution' },
    { id: 'memoire', label: 'Mémoire', hint: 'Analyse de la capture de mémoire vive' },
    { id: 'reseau', label: 'Réseau', hint: 'Flux, résolutions DNS, journaux de mandataire et de pare-feu' },
    { id: 'messagerie', label: 'Messagerie', hint: 'En-têtes, règles de boîte, pièces jointes' },
    { id: 'cloud', label: 'Cloud et SaaS', hint: 'Journaux d\'identité, d\'API et d\'espaces documentaires' }
  ];

  OF.sourceLabel = function (id) {
    for (var i = 0; i < OF.sources.length; i++) if (OF.sources[i].id === id) return OF.sources[i].label;
    return id;
  };

  /* Qualifications proposées pour la nature de l'incident. */
  OF.incidentTypes = [
    'Rançongiciel',
    'Exfiltration de données',
    'Fraude au virement (compromission de messagerie)',
    'Compromission de compte à privilèges',
    'Compromission de la chaîne logicielle',
    'Cryptominage illicite',
    'Menace interne',
    'Défiguration ou sabotage',
    'Accès non autorisé sans impact avéré',
    'Faux positif — activité légitime'
  ];

  /* Barème. Le détail est documenté dans le README. */
  OF.weights = {
    flag: 6,
    flagWrongAttempt: 0.5,
    flagWrongAttemptCap: 3,
    hint: 2,
    chainEvent: 3,
    chainTechnique: 1.5,
    synthesis: 8,
    synthesisMin: 220,
    synthesisMax: 1400
  };

  OF.grades = [
    { min: 90, letter: 'A', label: 'Investigation exemplaire — le rapport est exploitable en l\'état' },
    { min: 78, letter: 'B', label: 'Solide — la chaîne est comprise, quelques preuves manquent' },
    { min: 65, letter: 'C', label: 'Correct — les faits principaux sont établis, la reconstitution reste partielle' },
    { min: 50, letter: 'D', label: 'Fragile — trop de zones d\'ombre pour conclure devant un client' },
    { min: 0, letter: 'E', label: 'Insuffisant — reprendre les pièces avant de conclure' }
  ];

  OF.techniques = [
    /* --- Aucune --- */
    { id: 'NONE', tactic: 'Aucune', name: 'Aucune — activité légitime ou bénigne' },
    /* --- Reconnaissance --- */
    { id: 'T1595', tactic: 'Reconnaissance', name: 'T1595 — Balayage actif' },
    { id: 'T1595.002', tactic: 'Reconnaissance', name: 'T1595.002 — Balayage de vulnérabilités' },
    { id: 'T1592', tactic: 'Reconnaissance', name: 'T1592 — Collecte d\'informations sur les hôtes de la cible' },
    { id: 'T1589', tactic: 'Reconnaissance', name: 'T1589 — Collecte d\'informations d\'identité sur la cible' },
    { id: 'T1598', tactic: 'Reconnaissance', name: 'T1598 — Hameçonnage de renseignement' },
    /* --- Accès initial --- */
    { id: 'T1078', tactic: 'Accès initial', name: 'T1078 — Comptes valides' },
    { id: 'T1078.002', tactic: 'Accès initial', name: 'T1078.002 — Comptes valides : compte de domaine' },
    { id: 'T1078.003', tactic: 'Accès initial', name: 'T1078.003 — Comptes valides : compte local' },
    { id: 'T1078.004', tactic: 'Accès initial', name: 'T1078.004 — Comptes valides : compte cloud' },
    { id: 'T1133', tactic: 'Accès initial', name: 'T1133 — Service distant exposé' },
    { id: 'T1190', tactic: 'Accès initial', name: 'T1190 — Exploitation d\'une application exposée' },
    { id: 'T1189', tactic: 'Accès initial', name: 'T1189 — Compromission par navigation (drive-by)' },
    { id: 'T1566', tactic: 'Accès initial', name: 'T1566 — Hameçonnage' },
    { id: 'T1566.001', tactic: 'Accès initial', name: 'T1566.001 — Hameçonnage : pièce jointe' },
    { id: 'T1566.002', tactic: 'Accès initial', name: 'T1566.002 — Hameçonnage : lien' },
    { id: 'T1566.003', tactic: 'Accès initial', name: 'T1566.003 — Hameçonnage : via un service tiers' },
    { id: 'T1195.002', tactic: 'Accès initial', name: 'T1195.002 — Compromission de la chaîne logicielle' },
    { id: 'T1199', tactic: 'Accès initial', name: 'T1199 — Relation de confiance (prestataire, tiers)' },
    { id: 'T1200', tactic: 'Accès initial', name: 'T1200 — Ajout de matériel' },
    { id: 'T1091', tactic: 'Accès initial', name: 'T1091 — Propagation par média amovible' },
    /* --- Exécution --- */
    { id: 'T1059', tactic: 'Exécution', name: 'T1059 — Interpréteur de commandes et de scripts' },
    { id: 'T1059.001', tactic: 'Exécution', name: 'T1059.001 — PowerShell' },
    { id: 'T1059.003', tactic: 'Exécution', name: 'T1059.003 — Invite de commandes Windows' },
    { id: 'T1059.004', tactic: 'Exécution', name: 'T1059.004 — Shell Unix' },
    { id: 'T1059.005', tactic: 'Exécution', name: 'T1059.005 — Visual Basic / VBA' },
    { id: 'T1059.007', tactic: 'Exécution', name: 'T1059.007 — JavaScript / WScript' },
    { id: 'T1204.001', tactic: 'Exécution', name: 'T1204.001 — Exécution par l\'utilisateur : lien malveillant' },
    { id: 'T1204.002', tactic: 'Exécution', name: 'T1204.002 — Exécution par l\'utilisateur : fichier malveillant' },
    { id: 'T1047', tactic: 'Exécution', name: 'T1047 — Instrumentation WMI' },
    { id: 'T1569.002', tactic: 'Exécution', name: 'T1569.002 — Exécution par service' },
    { id: 'T1053.005', tactic: 'Exécution', name: 'T1053.005 — Tâche planifiée' },
    { id: 'T1106', tactic: 'Exécution', name: 'T1106 — Appel direct d\'API système' },
    { id: 'T1072', tactic: 'Exécution', name: 'T1072 — Outil de déploiement logiciel' },
    /* --- Persistance --- */
    { id: 'T1547.001', tactic: 'Persistance', name: 'T1547.001 — Clé Run et dossier de démarrage' },
    { id: 'T1543.003', tactic: 'Persistance', name: 'T1543.003 — Création ou modification de service Windows' },
    { id: 'T1543.002', tactic: 'Persistance', name: 'T1543.002 — Service systemd' },
    { id: 'T1053.003', tactic: 'Persistance', name: 'T1053.003 — Tâche planifiée cron' },
    { id: 'T1098.001', tactic: 'Persistance', name: 'T1098.001 — Ajout de clé ou de jeton d\'accès' },
    { id: 'T1136.001', tactic: 'Persistance', name: 'T1136.001 — Création de compte local' },
    { id: 'T1136.002', tactic: 'Persistance', name: 'T1136.002 — Création de compte de domaine' },
    { id: 'T1098', tactic: 'Persistance', name: 'T1098 — Manipulation de compte' },
    { id: 'T1098.005', tactic: 'Persistance', name: 'T1098.005 — Enregistrement d\'un appareil MFA' },
    { id: 'T1505.003', tactic: 'Persistance', name: 'T1505.003 — Webshell' },
    { id: 'T1546.003', tactic: 'Persistance', name: 'T1546.003 — Abonnement à un évènement WMI' },
    { id: 'T1574.002', tactic: 'Persistance', name: 'T1574.002 — Chargement latéral de DLL' },
    { id: 'T1197', tactic: 'Persistance', name: 'T1197 — Tâches BITS' },
    { id: 'T1556', tactic: 'Persistance', name: 'T1556 — Modification du processus d\'authentification' },
    /* --- Élévation de privilèges --- */
    { id: 'T1068', tactic: 'Élévation de privilèges', name: 'T1068 — Exploitation pour élévation de privilèges' },
    { id: 'T1134', tactic: 'Élévation de privilèges', name: 'T1134 — Manipulation de jeton d\'accès' },
    { id: 'T1548.002', tactic: 'Élévation de privilèges', name: 'T1548.002 — Contournement du contrôle de compte utilisateur (UAC)' },
    { id: 'T1055', tactic: 'Élévation de privilèges', name: 'T1055 — Injection dans un processus' },
    { id: 'T1484.001', tactic: 'Élévation de privilèges', name: 'T1484.001 — Modification de stratégie de groupe' },
    /* --- Contournement des défenses --- */
    { id: 'T1027', tactic: 'Contournement des défenses', name: 'T1027 — Fichiers ou informations obfusqués' },
    { id: 'T1027.010', tactic: 'Contournement des défenses', name: 'T1027.010 — Obfuscation de ligne de commande' },
    { id: 'T1140', tactic: 'Contournement des défenses', name: 'T1140 — Décodage de fichiers ou d\'informations' },
    { id: 'T1070.001', tactic: 'Contournement des défenses', name: 'T1070.001 — Effacement des journaux d\'évènements Windows' },
    { id: 'T1070.004', tactic: 'Contournement des défenses', name: 'T1070.004 — Suppression de fichiers' },
    { id: 'T1112', tactic: 'Contournement des défenses', name: 'T1112 — Modification du registre' },
    { id: 'T1218.005', tactic: 'Contournement des défenses', name: 'T1218.005 — Exécution par mshta' },
    { id: 'T1218.010', tactic: 'Contournement des défenses', name: 'T1218.010 — Exécution par regsvr32' },
    { id: 'T1218.011', tactic: 'Contournement des défenses', name: 'T1218.011 — Exécution par rundll32' },
    { id: 'T1036.005', tactic: 'Contournement des défenses', name: 'T1036.005 — Usurpation d\'un nom ou d\'un emplacement légitime' },
    { id: 'T1553.002', tactic: 'Contournement des défenses', name: 'T1553.002 — Abus de signature de code' },
    { id: 'T1562.001', tactic: 'Contournement des défenses', name: 'T1562.001 — Désactivation d\'outils de sécurité' },
    { id: 'T1562.004', tactic: 'Contournement des défenses', name: 'T1562.004 — Désactivation du pare-feu système' },
    { id: 'T1497', tactic: 'Contournement des défenses', name: 'T1497 — Détection d\'environnement d\'analyse' },
    { id: 'T1564.008', tactic: 'Contournement des défenses', name: 'T1564.008 — Masquage d\'éléments de messagerie (règle de boîte)' },
    { id: 'T1070.006', tactic: 'Contournement des défenses', name: 'T1070.006 — Falsification d\'horodatage (timestomping)' },
    { id: 'T1070.002', tactic: 'Contournement des défenses', name: 'T1070.002 — Effacement des journaux Unix' },
    { id: 'T1620', tactic: 'Contournement des défenses', name: 'T1620 — Chargement de code en mémoire' },
    /* --- Accès aux identifiants --- */
    { id: 'T1003.001', tactic: 'Accès aux identifiants', name: 'T1003.001 — Vidage de mémoire LSASS' },
    { id: 'T1003.002', tactic: 'Accès aux identifiants', name: 'T1003.002 — Export de la ruche SAM' },
    { id: 'T1003.003', tactic: 'Accès aux identifiants', name: 'T1003.003 — Extraction de la base NTDS' },
    { id: 'T1003.006', tactic: 'Accès aux identifiants', name: 'T1003.006 — Réplication d\'annuaire (DCSync)' },
    { id: 'T1558.001', tactic: 'Accès aux identifiants', name: 'T1558.001 — Forge d\'un ticket doré (Golden Ticket)' },
    { id: 'T1552.004', tactic: 'Accès aux identifiants', name: 'T1552.004 — Clés privées exposées' },
    { id: 'T1110.001', tactic: 'Accès aux identifiants', name: 'T1110.001 — Force brute : essais exhaustifs' },
    { id: 'T1110.002', tactic: 'Accès aux identifiants', name: 'T1110.002 — Force brute : cassage de condensats' },
    { id: 'T1110.003', tactic: 'Accès aux identifiants', name: 'T1110.003 — Pulvérisation de mots de passe' },
    { id: 'T1110.004', tactic: 'Accès aux identifiants', name: 'T1110.004 — Bourrage d\'identifiants (credential stuffing)' },
    { id: 'T1558.003', tactic: 'Accès aux identifiants', name: 'T1558.003 — Kerberoasting' },
    { id: 'T1552.001', tactic: 'Accès aux identifiants', name: 'T1552.001 — Identifiants stockés dans des fichiers' },
    { id: 'T1555.003', tactic: 'Accès aux identifiants', name: 'T1555.003 — Identifiants enregistrés dans le navigateur' },
    { id: 'T1056.001', tactic: 'Accès aux identifiants', name: 'T1056.001 — Enregistrement des frappes clavier' },
    { id: 'T1111', tactic: 'Accès aux identifiants', name: 'T1111 — Interception de l\'authentification forte' },
    { id: 'T1621', tactic: 'Accès aux identifiants', name: 'T1621 — Lassitude MFA (rafale de notifications)' },
    { id: 'T1528', tactic: 'Accès aux identifiants', name: 'T1528 — Vol de jeton d\'application OAuth' },
    { id: 'T1539', tactic: 'Accès aux identifiants', name: 'T1539 — Vol de cookie de session web' },
    { id: 'T1187', tactic: 'Accès aux identifiants', name: 'T1187 — Authentification forcée (fuite de condensats)' },
    /* --- Découverte --- */
    { id: 'T1087', tactic: 'Découverte', name: 'T1087 — Découverte de comptes' },
    { id: 'T1087.001', tactic: 'Découverte', name: 'T1087.001 — Découverte de comptes locaux' },
    { id: 'T1087.002', tactic: 'Découverte', name: 'T1087.002 — Découverte de comptes de domaine' },
    { id: 'T1069.002', tactic: 'Découverte', name: 'T1069.002 — Découverte de groupes de domaine' },
    { id: 'T1018', tactic: 'Découverte', name: 'T1018 — Découverte de systèmes distants' },
    { id: 'T1046', tactic: 'Découverte', name: 'T1046 — Découverte de services réseau' },
    { id: 'T1135', tactic: 'Découverte', name: 'T1135 — Découverte de partages réseau' },
    { id: 'T1082', tactic: 'Découverte', name: 'T1082 — Découverte d\'informations système' },
    { id: 'T1083', tactic: 'Découverte', name: 'T1083 — Découverte de fichiers et de répertoires' },
    { id: 'T1057', tactic: 'Découverte', name: 'T1057 — Découverte de processus' },
    { id: 'T1482', tactic: 'Découverte', name: 'T1482 — Découverte des relations d\'approbation de domaine' },
    { id: 'T1201', tactic: 'Découverte', name: 'T1201 — Découverte de la politique de mots de passe' },
    { id: 'T1518.001', tactic: 'Découverte', name: 'T1518.001 — Découverte des logiciels de sécurité' },
    { id: 'T1526', tactic: 'Découverte', name: 'T1526 — Découverte de services cloud' },
    { id: 'T1087.004', tactic: 'Découverte', name: 'T1087.004 — Découverte de comptes cloud' },
    { id: 'T1619', tactic: 'Découverte', name: 'T1619 — Découverte d\'objets de stockage cloud' },
    /* --- Déplacement latéral --- */
    { id: 'T1021.001', tactic: 'Déplacement latéral', name: 'T1021.001 — Services distants : bureau à distance (RDP)' },
    { id: 'T1021.002', tactic: 'Déplacement latéral', name: 'T1021.002 — Services distants : partages administratifs SMB' },
    { id: 'T1021.004', tactic: 'Déplacement latéral', name: 'T1021.004 — Services distants : SSH' },
    { id: 'T1021.006', tactic: 'Déplacement latéral', name: 'T1021.006 — Services distants : WinRM' },
    { id: 'T1021.007', tactic: 'Déplacement latéral', name: 'T1021.007 — Services distants : services cloud' },
    { id: 'T1570', tactic: 'Déplacement latéral', name: 'T1570 — Transfert latéral d\'outils' },
    { id: 'T1550.001', tactic: 'Déplacement latéral', name: 'T1550.001 — Utilisation d\'un jeton d\'application' },
    { id: 'T1550.002', tactic: 'Déplacement latéral', name: 'T1550.002 — Passe-le-condensat (pass the hash)' },
    { id: 'T1550.003', tactic: 'Déplacement latéral', name: 'T1550.003 — Passe-le-ticket (pass the ticket)' },
    { id: 'T1563.002', tactic: 'Déplacement latéral', name: 'T1563.002 — Détournement de session RDP' },
    { id: 'T1080', tactic: 'Déplacement latéral', name: 'T1080 — Contamination de contenu partagé' },
    { id: 'T1210', tactic: 'Déplacement latéral', name: 'T1210 — Exploitation d\'un service distant' },
    /* --- Collecte --- */
    { id: 'T1114.001', tactic: 'Collecte', name: 'T1114.001 — Collecte de messagerie locale' },
    { id: 'T1114.002', tactic: 'Collecte', name: 'T1114.002 — Collecte de messagerie distante' },
    { id: 'T1114.003', tactic: 'Collecte', name: 'T1114.003 — Règle de transfert de messagerie' },
    { id: 'T1005', tactic: 'Collecte', name: 'T1005 — Données du système local' },
    { id: 'T1039', tactic: 'Collecte', name: 'T1039 — Données d\'un partage réseau' },
    { id: 'T1213', tactic: 'Collecte', name: 'T1213 — Données d\'un référentiel documentaire' },
    { id: 'T1560.001', tactic: 'Collecte', name: 'T1560.001 — Archivage via un utilitaire' },
    { id: 'T1113', tactic: 'Collecte', name: 'T1113 — Capture d\'écran' },
    { id: 'T1074.001', tactic: 'Collecte', name: 'T1074.001 — Regroupement local de données' },
    /* --- Commande et contrôle --- */
    { id: 'T1071.001', tactic: 'Commande et contrôle', name: 'T1071.001 — Protocoles web' },
    { id: 'T1071.004', tactic: 'Commande et contrôle', name: 'T1071.004 — Tunnel DNS' },
    { id: 'T1105', tactic: 'Commande et contrôle', name: 'T1105 — Transfert d\'outil entrant' },
    { id: 'T1571', tactic: 'Commande et contrôle', name: 'T1571 — Port réseau non standard' },
    { id: 'T1573.002', tactic: 'Commande et contrôle', name: 'T1573.002 — Chiffrement asymétrique du canal' },
    { id: 'T1090', tactic: 'Commande et contrôle', name: 'T1090 — Relais ou mandataire (proxy)' },
    { id: 'T1102', tactic: 'Commande et contrôle', name: 'T1102 — Service web légitime détourné' },
    { id: 'T1219', tactic: 'Commande et contrôle', name: 'T1219 — Outil d\'accès distant légitime' },
    { id: 'T1568.002', tactic: 'Commande et contrôle', name: 'T1568.002 — Génération algorithmique de domaines' },
    { id: 'T1008', tactic: 'Commande et contrôle', name: 'T1008 — Canaux de secours' },
    /* --- Exfiltration --- */
    { id: 'T1041', tactic: 'Exfiltration', name: 'T1041 — Exfiltration par le canal de commande et contrôle' },
    { id: 'T1048.003', tactic: 'Exfiltration', name: 'T1048.003 — Exfiltration par un protocole non chiffré' },
    { id: 'T1567.002', tactic: 'Exfiltration', name: 'T1567.002 — Exfiltration vers un stockage cloud' },
    { id: 'T1020', tactic: 'Exfiltration', name: 'T1020 — Exfiltration automatisée' },
    { id: 'T1030', tactic: 'Exfiltration', name: 'T1030 — Fractionnement des transferts' },
    { id: 'T1052.001', tactic: 'Exfiltration', name: 'T1052.001 — Exfiltration par média amovible' },
    /* --- Impact --- */
    { id: 'T1486', tactic: 'Impact', name: 'T1486 — Chiffrement de données à des fins d\'extorsion' },
    { id: 'T1490', tactic: 'Impact', name: 'T1490 — Inhibition de la restauration système' },
    { id: 'T1489', tactic: 'Impact', name: 'T1489 — Arrêt de service' },
    { id: 'T1485', tactic: 'Impact', name: 'T1485 — Destruction de données' },
    { id: 'T1491.001', tactic: 'Impact', name: 'T1491.001 — Défiguration interne' },
    { id: 'T1498', tactic: 'Impact', name: 'T1498 — Déni de service réseau' },
    { id: 'T1531', tactic: 'Impact', name: 'T1531 — Suppression d\'accès au compte' },
    { id: 'T1496', tactic: 'Impact', name: 'T1496 — Détournement de ressources' },
    { id: 'T1657', tactic: 'Impact', name: 'T1657 — Gain financier (fraude au virement)' }
  ];

  /* Ordre d'affichage des groupes dans le sélecteur de clôture. */
  OF.tactics = ['Aucune', 'Reconnaissance', 'Accès initial', 'Exécution', 'Persistance', 'Élévation de privilèges', 'Contournement des défenses', 'Accès aux identifiants', 'Découverte', 'Déplacement latéral', 'Collecte', 'Commande et contrôle', 'Exfiltration', 'Impact'];

  OF.techniquesByTactic = function (tactic) {
    return OF.techniques.filter(function (t) { return t.tactic === tactic; });
  };

  OF.techniqueName = function (id) {
    for (var i = 0; i < OF.techniques.length; i++) if (OF.techniques[i].id === id) return OF.techniques[i].name;
    return id;
  };

  /* Tactiques proposées dans la reconstitution de chaîne, dans l'ordre
   * chronologique d'une intrusion. « Aucune » n'y figure pas : une tactique
   * non observée se déclare explicitement dans le formulaire. */
  OF.chainTactics = [
    'Accès initial',
    'Exécution',
    'Persistance',
    'Élévation de privilèges',
    'Contournement des défenses',
    'Accès aux identifiants',
    'Découverte',
    'Déplacement latéral',
    'Collecte',
    'Commande et contrôle',
    'Exfiltration',
    'Impact'
  ];

  OF.cases = [];

  root.OpenForensics = root.OpenForensics || {};
  root.OpenForensics.ref = OF;
  root.OpenForensics.cases = OF.cases;
})(typeof globalThis !== 'undefined' ? globalThis : this);
