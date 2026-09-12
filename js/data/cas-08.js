/* Open-Forensics — CAS-08. AVERTISSEMENT : contient les réponses attendues. */
(function (root) {
  'use strict';

  root.OpenForensics.cases.push({
    id: 'CAS-08',
    title: 'Prise de contrôle de l\'annuaire d\'une collectivité',
    client: 'Ville de Saint-Aubin — collectivité territoriale, 310 agents',
    difficulty: 'difficile',
    estimatedMin: 110,
    tags: ['Active Directory', 'DCSync', 'ticket doré', 'exfiltration'],

    env: {
      domain: 'SAINTAUBIN', dns: 'saint-aubin.lan', mail: 'ville-saint-aubin.example',
      lan: '10.90.2', edge: '198.51.100.83',
      hosts: ['PC-URBA-08', 'PC-FIN-03', 'PC-DSI-02', 'PC-ETAT-05', 'SRV-DC-05', 'SRV-DC-06', 'SRV-FIC-05', 'SRV-APP-02'],
      users: ['m.gauthier', 'l.rossi', 'p.tanguy', 'c.berger', 'd.nunez'],
      admins: ['adm_dsi', 'adm_sauvegarde']
    },

    brief: {
      saisine: 'Mercredi 9 septembre 2026. Le CERT régional signale à la ville que son adresse publique communique depuis plusieurs jours avec une infrastructure connue pour héberger des vols de données. La collectivité n\'a rien détecté. Les services d\'état civil et des finances fonctionnent normalement.',
      perimetre: 'Un domaine Active Directory à deux contrôleurs, 310 comptes agents, un serveur de fichiers portant les dossiers d\'état civil et d\'urbanisme, un serveur applicatif métier. Antivirus intégré au système, pas de solution de détection comportementale.',
      collecte: 'Journaux de sécurité des deux contrôleurs de domaine, télémétrie de processus des postes bureautiques, journaux du mandataire web, du pare-feu et du serveur de fichiers, du 30 août au 9 septembre. Horodatages en UTC.',
      limites: 'La télémétrie de processus n\'est pas déployée sur les serveurs, seulement sur les postes. Le journal de sécurité de SRV-APP-02 a été écrasé par rotation le 7 septembre : la fenêtre du 5 septembre n\'y est plus. Aucune capture réseau complète n\'est disponible, seulement des métadonnées de flux.',
      mission: 'Établir la chronologie complète depuis le point d\'entrée, déterminer jusqu\'où l\'attaquant est monté dans l\'annuaire, ce qui est sorti, et dire à la collectivité si la reconstruction du domaine est nécessaire. C\'est cette dernière conclusion qui engagera plusieurs semaines de travail et un budget considérable.'
    },

    evidence: [
      {
        id: 'PJ-01', source: 'reseau', system: 'Mandataire web',
        title: 'Journal du mandataire web',
        note: 'Catégorisation et âge de domaine. Les postes bureautiques sortent tous par ce mandataire.',
        lines: [
          { t: '2026-09-02 09:14:02', m: 'user=m.gauthier src=10.90.2.28 action=ALLOW method=GET url=https://docs-marches-publics.test/dossier/MP-2026-014 status=200 bytes=14820 category=uncategorized domain_age_days=6' },
          { t: '2026-09-02 09:15:44', m: 'user=m.gauthier src=10.90.2.28 action=ALLOW method=GET url=https://docs-marches-publics.test/dl/MP-2026-014.zip status=200 bytes=482114 category=uncategorized' },
          { t: '2026-09-02 09:21:30', m: 'user=m.gauthier src=10.90.2.28 action=ALLOW method=POST url=https://cdn-mairie-updates.test/api/status status=200 bytes_out=912 bytes_in=402 category=uncategorized domain_age_days=11' },
          { t: '2026-09-02 09:29:31', m: 'user=m.gauthier src=10.90.2.28 action=ALLOW method=POST url=https://cdn-mairie-updates.test/api/status status=200 bytes_out=884 bytes_in=1820' },
          { t: '2026-09-06 01:52:14', m: 'user=m.gauthier src=10.90.2.28 action=ALLOW method=POST url=https://cdn-mairie-updates.test/api/status status=200 bytes_out=1204 bytes_in=44820' },
          { t: '2026-09-08 03:41:02', m: 'user=m.gauthier src=10.90.2.28 action=ALLOW method=POST url=https://depot-archives-eu.test/upload status=200 bytes_out=4194304000 duration_s=2841 category=uncategorized note="volume sortant hors norme"' },
          { t: '2026-09-08 04:31:55', m: 'user=m.gauthier src=10.90.2.28 action=ALLOW method=POST url=https://depot-archives-eu.test/upload status=200 bytes_out=4194304000 duration_s=2610' },
          { t: '2026-09-08 05:18:20', m: 'user=m.gauthier src=10.90.2.28 action=ALLOW method=POST url=https://depot-archives-eu.test/upload status=200 bytes_out=616562688 duration_s=402' }
        ],
        noise: [{ family: 'proxy', count: 380, from: '2026-08-30 05:00:00', to: '2026-09-09 19:00:00' }]
      },
      {
        id: 'PJ-02', source: 'journaux', system: 'PC-URBA-08 et postes bureautiques',
        title: 'Télémétrie de processus — postes bureautiques',
        note: 'Sysmon déployé sur les postes uniquement. Les serveurs n\'en disposent pas : toute action côté serveur devra être reconstituée depuis les journaux de sécurité.',
        lines: [
          { t: '2026-09-02 09:20:41', m: 'EventCode=1 Computer=PC-URBA-08 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe ParentImage=C:\\Windows\\explorer.exe CommandLine="powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA" User=SAINTAUBIN\\m.gauthier ProcessId=6120' },
          { t: '2026-09-02 09:20:58', m: 'EventCode=11 Computer=PC-URBA-08 TargetFilename=C:\\Users\\m.gauthier\\AppData\\Roaming\\WinUpdSvc\\wupsvc.exe Image=powershell.exe SHA256=bf4c833f28eefa6cc6d59b09c3636eeb1ccc82bdc9e9adc662a7ec2ef53765ab' },
          { t: '2026-09-02 09:21:12', m: 'EventCode=13 Computer=PC-URBA-08 TargetObject=HKU\\S-1-5-21-8841\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinUpdSvc Details="C:\\Users\\m.gauthier\\AppData\\Roaming\\WinUpdSvc\\wupsvc.exe" Image=powershell.exe' },
          { t: '2026-09-03 10:02:18', m: 'EventCode=1 Computer=PC-URBA-08 Image=C:\\Windows\\System32\\net.exe ParentImage=wupsvc.exe CommandLine="net group \\"Admins du domaine\\" /domain" User=SAINTAUBIN\\m.gauthier' },
          { t: '2026-09-03 10:03:44', m: 'EventCode=1 Computer=PC-URBA-08 Image=C:\\Windows\\System32\\nltest.exe ParentImage=wupsvc.exe CommandLine="nltest /dclist:saint-aubin.lan"' },
          { t: '2026-09-03 10:11:09', m: 'EventCode=3 Computer=PC-URBA-08 Image=wupsvc.exe DestinationIp=10.90.2.5 DestinationPort=389 note="requetes LDAP soutenues, 2 480 objets enumeres en 6 minutes"' },
          { t: '2026-09-04 02:38:55', m: 'EventCode=1 Computer=PC-URBA-08 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe ParentImage=wupsvc.exe CommandLine="powershell.exe -c Add-Type -A System.IdentityModel; ... KerberosRequestorSecurityToken" User=SAINTAUBIN\\m.gauthier' },
          { t: '2026-09-06 01:33:02', m: 'EventCode=3 Computer=PC-URBA-08 Image=wupsvc.exe DestinationIp=10.90.2.5 DestinationPort=445 note="session prolongee vers SRV-DC-05"' },
          { t: '2026-09-08 03:12:40', m: 'EventCode=1 Computer=PC-URBA-08 Image=C:\\Program Files\\7-Zip\\7z.exe ParentImage=wupsvc.exe CommandLine="7z a -v4g -mx1 C:\\Users\\m.gauthier\\AppData\\Local\\Temp\\arch.7z \\\\SRV-FIC-05\\EtatCivil \\\\SRV-FIC-05\\Urbanisme"' },
          { t: '2026-09-08 03:40:11', m: 'EventCode=11 Computer=PC-URBA-08 TargetFilename=C:\\Users\\m.gauthier\\AppData\\Local\\Temp\\arch.7z.003 Image=7z.exe note="troisieme et derniere partie de l archive"' }
        ],
        noise: [{ family: 'sysmon', count: 380, from: '2026-08-30 05:00:00', to: '2026-09-09 19:00:00' }]
      },
      {
        id: 'PJ-03', source: 'journaux', system: 'SRV-DC-05',
        title: 'Journal de sécurité — contrôleur de domaine principal',
        note: 'Audit complet activé, y compris l\'accès aux objets de l\'annuaire (4662). Le code 4769 correspond à une demande de ticket de service, le 4768 à une demande de ticket initial.',
        lines: [
          { t: '2026-09-04 02:39:02', m: 'EventCode=4769 Account_Name=m.gauthier Service_Name=svc_app Client_Address=10.90.2.28 Ticket_Encryption_Type=0x17 Ticket_Options=0x40810000' },
          { t: '2026-09-04 02:39:03', m: 'EventCode=4769 Account_Name=m.gauthier Service_Name=svc_sql Client_Address=10.90.2.28 Ticket_Encryption_Type=0x17 Ticket_Options=0x40810000' },
          { t: '2026-09-04 02:39:04', m: 'EventCode=4769 Account_Name=m.gauthier Service_Name=svc_web Client_Address=10.90.2.28 Ticket_Encryption_Type=0x17 Ticket_Options=0x40810000' },
          { t: '2026-09-04 02:39:11', m: 'EventCode=4769 Account_Name=m.gauthier Service_Name=svc_impression Client_Address=10.90.2.28 Ticket_Encryption_Type=0x17 note="14 demandes en 9 secondes, toutes en chiffrement RC4"' },
          { t: '2026-09-05 21:12:40', m: 'EventCode=4624 Logon_Type=3 Account_Name=svc_app Computer=SRV-APP-02 Source_Network_Address=10.90.2.28 Authentication_Package=Kerberos' },
          { t: '2026-09-06 01:33:08', m: 'EventCode=4662 Object_Type=domainDNS Object_Name=DC=saint-aubin,DC=lan Account_Name=svc_app Client_Address=10.90.2.28 Properties="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" Access=Control_Access' },
          { t: '2026-09-06 01:33:09', m: 'EventCode=4662 Object_Type=domainDNS Object_Name=DC=saint-aubin,DC=lan Account_Name=svc_app Client_Address=10.90.2.28 Properties="1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" Access=Control_Access note="DS-Replication-Get-Changes-All"' },
          { t: '2026-09-06 01:41:22', m: 'EventCode=4662 Object_Type=user Object_Name=CN=krbtgt,CN=Users,DC=saint-aubin,DC=lan Account_Name=svc_app Client_Address=10.90.2.28 Access=Read_Property' },
          { t: '2026-09-08 03:02:11', m: 'EventCode=4769 Account_Name=adm_maintenance Service_Name=cifs/SRV-FIC-05 Client_Address=10.90.2.28 Ticket_Encryption_Type=0x12 note="aucun 4768 prealable pour ce compte"' },
          { t: '2026-09-08 03:02:12', m: 'EventCode=4769 Account_Name=adm_maintenance Service_Name=LDAP/SRV-DC-05 Client_Address=10.90.2.28 Ticket_Encryption_Type=0x12' },
          { t: '2026-09-08 03:02:44', m: 'EventCode=4624 Logon_Type=3 Account_Name=adm_maintenance Computer=SRV-FIC-05 Source_Network_Address=10.90.2.28 Authentication_Package=Kerberos note="compte absent de l annuaire"' },
          { t: '2026-09-09 11:02:00', m: 'EventCode=4662 Object_Type=user Object_Name=CN=krbtgt,CN=Users,DC=saint-aubin,DC=lan Account_Name=adm_dsi Client_Address=10.90.2.30 Access=Read_Property note="verification demandee par le CERT"' }
        ],
        noise: [{ family: 'win-security', count: 420, from: '2026-08-30 05:00:00', to: '2026-09-09 19:00:00' }]
      },
      {
        id: 'PJ-04', source: 'journaux', system: 'SRV-DC-06',
        title: 'Journal de sécurité — contrôleur de domaine secondaire',
        note: 'Second contrôleur, situé dans l\'annexe technique. Audit identique à celui du contrôleur principal.',
        lines: [
          { t: '2026-09-06 01:33:07', m: 'EventCode=4624 Logon_Type=3 Account_Name=SRV-DC-05$ Computer=SRV-DC-06 Source_Network_Address=10.90.2.5 note="replication normale entre controleurs"' },
          { t: '2026-09-09 10:44:12', m: 'EventCode=4662 Object_Type=domainDNS Account_Name=adm_dsi Client_Address=10.90.2.30 Properties="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" note="audit demande par le CERT, aucune trace anterieure de replication non planifiee sur ce controleur"' },
          { t: '2026-09-09 10:45:30', m: 'audit_summary host=SRV-DC-06 window=2026-08-30/2026-09-09 controle="4662 avec droits de replication hors comptes de controleurs" resultat=0_occurrence' }
        ],
        noise: [{ family: 'win-security', count: 300, from: '2026-08-30 05:00:00', to: '2026-09-09 19:00:00' }]
      },
      {
        id: 'PJ-05', source: 'journaux', system: 'SRV-FIC-05',
        title: 'Journal d\'accès du serveur de fichiers',
        note: 'Audit d\'accès aux partages. Les dossiers EtatCivil et Urbanisme contiennent des données personnelles.',
        lines: [
          { t: '2026-09-08 03:02:50', m: 'EventCode=5140 Share_Name=\\\\*\\EtatCivil Account_Name=adm_maintenance Source_Address=10.90.2.28 Access=ReadData,ListDirectory' },
          { t: '2026-09-08 03:03:02', m: 'EventCode=5140 Share_Name=\\\\*\\Urbanisme Account_Name=adm_maintenance Source_Address=10.90.2.28 Access=ReadData,ListDirectory' },
          { t: '2026-09-08 03:38:41', m: 'EventCode=5145 Share_Name=\\\\*\\EtatCivil Account_Name=adm_maintenance Source_Address=10.90.2.28 files_read_session=18402 bytes_read=6220147712' },
          { t: '2026-09-08 03:39:55', m: 'EventCode=5145 Share_Name=\\\\*\\Urbanisme Account_Name=adm_maintenance Source_Address=10.90.2.28 files_read_session=9114 bytes_read=2790105088' },
          { t: '2026-09-04 14:20:11', m: 'EventCode=5145 Share_Name=\\\\*\\Urbanisme Account_Name=m.gauthier Source_Address=10.90.2.28 files_read_session=34 bytes_read=48211044 note="activite metier normale en journee"' }
        ],
        noise: [{ family: 'win-security', count: 280, from: '2026-08-30 05:00:00', to: '2026-09-09 19:00:00' }]
      },
      {
        id: 'PJ-06', source: 'reseau', system: 'Pare-feu périmétrique',
        title: 'Journal du pare-feu et synthèses de volumétrie',
        note: 'Compteurs par session et synthèses quotidiennes de volumétrie sortante par machine.',
        lines: [
          { t: '2026-09-02 09:21:29', m: 'src=10.90.2.28 dst=203.0.113.66 dport=443 proto=tcp action=ALLOW bytes_out=912 bytes_in=402' },
          { t: '2026-09-08 03:41:00', m: 'src=10.90.2.28 dst=198.51.100.190 dport=443 proto=tcp action=ALLOW bytes_out=4194304000 duration_s=2841' },
          { t: '2026-09-08 04:31:52', m: 'src=10.90.2.28 dst=198.51.100.190 dport=443 proto=tcp action=ALLOW bytes_out=4194304000 duration_s=2610' },
          { t: '2026-09-08 05:18:18', m: 'src=10.90.2.28 dst=198.51.100.190 dport=443 proto=tcp action=ALLOW bytes_out=616562688 duration_s=402' },
          { t: '2026-09-09 06:00:00', m: 'egress_summary window=2026-09-08 host=10.90.2.28 total_bytes_out=9005170688 note="moyenne des 30 jours precedents pour ce poste : 81 Mo par jour"' }
        ],
        noise: [{ family: 'firewall', count: 360, from: '2026-08-30 05:00:00', to: '2026-09-09 19:00:00' }]
      }
    ],

    questions: [
      { id: 'Q1', type: 'domain', label: 'Domaine depuis lequel le fichier piégé a été téléchargé',
        answer: 'docs-marches-publics.test',
        hint: 'Le mandataire journalise un téléchargement depuis un domaine créé six jours plus tôt.',
        where: 'PJ-01, 2 septembre 09:15:44.',
        why: 'Point d\'entrée du dossier. Un domaine de six jours d\'âge, non catégorisé, consulté par un agent d\'urbanisme : trois signaux concordants.' },

      { id: 'Q2', type: 'text', label: 'Compte de l\'agent initialement compromis',
        answer: 'm.gauthier',
        hint: 'Le même utilisateur apparaît sur le téléchargement et sur la première exécution suspecte.',
        where: 'PJ-01 et PJ-02.',
        why: 'C\'est le patient zéro. Toute la suite se déroule dans son contexte utilisateur, jusqu\'à la forge du ticket.' },

      { id: 'Q3', type: 'text', label: 'Poste du patient zéro',
        answer: 'PC-URBA-08',
        hint: 'L\'adresse 10.90.2.28 revient dans tous les journaux du dossier.',
        where: 'PJ-02 (Computer=), et l\'adresse source dans PJ-03, PJ-05 et PJ-06.',
        why: 'Une seule machine porte toute l\'intrusion : c\'est elle qu\'il faudra reconstruire, et c\'est depuis elle que tout se recoupe.' },

      { id: 'Q4', type: 'text', label: 'Nom du binaire de persistance déposé sur le poste',
        answer: 'wupsvc.exe',
        hint: 'Un fichier est écrit dans le profil de l\'utilisateur, puis référencé dans une clé de démarrage.',
        where: 'PJ-02, création à 09:20:58 et clé Run à 09:21:12.',
        why: 'Le nom imite un service de mise à jour système ; c\'est ce binaire qui est parent de toutes les commandes des jours suivants.' },

      { id: 'Q5', type: 'domain', label: 'Domaine de commande et contrôle',
        answer: 'cdn-mairie-updates.test',
        hint: 'Des requêtes POST de petite taille partent régulièrement vers un domaine récent.',
        where: 'PJ-01 à partir du 2 septembre 09:21, et PJ-06 vers 203.0.113.66.',
        why: 'À distinguer du domaine d\'exfiltration, qui est différent et n\'apparaît que le 8 septembre : confondre les deux fausse la chronologie.' },

      { id: 'Q6', type: 'datetime', label: 'Horodatage de la rafale de demandes de tickets de service (UTC)',
        answer: '2026-09-04 02:39',
        hint: 'Quatorze demandes en neuf secondes, toutes avec le même type de chiffrement.',
        where: 'PJ-03, séquence de 4769 avec Ticket_Encryption_Type=0x17.',
        why: 'C\'est la signature du kerberoasting : demander des tickets de service en masse pour les casser hors ligne. Elle est détectable en une règle de corrélation.' },

      { id: 'Q7', type: 'text', label: 'Type de chiffrement demandé pour ces tickets',
        answer: 'RC4', alt: ['0x17', 'rc4-hmac', 'rc4 (0x17)'],
        hint: 'Le champ Ticket_Encryption_Type des évènements 4769 de cette rafale diffère de celui des tickets normaux.',
        where: 'PJ-03 : 0x17 pour la rafale, 0x12 (AES) pour le trafic normal et pour les tickets forgés du 8 septembre.',
        why: 'RC4 est demandé explicitement parce qu\'il se casse hors ligne bien plus vite qu\'AES. Un domaine qui l\'a désactivé rend cette attaque inopérante.' },

      { id: 'Q8', type: 'text', label: 'Compte de service dont le mot de passe a été cassé et réutilisé',
        answer: 'svc_app',
        hint: 'Parmi les comptes visés par la rafale, un seul s\'authentifie ensuite depuis le poste compromis.',
        where: 'PJ-03, authentification de svc_app depuis 10.90.2.28 le 5 septembre à 21:12.',
        why: 'C\'est le compte qui fait basculer le dossier : par une mauvaise configuration historique, il portait des droits de réplication d\'annuaire.' },

      { id: 'Q9', type: 'text', label: 'Identifiant de droit étendu caractérisant la réplication d\'annuaire',
        answer: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', alt: ['1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', 'DS-Replication-Get-Changes'],
        hint: 'Les évènements 4662 portent un champ Properties contenant un identifiant globalement unique.',
        where: 'PJ-03, deux évènements 4662 consécutifs le 6 septembre à 01:33.',
        why: 'Ces identifiants sont la seule trace d\'un DCSync : l\'attaque ne produit aucun processus, aucun fichier, aucun accès à la base de l\'annuaire. Sans l\'audit des accès aux objets, elle est invisible.' },

      { id: 'Q10', type: 'datetime', label: 'Horodatage de la réplication d\'annuaire frauduleuse (UTC)',
        answer: '2026-09-06 01:33',
        hint: 'Deux évènements 4662 en une seconde, depuis une adresse qui n\'est pas celle d\'un contrôleur de domaine.',
        where: 'PJ-03, Client_Address=10.90.2.28.',
        why: 'Un poste bureautique qui demande une réplication d\'annuaire n\'a aucune justification : c\'est l\'anomalie la plus nette du dossier.' },

      { id: 'Q11', type: 'text', label: 'Compte dont le secret a été extrait lors de cette réplication',
        answer: 'krbtgt',
        hint: 'Un objet précis de l\'annuaire est lu huit minutes après la réplication.',
        where: 'PJ-03, 4662 sur CN=krbtgt à 01:41:22.',
        why: 'Le secret de ce compte permet de forger des tickets pour n\'importe quel utilisateur. Sa compromission est ce qui impose une double rotation de son mot de passe — et c\'est la conclusion la plus coûteuse du rapport.' },

      { id: 'Q12', type: 'text', label: 'Nom du compte utilisé dans les tickets forgés',
        answer: 'adm_maintenance',
        hint: 'Le 8 septembre, des demandes de tickets de service concernent un compte qui n\'apparaît nulle part ailleurs dans l\'annuaire.',
        where: 'PJ-03, 4769 à 03:02:11 puis 4624 sur SRV-FIC-05, avec la mention « compte absent de l\'annuaire ».',
        why: 'Un compte inexistant qui obtient des tickets et ouvre des sessions : c\'est la démonstration qu\'un ticket doré a été forgé.' },

      { id: 'Q13', type: 'choice', label: 'Quel élément prouve l\'usage d\'un ticket forgé plutôt qu\'un simple vol de compte ?',
        answer: 'Des demandes de ticket de service sans demande de ticket initial préalable, pour un compte absent de l\'annuaire',
        options: [
          'Le chiffrement RC4 des tickets du 8 septembre',
          'Des demandes de ticket de service sans demande de ticket initial préalable, pour un compte absent de l\'annuaire',
          'L\'heure nocturne des connexions',
          'L\'adresse source, qui est celle d\'un poste bureautique'
        ],
        hint: 'Comparez les codes 4768 et 4769 pour ce compte, et cherchez-le dans l\'annuaire.',
        where: 'PJ-03 : les 4769 du 8 septembre portent la note « aucun 4768 préalable », et le 4624 signale un compte absent de l\'annuaire.',
        why: 'Un ticket doré est forgé hors ligne : il n\'y a donc jamais eu d\'authentification initiale auprès du contrôleur. L\'absence de 4768 associée à un 4769 est la détection canonique. Les tickets du 8 septembre sont d\'ailleurs en AES, pas en RC4 : répondre RC4 serait confondre avec le kerberoasting du 4 septembre.' },

      { id: 'Q14', type: 'number', label: 'Volume total exfiltré en octets',
        answer: '9005170688',
        hint: 'Trois transferts successifs vers le même destinataire dans la nuit du 8 septembre ; le pare-feu en donne aussi la somme.',
        where: 'PJ-06, egress_summary du 8 septembre, à rapprocher des trois sessions de PJ-01 et PJ-06.',
        why: 'Neuf gigaoctets contre 81 Mo de moyenne quotidienne pour ce poste : un facteur cent, qu\'aucune supervision n\'a relevé. C\'est la recommandation opérationnelle la plus immédiate.' },

      { id: 'Q15', type: 'ip', label: 'Adresse IP de destination de l\'exfiltration',
        answer: '198.51.100.190',
        hint: 'Le domaine d\'exfiltration diffère de celui du canal de commande.',
        where: 'PJ-06, trois sessions du 8 septembre.',
        why: 'Séparer l\'infrastructure de commande de celle d\'exfiltration est une pratique courante : le rapport doit fournir les deux au CERT.' },

      { id: 'Q16', type: 'choice', label: 'La reconstruction du domaine est-elle nécessaire ?',
        answer: 'Oui : le secret du compte krbtgt est compromis, une double rotation et une remise à plat des droits s\'imposent',
        options: [
          'Non : il suffit de réinitialiser le compte svc_app et de nettoyer le poste',
          'Oui : le secret du compte krbtgt est compromis, une double rotation et une remise à plat des droits s\'imposent',
          'Non : le second contrôleur de domaine est resté sain, il peut servir de référence',
          'Indéterminable tant que la capture réseau complète n\'est pas disponible'
        ],
        hint: 'Quel secret a été lu, et que permet-il de faire indépendamment de tout mot de passe utilisateur ?',
        where: 'PJ-03, lecture de l\'objet krbtgt à 01:41 et usage d\'un compte forgé deux jours plus tard.',
        why: 'Tant que le secret du compte krbtgt n\'a pas été changé deux fois, l\'attaquant peut forger un ticket pour n\'importe quel compte, y compris après réinitialisation de tous les mots de passe. Le second contrôleur n\'est pas « sain » : il partage la même base d\'annuaire. C\'est la conclusion qui engage plusieurs semaines de travail, et elle doit être énoncée sans ambiguïté.' }
    ],

    events: [
      { id: 'EV-01', t: '2026-09-02 09:15', label: 'Téléchargement d\'une archive depuis un domaine créé six jours plus tôt' },
      { id: 'EV-02', t: '2026-09-02 09:20', label: 'Exécution d\'une commande PowerShell encodée et dépôt de wupsvc.exe' },
      { id: 'EV-03', t: '2026-09-02 09:21', label: 'Création d\'une clé de démarrage pointant vers le binaire déposé' },
      { id: 'EV-04', t: '2026-09-02 09:21', label: 'Première balise vers cdn-mairie-updates.test' },
      { id: 'EV-05', t: '2026-09-03 10:02', label: 'Énumération des groupes du domaine et des contrôleurs' },
      { id: 'EV-06', t: '2026-09-04 02:39', label: 'Rafale de quatorze demandes de tickets de service en chiffrement RC4' },
      { id: 'EV-07', t: '2026-09-05 21:12', label: 'Authentification du compte de service svc_app depuis le poste compromis' },
      { id: 'EV-08', t: '2026-09-06 01:33', label: 'Réplication d\'annuaire demandée par un poste bureautique' },
      { id: 'EV-09', t: '2026-09-08 03:02', label: 'Tickets obtenus pour un compte absent de l\'annuaire' },
      { id: 'EV-10', t: '2026-09-08 03:12', label: 'Archivage en trois volumes des partages État civil et Urbanisme' },
      { id: 'EV-11', t: '2026-09-08 03:41', label: 'Transfert de neuf gigaoctets vers depot-archives-eu.test' },
      { id: 'EV-12', t: '2026-09-04 14:20', label: 'Consultation métier du partage Urbanisme en journée' },
      { id: 'EV-13', t: '2026-09-09 10:44', label: 'Audit du second contrôleur de domaine demandé par le CERT' }
    ],

    chain: [
      { tactic: 'Accès initial', event: 'EV-01', technique: 'T1566.002',
        where: 'PJ-01, téléchargement depuis docs-marches-publics.test par un agent d\'urbanisme.',
        why: 'Le prétexte — un dossier de marché public — est adapté au service visé. La cible a été choisie, pas tirée au hasard.' },
      { tactic: 'Exécution', event: 'EV-02', technique: 'T1059.001',
        where: 'PJ-02, PowerShell avec argument encodé, lancé par l\'explorateur de fichiers.',
        why: 'Le parent explorer.exe indique un double-clic de l\'utilisateur : c\'est l\'ouverture du contenu de l\'archive qui déclenche tout.' },
      { tactic: 'Persistance', event: 'EV-03', technique: 'T1547.001',
        where: 'PJ-02, clé Run WinUpdSvc créée trente secondes après le dépôt du binaire.',
        why: 'Persistance rudimentaire mais suffisante : elle a tenu sept jours sans être vue, faute de détection comportementale.' },
      { tactic: 'Élévation de privilèges', event: 'NONE', technique: 'NONE',
        where: 'Aucune exploitation de vulnérabilité locale, aucune manipulation de jeton, aucun contournement du contrôle de compte.',
        why: 'C\'est un point important du rapport : l\'attaquant n\'a jamais eu besoin d\'élever ses privilèges. Il est passé d\'un compte d\'agent à la maîtrise du domaine par une mauvaise configuration de droits sur un compte de service. Le problème est de gouvernance, pas de correctif manquant.' },
      { tactic: 'Contournement des défenses', event: 'EV-02', technique: 'T1027.010', techniqueAlt: ['T1027', 'T1036.005'],
        where: 'PJ-02, ligne de commande encodée en base64 et binaire nommé wupsvc.exe dans un répertoire de profil.',
        why: 'Deux dissimulations élémentaires suffisent quand il n\'y a ni détection comportementale ni supervision des journaux.' },
      { tactic: 'Accès aux identifiants', event: 'EV-08', technique: 'T1003.006', techniqueAlt: ['T1558.003', 'T1558.001'],
        where: 'PJ-03, évènements 4662 portant les identifiants de droits de réplication, puis lecture de l\'objet krbtgt.',
        why: 'Deux techniques d\'accès aux identifiants se succèdent : le kerberoasting du 4 septembre pour obtenir svc_app, puis la réplication d\'annuaire du 6 pour obtenir krbtgt. La seconde est celle qui a des conséquences durables.' },
      { tactic: 'Découverte', event: 'EV-05', technique: 'T1069.002', techniqueAlt: ['T1018', 'T1087.002'],
        where: 'PJ-02, net group, nltest, puis 2 480 objets énumérés en LDAP en six minutes.',
        why: 'L\'énumération LDAP massive est ce qui a permis de repérer que svc_app portait des droits anormaux : la reconnaissance a fait le travail d\'audit que la collectivité n\'avait jamais mené.' },
      { tactic: 'Déplacement latéral', event: 'EV-09', technique: 'T1550.003',
        where: 'PJ-03, tickets de service obtenus pour adm_maintenance sans authentification préalable, puis session ouverte sur SRV-FIC-05.',
        why: 'Le déplacement se fait avec un compte qui n\'existe pas : aucune réinitialisation de mot de passe ne peut l\'arrêter. Seule la rotation du secret krbtgt le peut.' },
      { tactic: 'Collecte', event: 'EV-10', technique: 'T1039', techniqueAlt: ['T1560.001'],
        where: 'PJ-02 (archivage en volumes de 4 Go) et PJ-05 (27 516 fichiers lus sur les deux partages).',
        why: 'Le découpage en volumes de quatre gigaoctets est un choix technique qui se lit dans les deux journaux : il annonce un transfert par sessions séparées.' },
      { tactic: 'Commande et contrôle', event: 'EV-04', technique: 'T1071.001',
        where: 'PJ-01 et PJ-06, requêtes POST régulières vers cdn-mairie-updates.test depuis le 2 septembre.',
        why: 'Le canal reste actif six jours avant la phase d\'exfiltration : c\'est une intrusion pilotée, pas un automate.' },
      { tactic: 'Exfiltration', event: 'EV-11', technique: 'T1041', techniqueAlt: ['T1567.002'],
        where: 'PJ-01 et PJ-06, trois sessions totalisant 9 005 170 688 octets vers 198.51.100.190.',
        why: 'Les données d\'état civil concernent l\'ensemble des administrés : c\'est cette constatation qui déclenche la notification à l\'autorité de contrôle et l\'information des personnes.' },
      { tactic: 'Impact', event: 'NONE', technique: 'NONE',
        where: 'Aucun chiffrement, aucune destruction, aucune interruption de service : les applications ont fonctionné normalement pendant toute l\'intrusion.',
        why: 'L\'absence d\'impact visible est précisément ce qui a permis à l\'intrusion de durer sept jours. Une collectivité qui attend la panne pour s\'inquiéter ne détecte jamais ce type d\'attaque.' }
    ],

    keyIndicators: ['docs-marches-publics.test', 'cdn-mairie-updates.test', 'wupsvc.exe', 'svc_app', 'krbtgt', 'adm_maintenance', '198.51.100.190', 'PC-URBA-08'],

    iocs: [
      { type: 'Domaine', value: 'docs-marches-publics.test', context: 'Distribution du fichier piégé, domaine âgé de six jours.' },
      { type: 'Domaine', value: 'cdn-mairie-updates.test', context: 'Canal de commande et contrôle, résolu en 203.0.113.66.' },
      { type: 'Domaine', value: 'depot-archives-eu.test', context: 'Destination de l\'exfiltration, résolu en 198.51.100.190.' },
      { type: 'Empreinte SHA-256', value: 'bf4c833f28eefa6cc6d59b09c3636eeb1ccc82bdc9e9adc662a7ec2ef53765ab', context: 'Binaire wupsvc.exe déposé dans le profil utilisateur.' },
      { type: 'Compte', value: 'adm_maintenance', context: 'Compte inexistant dans l\'annuaire, utilisé via un ticket forgé.' },
      { type: 'Motif de détection', value: '4769 sans 4768 préalable pour un même compte', context: 'Détection canonique d\'un ticket doré.' },
      { type: 'Motif de détection', value: '4662 avec Properties 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 depuis une adresse non-contrôleur', context: 'Détection d\'une réplication d\'annuaire frauduleuse.' }
    ],

    debrief: {
      story: 'Le 2 septembre à 09h14, un agent du service urbanisme consulte un faux portail de marchés publics et ouvre l\'archive téléchargée. Une commande PowerShell encodée dépose wupsvc.exe dans son profil et crée une clé de démarrage. Une balise part vers cdn-mairie-updates.test. Le 3, reconnaissance : groupes du domaine, liste des contrôleurs, puis 2 480 objets énumérés en LDAP en six minutes — de quoi repérer que le compte de service svc_app porte, par héritage de configuration, des droits de réplication d\'annuaire. Le 4 à 02h39, quatorze demandes de tickets de service en RC4 en neuf secondes : le mot de passe de svc_app est cassé hors ligne. Le 5 au soir, svc_app s\'authentifie depuis le poste de l\'agent. Le 6 à 01h33, ce poste bureautique demande une réplication de l\'annuaire et lit le secret du compte krbtgt. Le 8 à 03h02, des tickets sont obtenus pour adm_maintenance, un compte qui n\'existe pas : le ticket est forgé. Avec lui, 27 516 fichiers d\'état civil et d\'urbanisme sont lus, archivés en trois volumes, et neuf gigaoctets partent vers depot-archives-eu.test entre 03h41 et 05h25. Le 9, le CERT régional prévient la ville. Rien n\'a été chiffré, aucun service n\'a été interrompu.',
      lessons: [
        'La montée en privilèges n\'a exploité aucune vulnérabilité : un compte de service portait des droits de réplication hérités d\'une migration ancienne. L\'énumération LDAP de l\'attaquant a fait l\'audit de droits que la collectivité n\'avait jamais fait.',
        'Le DCSync ne laisse ni processus, ni fichier, ni connexion à la base de l\'annuaire. Sans l\'audit des accès aux objets et sans connaître les identifiants de droits étendus, l\'évènement le plus grave du dossier passe pour une ligne banale.',
        'Un 4769 sans 4768 pour un compte absent de l\'annuaire : deux anomalies dans une seule ligne, et la démonstration du ticket forgé. C\'est la détection qui distingue un vol de compte d\'une compromission de domaine.',
        'Neuf gigaoctets sortis d\'un poste qui en émet 81 Mo par jour, sans qu\'aucun seuil ne se déclenche. La supervision de volumétrie sortante par machine est la mesure la moins coûteuse et la plus efficace à recommander ici.',
        'La conclusion la plus lourde du rapport — la rotation double du secret krbtgt et la reconstruction des droits — doit être énoncée fermement. Un rapport qui reste prudent sur ce point laisse le client avec un domaine qui reste ouvert.'
      ],
      pitfalls: [
        'S\'arrêter à la compromission de svc_app et recommander sa seule réinitialisation : le ticket forgé fonctionne indépendamment de tout mot de passe.',
        'Conclure que le second contrôleur de domaine est sain et peut servir de référence : les deux partagent la même base d\'annuaire, donc le même secret krbtgt.',
        'Confondre le chiffrement RC4 du kerberoasting du 4 septembre avec les tickets forgés du 8, qui sont en AES.',
        'Confondre le domaine de commande et celui d\'exfiltration, et donner au CERT une liste d\'indicateurs incomplète.',
        'Compter la consultation métier du partage Urbanisme du 4 septembre en journée parmi les accès frauduleux : 34 fichiers, en heure ouvrée, sous le compte de l\'agent.'
      ]
    }
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
