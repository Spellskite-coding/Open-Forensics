# Politique de sécurité

Open-Forensics est un outil de formation à la sécurité : il serait malvenu qu'il en soit un
mauvais exemple. Les invariants ci-dessous sont vérifiés par la suite de tests et par les
contrôles statiques du dépôt.

## Invariants du projet

* Aucune dépendance tierce, aucune ressource distante, aucune police externe.
* Aucun appel réseau possible : la politique de sécurité du contenu déclare
  `default-src 'none'` et `connect-src 'none'`.
* Aucune écriture de balisage : le DOM est construit uniquement par `createElement` et
  `textContent`, y compris le surlignage des occurrences de recherche. Ni `innerHTML`, ni
  `eval`, ni `new Function`.
* La fabrique d'éléments `util.el()` refuse par construction tout attribut `on*` ainsi que
  `style`, `href`, `src`, `srcdoc`, `action`, `formaction`, `ping` et `background`.
* Le stockage local se limite à la progression par dossier ; il est validé, typé et borné à
  la relecture, et son indisponibilité n'empêche pas l'application de fonctionner. Aucune
  réponse rédigée n'y est conservée.
* Aucune donnée ne quitte le navigateur.

## Environnement fictif

Aucune organisation, personne, machine, adresse ou empreinte de ce dépôt n'existe. Les
adresses IP appartiennent aux plages réservées à la documentation (RFC 5737) et les domaines
aux TLD réservés `.test`, `.invalid` et `.example` (RFC 2606).

## Signaler un problème

Ouvrez une issue décrivant le problème, le navigateur utilisé et sa version. Si la faille
permettrait d'exécuter du code arbitraire dans le navigateur d'un utilisateur, indiquez-le
clairement dans le titre afin qu'elle soit traitée en priorité.
