# Open-Forensics

**Simulateur d'investigation numérique pour la formation des analystes CERT et DFIR.** Dix
dossiers d'incident, uniquement des journaux, quinze mille lignes à éplucher. On vous remet
ce que le client a su collecter, et vous devez établir les faits, reconstituer ce que
l'attaquant a fait, et le démontrer.

Application **statique** : trois fichiers ouverts dans un navigateur suffisent. Aucune
dépendance, aucun serveur, aucune connexion réseau, aucune donnée transmise.

Application compagnon d'[Open-SOC](https://github.com/) : là où Open-SOC entraîne la
décision sous pression, Open-Forensics entraîne la reconstitution méthodique.

---

## Démarrer

```bash
git clone <votre-dépôt> Open-Forensics
cd Open-Forensics
```

Puis, au choix :

* ouvrir `index.html` directement dans le navigateur, ou
* servir le dossier localement, recommandé pour un usage en salle :

```bash
python3 -m http.server 8000
# puis http://localhost:8000/
```

La suite de tests s'ouvre de la même façon : `tests/run.html`. Elle s'exécute dans le
navigateur et affiche `TOUS LES TESTS PASSENT` ou la liste des échecs. Aucun outil externe,
aucun `npm install`.

---

## Le déroulé d'un dossier

**1. Le briefing.** La saisine du client, le périmètre technique, les conditions de collecte
et surtout **les limites** : quels journaux manquent, sur quelle période, et pourquoi. Un
journal absent est une limite d'investigation à documenter, pas une excuse. À l'inverse, un
journal présent et couvrant la période permet de conclure à une absence — et c'est souvent
la conclusion la plus lourde de conséquences.

**2. Les journaux.** Il n'y a que cela : pas d'image disque, pas de capture mémoire. Chaque
pièce est un flux d'évènements horodatés, où les quelques lignes utiles sont noyées dans
l'activité normale du client. Le volet de gauche offre une **recherche transverse** qui
cherche la même chaîne dans toutes les pièces : c'est ainsi qu'on suit une adresse, un
compte ou un nom de fichier d'un journal à l'autre. Chaque pièce dispose en plus de son
propre filtre, avec surlignage des occurrences.

**3. Les constatations.** Une dizaine de questions factuelles par dossier, validées une par
une comme des drapeaux : adresse de l'attaquant, compte compromis, horodatage du point
d'entrée, empreinte du binaire, volume exfiltré, portée réelle de la compromission. Les
réponses sont normalisées avec indulgence — casse, accents, séparateurs de milliers,
horodatages français ou ISO, indicateurs « défangués » (`hxxp://`, `[.]`) sont acceptés.

**4. La chaîne d'attaque.** Pour chacune des douze tactiques ATT&CK, vous désignez
l'évènement du dossier qui la démontre et la technique correspondante. Le vivier
d'évènements contient aussi de l'activité légitime : tout n'est pas à placer. Et **déclarer
qu'une tactique n'a pas été observée rapporte autant de points que d'en trouver une** :
affirmer qu'il n'y a pas eu d'exfiltration, quand les journaux permettent de le démontrer,
est un résultat d'investigation.

**5. La synthèse.** Le livrable du CERT, noté sur sa longueur et sur les indicateurs du
dossier qu'il cite. Un rapport qui n'apporte aucune preuve à l'appui de ses affirmations
n'est pas exploitable.

**On peut clore à tout moment**, sans avoir tout trouvé. Le score sera partiel, le
débriefing sera entier.

---

## Les dix dossiers

| | Dossier | Difficulté | Durée estimée | Constatations | Lignes de journaux |
|---|---|---|---|---|---|
| CAS-01 | Rançongiciel via RDP exposé — transporteur | facile | 35 min | 11 | 1 220 |
| CAS-02 | Virement détourné après vol de session — cabinet d'avocats | facile | 45 min | 11 | 1 150 |
| CAS-03 | Fuite de plans avant un départ — bureau d'études | facile | 40 min | 10 | 1 003 |
| CAS-04 | Webshell et vol de base clients — boutique en ligne | moyen | 60 min | 12 | 1 421 |
| CAS-05 | Mise à jour téléchargée sur un faux miroir — industrie | moyen | 55 min | 12 | 1 572 |
| CAS-06 | Minage sur la chaîne d'intégration — éditeur logiciel | moyen | 55 min | 12 | 1 493 |
| CAS-07 | Fournisseur fictif dans l'ERP — cabinet comptable | moyen | 60 min | 12 | 1 441 |
| CAS-08 | DCSync et ticket doré — collectivité | difficile | 110 min | 16 | 2 163 |
| CAS-09 | Journaux effacés et horodatages falsifiés — fintech | difficile | 100 min | 15 | 2 002 |
| CAS-10 | Chiffrement de l'hyperviseur — centre hospitalier | difficile | 95 min | 15 | 1 888 |

Environ **onze heures d'investigation**, 126 constatations, 120 tactiques à qualifier et
15 353 lignes de journaux — dont moins de 3 % portent l'attaque. La difficulté augmente la
subtilité des cas, le nombre de sources à recouper et la durée : un dossier difficile
demande deux heures et refuse de se laisser résoudre par une seule recherche.

Chaque dossier comporte au moins deux tactiques non observées, et plusieurs contiennent une
activité légitime qui ressemble à s'y méprendre à l'attaque — un collègue qui branche une
clé USB, une opération comptable régulière, un développeur qui clone un dépôt. Les écarter
explicitement fait partie du travail.

> **Formateurs :** la vérité terrain vit dans `js/data/cas-*.js`. Chaque fichier porte un
> avertissement en tête. Demandez aux étudiants de ne pas les ouvrir avant d'avoir traité le
> dossier — c'est le seul moyen de tricher, et il est explicite.

---

## La notation

| Élément | Points |
|---|---|
| Constatation établie | 6 |
| Réponse erronée | −0,5, plafonné à −3 par constatation |
| Indice affiché | −2 |
| Évènement correct dans la chaîne d'attaque | 3 par tactique |
| Technique correcte dans la chaîne d'attaque | 1,5 par tactique |
| Synthèse | jusqu'à 8 (longueur, puis un et trois indicateurs cités) |

Le débriefing donne un score sur 100, une mention de A à E et quatre axes : établissement
des faits, reconstitution de la chaîne, restitution écrite, autonomie. Puis, pour **chaque**
constatation — trouvée ou non — la réponse attendue, la vôtre, **où elle se trouvait** dans
les pièces et **pourquoi elle comptait**. Idem pour chaque tactique de la chaîne. Le tout
suivi du récit réel de l'incident, des enseignements du dossier, de ses pièges, d'une fiche
d'indicateurs prête à transmettre à un SOC, et d'un rapport JSON exportable.

La progression — meilleur score et nombre de passages par dossier — est conservée dans le
`localStorage` du navigateur. Aucune réponse rédigée n'y est stockée.

---

## Le trafic de fond

Un journal réel n'est pas une liste de preuves. Les lignes utiles de chaque dossier sont
écrites à la main ; tout le reste est engendré par quinze générateurs de trafic normal
(`js/data/bruit.js`) : authentifications Windows, télémétrie de processus, agent de
sécurité, pare-feu, mandataire web, résolutions DNS, fédération d'identité, messagerie,
journaux Unix, serveur web, accès distant, plateforme collaborative, base de données,
chaîne d'intégration, hyperviseur.

Ce bruit est **déterministe** : la graine dérive de l'identifiant du dossier et de celui de
la pièce. Deux ouvertures du même dossier donnent exactement le même journal, ligne pour
ligne, ce qui permet à un formateur de préparer une correction et à deux étudiants de
comparer leurs démarches sur des pièces identiques.

---

## Posture de sécurité

* **Aucune dépendance.** Zéro bibliothèque tierce, zéro ressource distante, zéro police
  externe.
* **Aucun réseau.** `connect-src 'none'` : la page ne peut pas émettre de requête. Elle
  fonctionne en environnement isolé.
* **Politique de sécurité du contenu stricte**, déclarée dans `index.html` :
  `default-src 'none'`, scripts et styles limités à l'origine, ni script ni style en ligne,
  `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`.
* **Aucune injection possible.** Le DOM est construit exclusivement par `createElement` et
  `textContent` — y compris le surlignage des résultats de recherche. Il n'y a pas une seule
  occurrence de `innerHTML`, `eval` ou `new Function` dans le code.
* **Fabrique d'éléments verrouillée.** `util.el()` refuse par construction tout attribut
  `on*` ainsi que `style`, `href`, `src`, `srcdoc`, `action`, `formaction`, `ping` et
  `background`.
* **Stockage local validé à la relecture**, borné en taille et en nombre d'entrées ; un
  stockage indisponible n'empêche pas l'application de fonctionner.
* **Compatibilité.** JavaScript ES5 strict, sans syntaxe moderne ni promesse. `Math.imul`
  dispose d'un repli, `crypto` et `localStorage` sont encapsulés, `:focus-visible` est
  précédé d'une règle de repli. Firefox, Chrome, Edge, Safari, en version de bureau comme en
  `file://`.

### Tout est fictif

Aucune organisation, personne, machine, adresse ou empreinte de ce dépôt n'existe. Les
adresses IP appartiennent aux plages réservées à la documentation (RFC 5737 : `192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) et les domaines aux TLD réservés `.test`, `.invalid` et
`.example` (RFC 2606). Aucun indicateur de ce simulateur ne peut donc désigner une ressource
réelle, et les journaux d'exercice ne pollueront pas une plateforme de renseignement si un
étudiant les recopie par mégarde.

---

## Structure

```
index.html               Page unique, politique de sécurité du contenu
css/openforensics.css    Feuille de style unique, thème sombre
js/util.js               DOM sûr, aléatoire déterministe, formatage
js/data/referentiel.js   Tactiques et techniques ATT&CK, barème, natures de pièces
js/data/bruit.js         Quinze générateurs de trafic de fond
js/data/cas-01..10.js    Les dix dossiers et leur vérité terrain (SPOILERS)
js/engine.js             Journaux, recherche, constatations, notation (sans DOM)
js/ui.js                 Rendu et interactions
js/app.js                Amorçage et filet de sécurité
tests/run.html           Suite de tests exécutable dans le navigateur
tests/tests.js           59 assertions : normalisation, intégrité, volumétrie, notation
```

Le moteur ne touche jamais au DOM : c'est ce qui permet aux tests de rejouer des
investigations complètes — parfaite, abandonnée, partielle, entièrement assistée — et de
vérifier que la notation les sépare correctement.

---

## Ajouter un dossier

Créez `js/data/cas-11.js` sur le modèle des autres et déclarez-le dans `index.html` et dans
`tests/run.html`. Le contrat est vérifié automatiquement par la suite de tests :

* chaque pièce est un journal, avec des lignes `{ t, m }` horodatées `YYYY-MM-DD HH:MM:SS` et
  une ou plusieurs spécifications de bruit renvoyant à une famille existante ;
* chaque constatation porte un `hint`, un `where` et un `why`, et sa réponse doit se valider
  elle-même après normalisation — de même que chacune de ses variantes acceptées ;
* la chaîne couvre les douze tactiques, sans doublon, chaque technique appartenant bien à la
  tactique de sa ligne, avec entre deux et neuf tactiques non observées ;
* les indicateurs clés cités dans `keyIndicators` doivent réellement apparaître dans les
  journaux engendrés ;
* le volume de journaux et le nombre de constatations doivent correspondre à la difficulté
  déclarée, et les lignes utiles rester sous 12 % du total.

Ouvrez `tests/run.html` : tout écart est signalé nommément.

---

## Licence

MIT — voir [LICENSE](LICENSE). Utilisation libre en centre de formation, en école ou en
interne.
