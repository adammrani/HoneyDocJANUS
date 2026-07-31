# Génération multi-format JANUS

## État implémenté

| Format | Scénario | Génération | Détection automatique actuelle |
|---|---|---|---|
| DOCX | finance, RH, technique | narration IA + couches JANUS | Wazuh + beacon document si configuré |
| XLSX | comptabilité financière | synthèse IA + écritures calculées | Wazuh + beacon Excel |

Le classeur XLSX ne contient aucune macro. Il contient une image transparente
dont la relation OOXML cible l'URL unique du token `msexcel`. Microsoft Excel
contacte cette ressource à l'ouverture, ce qui déclenche la notification
Canarytokens. Si le fournisseur est indisponible, la même relation pointe vers
le beacon local JANUS.

## Responsabilités du pipeline

1. Le LLM rédige la synthèse et adapte le ton au corpus.
2. Le générateur métier produit des données financières cohérentes.
3. Le validateur refuse toute pièce dont le débit diffère du crédit.
4. Le rendu XLSX ajoute formules, tableaux, formats et graphique.
5. Le déployeur calcule SHA-256, copie dans `data/shared` et enregistre SQLite.
6. La SACL héritée permet à Wazuh de surveiller tous les formats du dossier.

## Métadonnées persistées

Les colonnes `file_format`, `scenario`, `sha256` et `generator_version` sont
ajoutées automatiquement à une base existante. La migration est additive et ne
supprime aucune ligne historique.

## Canarytoken Excel natif

Le mécanisme n'est pas un simple hyperlien visible. Le ZIP OOXML contient une
relation d'image `TargetMode="External"`, identique au principe du modèle
Microsoft Excel public de Canarytokens. Un contrôle automatique refuse le
fichier si cette relation manque ou si une partie VBA est détectée.

La détection reste composée de deux couches indépendantes :

1. Wazuh/SACL détecte les opérations locales dans `data/shared`.
2. Canarytokens détecte l'ouverture dans Microsoft Excel, y compris après copie
   du fichier sur une autre machine disposant d'un accès Internet.
