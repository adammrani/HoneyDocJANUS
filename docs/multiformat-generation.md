# Génération multi-format JANUS

## Formats réellement implémentés

| Type de leurre | Formats | Canarytoken officiel | Déclencheur distant |
|---|---|---|---|
| `financial_report` | DOCX, XLSX, CSV, JSON | `ms_word`, `ms_excel` ou `web` selon le format | contenu Office externe ou utilisation volontaire du lien |
| `hr_document` | DOCX, CSV, JSON | `ms_word` ou `web` | contenu Office externe ou utilisation volontaire du lien |
| `technical_config` | DOCX, ENV, YAML, JSON, ZIP | `ms_word` ou `web` | contenu Office externe ou utilisation volontaire du lien |
| `cloud_credentials` | ENV, YAML, JSON, ZIP | `aws_keys` | présentation des clés à une API AWS |

Tous les formats déployés dans `data/shared` sont aussi surveillés localement
par la SACL Windows et Wazuh. Aucun document ne contient de macro.

## Responsabilités du pipeline

1. `context_analyzer.py` construit un prompt métier sans transmettre le chemin
   local de déploiement au fournisseur IA.
2. `llm_engine.py` produit une synthèse ou utilise le contenu métier local.
3. Le contrôle anti-divulgation refuse les mots révélant le leurre, les chemins
   sensibles et les marqueurs JANUS avant toute création de token.
4. `canarytoken_handler.py` choisit le token selon le scénario et le format.
5. `document_assembler.py`, `accounting_workbook.py` ou
   `structured_decoy.py` assemble l'artefact.
6. Les contrôles structurels refusent les macros, relations externes manquantes
   ou URLs inattendues.
7. `injector.py` déploie atomiquement le fichier, calcule SHA-256 et enregistre
   le HoneyDoc et son token dans SQLite.

Le token distant est créé seulement après la validation du contenu IA. Avec
`CANARYTOKEN_FAIL_CLOSED=true`, une configuration absente ou une panne du
fournisseur interrompt la génération avant le déploiement.

## DOCX et XLSX

Les artefacts Office utilisent les types API `ms_word` et `ms_excel`. Le paquet
OOXML contient une seule relation externe attendue et aucune partie VBA. Office
peut contacter cette ressource à l'ouverture, mais une politique de sécurité, le
mode protégé ou le réseau peut la bloquer. Wazuh reste donc une couche
indépendante pour les accès sur la machine surveillée.

## Leurres AWS

Les fichiers ENV, YAML, JSON et ZIP du scénario `cloud_credentials` contiennent
exactement `aws_access_key_id`, `aws_secret_access_key` et la région renvoyés par
le Canarytoken `aws_keys`. JANUS ne fabrique pas de fausse alerte :

- lire le fichier sur la machine surveillée produit un événement Wazuh ;
- copier ou ouvrir le fichier hors de la machine surveillée ne produit pas à lui
  seul d'alerte Canarytokens ;
- utiliser les clés avec une API AWS déclenche la notification du fournisseur ;
- les clés ne donnent accès à aucune ressource AWS réelle.

L'artefact ne contient ni URL locale, ni chemin Windows, ni mot `JANUS`,
`HoneyDoc`, `Canarytoken` ou `cyberdéception`.

## Métadonnées persistées

Chaque ligne HoneyDoc contient au minimum le format, le scénario, le chemin,
l'empreinte SHA-256 et la version du générateur. La table des tokens conserve le
fournisseur, le type, le mode d'activation et la donnée de gestion nécessaire à
la révocation. Les secrets de configuration restent dans `.env`, exclu de Git.
