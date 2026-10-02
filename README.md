# HelpDesk ESIEA — application volontairement vulnérable

> ⚠️ **Application pédagogique volontairement vulnérable.** Ne jamais l'exposer sur Internet ni la déployer en production.

Projet du TP *Pratiques proactives de sécurité web* (ESIEA). Petite application de ticketing en Python/Flask
(code généré avec l'aide d'une IA, ce qui est autorisé dans le cadre du TP) servant de cible pour :

- **CodeQL** (analyse statique du code),
- **Dependabot** (dépendances obsolètes/vulnérables),
- **Trivy** (scan de l'image Docker),
- le futur mini-CTF (injection SQL, upload de fichier, exécution de commande).

## Lancer l'application

```bash
docker build -t helpdesk-esiea .
docker run --rm -p 5000:5000 helpdesk-esiea
```

Puis ouvrir <http://localhost:5000>. Comptes de démo : `admin` / `admin123` et `alice` / `password1`.

## Fonctionnalités

Inscription/connexion, tickets et commentaires, recherche, pièces jointes, aperçu de lien,
import YAML/Pickle, diagnostic réseau (admin).

## Vulnérabilités

La liste complète (volontaire) est dans [VULNERABILITIES.md](VULNERABILITIES.md).
