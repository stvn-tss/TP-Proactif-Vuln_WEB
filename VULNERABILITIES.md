# Vulnérabilités volontaires

## Code (`app.py`) — cibles CodeQL / revue manuelle

| # | Vulnérabilité | Endpoint | Règle CodeQL attendue |
|---|---|---|---|
| 1 | Injection SQL (bypass d'authentification, ex. `admin'--`) | `POST /login` | `py/sql-injection` |
| 2 | Injection SQL (`UNION SELECT`) | `GET /search?q=` | `py/sql-injection` |
| 3 | Injection de commande (`; cat flag.txt`) | `POST /admin/diagnostic` | `py/command-line-injection` |
| 4 | Path traversal (`../flag.txt`) | `GET /download?file=` | `py/path-injection` |
| 5 | Upload de fichier non contrôlé (html/svg/nom de fichier) | `POST /upload` | `py/path-injection` |
| 6 | XSS réfléchi / stocké (`\|safe`) | `/search`, `/ticket/<id>` | — (templates) |
| 7 | SSRF | `GET /preview?url=` | `py/full-ssrf` |
| 8 | Désérialisation non sûre (pickle / `yaml.Loader`) | `POST /import` | `py/unsafe-deserialization` |
| 9 | Open redirect | `/login?next=` | `py/url-redirection` |
| 10 | Mode debug Flask actif (console Werkzeug) | `app.run(debug=True)` | `py/flask-debug` |
| 11 | Secret hardcodé, identifiants par défaut | `app.secret_key`, `admin/admin123` | — |
| 12 | Hash MD5 sans sel | `hash_password()` | `py/weak-sensitive-data-hashing` |
| 13 | Mot de passe en clair dans les logs | `/register` | `py/clear-text-logging-sensitive-data` |
| 14 | Contrôle d'accès côté client (cookie `role`), IDOR sur les tickets | `/admin/diagnostic`, `/ticket/<id>` | — |
| 15 | Absence de protection CSRF, fuite de stack trace | global | — |

## Dépendances (`requirements.txt`) — cibles Dependabot / Trivy

Versions volontairement anciennes : `Flask 1.1.1`, `Werkzeug 0.16.0`, `Jinja2 2.10.1`, `PyYAML 5.3`,
`requests 2.19.1`, `urllib3 1.23`, `idna 2.7`, `certifi 2018.8.24`, etc.

## Image Docker (`Dockerfile`) — cible Trivy

- Image de base `python:3.8-bookworm` (Python 3.8 en fin de vie, paquets système non à jour).
- Exécution en `root`, serveur de développement lancé en mode debug.

## Flags (pour le futur CTF)

- `FLAG{sqli_union_select_ftw}` : ticket privé de l'admin (injection SQL).
- `flag{rce_via_command_injection}` : `flag.txt` (injection de commande / path traversal).
