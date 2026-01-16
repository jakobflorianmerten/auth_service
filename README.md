# Auth Service

Ein Spring Boot Authentifizierungs-Service mit folgenden Features:

- **JWT-basierte Authentifizierung** mit Access- und Refresh-Tokens (RS256)
- **Benutzerregistrierung** mit E-Mail-Verifizierung (6-stelliger Code)
- **Passwort-Reset-Funktionalität** via E-Mail
- **Google OAuth2 Integration** für Social Login
- **JWKS-Endpoint** zur Token-Validierung durch andere Services

## API-Endpoints

| Endpoint | Methode | Beschreibung |
|----------|---------|--------------|
| `/login` | POST | Benutzeranmeldung mit E-Mail/Passwort |
| `/register` | POST | Neue Benutzerregistrierung |
| `/refresh` | POST | Access-Token erneuern |
| `/logout` | POST | Refresh-Token widerrufen |
| `/verify-email` | POST | E-Mail-Adresse verifizieren |
| `/resend-verification-code` | POST | Neuen Verifizierungscode senden |
| `/request-password-reset` | POST | Passwort-Reset anfordern |
| `/reset-password` | POST | Passwort zurücksetzen |
| `/google` | POST | Google OAuth2 Anmeldung |
| `/.well-known/jwks.json` | GET | Public Key für Token-Validierung |

### Request-Bodies

#### POST /login
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

#### POST /register
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```
Das Passwort muss mindestens 8 Zeichen lang sein.

#### POST /refresh
Erfordert den Refresh-Token im Authorization-Header:
```
Authorization: Bearer <refresh_token>
```

#### POST /logout
Erfordert Authentifizierung via Access-Token.
```json
{
  "refreshToken": "<refresh_token>"
}
```

#### POST /verify-email
```json
{
  "code": "123456"
}
```
Der Code ist 6-stellig und wird per E-Mail gesendet.

#### POST /resend-verification-code
```json
{
  "email": "user@example.com"
}
```

#### POST /request-password-reset
```json
{
  "email": "user@example.com"
}
```

#### POST /reset-password
```json
{
  "code": "123456",
  "newPassword": "newpassword123"
}
```

#### POST /google
```json
{
  "idToken": "<google_id_token>"
}
```
Das ID-Token wird vom Google OAuth-Flow generiert.

### Response-Format

Erfolgreiche Authentifizierung gibt folgendes Format zurück:
```json
{
  "accessToken": "<jwt_access_token>",
  "refreshToken": "<refresh_token>",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

## Environment Variables

| Variable | Beschreibung |
|----------|--------------|
| `SPRING_DATASOURCE_URL` | PostgreSQL Verbindungs-URL (z.B. `jdbc:postgresql://localhost:5432/auth`) |
| `SPRING_DATASOURCE_USERNAME` | Datenbank-Benutzername |
| `SPRING_DATASOURCE_PASSWORD` | Datenbank-Passwort |
| `MAIL_HOST` | SMTP-Server Hostname |
| `MAIL_PORT` | SMTP-Port |
| `MAIL_USERNAME` | E-Mail-Benutzername |
| `MAIL_PASSWORD` | E-Mail-Passwort |
| `JWT_PRIVATE_KEY` | RSA Private Key (PEM-Format) |
| `JWT_PUBLIC_KEY` | RSA Public Key (PEM-Format) |

### Konfiguration in application.yaml

Zusätzlich müssen folgende Werte in `application.yaml` angepasst werden:

**Google OAuth2 Client IDs:**
```yaml
google:
  client-ids:
    - <ANDROID_CLIENT_ID>
    - <IOS_CLIENT_ID>
    - <WEB_CLIENT_ID>
```

**CORS Origins:**
```yaml
security:
  cors:
    allowed-origins:
      - https://your-frontend.com
      - https://your-app.com
```

## Produktionshinweise

Dieses Projekt ist **nicht produktionsreif**. Folgende Punkte sollten vor einem Produktionseinsatz adressiert werden:

- **Rate Limiting**: Aktuell deaktiviert (`security.rate-limiting.enabled: false`)
- **Weitere OAuth2 Provider**: Apple, GitHub, etc. fehlen noch
- **Festes Datenbankschema**: `ddl-auto: update` sollte durch Migrations (Flyway/Liquibase) ersetzt werden
- **Explizitere Security-Konfiguration**: Weitere Härtung der Endpoints
- **HTTPS/TLS**: Muss in der Produktionsumgebung konfiguriert werden
- **Secrets Management**: Vault, AWS Secrets Manager o.ä. statt Environment Variables
- **Logging und Monitoring**: Strukturiertes Logging, Metriken, Alerting
- **Token-Blacklisting**: Für sofortigen Logout (aktuell warten Access-Tokens bis zum Ablauf)
