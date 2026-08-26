# mTLS Certificate Manager

Ein schlankes Admin-Webinterface zur Verwaltung von Client-Zertifikaten für
ein mTLS-Setup. Läuft als einzelner Docker-Container, keine Datenbank — alle
Metadaten liegen als YAML-Dateien unter `data/`, alle Krypto-Artefakte
(CA-Zertifikat/-Key, ausgestellte Zertifikate/Keys) unter `pki/`.

## Tech-Stack

- Node.js 22 LTS, Express
- Server-seitiges Rendering mit EJS, keine Client-Framework/SPA
- YAML-Persistenz über `js-yaml`
- Kryptografie: Node's `crypto`-Modul + [`node-forge`](https://github.com/digitalbazaar/forge) für X.509-Zertifikats-, CRL- und PKCS#12-Konstruktion (siehe Design-Entscheidungen unten)
- `argon2` (Argon2id) für Passwort-Hashing und Schlüsselableitung

## Design-Entscheidungen

Ein paar Punkte, an denen die Aufgabenstellung bewusst Spielraum ließ oder wo
sich beim Bauen eine Design-Entscheidung als nötig herausstellte:

**Schlüsseltyp: RSA statt ECDSA.**
Node's `crypto`-Modul kann zwar Schlüsselpaare erzeugen und roh signieren,
aber keine X.509-Zertifikate oder CRLs mit Extensions *konstruieren* — dafür
gibt es keine native API. Das übernimmt hier `node-forge` (reine JS-Bibliothek,
kein externes CA-Tool/Binary). Forges Zertifikats-/PKCS#12-Code ist für RSA
ausgereift und gut getestet, die ECDSA-Unterstützung dagegen dünn. Daher: RSA
statt ECDSA. Die CA nutzt RSA-4096 (einmalig erzeugt, langlebig), ausgestellte
Nutzer-Zertifikate RSA-2048 (kurzlebiger, dafür deutlich schneller erzeugt —
relevant, weil `node-forge`'s Schlüsselerzeugung reines JS ist, kein
OpenSSL-Binding, und ein Admin "Neu ausstellen" öfter klickt als die CA neu
aufzusetzen).

**CRL-Konstruktion.**
`node-forge` hat *keine* CRL-API (nur Zertifikate/CSRs/PKCS#12). Die CRL wird
daher händisch nach RFC 5280 aus forges Low-Level-ASN.1-Bausteinen
zusammengesetzt (`src/services/pki.js`, Funktion `buildCrl`) — mit denselben
Bausteinen, die forge intern für Zertifikate verwendet. Verifiziert gegen
OpenSSL (`openssl crl -in crl.pem -CAfile ca.crt -noout` → `verify OK`).

**CRL-Gültigkeit (`nextUpdate`): 7 Tage, konfigurierbar über `CRL_VALIDITY_DAYS`.**
Es gibt keinen CRL-Distribution-Point/Auto-Refresh — der Export ist ein
manueller Klick. `nextUpdate` ist damit im Kern die Antwort auf "wie oft muss
ein Admin die CRL neu exportieren, bevor sie als veraltet gilt". 7 Tage sind
ein vernünftiger Mittelweg zwischen Pflegeaufwand und Frische. Strikte
CRL-Validatoren (nicht alle, aber z. B. `openssl verify -crl_check strict`)
behandeln eine abgelaufene CRL als ungültig und können dann *alle* mTLS-Handshakes
verweigern, nicht nur die des widerrufenen Zertifikats — regelmäßiger Re-Export
ist also relevant.

**CRL-Reason-Codes.** `reissued` → `superseded` (4), `manually_deactivated` →
`privilegeWithdrawn` (9) — passt inhaltlich besser als `cessationOfOperation`,
das für "CA stellt Betrieb ein" gedacht ist.

**Export-Passwort für .p12-Dateien.** Wird serverseitig zufällig generiert
(20 Zeichen, `crypto.randomBytes`-basiert) und einmalig zusammen mit dem
Download-Link angezeigt — nicht vom Admin frei wählbar, nicht gespeichert.

**GoKapi-API.** Gegen den tatsächlichen Quellcode
([Forceu/Gokapi](https://github.com/Forceu/Gokapi)) verifiziert:
`POST {GOKAPI_API_URL}/api/files/add`, Header `apikey`, Multipart-Felder
`file`, `allowedDownloads`, `expiryDays`, `password`. Antwort:
`{ Result: "OK", FileInfo: { UrlDownload, ... } }`. Wichtige Einschränkung:
GoKapis API kennt nur ganztägige Ablaufzeiten (`expiryDays`, keine Stunden) —
`GOKAPI_SHARE_EXPIRY_HOURS` wird daher auf ganze Tage aufgerundet
(Default 48h → 2 Tage).

**Session-Store.** `express-session` läuft mit dem eingebauten
In-Memory-Store (keine Datenbank, kein Redis). Für einen einzelnen,
nicht horizontal skalierten Admin-Container ist das ein akzeptabler
Kompromiss — die einzige Konsequenz ist, dass alle Sessions bei einem
Container-Neustart verloren gehen (erneuter Login nötig). Die
Node-eigene Warnung dazu beim Start ist bekannt und unbedenklich.

## Sicherheitsmodell (Kurzfassung)

- Das Admin-Login-Passwort dient zwei Zwecken: (a) Argon2id-Hash zur
  Login-Prüfung, (b) via Argon2id mit eigenem Salt abgeleiteter AES-256-Schlüssel
  zur Verschlüsselung von `ca.key` und allen Zertifikats-Keys (AES-256-GCM).
  Es gibt kein zweites Master-Passwort.
- Der abgeleitete Schlüssel wird nie in der Session gecacht — jede
  Operation, die ihn braucht (Zertifikat ausstellen, CRL exportieren,
  Zertifikat versenden), fragt das Passwort erneut ab und hält den
  Schlüssel nur für die Dauer der jeweiligen Anfrage im Speicher.
- `ca.key` und alle Nutzer-Keys liegen nie unverschlüsselt auf Platte.
- CSRF-Schutz (Synchronizer-Token) auf allen Formularen, `httpOnly` +
  `sameSite=strict` Session-Cookie, `secure` automatisch bei HTTPS.
- Rate-Limiting auf `/login` (10 Versuche / 15 min pro IP) zusätzlich zur
  permanenten Account-Sperre nach 3 Fehlversuchen.
- `GOKAPI_API_KEY` wird nie geloggt und nie in eine YAML-Datei geschrieben.

## Ersteinrichtung

1. Container starten (siehe unten). Beim allerersten Aufruf von `/` (kein
   `data/admin.yml` vorhanden) erscheint automatisch der Setup-Wizard.
2. **Schritt 1:** Admin-Benutzername + Passwort festlegen (mind. 12 Zeichen —
   das Passwort schützt später auch die privaten Schlüssel).
3. **Schritt 2:** Organisationsname eingeben, Passwort aus Schritt 1 erneut
   eingeben → die CA wird erzeugt (`pki/ca.crt` unverschlüsselt zur
   Verteilung, `pki/ca.key.enc` verschlüsselt). `ca.crt` an den
   TLS-terminierenden Reverse-Proxy (z. B. Nginx Proxy Manager) verteilen,
   damit dieser Client-Zertifikate gegen diese CA prüfen kann.
4. Danach ganz normaler Login-Screen für alle weiteren Zugriffe.

## Admin-Konto entsperren

Nach 3 Fehlversuchen wird das Konto **permanent** gesperrt (kein
automatisches Entsperren nach Zeitablauf). Entsperren geht nur manuell:

```bash
docker exec -it mtls-certificate-manager node cli.js unlock-admin
```

Alternativ direkt in `data/admin.yml` `locked: false` setzen und
`failedAttempts: 0` — das CLI-Kommando macht genau das, atomar.

## Umgebungsvariablen

| Variable | Default | Beschreibung |
|---|---|---|
| `PORT` | `3000` | Port der Web-UI |
| `PUID` / `PGID` | `1000` / `1000` | User/Group-ID, unter der der Node-Prozess im Container läuft (linuxserver.io-Muster) — wichtig für korrekte Dateirechte auf `data/`/`pki/` |
| `CERT_VALIDITY_DAYS` | `365` | Gültigkeitsdauer neu ausgestellter Zertifikate |
| `CRL_VALIDITY_DAYS` | `7` | Wie lange eine exportierte CRL gültig ist (`nextUpdate`) |
| `CA_VALIDITY_DAYS` | `3650` | Gültigkeitsdauer des CA-Zertifikats (nur bei Ersteinrichtung relevant) |
| `GOKAPI_API_URL` | — | Basis-URL der GoKapi-Instanz, z. B. `https://files.example.com` |
| `GOKAPI_API_KEY` | — | GoKapi-API-Key. **Nur** per Env-Var/Docker-Secret, nie in YAML, nie geloggt |
| `GOKAPI_SHARE_EXPIRY_HOURS` | `48` | Ablaufzeit des Einmal-Links (wird von GoKapis API auf ganze Tage aufgerundet) |
| `GOKAPI_SHARE_MAX_DOWNLOADS` | `1` | Erlaubte Downloads für den Einmal-Link |
| `SESSION_SECRET` | *(auto-generiert)* | Optional; falls nicht gesetzt, wird ein Secret einmalig generiert und in `data/config.yml` persistiert |

## Volumes

| Pfad im Container | Inhalt |
|---|---|
| `/app/data` | `admin.yml`, `users.yml`, `revoked.yml`, `config.yml` |
| `/app/pki` | `ca.crt`, `ca.key.enc`, `crl.pem`, `certs/<user-id>/<serial>.{crt.pem,key.enc}` |

## Docker

```bash
cp .env.example .env   # GOKAPI_API_KEY eintragen
docker compose up -d --build
```

Siehe `docker-compose.yml` für alle Optionen. Das Image baut `argon2` (native
Node-Addon) in einer separaten Build-Stage, damit das Laufzeit-Image keinen
C-Compiler enthalten muss.

## Backup

Für ein vollständiges Backup genügen zwei Verzeichnisse:

- **`data/`** — alle Metadaten (Nutzerliste, Sperrliste, Admin-Konto, Config)
- **`pki/`** — CA-Zertifikat/-Key und alle ausgestellten Zertifikate/Keys

Ohne `pki/ca.key.enc` kann die CA nicht mehr zum Signieren neuer Zertifikate
oder CRLs verwendet werden — es gibt keinen Wiederherstellungsweg dafür außer
einem Backup oder einer komplett neuen CA (was alle bestehenden
Client-Zertifikate ungültig macht, da sie gegen die alte CA signiert sind).
Beide Verzeichnisse regelmäßig gemeinsam sichern.

## CLI-Referenz

```bash
node cli.js unlock-admin   # Admin-Konto manuell entsperren
```
