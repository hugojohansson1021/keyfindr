# KeyFindr GUI — Plan

Plan för att bygga ett enkelt webbaserat GUI ovanpå de befintliga
Python-scripten i projektet. Målet är en lokal server med
cybersäkerhets-tema som kör alla verktyg och visar output live i en
inbyggd terminalvy.

## 1. Mål

- **Enkel onboarding.** Användaren ska kunna komma igång på fyra steg:
  1. Klona repot
  2. Skapa och aktivera `venv`
  3. `pip install -r requirements.txt`
  4. Starta lokal server (`python app.py`)
- **Alla verktyg i ett gränssnitt.** `keyFinder.py`,
  `find_hidden_pages.py`, `subdomain_spider.py` och
  `api_secret_scanner.py` ska kunna startas från webb-UI.
- **Live-terminal.** Stdout/stderr från det körande scriptet streamas
  direkt in i en terminalvy i webbläsaren, med autoscroll.
- **Cybersäkerhets-look.** Mörk bakgrund, monospace, neon-grön/cyan
  accentfärg. Enkelt nu — vi finslipar i en senare iteration.

## 2. Teknikval

| Lager      | Val                              | Motivering                                                              |
|------------|----------------------------------|--------------------------------------------------------------------------|
| Backend    | **Flask**                        | Minimalt, en fil, redan Python-only.                                     |
| Streaming  | **Server-Sent Events (SSE)**     | Enklare än WebSocket, perfekt för envägs-stdout till webbläsaren.        |
| Processer  | `subprocess.Popen` + tråd        | Vi kör script som subprocesser och läser stdout rad för rad.             |
| Frontend   | Vanilla HTML/CSS/JS              | Inga byggsteg, inget npm. Lätt att klona och köra direkt.                |
| Typsnitt   | Systemets monospace + Google Fonts (JetBrains Mono som fallback via CDN) | Cyber-känsla utan extra dependency. |

Inga nya Python-dependencies utöver `flask`. Inget Node, inget bundler-steg.

## 3. Filstruktur (nytt)

```
Keyfindr/
├── app.py                     # Flask-server: routes + subprocess-runner
├── gui/
│   ├── __init__.py
│   ├── runner.py              # ProcessRunner: startar/stoppar/streamar
│   └── tools.py               # Definitioner av varje verktyg + argument-schema
├── templates/
│   └── index.html             # Enda sidan i appen
├── static/
│   ├── css/styles.css         # Cyber-tema (mörk + neongrön)
│   └── js/app.js              # Form-hantering, SSE-prenumeration, terminal-render
├── requirements.txt           # + flask
├── GUI_PLAN.md                # (denna fil)
└── README.md                  # Uppdaterad med 4-stegs setup
```

Befintliga script rör vi inte. GUI:t kör dem som vanliga subprocesser
med samma argument som från terminalen.

## 4. Backend-design

### 4.1 Verktygsregister (`gui/tools.py`)

Varje verktyg beskrivs som ett dict med id, namn, script och fält. UI:t
renderas dynamiskt utifrån registret, så att lägga till ett nytt
verktyg = lägga till en post.

```python
TOOLS = {
    "keyfinder": {
        "name": "Hybrid Secret Scanner",
        "script": "keyFinder.py",
        "fields": [
            {"name": "url",          "flag": "--url",          "type": "text",   "required": True},
            {"name": "active",       "flag": "--active",       "type": "bool"},
            {"name": "max_pages",    "flag": "--max-pages",    "type": "int"},
            {"name": "max_js_files", "flag": "--max-js-files", "type": "int"},
        ],
    },
    "hidden_pages": { ... },
    "subdomain_spider": { ... },
    "api_secret_scanner": { ... },
}
```

### 4.2 ProcessRunner (`gui/runner.py`)

- En `ProcessRunner` per körning. Tilldelas ett `run_id` (UUID).
- Startar verktyget med `subprocess.Popen([sys.executable, script, *args],
  stdout=PIPE, stderr=STDOUT, bufsize=1, text=True)`.
- Bakgrundstråd läser stdout rad för rad och pushar till en
  `queue.Queue` per run.
- Buffrar dessutom de senaste N raderna så att en sen prenumerant
  fortfarande får tidig output.
- Stöder `stop()` (skickar SIGTERM, sedan SIGKILL efter timeout).
- Håller status: `running`, `exited(code)`, `killed`, `error`.

### 4.3 Endpoints (`app.py`)

| Metod | Path                       | Syfte                                     |
|-------|----------------------------|-------------------------------------------|
| GET   | `/`                        | Renderar `index.html`                     |
| GET   | `/api/tools`               | Returnerar TOOLS-registret som JSON       |
| POST  | `/api/runs`                | Startar en körning, returnerar `run_id`   |
| GET   | `/api/runs/<id>/stream`    | SSE-stream av stdout                      |
| POST  | `/api/runs/<id>/stop`      | Stoppar körningen                         |
| GET   | `/api/runs/<id>`           | Status + senaste buffer                   |
| GET   | `/api/reports`             | Listar filer under `reports/`             |

### 4.4 Säkerhet (lokal app, men ändå)

- Binder bara till `127.0.0.1`, inte `0.0.0.0`.
- Inga shell-strängar — alltid argument-listor till `Popen`.
- Argument valideras mot tool-schemat innan de skickas vidare.
- Tydlig disclaimer i UI:t: kör endast mot system du har tillstånd att testa.

## 5. Frontend-design

### 5.1 Layout

```
+-----------------------------------------------------------+
|  KEYFINDR                              ● local · v0.1     |  <- header, neongrön
+--------------------+--------------------------------------+
|  TOOLS             |  > keyfinder                         |
|  ▸ Hidden Pages    |  --------------------------------    |
|  ▸ Subdomain Spider|  URL          [ https://...      ]   |
|  ▸ Secret Scanner  |  --active     [x]                    |
|  ▸ API Scanner     |  --max-pages  [ 25  ]                |
|                    |                                      |
|  RECENT RUNS       |  [ RUN ]   [ STOP ]                  |
|  · keyfinder 14:02 |                                      |
|  · spider 13:48    |  ┌──────── TERMINAL ─────────────┐   |
|                    |  │ $ python keyFinder.py ...     │   |
|  REPORTS           |  │ [PASSIV] Hämtar https://...   │   |
|  · ...json         |  │ ...                           │   |
|                    |  └────────────────────────────────┘  |
+--------------------+--------------------------------------+
```

### 5.2 Tema

- Bakgrund: `#0b0f10`
- Panel: `#11181c`
- Accent: `#39ff14` (klassisk hacker-grön), sekundär `#00e5ff` (cyan)
- Text: `#d7e1d8`, dim `#7a8a7c`
- Monospace: `JetBrains Mono`, fallback `Menlo, Consolas, monospace`
- Subtil scanline-overlay (CSS gradient) — billig effekt, stor stilvinst.
- Knappar = ramad text utan fyllning, hover lyser grönt.

### 5.3 Terminal-komponent

- `<pre>` med fast höjd och `overflow-y: auto`.
- Varje SSE-event = en rad i pre-elementet.
- Autoscroll till botten om användaren redan är i botten (annars
  respekteras manuell scroll).
- Knappar: `Clear`, `Copy`, `Download .log`.

### 5.4 SSE-flöde i `app.js`

1. Användaren fyller i formulär, klickar **RUN**.
2. `POST /api/runs` → får tillbaka `run_id`.
3. Öppnar `new EventSource('/api/runs/<id>/stream')`.
4. På `message` → append rad till terminalen.
5. På `event: end` → markera körning som klar, stäng stream.

## 6. Implementationsordning

Inkrementell — varje steg ska gå att köra och testa innan nästa.

1. **Lägg till `flask` i `requirements.txt`**.
2. **`app.py` minimal**: en route som returnerar "hello" — verifiera att
   `python app.py` startar lokalt.
3. **`gui/tools.py` med ett verktyg** (`find_hidden_pages.py`, enklast).
4. **`gui/runner.py`** med start/stop/stream för ett enda jobb.
5. **`index.html` + `app.js` minimal**: formulär för det första
   verktyget + terminal-pre + SSE.
6. **Lägg till resterande verktyg** i registret.
7. **Sidopanel + recent runs + reports-listning**.
8. **Cyber-tema** (CSS) — gör det snyggt.
9. **Polering**: stop-knapp, copy/download, felmeddelanden, validering.

## 7. Setup som användaren ska gå igenom

Detta är hela onboarding-ytan efter GUI:t finns på plats:

```bash
git clone <repo-url> keyfindr
cd keyfindr
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Sista raden öppnar servern på `http://127.0.0.1:5000`. Inga andra steg.

> Notera: `playwright install chromium` behövs bara för `keyFinder.py`
> och `api_secret_scanner.py`. Vi visar en hjälpknapp i UI:t som kör
> det åt användaren första gången ett av de verktygen startas och
> Playwright saknar browser — istället för att tvinga in steget i
> onboardingen.

## 8. Öppna frågor (att besluta senare)

- Ska resultat-filer (under `reports/`) kunna förhandsvisas i UI:t,
  eller räcker det med en länk för nedladdning?
- Ska vi kunna köra flera scans parallellt, eller en i taget?
  (Förslag: tillåt parallellt — varje run har eget `run_id`, terminalen
  växlar mellan körningar via fliklist.)
- Autentisering? Eftersom servern bara binder till `127.0.0.1` är det
  inte kritiskt, men en enkel token vore lätt att lägga till.
- Persistens av tidigare runs efter omstart? (Förslag: nej i v1, allt
  är i minnet. Rapporterna på disk räcker som "historik".)
