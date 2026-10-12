# Vulnerable Notes App — Security Learning Project

A deliberately built-and-broken Flask app. Each feature was implemented
naively first, exploited, then fixed. Built to learn auth and access
control bug classes hands-on.

## Stack
Flask, SQLite, Werkzeug (password hashing), Flask-Limiter.

## Vulnerabilities built, exploited, and fixed

### 1. IDOR on notes (Broken Access Control)
- **Vuln:** `GET /notes/<id>` returned any note regardless of owner.
- **Impact:** Any authenticated user could read any other user's notes.
- **PoC:** Log in as User A, note User B's note id, request
  `GET /notes/<B's id>` with A's session → returns B's note.
- **Fix:** Added `AND owner_id = ?` to the query, scoped to the
  requester's session.

### 2. Forgeable session (weak secret key)
- **Vuln:** `app.secret_key = "dev"`, a hardcoded, guessable value.
- **Impact:** Anyone who guesses or finds the secret can forge a
  session cookie for any user id, full account takeover.
- **PoC:** Cracked with `flask-unsign --unsign --cookie "<cookie>"
  --wordlist wordlist.txt`, then forged a cookie for another user id
  with `flask-unsign --sign`.
- **Fix:** Secret key should be loaded from environment, no hardcoded
  fallback (`os.environ["SECRET_KEY"]`, fails loudly if unset).

### 3. Predictable password reset token
- **Vuln:** Reset token was `base64(timestamp)`, no randomness.
- **Impact:** Token could be reconstructed without ever receiving it,
  account takeover via password reset.
- **PoC:** `base64.b64decode(token)` reveals the exact timestamp used.
- **Fix:** `secrets.token_urlsafe(32)`, plus 10-minute expiry and
  single-use enforcement (`used` flag).

### 4. No rate limiting on login (brute force)
- **Vuln:** `/login` accepted unlimited attempts.
- **Impact:** Password brute forcing and credential stuffing.
- **PoC:** Burp Intruder against `/login`, unlimited attempts with no
  lockout or delay.
- **Fix:** Flask-Limiter, 5 attempts per minute on `/login`,
  `/register`, `/forgot-password`.

### 5. Username enumeration
- **Vuln:** Different responses for "no such user" vs "wrong password".
- **Impact:** Attacker can build a list of valid usernames to target.
- **PoC:** Burp Intruder on username, sorted by response length/status.
- **Fix:** Rate limited (full fix would unify messages/timing; noted
  as a known limitation below).

## Known limitations (not fixed, intentionally)
- Enumeration messages still differ (see above), rate limiting
  mitigates but doesn't eliminate this.
- IP-based rate limiting can be bypassed with IP rotation (proxies,
  botnets); no per-account lockout implemented.

## Setup
\`\`\`
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
flask --app app init-db
flask --app app run --debug
\`\`\`