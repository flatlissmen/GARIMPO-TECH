import os
import base64
import hashlib
import secrets
import time
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
import requests
from flask import Flask, request, redirect, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
DATABASE_URL     = os.environ["DATABASE_URL"]
ML_CLIENT_ID     = os.environ["ML_CLIENT_ID"]
ML_CLIENT_SECRET = os.environ["ML_CLIENT_SECRET"]
ML_REDIRECT_URI  = os.environ["ML_REDIRECT_URI"]

ML_AUTH_URL  = "https://auth.mercadolivre.com.br/authorization"
ML_TOKEN_URL = "https://api.mercadolibre.com/oauth/token"
ML_API_BASE  = "https://api.mercadolibre.com"


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------
def get_conn():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Tabela de tokens
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ml_tokens (
            id SERIAL PRIMARY KEY,
            user_id BIGINT,
            access_token TEXT,
            refresh_token TEXT,
            token_type TEXT,
            expires_at BIGINT,
            scope TEXT,
            updated_at TIMESTAMPTZ DEFAULT now()
        )
    """)

    # Garante colunas / remove NOT NULL antigo do refresh_token
    for coldef in [
        "ADD COLUMN IF NOT EXISTS scope TEXT",
        "ADD COLUMN IF NOT EXISTS refresh_token TEXT",
        "ADD COLUMN IF NOT EXISTS token_type TEXT",
        "ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now()",
    ]:
        try:
            cur.execute(f"ALTER TABLE ml_tokens {coldef}")
        except Exception:
            conn.rollback()

    try:
        cur.execute("ALTER TABLE ml_tokens ALTER COLUMN refresh_token DROP NOT NULL")
    except Exception:
        conn.rollback()

    # Tabela para persistir o PKCE code_verifier entre /login e /callback,
    # indexado pelo state. Sobrevive a reinícios do Railway.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS oauth_pkce (
            state TEXT PRIMARY KEY,
            code_verifier TEXT NOT NULL,
            created_at BIGINT NOT NULL
        )
    """)

    conn.commit()
    cur.close()
    conn.close()


init_db()


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def gen_pkce_pair():
    verifier = _b64url(secrets.token_bytes(64))          # 43..128 chars
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def save_verifier(state: str, verifier: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO oauth_pkce (state, code_verifier, created_at) "
        "VALUES (%s, %s, %s) "
        "ON CONFLICT (state) DO UPDATE SET code_verifier = EXCLUDED.code_verifier, "
        "created_at = EXCLUDED.created_at",
        (state, verifier, int(time.time())),
    )
    conn.commit()
    cur.close()
    conn.close()


def pop_verifier(state: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT code_verifier FROM oauth_pkce WHERE state = %s", (state,))
    row = cur.fetchone()
    verifier = row[0] if row else None
    if row:
        cur.execute("DELETE FROM oauth_pkce WHERE state = %s", (state,))
    # limpeza de states antigos (>10 min)
    cur.execute("DELETE FROM oauth_pkce WHERE created_at < %s", (int(time.time()) - 600,))
    conn.commit()
    cur.close()
    conn.close()
    return verifier


# ---------------------------------------------------------------------------
# TOKEN storage
# ---------------------------------------------------------------------------
def save_tokens(data: dict):
    user_id       = data.get("user_id")
    access_token  = data.get("access_token")
    refresh_token = data.get("refresh_token")
    token_type    = data.get("token_type")
    scope         = data.get("scope")
    expires_in    = data.get("expires_in")
    expires_at    = int(time.time()) + int(expires_in) if expires_in else None

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO ml_tokens
            (user_id, access_token, refresh_token, token_type, expires_at, scope, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, now())
        """,
        (user_id, access_token, refresh_token, token_type, expires_at, scope),
    )
    conn.commit()
    cur.close()
    conn.close()


def get_latest_token():
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM ml_tokens ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return """
    <h1>GARIMPO TECH</h1>
    <ul>
      <li><a href="/login">Conectar Mercado Livre</a></li>
      <li><a href="/buscar?q=snow%20foam">Testar busca</a></li>
      <li><a href="/status">Status</a></li>
      <li><a href="/verificar-permissoes">Verificar permissões</a></li>
    </ul>
    """


@app.route("/login")
def login():
    state = secrets.token_urlsafe(24)
    verifier, challenge = gen_pkce_pair()
    save_verifier(state, verifier)

    params = {
        "response_type":         "code",
        "client_id":             ML_CLIENT_ID,
        "redirect_uri":          ML_REDIRECT_URI,
        "state":                 state,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    }
    query = "&".join(f"{k}={requests.utils.quote(str(v), safe='')}" for k, v in params.items())
    return redirect(f"{ML_AUTH_URL}?{query}")


@app.route("/oauth/callback")
def callback():
    code  = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    if error:
        return jsonify({"erro": error, "descricao": request.args.get("error_description")}), 400
    if not code:
        return jsonify({"erro": "sem code na resposta"}), 400

    verifier = pop_verifier(state) if state else None
    if not verifier:
        return jsonify({"erro": "code_verifier nao encontrado para este state (state invalido ou expirado)"}), 400

    payload = {
        "grant_type":    "authorization_code",
        "client_id":     ML_CLIENT_ID,
        "client_secret": ML_CLIENT_SECRET,
        "code":          code,
        "redirect_uri":  ML_REDIRECT_URI,
        "code_verifier": verifier,
    }
    resp = requests.post(
        ML_TOKEN_URL,
        data=payload,
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )

    # LOG BRUTO temporario para diagnostico (aparece nos logs do Railway)
    print("=== ML TOKEN RESPONSE STATUS:", resp.status_code)
    print("=== ML TOKEN RESPONSE BODY:", resp.text)

    if resp.status_code != 200:
        return jsonify({"erro": "falha na troca de token", "status": resp.status_code, "body": resp.text}), 400

    data = resp.json()
    save_tokens(data)

    return jsonify({
        "ok": True,
        "user_id":       data.get("user_id"),
        "access_token":  bool(data.get("access_token")),
        "refresh_token": bool(data.get("refresh_token")),
        "scope":         data.get("scope"),
        "expires_in":    data.get("expires_in"),
    })


@app.route("/refresh")
def refresh():
    tok = get_latest_token()
    if not tok or not tok.get("refresh_token"):
        return jsonify({"erro": "sem refresh_token salvo"}), 400

    payload = {
        "grant_type":    "refresh_token",
        "client_id":     ML_CLIENT_ID,
        "client_secret": ML_CLIENT_SECRET,
        "refresh_token": tok["refresh_token"],
    }
    resp = requests.post(
        ML_TOKEN_URL,
        data=payload,
        headers={"Accept": "application/json"},
        timeout=30,
    )
    if resp.status_code != 200:
        return jsonify({"erro": "falha ao renovar", "status": resp.status_code, "body": resp.text}), 400

    data = resp.json()
    save_tokens(data)
    return jsonify({
        "ok": True,
        "refresh_token": bool(data.get("refresh_token")),
        "scope": data.get("scope"),
        "expires_in": data.get("expires_in"),
    })


@app.route("/status")
def status():
    tok = get_latest_token()
    if not tok:
        return jsonify({"status": "sem token"})
    return jsonify({
        "status":        "ok",
        "user_id":       tok.get("user_id"),
        "refresh_token": bool(tok.get("refresh_token")),
        "scope":         tok.get("scope"),
        "expires_at":    tok.get("expires_at"),
        "expira_em_seg": (tok.get("expires_at") - int(time.time())) if tok.get("expires_at") else None,
    })


@app.route("/verificar-permissoes")
def verificar_permissoes():
    tok = get_latest_token()
    if not tok:
        return jsonify({"erro": "sem token"}), 400

    headers = {"Authorization": f"Bearer {tok['access_token']}"}

    # Endpoint correto para inspecionar o grant da aplicacao
    url = f"{ML_API_BASE}/users/{tok['user_id']}/applications/{ML_CLIENT_ID}"
    resp = requests.get(url, headers=headers, timeout=30)

    return jsonify({
        "status_code": resp.status_code,
        "body": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
    })


@app.route("/buscar")
def buscar():
    q = request.args.get("q", "")
    tok = get_latest_token()
    headers = {"Authorization": f"Bearer {tok['access_token']}"} if tok else {}

    resp = requests.get(
        f"{ML_API_BASE}/sites/MLB/search",
        params={"q": q},
        headers=headers,
        timeout=30,
    )
    if resp.status_code != 200:
        return jsonify({"erro": "falha na busca", "status": resp.status_code, "body": resp.text}), 400

    results = resp.json().get("results", [])
    out = []
    for r in results:
        out.append({
            "id":                    r.get("id"),
            "titulo":                r.get("title"),
            "preco":                 r.get("price"),
            "preco_original":        r.get("original_price"),
            "quantidade_disponivel": r.get("available_quantity"),
            "quantidade_vendida":    r.get("sold_quantity"),
            "categoria":             r.get("category_id"),
            "link":                  r.get("permalink"),
            "imagem":                r.get("thumbnail"),
        })
    return jsonify({"total": len(out), "resultados": out})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
