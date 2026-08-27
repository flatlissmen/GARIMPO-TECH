import os
import secrets
import hashlib
import base64
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone

import httpx
import psycopg
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI(title="Garimpo Tech")


# =========================================================
# CONFIGURAÇÕES
# =========================================================

ML_AUTH_URL = "https://auth.mercadolivre.com.br/authorization"
ML_TOKEN_URL = "https://api.mercadolibre.com/oauth/token"
ML_API_URL = "https://api.mercadolibre.com"

CLIENT_ID = os.getenv("ML_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("ML_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("ML_REDIRECT_URI", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")

oauth_sessions = {}


# =========================================================
# BANCO DE DADOS
# =========================================================

def get_db_url():
    if DATABASE_URL.startswith("postgres://"):
        return DATABASE_URL.replace("postgres://", "postgresql://", 1)

    return DATABASE_URL


def init_database():
    if not DATABASE_URL:
        return

    with psycopg.connect(get_db_url()) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ml_tokens (
                    id INTEGER PRIMARY KEY,
                    user_id BIGINT,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    token_type TEXT DEFAULT 'Bearer',
                    expires_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

        conn.commit()


# =========================================================
# PKCE
# =========================================================

def make_pkce():
    verifier = secrets.token_urlsafe(64)

    digest = hashlib.sha256(verifier.encode()).digest()

    challenge = base64.urlsafe_b64encode(
        digest
    ).rstrip(b"=").decode()

    return verifier, challenge


# =========================================================
# TOKEN
# =========================================================

def save_tokens(token_data):
    access_token = token_data["access_token"]
    refresh_token = token_data["refresh_token"]

    expires_in = int(token_data.get("expires_in", 21600))

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(seconds=expires_in)
    )

    user_id = token_data.get("user_id")

    with psycopg.connect(get_db_url()) as conn:

        with conn.cursor() as cur:

            cur.execute("""
                INSERT INTO ml_tokens
                (
                    id,
                    user_id,
                    access_token,
                    refresh_token,
                    token_type,
                    expires_at,
                    updated_at
                )
                VALUES
                (
                    1,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    NOW()
                )
                ON CONFLICT (id)
                DO UPDATE SET
                    user_id = EXCLUDED.user_id,
                    access_token = EXCLUDED.access_token,
                    refresh_token = EXCLUDED.refresh_token,
                    token_type = EXCLUDED.token_type,
                    expires_at = EXCLUDED.expires_at,
                    updated_at = NOW()
            """, (
                user_id,
                access_token,
                refresh_token,
                token_data.get("token_type", "Bearer"),
                expires_at
            ))

        conn.commit()


def get_saved_token():

    with psycopg.connect(get_db_url()) as conn:

        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    user_id,
                    access_token,
                    refresh_token,
                    token_type,
                    expires_at
                FROM ml_tokens
                WHERE id = 1
            """)

            return cur.fetchone()


async def refresh_access_token():

    token = get_saved_token()

    if not token:
        raise Exception("Mercado Livre ainda não foi conectado.")

    (
        user_id,
        old_access_token,
        old_refresh_token,
        token_type,
        expires_at
    ) = token

    payload = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": old_refresh_token
    }

    async with httpx.AsyncClient(timeout=30) as client:

        response = await client.post(
            ML_TOKEN_URL,
            data=payload,
            headers={
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded"
            }
        )

    if response.status_code >= 400:
        raise Exception(
            f"Erro ao renovar token: {response.text}"
        )

    data = response.json()

    # O Mercado Livre pode devolver um novo refresh_token.
    # Quando isso acontecer, substituímos o anterior.
    if not data.get("refresh_token"):
        data["refresh_token"] = old_refresh_token

    data["user_id"] = user_id

    save_tokens(data)

    return data["access_token"]


async def get_access_token():

    token = get_saved_token()

    if not token:
        raise Exception(
            "Mercado Livre ainda não foi conectado."
        )

    (
        user_id,
        access_token,
        refresh_token,
        token_type,
        expires_at
    ) = token

    now = datetime.now(timezone.utc)

    # Renova automaticamente se faltarem menos de 5 minutos.
    if expires_at <= now + timedelta(minutes=5):

        return await refresh_access_token()

    return access_token


# =========================================================
# INÍCIO
# =========================================================

@app.on_event("startup")
def startup():

    init_database()


# =========================================================
# HOME
# =========================================================

@app.get("/", response_class=HTMLResponse)
async def home():

    return """
    <html>

        <head>
            <title>Garimpo Tech</title>

            <style>

                body {
                    font-family: Arial;
                    background: #111;
                    color: white;
                    text-align: center;
                    padding: 60px;
                }

                h1 {
                    color: #ffd400;
                    font-size: 42px;
                }

                a {
                    display: inline-block;
                    background: #ffd400;
                    color: #111;
                    padding: 15px 25px;
                    border-radius: 8px;
                    text-decoration: none;
                    font-weight: bold;
                }

            </style>

        </head>

        <body>

            <h1>🚀 GARIMPO TECH</h1>

            <h2>Motor de Ofertas</h2>

            <p>
                Mercado Livre conectado ao Garimpo Tech.
            </p>

            <br>

            <a href="/login">
                Conectar Mercado Livre
            </a>

            <br><br>

            <a href="/buscar?q=snow%20foam">
                🔎 Testar busca
            </a>

        </body>

    </html>
    """


# =========================================================
# LOGIN MERCADO LIVRE
# =========================================================

@app.get("/login")
async def login():

    if not all([
        CLIENT_ID,
        CLIENT_SECRET,
        REDIRECT_URI,
        DATABASE_URL
    ]):

        return HTMLResponse(
            "<h1>Configuração incompleta</h1>"
            "<p>Verifique as variáveis do Railway.</p>",
            status_code=500
        )

    state = secrets.token_urlsafe(32)

    verifier, challenge = make_pkce()

    oauth_sessions[state] = {
        "code_verifier": verifier
    }

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    }

    url = (
        f"{ML_AUTH_URL}?"
        f"{urlencode(params)}"
    )

    return RedirectResponse(url)


# =========================================================
# CALLBACK OAUTH
# =========================================================

@app.get("/oauth/callback")
async def oauth_callback(
    code: str = None,
    state: str = None
):

    if not code or not state:

        return HTMLResponse(
            "<h1>Erro</h1>"
            "<p>Código de autorização não recebido.</p>",
            status_code=400
        )

    if state not in oauth_sessions:

        return HTMLResponse(
            "<h1>Erro de segurança</h1>"
            "<p>Estado OAuth inválido.</p>",
            status_code=400
        )

    session = oauth_sessions.pop(state)

    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": session["code_verifier"]
    }

    async with httpx.AsyncClient(timeout=30) as client:

        response = await client.post(
            ML_TOKEN_URL,
            data=payload,
            headers={
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded"
            }
        )

    if response.status_code >= 400:

        return HTMLResponse(
            "<h1>Erro ao obter autorização</h1>"
            f"<pre>{response.text}</pre>",
            status_code=500
        )

    token_data = response.json()

    # Salva os tokens no PostgreSQL.
    save_tokens(token_data)

    return HTMLResponse(
        """
        <html>

            <body
                style="
                font-family:Arial;
                text-align:center;
                padding:60px;
                background:#111;
                color:white;
                "
            >

                <h1 style="color:#ffd400">
                    ✅ GARIMPO TECH CONECTADO!
                </h1>

                <p>
                    A conta do Mercado Livre foi conectada
                    com sucesso.
                </p>

                <p>
                    🔐 Tokens armazenados com segurança.
                </p>

                <p>
                    🔄 Renovação automática habilitada.
                </p>

                <br>

                <a
                    href="/buscar?q=snow%20foam"
                    style="
                    background:#ffd400;
                    color:#111;
                    padding:15px 25px;
                    text-decoration:none;
                    border-radius:8px;
                    font-weight:bold;
                    "
                >
                    🔎 Testar busca no Mercado Livre
                </a>

            </body>

        </html>
        """
    )


# =========================================================
# BUSCAR PRODUTOS
# =========================================================

@app.get("/buscar")
async def buscar(
    q: str = Query(
        ...,
        min_length=2,
        description="Produto que deseja pesquisar"
    )
):

    try:

        access_token = await get_access_token()

    except Exception as error:

        return {
            "erro": str(error)
        }

    params = {
        "q": q,
        "limit": 20
    }

    async with httpx.AsyncClient(timeout=30) as client:

        response = await client.get(
            f"{ML_API_URL}/sites/MLB/search",
            params=params,
            headers={
                "Authorization":
                f"Bearer {access_token}"
            }
        )

    if response.status_code >= 400:

        return {
            "erro": "Erro na API do Mercado Livre",
            "status": response.status_code,
            "detalhes": response.text
        }

    data = response.json()

    produtos = []

    for item in data.get("results", []):

        produtos.append({

            "id": item.get("id"),

            "titulo": item.get("title"),

            "preco": item.get("price"),

            "preco_original":
                item.get("original_price"),

            "disponibilidade":
                item.get("available_quantity"),

            "vendidos":
                item.get("sold_quantity"),

            "categoria":
                item.get("category_id"),

            "link":
                item.get("permalink"),

            "imagem":
                item.get("thumbnail")

        })

    return {
        "consulta": q,
        "total_encontrado":
            data.get("paging", {}).get("total", 0),
        "produtos": produtos
    }
