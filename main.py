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


# ============================================================
# CONFIGURAÇÕES
# ============================================================

ML_AUTH_URL = "https://auth.mercadolivre.com.br/authorization"
ML_TOKEN_URL = "https://api.mercadolibre.com/oauth/token"
ML_API_URL = "https://api.mercadolibre.com"

CLIENT_ID = os.getenv("ML_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("ML_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("ML_REDIRECT_URI", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Guarda temporariamente o state/PKCE durante o login.
oauth_sessions = {}


# ============================================================
# BANCO DE DADOS
# ============================================================

def get_database_url():
    """
    Compatibilidade com URLs postgres:// e postgresql://
    """

    if DATABASE_URL.startswith("postgres://"):
        return DATABASE_URL.replace(
            "postgres://",
            "postgresql://",
            1
        )

    return DATABASE_URL


def init_database():
    """
    Cria a tabela de tokens caso ela ainda não exista.
    """

    if not DATABASE_URL:
        print("DATABASE_URL não configurada.")
        return

    with psycopg.connect(get_database_url()) as conn:

        with conn.cursor() as cur:

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ml_tokens (
                    id INTEGER PRIMARY KEY,
                    user_id BIGINT,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT,
                    token_type TEXT DEFAULT 'Bearer',
                    expires_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

        conn.commit()

    print("Banco de dados inicializado.")


# ============================================================
# PKCE
# ============================================================

def make_pkce():
    """
    Gera code_verifier e code_challenge para OAuth PKCE.
    """

    verifier = secrets.token_urlsafe(64)

    digest = hashlib.sha256(
        verifier.encode("utf-8")
    ).digest()

    challenge = base64.urlsafe_b64encode(
        digest
    ).rstrip(b"=").decode("utf-8")

    return verifier, challenge


# ============================================================
# SALVAR TOKENS
# ============================================================

def save_tokens(token_data):
    """
    Salva ou atualiza os tokens no PostgreSQL.

    O refresh_token é obrigatório para manter a conexão
    automática. Se o Mercado Livre não o devolver,
    mostramos um erro claro.
    """

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")

    if not access_token:
        raise Exception(
            "O Mercado Livre não retornou access_token."
        )

    if not refresh_token:
        raise Exception(
            "O Mercado Livre não retornou refresh_token. "
            "Verifique se a aplicação possui o escopo "
            "offline_access habilitado."
        )

    expires_in = int(
        token_data.get(
            "expires_in",
            21600
        )
    )

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(seconds=expires_in)
    )

    user_id = token_data.get("user_id")

    token_type = token_data.get(
        "token_type",
        "Bearer"
    )

    with psycopg.connect(
        get_database_url()
    ) as conn:

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
                token_type,
                expires_at
            ))

        conn.commit()

    print(
        f"Token do Mercado Livre salvo. "
        f"user_id={user_id}"
    )


# ============================================================
# LER TOKEN DO BANCO
# ============================================================

def get_saved_token():

    with psycopg.connect(
        get_database_url()
    ) as conn:

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


# ============================================================
# RENOVAR ACCESS TOKEN
# ============================================================

async def refresh_access_token():

    token = get_saved_token()

    if not token:

        raise Exception(
            "Mercado Livre ainda não foi conectado."
        )

    (
        user_id,
        old_access_token,
        old_refresh_token,
        token_type,
        expires_at
    ) = token

    if not old_refresh_token:

        raise Exception(
            "Não existe refresh_token armazenado. "
            "É necessário autorizar novamente "
            "o Mercado Livre com offline_access."
        )

    payload = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": old_refresh_token
    }

    async with httpx.AsyncClient(
        timeout=30
    ) as client:

        response = await client.post(
            ML_TOKEN_URL,
            data=payload,
            headers={
                "accept": "application/json",
                "content-type":
                    "application/x-www-form-urlencoded"
            }
        )

    if response.status_code >= 400:

        raise Exception(
            "Erro ao renovar token do Mercado Livre: "
            + response.text
        )

    new_token_data = response.json()

    # O Mercado Livre normalmente devolve
    # um NOVO refresh_token.
    #
    # Se não devolver, preservamos o anterior.
    if not new_token_data.get(
        "refresh_token"
    ):

        new_token_data[
            "refresh_token"
        ] = old_refresh_token

    new_token_data[
        "user_id"
    ] = user_id

    save_tokens(
        new_token_data
    )

    return new_token_data[
        "access_token"
    ]


# ============================================================
# OBTER ACCESS TOKEN VÁLIDO
# ============================================================

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

    now = datetime.now(
        timezone.utc
    )

    # Renovamos 5 minutos antes de expirar.
    if expires_at <= (
        now + timedelta(minutes=5)
    ):

        print(
            "Access token próximo de expirar. "
            "Renovando..."
        )

        return await refresh_access_token()

    return access_token


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup():

    init_database()


# ============================================================
# PÁGINA PRINCIPAL
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
async def home():

    return """
    <!DOCTYPE html>

    <html>

    <head>

        <title>Garimpo Tech</title>

        <style>

            body {
                font-family: Arial, sans-serif;
                background: #111;
                color: white;
                text-align: center;
                padding: 60px;
            }

            h1 {
                color: #ffd400;
                font-size: 44px;
            }

            h2 {
                font-weight: normal;
            }

            .button {
                display: inline-block;
                background: #ffd400;
                color: #111;
                padding: 15px 25px;
                border-radius: 8px;
                text-decoration: none;
                font-weight: bold;
                margin: 8px;
            }

            .button:hover {
                opacity: 0.85;
            }

        </style>

    </head>

    <body>

        <h1>🚀 GARIMPO TECH</h1>

        <h2>Motor de Ofertas</h2>

        <p>
            Automação de ofertas do Mercado Livre.
        </p>

        <br>

        <a
            class="button"
            href="/login"
        >
            🔗 Conectar Mercado Livre
        </a>

        <br>

        <a
            class="button"
            href="/buscar?q=snow%20foam"
        >
            🔎 Testar busca
        </a>

    </body>

    </html>
    """


# ============================================================
# LOGIN / AUTORIZAÇÃO
# ============================================================

@app.get("/login")
async def login():

    # Verifica configurações obrigatórias.

    if not CLIENT_ID:

        return HTMLResponse(
            "<h1>Erro</h1>"
            "<p>ML_CLIENT_ID não configurado.</p>",
            status_code=500
        )

    if not CLIENT_SECRET:

        return HTMLResponse(
            "<h1>Erro</h1>"
            "<p>ML_CLIENT_SECRET não configurado.</p>",
            status_code=500
        )

    if not REDIRECT_URI:

        return HTMLResponse(
            "<h1>Erro</h1>"
            "<p>ML_REDIRECT_URI não configurado.</p>",
            status_code=500
        )

    if not DATABASE_URL:

        return HTMLResponse(
            "<h1>Erro</h1>"
            "<p>DATABASE_URL não configurado.</p>",
            status_code=500
        )

    # Gera state.

    state = secrets.token_urlsafe(
        32
    )

    # Gera PKCE.

    verifier, challenge = make_pkce()

    # Guarda temporariamente.

    oauth_sessions[state] = {
        "code_verifier": verifier
    }

    # Escopos solicitados.
    #
    # offline_access:
    # permite trabalhar com refresh_token.
    #
    # read:
    # permite acesso de leitura.

    params = {
        "response_type": "code",

        "client_id": CLIENT_ID,

        "redirect_uri": REDIRECT_URI,

        "state": state,

        "scope": "offline_access read",

        "code_challenge": challenge,

        "code_challenge_method": "S256"
    }

    authorization_url = (
        f"{ML_AUTH_URL}?"
        f"{urlencode(params)}"
    )

    return RedirectResponse(
        authorization_url
    )


# ============================================================
# CALLBACK DO MERCADO LIVRE
# ============================================================

@app.get(
    "/oauth/callback"
)
async def oauth_callback(
    code: str = None,
    state: str = None,
    error: str = None
):

    # Caso o usuário cancele.

    if error:

        return HTMLResponse(
            f"""
            <h1>Autorização cancelada</h1>

            <p>
                O Mercado Livre retornou:
                {error}
            </p>

            <a href="/">
                Voltar
            </a>
            """,
            status_code=400
        )

    # Verifica code/state.

    if not code:

        return HTMLResponse(
            "<h1>Erro</h1>"
            "<p>Código de autorização não recebido.</p>",
            status_code=400
        )

    if not state:

        return HTMLResponse(
            "<h1>Erro</h1>"
            "<p>State não recebido.</p>",
            status_code=400
        )

    # Verifica state.

    if state not in oauth_sessions:

        return HTMLResponse(
            "<h1>Erro de segurança</h1>"
            "<p>Estado OAuth inválido ou expirado.</p>",
            status_code=400
        )

    session = oauth_sessions.pop(
        state
    )

    code_verifier = session[
        "code_verifier"
    ]

    # Monta requisição de token.

    payload = {

        "grant_type":
            "authorization_code",

        "client_id":
            CLIENT_ID,

        "client_secret":
            CLIENT_SECRET,

        "code":
            code,

        "redirect_uri":
            REDIRECT_URI,

        "code_verifier":
            code_verifier
    }

    async with httpx.AsyncClient(
        timeout=30
    ) as client:

        response = await client.post(
            ML_TOKEN_URL,

            data=payload,

            headers={
                "accept":
                    "application/json",

                "content-type":
                    "application/x-www-form-urlencoded"
            }
        )

    # Erro do Mercado Livre.

    if response.status_code >= 400:

        return HTMLResponse(
            f"""
            <h1>Erro no Mercado Livre</h1>

            <p>
                O Mercado Livre rejeitou
                a autorização.
            </p>

            <pre>
            {response.text}
            </pre>

            <a href="/">
                Voltar
            </a>
            """,
            status_code=500
        )

    token_data = response.json()

    # Verifica se recebeu access token.

    if not token_data.get(
        "access_token"
    ):

        return HTMLResponse(
            "<h1>Erro</h1>"
            "<p>Access token não recebido.</p>",
            status_code=500
        )

    # Verifica refresh token.

    if not token_data.get(
        "refresh_token"
    ):

        return HTMLResponse(
            """
            <h1>⚠️ Refresh Token não recebido</h1>

            <p>
                O Mercado Livre não devolveu
                um refresh_token.
            </p>

            <p>
                Verifique se a aplicação possui
                o escopo <b>offline_access</b>
                habilitado.
            </p>

            <br>

            <a href="/">
                Voltar
            </a>
            """,
            status_code=500
        )

    # Salva no PostgreSQL.

    try:

        save_tokens(
            token_data
        )

    except Exception as error:

        return HTMLResponse(
            f"""
            <h1>Erro ao salvar token</h1>

            <p>
                {error}
            </p>

            <a href="/">
                Voltar
            </a>
            """,
            status_code=500
        )

    # Sucesso.

    return HTMLResponse(
        """
        <!DOCTYPE html>

        <html>

        <head>

            <title>
                Garimpo Tech conectado
            </title>

        </head>

        <body style="
            font-family:Arial;
            text-align:center;
            padding:60px;
            background:#111;
            color:white;
        ">

            <h1 style="
                color:#ffd400;
            ">
                ✅ GARIMPO TECH CONECTADO!
            </h1>

            <p>
                Sua conta do Mercado Livre
                foi conectada com sucesso.
            </p>

            <p>
                🔐 Token armazenado no PostgreSQL.
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


# ============================================================
# BUSCA DE PRODUTOS
# ============================================================

@app.get("/buscar")
async def buscar(
    q: str = Query(
        ...,
        min_length=2
    )
):

    # Obtém token válido.

    try:

        access_token = (
            await get_access_token()
        )

    except Exception as error:

        return {
            "erro": str(error)
        }

    # Parâmetros da busca.

    params = {
        "q": q,
        "limit": 20
    }

    # Consulta Mercado Livre.

    async with httpx.AsyncClient(
        timeout=30
    ) as client:

        response = await client.get(

            f"{ML_API_URL}/sites/MLB/search",

            params=params,

            headers={
                "Authorization":
                    f"Bearer {access_token}"
            }
        )

    # Erro da API.

    if response.status_code >= 400:

        return {
            "erro":
                "Erro na API do Mercado Livre",

            "status":
                response.status_code,

            "detalhes":
                response.text
        }

    data = response.json()

    produtos = []

    # Processa resultados.

    for item in data.get(
        "results",
        []
    ):

        produtos.append({

            "id":
                item.get("id"),

            "titulo":
                item.get("title"),

            "preco":
                item.get("price"),

            "preco_original":
                item.get("original_price"),

            "quantidade_disponivel":
                item.get(
                    "available_quantity"
                ),

            "quantidade_vendida":
                item.get(
                    "sold_quantity"
                ),

            "categoria":
                item.get(
                    "category_id"
                ),

            "link":
                item.get(
                    "permalink"
                ),

            "imagem":
                item.get(
                    "thumbnail"
                )
        })

    return {

        "consulta":
            q,

        "total_encontrado":
            data.get(
                "paging",
                {}
            ).get(
                "total",
                0
            ),

        "quantidade_retornada":
            len(produtos),

        "produtos":
            produtos
    }


# ============================================================
# STATUS DO SISTEMA
# ============================================================

@app.get("/status")
async def status():

    try:

        token = get_saved_token()

        if not token:

            return {
                "status": "não conectado",
                "mercado_livre": False
            }

        (
            user_id,
            access_token,
            refresh_token,
            token_type,
            expires_at
        ) = token

        return {

            "status":
                "conectado",

            "mercado_livre":
                True,

            "user_id":
                user_id,

            "refresh_token":
                bool(refresh_token),

            "expires_at":
                expires_at.isoformat()
                if expires_at
                else None
        }

    except Exception as error:

        return {

            "status":
                "erro",

            "mensagem":
                str(error)
        }
