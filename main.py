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


# ============================================================
# APLICAÇÃO
# ============================================================

app = FastAPI(
    title="Garimpo Tech",
    version="1.0"
)


# ============================================================
# CONFIGURAÇÕES
# ============================================================

ML_AUTH_URL = (
    "https://auth.mercadolivre.com.br/authorization"
)

ML_TOKEN_URL = (
    "https://api.mercadolibre.com/oauth/token"
)

ML_API_URL = (
    "https://api.mercadolibre.com"
)

CLIENT_ID = os.getenv(
    "ML_CLIENT_ID",
    ""
)

CLIENT_SECRET = os.getenv(
    "ML_CLIENT_SECRET",
    ""
)

REDIRECT_URI = os.getenv(
    "ML_REDIRECT_URI",
    ""
)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    ""
)


# Armazena temporariamente o state e o
# code_verifier durante o processo OAuth.

oauth_sessions = {}


# ============================================================
# BANCO DE DADOS
# ============================================================

def get_database_url():

    if DATABASE_URL.startswith(
        "postgres://"
    ):

        return DATABASE_URL.replace(
            "postgres://",
            "postgresql://",
            1
        )

    return DATABASE_URL


def init_database():

    if not DATABASE_URL:

        print(
            "ERRO: DATABASE_URL não configurada."
        )

        return

    with psycopg.connect(
        get_database_url()
    ) as conn:

        with conn.cursor() as cur:

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ml_tokens (

                    id INTEGER PRIMARY KEY,

                    user_id BIGINT,

                    access_token TEXT NOT NULL,

                    refresh_token TEXT,

                    token_type TEXT DEFAULT 'Bearer',

                    expires_at TIMESTAMPTZ NOT NULL,

                    scope TEXT,

                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

        conn.commit()

    print(
        "Banco de dados inicializado."
    )


# ============================================================
# PKCE
# ============================================================

def make_pkce():

    verifier = secrets.token_urlsafe(
        64
    )

    digest = hashlib.sha256(
        verifier.encode("utf-8")
    ).digest()

    challenge = (
        base64
        .urlsafe_b64encode(digest)
        .rstrip(b"=")
        .decode("utf-8")
    )

    return verifier, challenge


# ============================================================
# SALVAR TOKENS
# ============================================================

def save_tokens(token_data):

    access_token = token_data.get(
        "access_token"
    )

    refresh_token = token_data.get(
        "refresh_token"
    )

    if not access_token:

        raise Exception(
            "O Mercado Livre não retornou "
            "access_token."
        )

    expires_in = int(
        token_data.get(
            "expires_in",
            21600
        )
    )

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(
            seconds=expires_in
        )
    )

    user_id = token_data.get(
        "user_id"
    )

    token_type = token_data.get(
        "token_type",
        "Bearer"
    )

    scope = token_data.get(
        "scope"
    )

    # --------------------------------------------------------
    # Se já existir um refresh_token no banco e a nova
    # resposta não trouxer outro, preservamos o anterior.
    # --------------------------------------------------------

    old_refresh_token = None

    try:

        existing = get_saved_token()

        if existing:

            old_refresh_token = existing[2]

    except Exception:

        pass

    if not refresh_token:

        refresh_token = old_refresh_token

    # --------------------------------------------------------
    # Grava no PostgreSQL
    # --------------------------------------------------------

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
                    scope,
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
                    %s,
                    NOW()
                )

                ON CONFLICT (id)

                DO UPDATE SET

                    user_id =
                        EXCLUDED.user_id,

                    access_token =
                        EXCLUDED.access_token,

                    refresh_token =
                        EXCLUDED.refresh_token,

                    token_type =
                        EXCLUDED.token_type,

                    expires_at =
                        EXCLUDED.expires_at,

                    scope =
                        EXCLUDED.scope,

                    updated_at =
                        NOW()
            """, (

                user_id,

                access_token,

                refresh_token,

                token_type,

                expires_at,

                scope
            ))

        conn.commit()

    print(
        "Token salvo no PostgreSQL."
    )

    print(
        f"user_id={user_id}"
    )

    print(
        "refresh_token="
        + (
            "SIM"
            if refresh_token
            else "NAO"
        )
    )

    print(
        f"scope={scope}"
    )


# ============================================================
# LER TOKEN
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

                    expires_at,

                    scope

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
        expires_at,
        old_scope
    ) = token

    if not old_refresh_token:

        raise Exception(
            "Não existe refresh_token armazenado."
        )

    payload = {

        "grant_type":
            "refresh_token",

        "client_id":
            CLIENT_ID,

        "client_secret":
            CLIENT_SECRET,

        "refresh_token":
            old_refresh_token
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

    if response.status_code >= 400:

        raise Exception(
            "Erro ao renovar token: "
            + response.text
        )

    new_token_data = (
        response.json()
    )

    # O Mercado Livre deve devolver um
    # novo refresh_token.

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
        expires_at,
        scope
    ) = token

    now = datetime.now(
        timezone.utc
    )

    # Renova 5 minutos antes da expiração.

    if expires_at <= (
        now + timedelta(
            minutes=5
        )
    ):

        print(
            "Token próximo de expirar."
        )

        return await refresh_access_token()

    return access_token


# ============================================================
# STARTUP
# ============================================================

@app.on_event(
    "startup"
)
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

                font-family:
                    Arial,
                    sans-serif;

                background:
                    #111;

                color:
                    white;

                text-align:
                    center;

                padding:
                    60px;
            }

            h1 {

                color:
                    #ffd400;

                font-size:
                    44px;
            }

            .button {

                display:
                    inline-block;

                background:
                    #ffd400;

                color:
                    #111;

                padding:
                    15px 25px;

                border-radius:
                    8px;

                text-decoration:
                    none;

                font-weight:
                    bold;

                margin:
                    8px;
            }

        </style>

    </head>

    <body>

        <h1>
            🚀 GARIMPO TECH
        </h1>

        <h2>
            Motor de Ofertas
        </h2>

        <p>
            Automação de ofertas
            do Mercado Livre.
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

        <br>

        <a
            class="button"
            href="/status"
        >
            📊 Status
        </a>

        <br>

        <a
            class="button"
            href="/verificar-permissoes"
        >
            🔐 Verificar permissões
        </a>

    </body>

    </html>
    """


# ============================================================
# LOGIN MERCADO LIVRE
# ============================================================

@app.get(
    "/login"
)
async def login():

    # --------------------------------------------------------
    # Verificações
    # --------------------------------------------------------

    if not CLIENT_ID:

        return HTMLResponse(
            """
            <h1>Erro</h1>
            <p>
            ML_CLIENT_ID não configurado.
            </p>
            """,
            status_code=500
        )

    if not CLIENT_SECRET:

        return HTMLResponse(
            """
            <h1>Erro</h1>
            <p>
            ML_CLIENT_SECRET não configurado.
            </p>
            """,
            status_code=500
        )

    if not REDIRECT_URI:

        return HTMLResponse(
            """
            <h1>Erro</h1>
            <p>
            ML_REDIRECT_URI não configurado.
            </p>
            """,
            status_code=500
        )

    if not DATABASE_URL:

        return HTMLResponse(
            """
            <h1>Erro</h1>
            <p>
            DATABASE_URL não configurado.
            </p>
            """,
            status_code=500
        )

    # --------------------------------------------------------
    # STATE
    # --------------------------------------------------------

    state = secrets.token_urlsafe(
        32
    )

    # --------------------------------------------------------
    # PKCE
    # --------------------------------------------------------

    verifier, challenge = make_pkce()

    oauth_sessions[
        state
    ] = {

        "code_verifier":
            verifier
    }

    # --------------------------------------------------------
    # AUTORIZAÇÃO
    # --------------------------------------------------------

    params = {

        "response_type":
            "code",

        "client_id":
            CLIENT_ID,

        "redirect_uri":
            REDIRECT_URI,

        "state":
            state,

        "scope":
            "offline_access read",

        "code_challenge":
            challenge,

        "code_challenge_method":
            "S256"
    }

    authorization_url = (

        f"{ML_AUTH_URL}?"

        f"{urlencode(params)}"
    )

    return RedirectResponse(
        authorization_url
    )


# ============================================================
# CALLBACK OAUTH
# ============================================================

@app.get(
    "/oauth/callback"
)
async def oauth_callback(

    code: str = None,

    state: str = None,

    error: str = None
):

    # --------------------------------------------------------
    # Usuário cancelou
    # --------------------------------------------------------

    if error:

        return HTMLResponse(
            f"""
            <h1>
                Autorização cancelada
            </h1>

            <p>
                Mercado Livre retornou:
                {error}
            </p>

            <a href="/">
                Voltar
            </a>
            """,
            status_code=400
        )

    # --------------------------------------------------------
    # Valida code
    # --------------------------------------------------------

    if not code:

        return HTMLResponse(
            """
            <h1>Erro</h1>

            <p>
                Código de autorização
                não recebido.
            </p>
            """,
            status_code=400
        )

    # --------------------------------------------------------
    # Valida state
    # --------------------------------------------------------

    if not state:

        return HTMLResponse(
            """
            <h1>Erro</h1>

            <p>
                State não recebido.
            </p>
            """,
            status_code=400
        )

    if state not in oauth_sessions:

        return HTMLResponse(
            """
            <h1>
                Erro de segurança
            </h1>

            <p>
                State inválido ou expirado.
            </p>
            """,
            status_code=400
        )

    session = oauth_sessions.pop(
        state
    )

    code_verifier = session[
        "code_verifier"
    ]

    # --------------------------------------------------------
    # TROCAR CODE POR TOKEN
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Erro do Mercado Livre
    # --------------------------------------------------------

    if response.status_code >= 400:

        return HTMLResponse(
            f"""
            <h1>
                Erro no Mercado Livre
            </h1>

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

    token_data = (
        response.json()
    )

    # --------------------------------------------------------
    # Valida access token
    # --------------------------------------------------------

    if not token_data.get(
        "access_token"
    ):

        return HTMLResponse(
            """
            <h1>Erro</h1>

            <p>
                O Mercado Livre não
                retornou access_token.
            </p>
            """,
            status_code=500
        )

    # --------------------------------------------------------
    # SALVA TOKEN
    # --------------------------------------------------------

    try:

        save_tokens(
            token_data
        )

    except Exception as error:

        return HTMLResponse(
            f"""
            <h1>
                Erro ao salvar token
            </h1>

            <p>
                {error}
            </p>

            <br>

            <p>
                Refresh token recebido:
                {
                    "SIM"
                    if token_data.get(
                        "refresh_token"
                    )
                    else "NÃO"
                }
            </p>

            <br>

            <a href="/">
                Voltar
            </a>
            """,
            status_code=500
        )

    # --------------------------------------------------------
    # SUCESSO
    # --------------------------------------------------------

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
                🔐 Token salvo no PostgreSQL.
            </p>

            <p>
                🔄 Renovação automática
                preparada.
            </p>

            <br>

            <a
                href="/verificar-permissoes"
                style="
                    background:#ffd400;
                    color:#111;
                    padding:15px 25px;
                    text-decoration:none;
                    border-radius:8px;
                    font-weight:bold;
                "
            >
                🔐 Verificar permissões
            </a>

            <br><br>

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
                🔎 Testar busca
            </a>

        </body>

        </html>
        """
    )


# ============================================================
# VERIFICAR PERMISSÕES CONCEDIDAS
# ============================================================

@app.get(
    "/verificar-permissoes"
)
async def verificar_permissoes():

    token = get_saved_token()

    if not token:

        return {

            "erro":
                "Nenhum token encontrado."

        }

    (
        user_id,
        access_token,
        refresh_token,
        token_type,
        expires_at,
        saved_scope
    ) = token

    # --------------------------------------------------------
    # Consulta as aplicações autorizadas pelo usuário
    # --------------------------------------------------------

    async with httpx.AsyncClient(
        timeout=30
    ) as client:

        response = await client.get(

            f"{ML_API_URL}/users/"
            f"{user_id}/applications",

            headers={

                "Authorization":
                    f"Bearer {access_token}"
            }
        )

    if response.status_code >= 400:

        return {

            "erro":
                "Não foi possível consultar "
                "as permissões.",

            "status":
                response.status_code,

            "detalhes":
                response.text
        }

    applications = (
        response.json()
    )

    resultado = []

    for application in applications:

        app_id = str(
            application.get(
                "app_id",
                ""
            )
        )

        if app_id == str(
            CLIENT_ID
        ):

            resultado.append({

                "app_id":
                    app_id,

                "scopes":
                    application.get(
                        "scopes",
                        []
                    )
            })

    return {

        "user_id":
            user_id,

        "refresh_token_recebido":
            bool(
                refresh_token
            ),

        "scope_recebido_no_oauth":
            saved_scope,

        "aplicacao":
            resultado
    }


# ============================================================
# STATUS
# ============================================================

@app.get(
    "/status"
)
async def status():

    try:

        token = get_saved_token()

        if not token:

            return {

                "status":
                    "não conectado",

                "mercado_livre":
                    False
            }

        (
            user_id,
            access_token,
            refresh_token,
            token_type,
            expires_at,
            scope
        ) = token

        return {

            "status":
                "conectado",

            "mercado_livre":
                True,

            "user_id":
                user_id,

            "refresh_token":
                bool(
                    refresh_token
                ),

            "scope":
                scope,

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


# ============================================================
# BUSCAR PRODUTOS
# ============================================================

@app.get(
    "/buscar"
)
async def buscar(

    q: str = Query(
        ...,
        min_length=2
    )
):

    # --------------------------------------------------------
    # Access token
    # --------------------------------------------------------

    try:

        access_token = (
            await get_access_token()
        )

    except Exception as error:

        return {

            "erro":
                str(error)
        }

    # --------------------------------------------------------
    # Busca
    # --------------------------------------------------------

    params = {

        "q":
            q,

        "limit":
            20
    }

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

    # --------------------------------------------------------
    # Erro
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Produtos
    # --------------------------------------------------------

    for item in data.get(
        "results",
        []
    ):

        produtos.append({

            "id":
                item.get(
                    "id"
                ),

            "titulo":
                item.get(
                    "title"
                ),

            "preco":
                item.get(
                    "price"
                ),

            "preco_original":
                item.get(
                    "original_price"
                ),

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
