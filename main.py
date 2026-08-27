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
# GARIMPO TECH
# Mercado Livre OAuth + PostgreSQL
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


# ============================================================
# SESSÕES OAUTH
# ============================================================

oauth_sessions = {}


# ============================================================
# DATABASE URL
# ============================================================

def get_database_url():

    if DATABASE_URL.startswith("postgres://"):

        return DATABASE_URL.replace(
            "postgres://",
            "postgresql://",
            1
        )

    return DATABASE_URL


# ============================================================
# BANCO DE DADOS
# ============================================================

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

            # ------------------------------------------------
            # Cria a tabela caso ainda não exista
            # ------------------------------------------------

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

            # ------------------------------------------------
            # Compatibilidade com tabela antiga
            # ------------------------------------------------

            cur.execute("""
                ALTER TABLE ml_tokens
                ADD COLUMN IF NOT EXISTS scope TEXT
            """)

            cur.execute("""
                ALTER TABLE ml_tokens
                ADD COLUMN IF NOT EXISTS refresh_token TEXT
            """)

            cur.execute("""
                ALTER TABLE ml_tokens
                ADD COLUMN IF NOT EXISTS token_type TEXT
            """)

            cur.execute("""
                ALTER TABLE ml_tokens
                ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ
                DEFAULT NOW()
            """)

            # ------------------------------------------------
            # IMPORTANTE
            #
            # A tabela antiga tinha refresh_token como NOT NULL.
            #
            # Removemos essa obrigação para que possamos
            # diagnosticar o retorno do Mercado Livre.
            # ------------------------------------------------

            cur.execute("""
                ALTER TABLE ml_tokens
                ALTER COLUMN refresh_token DROP NOT NULL
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
# SALVAR TOKENS
# ============================================================

def save_tokens(token_data):

    access_token = token_data.get(
        "access_token"
    )

    refresh_token = token_data.get(
        "refresh_token"
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

    expires_in = int(
        token_data.get(
            "expires_in",
            21600
        )
    )

    if not access_token:

        raise Exception(
            "O Mercado Livre não retornou "
            "access_token."
        )

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(
            seconds=expires_in
        )
    )

    # --------------------------------------------------------
    # Se o Mercado Livre não devolver refresh_token,
    # preservamos o antigo, caso exista.
    # --------------------------------------------------------

    if not refresh_token:

        try:

            old_token = get_saved_token()

            if old_token:

                refresh_token = old_token[2]

        except Exception:

            pass

    # --------------------------------------------------------
    # Gravar no PostgreSQL
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
        "========================================"
    )

    print(
        "TOKEN RECEBIDO DO MERCADO LIVRE"
    )

    print(
        f"user_id: {user_id}"
    )

    print(
        "access_token: SIM"
        if access_token
        else "access_token: NAO"
    )

    print(
        "refresh_token: SIM"
        if refresh_token
        else "refresh_token: NAO"
    )

    print(
        f"scope: {scope}"
    )

    print(
        f"expires_in: {expires_in}"
    )

    print(
        "========================================"
    )


# ============================================================
# RENOVAR TOKEN
# ============================================================

async def refresh_access_token():

    token = get_saved_token()

    if not token:

        raise Exception(
            "Nenhum token encontrado."
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
# ACCESS TOKEN VÁLIDO
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

    # --------------------------------------------------------
    # Renova 5 minutos antes da expiração
    # --------------------------------------------------------

    if expires_at <= (
        now + timedelta(
            minutes=5
        )
    ):

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
# HOME
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

        <title>
            Garimpo Tech
        </title>

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
# LOGIN
# ============================================================

@app.get(
    "/login"
)
async def login():

    # --------------------------------------------------------
    # Valida configurações
    # --------------------------------------------------------

    if not CLIENT_ID:

        return HTMLResponse(
            "<h1>ML_CLIENT_ID não configurado.</h1>",
            status_code=500
        )

    if not CLIENT_SECRET:

        return HTMLResponse(
            "<h1>ML_CLIENT_SECRET não configurado.</h1>",
            status_code=500
        )

    if not REDIRECT_URI:

        return HTMLResponse(
            "<h1>ML_REDIRECT_URI não configurado.</h1>",
            status_code=500
        )

    if not DATABASE_URL:

        return HTMLResponse(
            "<h1>DATABASE_URL não configurado.</h1>",
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
    #
    # A aplicação atualmente está com PKCE DESABILITADO.
    #
    # Portanto não vamos enviar code_challenge.
    #
    # Isso deixa nosso código alinhado exatamente com
    # a configuração que você mostrou no DevCenter.
    # --------------------------------------------------------

    oauth_sessions[
        state
    ] = {}

    # --------------------------------------------------------
    # SCOPES
    # --------------------------------------------------------
    #
    # Agora vamos solicitar explicitamente os 3 scopes
    # válidos documentados pelo Mercado Livre:
    #
    # offline_access
    # read
    # write
    #
    # O objetivo principal aqui é conseguir o
    # refresh_token.
    # --------------------------------------------------------

    requested_scope = (
        "offline_access read write"
    )

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
            requested_scope
    }

    authorization_url = (

        f"{ML_AUTH_URL}?"

        f"{urlencode(params)}"
    )

    print(
        "========================================"
    )

    print(
        "INICIANDO OAUTH MERCADO LIVRE"
    )

    print(
        f"scopes solicitados: {requested_scope}"
    )

    print(
        "PKCE: DESABILITADO"
    )

    print(
        "========================================"
    )

    return RedirectResponse(
        authorization_url
    )


# ============================================================
# CALLBACK
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
    # Erro de autorização
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
    # Código
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
    # State
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

    oauth_sessions.pop(
        state
    )

    # --------------------------------------------------------
    # TROCA CODE POR TOKEN
    # --------------------------------------------------------
    #
    # Como PKCE está DESABILITADO na aplicação,
    # não enviamos code_verifier.
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
            REDIRECT_URI
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
                a troca do código.
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
    # Informações recebidas
    # --------------------------------------------------------

    access_token = token_data.get(
        "access_token"
    )

    refresh_token = token_data.get(
        "refresh_token"
    )

    scope = token_data.get(
        "scope"
    )

    user_id = token_data.get(
        "user_id"
    )

    # --------------------------------------------------------
    # Sem access token
    # --------------------------------------------------------

    if not access_token:

        return HTMLResponse(
            """
            <h1>
                Erro
            </h1>

            <p>
                O Mercado Livre não retornou
                access_token.
            </p>
            """,
            status_code=500
        )

    # --------------------------------------------------------
    # Salvar
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

            <hr>

            <p>
                User ID:
                {user_id}
            </p>

            <p>
                Refresh token recebido:
                {
                    "SIM"
                    if refresh_token
                    else "NÃO"
                }
            </p>

            <p>
                Scope recebido:
                {scope}
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

    refresh_status = (

        "SIM"
        if refresh_token
        else "NÃO"
    )

    return HTMLResponse(
        f"""
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
                foi conectada.
            </p>

            <p>
                🔐 Token salvo no PostgreSQL.
            </p>

            <p>
                Refresh Token:
                <strong>
                    {refresh_status}
                </strong>
            </p>

            <p>
                Scope recebido:
                <strong>
                    {scope}
                </strong>
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
# VERIFICAR PERMISSÕES
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

    try:

        access_token = (
            await get_access_token()
        )

    except Exception as error:

        return {

            "erro":
                str(error)
        }

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
            len(produtos
            ),

        "produtos":
            produtos
    }
