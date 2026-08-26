import os
import secrets
import hashlib
import base64
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI(title="Garimpo Tech")

ML_AUTH_URL = "https://auth.mercadolivre.com.br/authorization"
ML_TOKEN_URL = "https://api.mercadolibre.com/oauth/token"

CLIENT_ID = os.getenv("ML_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("ML_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("ML_REDIRECT_URI", "")

oauth_sessions = {}


def make_pkce():
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    return verifier, challenge


@app.get("/", response_class=HTMLResponse)
async def home():

    return """
    <html>
        <head>
            <title>Garimpo Tech</title>
        </head>

        <body>

            <h1>🚀 GARIMPO TECH</h1>

            <h2>Conexão com Mercado Livre</h2>

            <p>
                Sistema inicial de automação do Garimpo Tech.
            </p>

            <a href="/login">
                <button>
                    Conectar Mercado Livre
                </button>
            </a>

        </body>
    </html>
    """


@app.get("/login")
async def login():

    if not all([CLIENT_ID, CLIENT_SECRET, REDIRECT_URI]):
        return HTMLResponse(
            "As variáveis do Mercado Livre ainda não foram configuradas.",
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

    url = f"{ML_AUTH_URL}?{urlencode(params)}"

    return RedirectResponse(url)


@app.get("/oauth/callback")
async def oauth_callback(code: str = None, state: str = None):

    if not code or not state:
        return HTMLResponse(
            "<h1>Erro</h1><p>Código de autorização não recebido.</p>",
            status_code=400
        )

    if state not in oauth_sessions:
        return HTMLResponse(
            "<h1>Erro de segurança</h1><p>Estado OAuth inválido.</p>",
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
            "<pre>"
            + response.text
            + "</pre>",
            status_code=500
        )

    token_data = response.json()

    return HTMLResponse(
        f"""
        <h1>✅ GARIMPO TECH CONECTADO!</h1>

        <p>
            A autorização do Mercado Livre foi concluída.
        </p>

        <p>
            <b>ID do usuário:</b>
            {token_data.get("user_id", "não informado")}
        </p>

        <p>
            <b>Expiração:</b>
            {token_data.get("expires_in", "não informado")} segundos
        </p>

        <p>
            O próximo passo será armazenar os tokens
            com segurança e testar a API do Mercado Livre.
        </p>
        """
    )
