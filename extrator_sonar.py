# =============================================================================
# 🔍 EXTRATOR DE ISSUES DO SONARQUBE / SONARCLOUD
# =============================================================================
#
# DESCRIÇÃO:
#   Este script busca vulnerabilidades e code smells de um projeto no
#   SonarQube (self-hosted) ou SonarCloud (nuvem) e gera um arquivo JSON
#   com todos os problemas encontrados, além de exibi-los no terminal.
#
# PRÉ-REQUISITOS:
#   - Python 3.7+
#   - Biblioteca 'requests' instalada → rode: pip install requests
#
# COMO CONFIGURAR:
#   Edite as variáveis da seção "⚙️ CONFIGURAÇÕES" logo abaixo com os seus dados.
#
#   1. TOKEN DE AUTENTICAÇÃO:
#      - No SonarCloud: Acesse https://sonarcloud.io → Meu Perfil (ícone no canto superior direito)
#                       → Security → Generate Tokens → Copie o token gerado.
#      - No SonarQube:  Acesse sua instância → Meu Perfil → Security → Generate Tokens.
#      - Cole o token na variável SONAR_TOKEN (nunca compartilhe este token!).
#
#   2. CHAVE DO PROJETO (PROJECT_KEY):
#      - No SonarCloud: Abra seu projeto → vá em Information (ícone ℹ️ no menu lateral)
#                       → copie o valor de "Project Key".
#      - No SonarQube:  Abra seu projeto → Administration → Update Key.
#
#   3. URL BASE (SONAR_BASE_URL):
#      - SonarCloud:    https://sonarcloud.io
#      - SonarQube:     Coloque o endereço da sua instância, ex: http://localhost:9000
#                       ou https://sonar.minha-empresa.com
#
#   4. ORGANIZAÇÃO (SONAR_ORG) — APENAS PARA SONARCLOUD:
#      - Acesse https://sonarcloud.io → clique na sua organização no menu superior.
#      - Copie o nome que aparece na URL: sonarcloud.io/organizations/NOME_AQUI
#      - Se estiver usando SonarQube self-hosted, deixe como string vazia: ""
#
# COMO RODAR:
#   No terminal, dentro da pasta do script, execute:
#       python extrator_sonar.py
#
# RESULTADO:
#   - Um arquivo JSON chamado 'sonar_issues.json' será gerado na mesma pasta.
#   - A lista de problemas será exibida no terminal formatada.
#
# =============================================================================

import json
import os

import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# =============================================================================
# ⚙️ CONFIGURAÇÕES — EDITE APENAS ESTA SEÇÃO
# =============================================================================

SONAR_TOKEN    = os.environ.get("SONAR_TOKEN")
PROJECT_KEY    = os.environ.get("PROJECT_KEY")
SONAR_BASE_URL = os.environ.get("SONAR_BASE_URL")
SONAR_ORG      = os.environ.get("SONAR_ORG")

# =============================================================================


def get_sonar_issues():
    # Verifica se as variáveis obrigatórias foram configuradas
    if not SONAR_BASE_URL or not PROJECT_KEY:
        print("Erro: As variáveis de ambiente SONAR_BASE_URL e PROJECT_KEY são obrigatórias.")
        return

    # Monta a URL da API de issues
    url = f"{SONAR_BASE_URL}/api/issues/search"

    # Parâmetros da busca
    params = {
        "componentKeys": PROJECT_KEY,
        "types":         "VULNERABILITY,CODE_SMELL",
        "resolved":      "false",
        "ps":            100  # Máximo de 100 resultados por página
    }

    # Adiciona o parâmetro de organização somente se for informado (SonarCloud)
    if SONAR_ORG:
        params["organization"] = SONAR_ORG

    # A autenticação é feita com o token no campo de usuário e senha em branco
    auth = HTTPBasicAuth(SONAR_TOKEN, "")

    print(f"🔍 Buscando issues do projeto '{PROJECT_KEY}' em {SONAR_BASE_URL}...")

    response = requests.get(url, params=params, auth=auth, timeout=30)

    if response.status_code == 401:
        print("Erro de autenticação! Verifique se o SONAR_TOKEN está correto.")
        return

    if response.status_code == 404:
        print("Projeto não encontrado! Verifique se o PROJECT_KEY está correto.")
        return

    if response.status_code != 200:
        print(f"Erro na requisição: {response.status_code} - {response.text}")
        return

    data = response.json()

    # Salva o resultado em JSON
    nome_arquivo = "sonar_issues.json"
    with open(nome_arquivo, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    print(f"\nSucesso! Arquivo '{nome_arquivo}' gerado com {data['total']} problema(s).\n")
    print("=" * 60)
    print("         LISTA DE ISSUES ENCONTRADAS")
    print("=" * 60)

    for issue in data["issues"]:
        severidade = issue.get("severity", "UNKNOWN")
        tipo       = issue.get("type", "UNKNOWN")
        mensagem   = issue.get("message", "Sem descrição")
        arquivo    = issue.get("component", "").split(":")[-1]

        # Ícone visual por severidade
        types = {
            "BLOCKER":  "BLOCKER",
            "CRITICAL": "CRITICAL",
            "MAJOR":    "MAJOR",
            "MINOR":    "MINOR",
            "INFO":     "INFO",
        }
        type_ = types.get(severidade, " - ")

        print(f"{type_} [{severidade}] {tipo}")
        print(f"   Arquivo:    {arquivo}")
        print(f"   Descrição:  {mensagem}")
        print("-" * 60)

    print(f"\nArquivo salvo: {nome_arquivo}")


if __name__ == "__main__":
    get_sonar_issues()
