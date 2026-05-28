# auth.py
# Autor: [Arthur Fernandes Silva Reis ]
# Descrição: Gerencia login/logout com suporte a bcrypt e auditoria de acessos.

import sys
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

from datetime import datetime
from connection import get_connection

# ─────────────────────────────────────────────
# Tentativa de importação do bcrypt
# ─────────────────────────────────────────────
try:
    import bcrypt  # type: ignore[import]
    _HAS_BCRYPT = True
except ImportError:
    bcrypt = None
    _HAS_BCRYPT = False

#Função _check_passoword
"""
    Verifica a senha do usuário contra o valor armazenado no banco.

    Suporta dois modos:
    - Hash bcrypt : validação segura via bcrypt.checkpw()
    - Texto puro: comparação direta (legado / ambientes sem hash)

    Args:
        senha_digitada : Senha informada pelo usuário.
        stored : Valor armazenado no banco de dados.

    Returns:
        bool: True se a senha for válida, False caso contrário.
    """
def _check_password(senha_digitada: str, stored: str) -> bool:
    
    if not stored:
        return False

    # Validação via bcrypt
    if stored.startswith(("$2a$", "$2b$", "$2y$")):
        if not _HAS_BCRYPT:
            print("bcrypt não disponível. Instale com: pip install bcrypt")
            return False
        try:
            return bcrypt.checkpw(
                senha_digitada.encode("utf-8"),
                stored.encode("utf-8")
            )
        except Exception:
            return False

    # Fallback: comparação direta (texto puro — legado)
    return senha_digitada == stored
  #Função de Login 
 """
    Autentica um usuário pelo email e senha.

    Fluxo:
    1. Busca o usuário no banco pelo email.
    2. Verifica se a conta está ativa.
    3. Valida a senha (bcrypt ou texto puro).
    4. Registra o evento de login em audit_logs.
    5. Retorna um dicionário de sessão com dados e papéis do usuário.

    Args:
        email (str): Email do usuário.
        senha_digitada (str): Senha informada no login.

    Returns:
        dict | None: Dados da sessão do usuário, ou None em caso de falha.

    Exemplo de retorno:
        {
            'id': 1,
            'name': 'João Silva',
            'email': 'joao@email.com',
            'roles': ['admin'],
            'role_ids': [1],
            'tipo_principal': 'admin'
        }
    """
def login(email: str, senha_digitada: str) -> dict | None:
   
    conn = get_connection()
    cursor = conn.cursor(dictionary=True, buffered=True)

    try:
        # Query com GROUP BY completo — compatível com ONLY_FULL_GROUP_BY
        query = """
            SELECT
                u.id,
                u.name,
                u.email,
                u.password_hash,
                u.active,
                GROUP_CONCAT(DISTINCT r.id)   AS role_ids,
                GROUP_CONCAT(DISTINCT r.name) AS role_names
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r       ON ur.role_id = r.id
            WHERE u.email = %s
            GROUP BY u.id, u.name, u.email, u.password_hash, u.active
        """
        cursor.execute(query, (email,))
        usuario_banco = cursor.fetchone()

        # Validações de acesso
        if not usuario_banco:
            print("[AUTH] Email não encontrado.")
            return None

        if not usuario_banco['active']:
            print("[AUTH] Conta desativada.")
            return None

        stored = usuario_banco.get('password_hash') or ""
        if not _check_password(senha_digitada, stored):
            print("[AUTH] Senha incorreta.")
            return None

        # Registro de auditoria
        try:
            cursor.execute(
                "INSERT INTO audit_logs (user_id, action, timestamp) VALUES (%s, %s, %s)",
                (usuario_banco['id'], 'login', datetime.now())
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[AVISO] Login realizado, mas auditoria não registrada: {e}")

        # Processamento dos papéis (roles)
        roles_list = []
        role_ids_list = []

        if usuario_banco.get('role_names'):
            roles_list = [
                r.strip()
                for r in usuario_banco['role_names'].split(',')
                if r.strip()
            ]
        if usuario_banco.get('role_ids'):
            role_ids_list = [
                int(x)
                for x in usuario_banco['role_ids'].split(',')
                if x and x.isdigit()
            ]

        # Determinação do papel principal
        roles_lower = [r.lower() for r in roles_list]
        if 'admin' in roles_lower:
            tipo = 'admin'
        elif 'professor' in roles_lower:
            tipo = 'professor'
        elif 'aluno' in roles_lower:
            tipo = 'aluno'
        else:
            tipo = 'desconhecido'

        usuario = {
            'id':             usuario_banco['id'],
            'name':           usuario_banco['name'],
            'email':          usuario_banco['email'],
            'roles':          roles_list,
            'role_ids':       role_ids_list,
            'tipo_principal': tipo
        }

        print(f"Login bem-sucedido — Bem-vindo(a), {usuario['name']}!")
        return usuario

    except Exception as e:
        print(f"Falha durante o login: {e}")
        return None

    finally:
        cursor.close()
        conn.close()
#Função Logout 
 """
    Registra o evento de logout do usuário em audit_logs.

    Args:
        usuario_id (int): ID do usuário que está encerrando a sessão.

    Returns:
        bool: Sempre True (logout é sempre bem-sucedido na sessão,
              mesmo que o registro em banco falhe).
    """
def logout(usuario_id: int) -> bool:
    conn = get_connection()
    cursor = conn.cursor(buffered=True)

    try:
        cursor.execute(
            "INSERT INTO audit_logs (user_id, action, timestamp) VALUES (%s, 'logout', NOW())",
            (usuario_id,)
        )
        conn.commit()
        print("[AUTH] Logout registrado com sucesso.")
        return True

    except Exception as e:
        conn.rollback()
        print(f"[AVISO] Logout realizado, mas não registrado em audit_logs: {e}")
        return True

    finally:
        cursor.close()
        conn.close()
 
