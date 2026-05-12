import re
import jwt
import datetime
import smtplib
import random
import string
import os
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash


def verificar_senha(senha):
    if len(senha) < 8:
        return "A senha deve ter no mínimo 8 caracteres."

    if not re.search(r"[A-Z]", senha):
        return "A senha precisa de pelo menos uma letra maiúscula."

    if not re.search(r"[0-9]", senha):
        return "A senha precisa de pelo menos um número."

    if not re.search(r"[@$!%*?&]", senha):
        return "A senha precisa de um caractere especial (@$!%*?&)."

    return None


def criptografar(senha):
    return generate_password_hash(senha)


def checar_senha(senha_digitada, senha_hash):
    if not senha_hash:
        return False
    return check_password_hash(senha_hash, senha_digitada)


def gerar_codigo():
    return ''.join(random.choices(string.digits, k=6))


import smtplib
from email.message import EmailMessage

def enviando_email(destinatario, assunto, corpo):
    try:
        msg = EmailMessage()
        msg['Subject'] = assunto
        msg['From'] = 'seu_email@gmail.com' # Seu e-mail
        msg['To'] = destinatario
        msg.set_content(corpo)

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login('oliveirarodriguesotavio280@gmail.com', 'roeg-sosj-iviv-pfjy')
            smtp.send_message(msg)
        print(f"✅ E-mail enviado para {destinatario}")
    except Exception as e:
        print(f"❌ Erro ao enviar e-mail: {e}")


def gerar_token(id_usuario):
    from main import app  # evita import circular

    payload = {
        "id_usuario": id_usuario,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    }

    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")


def remover_bearer(token):
    if token and token.startswith("Bearer "):
        return token.split(" ")[1]
    return token


def verificar_reuso_senha(id_usuario, nova_senha, cursor):
    cursor.execute("""
        SELECT FIRST 3 senha_antiga
        FROM HISTORICO_SENHAS
        WHERE id_usuario = ?
        ORDER BY data_alteracao DESC
    """, (id_usuario,))

    historico = cursor.fetchall()

    for registro in historico:
        if checar_senha(nova_senha, registro[0]):
            return True

    return False