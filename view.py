import datetime
import os
import threading
import random
import jwt
from flask import jsonify, request, make_response
from main import app, get_db_connection
from funcao import (verificar_senha, criptografar, checar_senha,
                    enviando_email, gerar_token, verificar_reuso_senha, gerar_codigo)

# Configuração de Pasta de Upload
UPLOAD_FOLDER = os.path.join(app.config['UPLOAD_FOLDER'], "usuarios")
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)



@app.route('/criar_usuario', methods=['POST'])
def criar_usuario():
    con = get_db_connection()
    cur = con.cursor()
    try:
        dados = request.form if request.form else request.json
        nome = dados.get('nome')
        email = dados.get('email')
        senha = dados.get('senha')
        tipo_nome = dados.get('tipo', 'cliente').lower()
        id_tipo = 1 if tipo_nome == 'admin' else 2
        foto = request.files.get('foto')

        if not nome or not email or not senha:
            return jsonify({'erro': 'Campos obrigatórios faltando.'}), 400

        # Verifica se e-mail existe
        cur.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?", (email,))
        if cur.fetchone(): return jsonify({'erro': 'E-mail já cadastrado.'}), 409

        senha_hash = criptografar(senha)
        # Gera código de 6 dígitos
        codigo_confirmacao = str(random.randint(100000, 999999))

        cur.execute("""
            INSERT INTO USUARIO (NOME, EMAIL, SENHA, ID_TIPO, TIPO_NOME, CONTA_CONFIRMADA, BLOQUEADO, TENTATIVAS_LOGIN)
            VALUES (?, ?, ?, ?, ?, False, False, 0)
        """, (nome, email, senha_hash, id_tipo, tipo_nome))

        cur.execute("SELECT MAX(ID_USUARIO) FROM USUARIO")
        id_usuario = cur.fetchone()[0]

        if foto:
            foto.save(os.path.join(UPLOAD_FOLDER, f"perfil_{id_usuario}.jpg"))

        # Insere na tabela CODIGOS do seu banco
        cur.execute("""
            INSERT INTO CODIGOS (ID_USUARIO, CODIGO, TIPO, UTILIZADO) 
            VALUES (?, ?, 'CONFIRMACAO', False)
        """, (id_usuario, codigo_confirmacao))

        con.commit()

        # Envio de E-mail Assíncrono
        threading.Thread(target=enviando_email, args=(
            email, "Confirmação de Conta", f"Seu código é: {codigo_confirmacao}"
        )).start()

        return jsonify({"mensagem": "Usuário criado! Verifique seu e-mail.", "id": id_usuario}), 201
    except Exception as e:
        con.rollback()
        return jsonify({'erro': str(e)}), 500
    finally:
        con.close()


# ---------------------------------------------------------
# 2. CONFIRMAR CÓDIGO (Ativação de Conta)
# ---------------------------------------------------------
@app.route('/confirmar_codigo', methods=['POST'])
def confirmar_codigo():
    con = get_db_connection()
    cur = con.cursor()
    try:
        dados = request.json
        email = dados.get('email')
        codigo = dados.get('codigo')

        cur.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?", (email,))
        user = cur.fetchone()
        if not user: return jsonify({'erro': 'Usuário não encontrado'}), 404
        id_user = user[0]

        # Verifica se o código existe e não foi usado
        cur.execute("SELECT ID FROM CODIGOS WHERE ID_USUARIO = ? AND CODIGO = ? AND UTILIZADO = False",
                    (id_user, codigo))
        cod_id = cur.fetchone()

        if cod_id:
            cur.execute("UPDATE USUARIO SET CONTA_CONFIRMADA = True WHERE ID_USUARIO = ?", (id_user,))
            cur.execute("UPDATE CODIGOS SET UTILIZADO = True WHERE ID = ?", (cod_id[0],))
            con.commit()
            return jsonify({"mensagem": "Conta ativada com sucesso!"}), 200
        return jsonify({"erro": "Código inválido ou já utilizado"}), 400
    finally:
        con.close()


# ---------------------------------------------------------
# 3. LOGIN USUÁRIO
# ---------------------------------------------------------
@app.route('/login_usuario', methods=['POST'])
def login_usuario():
    con = get_db_connection()
    cur = con.cursor()
    dados = request.json
    try:
        cur.execute(
            "SELECT ID_USUARIO, SENHA, NOME, TIPO_NOME, CONTA_CONFIRMADA, BLOQUEADO FROM USUARIO WHERE EMAIL = ?",
            (dados['email'],))
        res = cur.fetchone()
        if not res: return jsonify({'erro': 'Login inválido'}), 401

        id_u, hash_db, nome, tipo, conf, block = res

        if block: return jsonify({'erro': 'Conta bloqueada'}), 403
        if not conf: return jsonify({'erro': 'E-mail não confirmado'}), 403

        if checar_senha(dados['senha'], hash_db):
            token = jwt.encode({'id': id_u, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)},
                               app.config['SECRET_KEY'])
            return jsonify({'token': token, 'nome': nome, 'tipo': tipo}), 200

        return jsonify({'erro': 'Senha incorreta'}), 401
    finally:
        con.close()


# ---------------------------------------------------------
# 4. LISTAR USUÁRIOS
# ---------------------------------------------------------
@app.route('/usuarios', methods=['GET'])
def listar_usuarios():
    con = get_db_connection()
    cur = con.cursor()
    cur.execute("SELECT ID_USUARIO, NOME, EMAIL, TIPO_NOME FROM USUARIO")
    rows = cur.fetchall()
    res = [{'id': r[0], 'nome': r[1], 'email': r[2], 'tipo': r[3]} for r in rows]
    con.close()
    return jsonify(res), 200


# ---------------------------------------------------------
# 5. EDITAR USUÁRIO
# ---------------------------------------------------------
@app.route('/editar_usuario/<int:id>', methods=['PUT'])
def editar_usuario(id):
    con = get_db_connection()
    cur = con.cursor()
    try:
        dados = request.form
        nome = dados.get('nome')
        cur.execute("UPDATE USUARIO SET NOME = ? WHERE ID_USUARIO = ?", (nome, id))
        con.commit()
        return jsonify({"mensagem": "Usuário atualizado"}), 200
    finally:
        con.close()


# ---------------------------------------------------------
# 6. EXCLUIR USUÁRIO
# ---------------------------------------------------------
@app.route('/excluir_usuario/<int:id>', methods=['DELETE'])
def excluir_usuario(id):
    con = get_db_connection()
    cur = con.cursor()
    try:
        cur.execute("DELETE FROM USUARIO WHERE ID_USUARIO = ?", (id,))
        con.commit()
        return jsonify({"mensagem": "Removido com sucesso"}), 200
    except Exception as e:
        return jsonify({"erro": str(e)}), 500
    finally:
        con.close()


# ---------------------------------------------------------
# 7. RECUPERAÇÃO DE SENHA (Solicitar e Redefinir)
# ---------------------------------------------------------
@app.route('/solicitar_recuperacao', methods=['POST'])
def solicitar_recuperacao():
    con = get_db_connection()
    cur = con.cursor()
    email = request.json.get('email')
    cur.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?", (email,))
    user = cur.fetchone()
    if user:
        codigo = str(random.randint(100000, 999999))
        expira = datetime.datetime.now() + datetime.timedelta(minutes=15)
        cur.execute("INSERT INTO RECUPERAR_SENHA (ID_USUARIO, CODIGO, EXPIRACAO, UTILIZADO) VALUES (?, ?, ?, False)",
                    (user[0], codigo, expira))
        con.commit()
        threading.Thread(target=enviando_email, args=(email, "Recuperar Senha", f"Seu código é: {codigo}")).start()
    con.close()
    return jsonify({"mensagem": "Se o e-mail existir, você receberá um código"}), 200


@app.route('/redefinir_senha', methods=['POST'])
def redefinir_senha():
    con = get_db_connection()
    cur = con.cursor()
    try:
        dados = request.json
        # Busca o código válido na tabela RECUPERAR_SENHA
        cur.execute("SELECT ID_USUARIO FROM RECUPERAR_SENHA WHERE CODIGO = ? AND UTILIZADO = False", (dados['codigo'],))
        res = cur.fetchone()
        if not res: return jsonify({"erro": "Código inválido"}), 400

        nova_hash = criptografar(dados['nova_senha'])
        cur.execute("UPDATE USUARIO SET SENHA = ? WHERE ID_USUARIO = ?", (nova_hash, res[0]))
        cur.execute("UPDATE RECUPERAR_SENHA SET UTILIZADO = True WHERE CODIGO = ?", (dados['codigo'],))
        con.commit()
        return jsonify({"mensagem": "Senha alterada com sucesso!"}), 200
    finally:
        con.close()


# ---------------------------------------------------------
# 8. LOGOUT
# ---------------------------------------------------------
@app.route('/logout', methods=['POST'])
def logout():
    return jsonify({"mensagem": "Logout efetuado. Remova o token no frontend."}), 200