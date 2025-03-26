from _datetime import datetime
import time
from app.validation import *
from app.reading import *
from flask import request, jsonify, redirect, url_for, render_template, session, make_response
from app import app
from app.encryption import *
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from datetime import timedelta

login_attempts = {}
MAX_ATTEMPTS = 3
BLOCK_TIME = 300  # 5 minutos en segundos
app.secret_key = 'your_secret_key'

def encrypt_dni(dni, key):
    db = read_db("db.txt")
    cipher = AES.new(key, AES.MODE_EAX)
    dni = dni.encode()
    ciphertext, tag = cipher.encrypt_and_digest(dni)
    return ciphertext.hex(), cipher.nonce.hex()

def decrypt_dni(ciphertext, key, nonce):
    decipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    ciphertext = bytes.fromhex(ciphertext)
    plaintext = decipher.decrypt(ciphertext)
    plaintext = plaintext.decode()
    return plaintext

def hash_with_salt(password, salt):
    if salt is None:
        salt = get_random_bytes(16)
    else:
        salt = bytes.fromhex(salt)

    # Deriva una clave usando scrypt
    key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)

    # Crea un hash SHA-256 de la clave derivada
    hash_obj = SHA256.new(key)
    hash_value = hash_obj.hexdigest()

    return hash_value, salt

def compare_salt(password, password_db, salt_db):
    hash_value2 = hash_with_salt(password, salt_db)[0]
    if (hash_value2 == password_db):
        return True
    else:
        return False
    
@app.before_request
def before_request_func():
    session.permanent = False
    app.permanent_session_lifetime = timedelta(minutes=5)

@app.route('/api/users', methods=['POST'])
def create_record():
    data = request.form
    email = data.get('email')
    username = data.get('username')
    nombre = data.get('nombre')
    apellido = data.get('Apellidos')
    password = data.get('password')
    dni = data.get('dni')
    dob = data.get('dob')
    errores = []
    # Validaciones
    if not validate_email(email):
        errores.append("Email inválido")
    if not validate_pswd(password):
        errores.append("Contraseña inválida")
    if not validate_dob(dob):
        errores.append("Fecha de nacimiento inválida")
    if not validate_dni(dni):
        errores.append("DNI inválido")
    if not validate_user(username):
        errores.append("Usuario inválido")
    if not validate_name(nombre):
        errores.append("Nombre inválido")
    if not validate_name(apellido):
        errores.append("Apellido inválido")

    if errores:
        return render_template('form.html', error=errores)

    email = normalize_input(email)

    hashed_pwd, salt = hash_with_salt(password, None)
    db = read_db("db.txt")
    k = db["Key"]
    dni_c, nonce = encrypt_dni(dni, bytes.fromhex(k))
    db[email] = {
        'nombre': normalize_input(nombre),
        'apellido': normalize_input(apellido),
        'username': normalize_input(username),
        'password': hashed_pwd,
        "password_salt": salt.hex(),
        "dni": dni_c,
        'dob': normalize_input(dob),
        "role": "Admin",
        "nonce": nonce
    }

    write_db("db.txt", db)
    return redirect("/login")


# Endpoint para el login
@app.route('/api/login', methods=['POST'])
def api_login():
    email = normalize_input(request.form['email'])
    password = request.form['password']

    db = read_db("db.txt")
    if email not in db:
        error = "Credenciales inválidas"
        return render_template('login.html', error=error)

    # Verificar si el usuario está bloqueado
    if email in login_attempts and login_attempts[email]['blocked_until'] > time.time():
        block_time_remaining = int((login_attempts[email]['blocked_until'] - time.time()) / 60)
        error = f"Cuenta bloqueada. Intenta nuevamente en {block_time_remaining} minutos."
        return render_template('login.html', error=error)

    password_db = db.get(email)["password"]
    salt_db = db.get(email)["password_salt"]

    # Validar si el correo existe en la base de datos
    if compare_salt(password, password_db, salt_db):
        # Resetear intentos fallidos
        login_attempts[email] = {'attempts': 0, 'blocked_until': 0}

        session['email'] = email
        session['role'] = db[email]['role']

        return redirect(url_for('customer_menu'))
    else:
        # Aumentar el contador de intentos fallidos
        if email not in login_attempts:
            login_attempts[email] = {'attempts': 0, 'blocked_until': 0}

        login_attempts[email]['attempts'] += 1

        # Bloquear la cuenta si se exceden los intentos
        if login_attempts[email]['attempts'] >= MAX_ATTEMPTS:
            login_attempts[email]['blocked_until'] = time.time() + BLOCK_TIME
            error = f"Se han excedido los intentos permitidos. Cuenta bloqueada por {BLOCK_TIME // 60} minutos."
        else:
            remaining_attempts = MAX_ATTEMPTS - login_attempts[email]['attempts']
            error = f"Credenciales incorrectas. Tienes {remaining_attempts} intentos restantes."

        return render_template('login.html', error=error)



# Página principal del menú del cliente
@app.route('/customer_menu')
def customer_menu():
    cookie = request.cookies.get('darkmode')
    if 'email' not in session:
        # Redirigir a la página de inicio de sesión si el usuario no está autenticado
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)

    email = session.get('email')
    db = read_db("db.txt")
    transactions = read_db("transaction.txt")
    current_balance = sum(float(t['balance']) for t in transactions.get(email, []))
    last_transactions = transactions.get(email, [])[-5:]
    message = request.args.get('message', '')
    error = request.args.get('error', 'false').lower() == 'true'
    return render_template('customer_menu.html',
                           message=message,
                           nombre=db.get(email)['nombre'],
                           balance=current_balance,
                           last_transactions=last_transactions,
                           error=error, darkmode=cookie)


# Endpoint para leer un registro
@app.route('/records', methods=['GET'])
def read_record():
    if 'email' not in session:
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)
    db = read_db("db.txt")
    email = session.get('email')  # Obtener el email del usuario autenticado
    role = session.get('role')  # Obtener el rol del usuario
    message = request.args.get('message', '')
    cookie = request.cookies.get('darkmode')
    
    # Si el usuario es admin, ve todos los registros; si no, solo su propio perfil
    users = {}
    if role == "Admin":
        for k in db:
            if (k != "Key"):
                users[k] = db[k]
        for k in users:
            users[k]["dni"] = decrypt_dni(users[k]["dni"], bytes.fromhex(db["Key"]), bytes.fromhex(db[k]["nonce"]))
            users[k]["dni"] = '****' + users[k]["dni"][-4:]
    elif role == "User":
        if email in db:
            users[email] = db[email]
            users[email]["dni"] = decrypt_dni(users[email]["dni"], bytes.fromhex(db["Key"]), bytes.fromhex(db[email]["nonce"]))
            users[email]["dni"] = '****' + users[email]["dni"][-4:]

    return render_template('records.html', users=users, role=role, message=message, darkmode=cookie)


@app.route('/update_user/<email>', methods=['POST', 'GET'])
def update_user(email):
    if 'email' not in session:
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)
    # Leer la base de datos de usuarios
    db = read_db("db.txt")

    cookie = request.cookies.get('darkmode')
    username = request.form['username']
    dni = request.form['dni']
    dob = request.form['dob']
    nombre = request.form['nombre']
    apellido = request.form['apellido']
    errores = []

    if not validate_dob(dob):
        errores.append("Fecha de nacimiento inválida")
    if not validate_dni(dni):
        errores.append("DNI inválido")
    if not validate_user(username):
        errores.append("Usuario inválido")
    if not validate_name(nombre):
        errores.append("Nombre inválido")
    if not validate_name(apellido):
        errores.append("Apellido inválido")

    if errores:
        return render_template('edit_user.html',
                               user_data=db[email],
                               email=email,
                               error=errores, darkmode=cookie)


    db[email]['username'] = normalize_input(username)
    db[email]['nombre'] = normalize_input(nombre)
    db[email]['apellido'] = normalize_input(apellido)
    dni_c, nonce = encrypt_dni(dni, bytes.fromhex(db["Key"]))
    db[email]['dni'] = dni_c
    db[email]['dob'] = normalize_input(dob)
    db[email]['nonce'] = nonce

    darkmode = 'dark' if request.form.get('darkmode') else 'light'

    write_db("db.txt", db)
    resp = make_response(redirect(url_for('read_record', message="Información actualizada correctamente")))
    resp.set_cookie('darkmode', darkmode, max_age=30*24*60*60, secure=True, httponly=False, samesite='Strict')  # La cookie expira en 30 días

    # Redirigir al usuario a la página de records con un mensaje de éxito
    return resp

@app.route('/api/delete_user/<email>', methods=['GET'])
def delete_user(email):
    if 'email' not in session:
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)
    
    cookie = request.cookies.get('darkmode')
    if session.get('role') == 'admin':
        db = read_db("db.txt")

        if email not in db:
            return redirect(url_for('read_record', message="Usuario no encontrado"))

        del db[email]

        write_db("db.txt", db)

        return redirect(url_for('read_record', message="Usuario eliminado"))
    else:
        return redirect(url_for('read_record', message="No autorizado"))

# Endpoint para depósito
@app.route('/api/deposit', methods=['POST'])
def api_deposit():
    if 'email' not in session:
        # Redirigir a la página de inicio de sesión si el usuario no está autenticado
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)

    deposit_balance = request.form['balance']
    deposit_email = session.get('email')

    db = read_db("db.txt")
    transactions = read_db("transaction.txt")

    # Verificamos si el usuario existe
    if deposit_email in db:
        # Guardamos la transacción
        transaction = {"balance": deposit_balance, "type": "Deposit", "timestamp": str(datetime.now())}

        # Verificamos si el usuario tiene transacciones previas
        if deposit_email in transactions:
            transactions[deposit_email].append(transaction)
        else:
            transactions[deposit_email] = [transaction]
        write_db("transaction.txt", transactions)

        return redirect(url_for('customer_menu', message="Depósito exitoso"))

    return redirect(url_for('customer_menu', message="Email no encontrado"))


# Endpoint para retiro
@app.route('/api/withdraw', methods=['POST'])
def api_withdraw():
    if 'email' not in session:
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)
    cookie = request.cookies.get('darkmode')
    db = read_db("db.txt")
    email = session.get('email')
    amount = float(request.form['balance'])

    if amount <= 0:
        return redirect(url_for('customer_menu',
                                message="La cantidad a retirar debe ser positiva",
                                error=True, darkmode=cookie))

    transactions = read_db("transaction.txt")
    current_balance = sum(float(t['balance']) for t in transactions.get(email, []))

    if amount > current_balance:
        return redirect(url_for('customer_menu',
                                message="Saldo insuficiente para retiro",
                                error=True, darkmode=cookie))

    transaction = {"balance": -amount, "type": "Withdrawal", "timestamp": str(datetime.now())}

    if email in transactions:
        transactions[email].append(transaction)
    else:
        transactions[email] = [transaction]

    write_db("transaction.txt", transactions)

    return redirect(url_for('customer_menu',
                            message="Retiro exitoso",
                            error=False, darkmode=cookie))

#Endpoint para validar la contraseña
@app.route('/api/password_form', methods=['POST'])	
def api_password_form():
    if 'email' not in session:
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)
    password = request.form['password']
    email = session.get('email')
    db = read_db("db.txt")
    if compare_salt(password, db[email]["password"], db[email]["password_salt"]):
        return redirect(url_for('withdraw',
                        message="Contraseña valida",
                        error=False))
    else:
        return redirect(url_for('customer_menu',
                        message="Contraseña invalida",
                        error=True))
    
#Endpoint para cerrar sesión
@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('email', None)
    session.pop('role', None)
    return redirect(url_for('index'))
    