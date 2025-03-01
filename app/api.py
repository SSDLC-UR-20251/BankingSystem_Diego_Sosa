from _datetime import datetime
import time
from app.validation import *
from app.reading import *
from flask import request, jsonify, redirect, url_for, render_template, session, make_response
from app import app

app.secret_key = 'your_secret_key'
max_intentos = 3
tiempo_bloq = 5
estado_usuario = {}

for k, p in read_db('db.txt').items():
    estado_usuario[p["username"]] = {"intentos": 0, "tiempoBloqueo": 0}


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
    print(data)
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

    db = read_db("db.txt")
    db[email] = {
        'nombre': normalize_input(nombre),
        'apellido': normalize_input(apellido),
        'username': normalize_input(username),
        'password': normalize_input(password),
        "dni": dni,
        'dob': normalize_input(dob),
        "role":"admin"
    }

    write_db("db.txt", db)
    return redirect("/login")

# ---- SOLUCION PUNTO 1 
from time import time

# Definir variables globales para intentos y bloqueo
max_intentos = 3
tiempo_bloq = 300  # 5 minutos en segundos
estado_usuario = {}  # Diccionario para almacenar intentos fallidos y tiempo de bloqueo

@app.route('/api/login', methods=['POST'])
def api_login():
    global max_intentos, tiempo_bloq, estado_usuario

    db = read_db('db.txt')
    email = normalize_input(request.form['email'])
    password = normalize_input(request.form['password'])

    # Verificar si el usuario existe antes de acceder a sus datos
    if email not in db:
        return render_template('login.html', error="Credenciales inválidas")

    usuario = db[email]['username']  # Ahora seguro acceder a username
    password_db = db[email]['password']

    # Inicializar estado del usuario si no existe
    if usuario not in estado_usuario:
        estado_usuario[usuario] = {"intentos": 0, "tiempoBloqueo": 0}

    # Verificar si el usuario está bloqueado
    if estado_usuario[usuario]["intentos"] >= max_intentos:
        tiempo_restante = (estado_usuario[usuario]["tiempoBloqueo"] + tiempo_bloq) - time()
        if tiempo_restante > 0:
            return render_template('login.html', error=f"Cuenta bloqueada. Intente en {int(tiempo_restante / 60)} min.")
        else:
            # Restablecer intentos después del tiempo de bloqueo
            estado_usuario[usuario]["intentos"] = 0


    # ----PUNTO 2
    if password_db == password:
        # Reiniciar intentos fallidos al iniciar sesión correctamente
        estado_usuario[usuario]["intentos"] = 0

        # Guardar rol del usuario en la sesión
        session['role'] = db[email]['role']
        session['email'] = email

        # Redirigir según el rol del usuario
        
        return redirect(url_for('customer_menu'))  # Ruta para usuarios normales



    else:
        # Incrementar intentos fallidos
        estado_usuario[usuario]["intentos"] += 1
        
        if estado_usuario[usuario]["intentos"] >= max_intentos:
            estado_usuario[usuario]["tiempoBloqueo"] = time()  # Registrar tiempo de bloqueo
            return render_template('login.html', error="Cuenta bloqueada por intentos fallidos. Espere 5 minutos.")
        else:
            return render_template('login.html', error=f"Credenciales inválidas. Intento {estado_usuario[usuario]['intentos']} de {max_intentos}.")



# Página principal del menú del cliente
@app.route('/customer_menu')
def customer_menu():

    db = read_db("db.txt")

    transactions = read_db("transaction.txt")
    current_balance = 100
    last_transactions = []
    message = request.args.get('message', '')
    error = request.args.get('error', 'false').lower() == 'true'
    return render_template('customer_menu.html',
                           message=message,
                           nombre="",
                           balance=current_balance,
                           last_transactions=last_transactions,
                           error=error,)


# Endpoint para leer un registro
@app.route('/records', methods=['GET'])
def read_record():
    db = read_db("db.txt")
    email = session.get('email')  # Obtener el email del usuario autenticado
    role = session.get('role')  # Obtener el rol del usuario
    message = request.args.get('message', '')
    print(email)
    
    # Si el usuario es admin, ve todos los registros; si no, solo su propio perfil
    if role == "admin":
        users = db  # Mostrar todos los usuarios
    elif role == "user":
        users = {}  # Mostrar solo su propio perfil
        if email in db:
            users[email] = db[email]
    else:
        users = {}

    return render_template('records.html', users=users, role=role, message=message)
    #return render_template('records.html', users=db,role=session.get('role'),message=message)


@app.route('/update_user/<email>', methods=['POST'])
def update_user(email):
    # Leer la base de datos de usuarios
    db = read_db("db.txt")

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
                               error=errores)


    db[email]['username'] = normalize_input(username)
    db[email]['nombre'] = normalize_input(nombre)
    db[email]['apellido'] = normalize_input(apellido)
    db[email]['dni'] = dni
    db[email]['dob'] = normalize_input(dob)


    write_db("db.txt", db)
    

    # Redirigir al usuario a la página de records con un mensaje de éxito
    return redirect(url_for('read_record', message="Información actualizada correctamente"))

