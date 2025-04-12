from flask import render_template, redirect, url_for, session, request
from app import app
from app.encryption import decrypt_aes, ofuscar_dni
from app.reading import read_db
from Crypto.Cipher import AES

def decrypt_dni(ciphertext, key, nonce):
    decipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    ciphertext = bytes.fromhex(ciphertext)
    plaintext = decipher.decrypt(ciphertext)
    plaintext = plaintext.decode()
    return plaintext

# app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/deposit', methods=['GET'])
def deposit():
    cookie = request.cookies.get('darkmode')

    return render_template('deposit.html', darkmode=cookie)


@app.route('/register', methods=["GET", "POST"])
def register():
    return render_template('form.html')


@app.route('/login', methods=["GET"])
def login():
    return render_template("login.html")


@app.route('/edit_user/<email>', methods=['GET'])
def edit_user(email):

    db = read_db("db.txt")

    if email not in db:
        return redirect(url_for('records', message="Usuario no encontrado"))

    user_info = db[email]
    dni = decrypt_dni(user_info['dni'], bytes.fromhex(db["Key"]), bytes.fromhex(db[email]["nonce"]))
    user_info['dni'] = dni

    return render_template('edit_user.html', user_data=user_info, email=email)


# Formulario de retiro
@app.route('/withdraw', methods=['GET'])
def withdraw():
    cookie = request.cookies.get('darkmode')
    email = session.get('email')
    print(email)
    transactions = read_db("transaction.txt")
    current_balance = sum(float(t['balance']) for t in transactions.get(email, []))
    return render_template('withdraw.html', balance=current_balance, darkmode=cookie)

@app.route('/password_form', methods=['GET'])
def password_form():
    cookie = request.cookies.get('darkmode')
    return render_template('password_form.html', darkmode=cookie)

@app.route('/logout', methods=['GET'])
def logout():
    cookie = request.cookies.get('darkmode')
    return render_template('logout.html', darkmode=cookie)