from _datetime import datetime
import re

import unicodedata


def normalize_input(data):
    return data


# valido el email
def validate_email(email):
    email = normalize_input(email)
    i = email.index('@')
    dir = email[i:len(email)]
    if (dir == '@urosario.edu.co'):
        return True
    else:
        return False


# valido la edad
def validate_dob(dob):
    fecha = datetime.strptime(dob, '%d/%m/%Y')
    ahora = datetime.today()
    days = ahora - fecha
    days = days.days
    if (days / 365 > 16):
        return True
    else:
        return False


# valido el usuario
def validate_user(user):
    I = [chr(i) for i in range(65, 91)] + [chr(j) for j in range(97, 123)] + ['.']
    for c in user:
        if (c not in I):
            return False
    return True


# valido el dni
def validate_dni(dni):
    if (len(dni) > 10):
        return False
    ini = dni[0:10]
    if (ini == "1000000000"):
        return True
    else:
        return False


# valido la contraseña
def validate_pswd(pswd):
    if ((len(pswd) < 8) or (len(pswd) > 35)):
        return False
    invalid_char = ['#', '*', '@', '$', '%', '&', '-', '!', '+', '=', '?']
    mas = [chr(i) for i in range(65, 91)] 
    min = [chr(j) for j in range(97, 123)]
    nume = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    has_mas = False
    has_min = False
    has_num = False
    has_inv_char = False
    for c in pswd:
        if (not has_mas and c in mas):
            has_mas = True
        elif (not has_min and c in min):
            has_min = True
        elif (not has_num and c in nume):
            has_num = True
        elif (not has_inv_char and c in invalid_char):
            has_inv_char = True
    if (has_mas and has_min and has_num and not has_inv_char):
        return True
    else:
        return False


def validate_name(name):
    return True
