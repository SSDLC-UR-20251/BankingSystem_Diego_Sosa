from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time

driver = webdriver.ChromiumEdge() #Para definir el navegador
driver.get("http://127.0.0.1:5000/login") #Para abrir la página

#Iniciar sesión
driver.find_element(By.ID, "email").send_keys("user.a@urosario.edu.co") #Para ingresar el correo con el que deseo hacer la prueba
driver.find_element(By.ID, "password").send_keys("Usera12345") #Para ingresar la contraseña con la que deseo hacer la prueba
driver.find_element(By.ID, "login").click() #Para hacer click en el botón de iniciar sesión

time.sleep(1) #Tiempo de espera a que cargue la página

#Consultar el balance
saldo_texto = driver.find_element(By.ID, "saldo_usuario").text #Para obtener el texto del saldo
saldo_inicial = float(saldo_texto.split(":")[-1].strip()) #Para obtener el saldo como número
print(f"El saldo inicial es: {saldo_inicial}")

#Ingresar a la sección deposit
driver.find_element(By.ID, "deposit_button").click() #Para hacer click en el botón de depositar

#Hacer un deposito de 100
driver.find_element(By.ID, "balance").send_keys("100") #Para ingresar el monto a depositar
driver.find_element(By.ID, "deposit_button").click() #Para hacer click en el botón de depositar

time.sleep(1)

saldo_texto_n = driver.find_element(By.ID, "saldo_usuario").text #Para obtener el texto del saldo
saldo_final = float(saldo_texto_n.split(":")[-1].strip()) #Para obtener el saldo como número

#Hacer la prueba
#assert saldo_final == saldo_inicial + 100, f"Error: saldo esperado: {saldo_inicial + 100}, saldo obtenido: {saldo_final}"

time.sleep(1)

#Para intentar cerrar sesión y cancelar
driver.find_element(By.ID, "logout").click()
time.sleep(1)
driver.find_element(By.ID, "no_confirm").click()
time.sleep(1)

#Para hacer un retiro con una contraseña fraudulenta
driver.find_element(By.ID, "pss_f").click()
time.sleep(1)
driver.find_element(By.ID, "password").send_keys("123456")
driver.find_element(By.ID, "confirm").click()
time.sleep(1)

#Para hacer un retiro con la contraseña correcta
driver.find_element(By.ID, "pss_f").click()
time.sleep(1)
driver.find_element(By.ID, "password").send_keys("Usera12345")
driver.find_element(By.ID, "confirm").click()
time.sleep(1)
driver.find_element(By.ID, "balance").send_keys("100") #Para ingresar el monto a retirar
driver.find_element(By.ID, "confirm").click()
time.sleep(1)

#Para intentar cerrar sesión y confirmar
driver.find_element(By.ID, "logout").click()
time.sleep(1)
driver.find_element(By.ID, "confirm").click()
time.sleep(1)

driver.quit() #Para cerrar el navegador