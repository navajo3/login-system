#!/usr/bin/python

#
#  finish login function X
#  add menu loop X
#  debug register, login and decrypt/encrypt functions X
#  compile as exe then reverse engineer with IDA or x32dbg to find security flaws and fix if any  !!!!!!!!!!!!
#  ATTEMPT (not try for more than like 6 hrs) to make a GUI for this (too tired out after finishing probably wont do)
#  ATTEMPT (not try for more than like 2 hrs) to remove global variables for this:
#     remove global variables for return values if possible, possible interference if not (also not very bothered about this)
#

import os # OS interacting Function
import sys # System calls function
import re # Regular expression function (regex)
import traceback # Error handling function
import base64 # Base64 encoding algorithm
import time # Time logic function
from cryptography.fernet import Fernet # Encryption algorithm
from cryptography.hazmat.primitives import hashes # Hashing algorithm
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Key derivation function

salt = os.urandom(16) # Salt value, used to generate a key from a password
    
kdf = PBKDF2HMAC(                             # Key derivation function, used to generate a key from a password and a salt value
    algorithm=hashes.SHA256(),          # SHA256 hashing algorithm
    length=32,                                # 256 bits
    salt=salt,                      # Salt value
    iterations=480000,            # Number of iterations (480k standard)
)

keyloc = "./data/keylocation.key" # switch to a SSH into remote location perhaps idk yet

illegalcharacters = r"!@#$%^&*()_+{}|:<>?[]\;',./`~" # Illegal characters for username

menuactive = True # Menu loop variable

def info():  # Info as always
    menuactive = False
    os.system("cls")
    print("""
    ░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄░░░░░░░
    ░░░░░█░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░▀▀▄░░░░
    ░░░░█░░░▒▒▒▒▒▒░░░░░░░░▒▒▒░░█░░░
    ░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█░░
    ░▄▀▒▄▄▄▒░█▀▀▀▀▄▄█░░░██▄▄█░░░░█░
    █░▒█▒▄░▀▄▄▄▀░░░░░░░░█░░░▒▒▒▒▒░█
    █░▒█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄▒█
    ░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█░
    ░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█░░
    ░░░█░░░░██░░▀█▄▄▄█▄▄█▄████░█░░░
    ░░░░█░░░░▀▀▄░█░░░█░█▀██████░█░░
    ░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█░░
    ░░░░░░░▀▄▄░▒▒▒▒░░░░░░░░░░▒░░░█░
    ░░░░░░░░░░▀▀▄▄░▒▒▒▒▒▒▒▒▒▒░░░░█░
    ░░░░░░░░░░░░░░▀▄▄▄▄▄░░░░░░░░█░░

    made by: voidd#0291
    Released under the GNU General Public License v3.0 # except for tom
    Using crypt under the MIT license
    """.center(40))

def menu(): # menu function
    global selection
    print("""
    Menu
    
    1. Login
    2. Register
    3. Info
    4. Abort
    """.center(40))
    selection = int(input("Select: "))

def protection(): # key generation function for register                   # !!!!! DEBUG AGAINST MULTIPLE USERS 
    global key, f, password
    if os.path.exists(keyloc): # checking if key exists
        keyfile = open(keyloc, "r") # opening key file in read mode
        key = keyfile.read() 
        f = Fernet(key) # declaring f as Fernet key
        return f, key
    elif not os.path.exists(keyloc): # if key does not exist create one
        os.mkdir("./data") # create data folder
        key = base64.urlsafe_b64encode(kdf.derive(password.encode())) # key generation using base64 and kdf with password as base
        f = Fernet(key) 
        keytxt = open(keyloc, "wb") # writing key to file in byte mode
        keytxt.write(key) # writing key to file
        return f, key
    else:
        print("Error")
        time.sleep(2)
        exit(0)

def recordencrypt(): # encryption function for register
        global token, password, username
        token = f.encrypt(password.encode()) # encrypting password
        file = open(username+ ".txt", "ab")
        file.write(token) # writing encrypted password to file
        print("""
        Registered
        """)
        return

def logincheck():
    global token, password, username 
    if passwinput == password: # comparing password input to decrypted password stored in file at register
        print("""
        Logged in
        """)
        return
    elif passwinput != password: # if password is not matching registered password
        print("""
        Incorrect password
        """)
        passwordrequest() # looping back if password is incorrect
    else:
        print("Error")
        time.sleep(2)
        exit(0)

def passwordrequest(): # password request function for login (simply made a separate function cuz of conflicts)
    global passwinput
    passwinput = input("Enter password: ")
    logincheck()  # calling logincheck function through passwordrequest function to avoid loop conflict
    
def decrypt():  ## parse before logincheck() # decryption function for login
    global f, password, userinput
    keyfile = open(keyloc, "r") # opening key file to read bytes
    key = keyfile.read()
    f = Fernet(key) # declaring as fernet object
    # print(key)  # debug
    userinput = input("Enter username: ")
    if userinput+ ".txt" in os.listdir("./"):  # checking if user exists in files                   
        file = open(userinput+ ".txt", "rb") # opening user file to read bytes of password (using username input (if correct) and the .txt file extention to find)
        file.users = file.read()
        token = file.users # reading bytes of password from file (stored single line without other info, for easy parsing)
        password = f.decrypt(token) # decrypting token with key
        password = password.decode() # decoding from bytes to string
        return
    elif not userinput+ ".txt" in os.listdir("./"): 
        print("""User not found
        """)
        time.sleep(1)
        os.system("cls")  # clearing screen to avoid clutter with os cli call
        decrypt()
    else:
        print("Error")
        time.sleep(2)
        exit(0)
    
    

def login(): # depricated and not needed, used only as a header and to declare loop off to avoid loop of header
    global token, passwinput, userinput
    menuactive = False
    print("""Login
    """)
    return

def returnfunc():
    rt = input("Press enter to return to menu: ")   # return function to return to menu
    if rt == "":
        menuactive = True
        os.system("cls")
        return
    else:
        print("Thats not enter you schizo") # input validation handling
        returnfunc()


def register():
    global token, password, username
    menuactive = False
    print("""Register
    """)
    username = input("Enter username: ") # username input
    password = input("Enter password: ") # password input
    password2 = input("Enter password again: ") # double password input
    if any(elem in username for elem in illegalcharacters): # checking if username contains illegal characters
        print("""Illegal characters in username
        """)
        register() # redirecting to register function to try again
    else:
        pass
    if password == password2:
        return
    else:
        print("""Passwords do not match 
        """)
        register() # redirecting to register function if passwords do not match
try: # try except to catch errors and print them to console (for user debugging)
    while menuactive == True:
        menu()
        if selection == "1":
            login()
            decrypt()
            passwordrequest()
            returnfunc()
        elif selection == "2":
            register()
            protection()
            recordencrypt()
            returnfunc()
            # print(f)
            # print(key) #debug thing # i refuse to remove this later 
        elif selection == "3":
            info()
            returnfunc()
        elif selection == "4":
            menuactive = False
            print("Aborting...")
            time.sleep(1)
            exit(0)
        elif selection != int:
            print("Numbers only")
            time.sleep(1)
            menu()
        else: 
            print("Can you not read numbers")
            time.sleep(1)
            menu()
except Exception: 
    print(traceback.format_exc()) # printing error to console using traceback module
    time.sleep(5)
    exit(0)