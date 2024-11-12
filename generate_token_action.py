from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.schemes.abenc.abenc_maabe_yj14 import MAABE
from charm.toolbox.pairinggroup import *
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.toolbox.hash_module import Waters
from hashlib import sha256
from charm.core.engine.util import objectToBytes,bytesToObject
import ast
import json
import os
import base64
import sqlite3
import charm.toolbox.symcrypto
import pickle

base_path='/home/charm/workspace/python_projects/dacmabe'
db_path = os.path.join(base_path, 'databases', 'fog_database.db')

# Connexion à la base de données SQLite (la base sera créée si elle n'existe pas)
conn_with_bdd_fog = sqlite3.connect(db_path)
cursor_fog = conn_with_bdd_fog.cursor()

    
group = PairingGroup('SS512')
maabe = MaabeRW15(group)
 

def get_public_params():
    with open(os.path.join(base_path, 'authority_params/public_params_auth.json'),'r') as file:
        params = file.read()
        orig_params = bytesToObject(params, group)

        # Remplacer les lambdas fictives H et F par des lambdas fonctionnelles
        orig_params['H'] = lambda x: group.hash(x, G2)
        orig_params['F'] = lambda x: group.hash(x, G2)

        print("my orig_params:", orig_params)
    
    with open(os.path.join(base_path, 'authority_params/public_keys.json'), 'r') as file:
        public_keys = file.read()
        orig_public_keys = bytesToObject(public_keys, group)
        
    with open(os.path.join(base_path, 'authority_params/secret_key1.json'), 'r') as file:
        secret_key1 = file.read()
        orig_secret_key1 = bytesToObject(secret_key1, group)
    
    with open(os.path.join(base_path, 'authority_params/secret_key2.json'), 'r') as file:
        secret_key2 = file.read()
        orig_secret_key2 = bytesToObject(secret_key2, group)
           
    return orig_params, orig_public_keys, orig_secret_key1, orig_secret_key2

# Appel de la fonction
public_parameters, public_keys, secret_key1, secret_key2 = get_public_params()

 

 
#--------------------------------------------------------------------------------------------------------
# Création de la table pour stocker les chemins des fichiers si elle n'existe pas
cursor_fog.execute('''
CREATE TABLE IF NOT EXISTS obj_abe_keys_table (
    id INTEGER PRIMARY KEY,
    obj_id INTEGER,
    action_name TEXT UNIQUE,
    key_value TEXT UNIQUE
)
''')

def generate_token_for_action(actions, id_obj):
    
    # Définition de la politique d'accès (exemple)
    access_policy = '(STUDENT@UT or PROFESSOR@OU) and (STUDENT@UT or MASTERS@OU)'

    # Parcourir la liste des actions
    for action in actions:
        # Génération du message aléatoire
        message1 = group.random(GT)
        
        # Chiffrement du message avec MA-ABE
        cipher_text = maabe.encrypt(public_parameters, public_keys, message1, access_policy)
        print("first is: ", type(cipher_text))
        print(cipher_text)
        serialized_message = objectToBytes(cipher_text, group)

        print("have ben seralized")
        
        # Stocker le chemin du fichier dans la base de données
        print("id_obj:", id_obj, "action:", action)
        cursor_fog.execute('INSERT INTO obj_abe_keys_table (obj_id, action_name, key_value) VALUES (?, ?, ?)', 
                       (id_obj, action, serialized_message))
    
    # Commit des changements dans la base de données
    conn_with_bdd_fog.commit()
    
#--------------------------------------------------------------------------------------------------------
 

generate_token_for_action(["action1", "action2"], 1)

 



