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

# Connexion à la base de données SQLite (la base sera créée si elle n'existe pas)
base_path='/home/charm/workspace/python_projects/dacmabe'
db_path_fog = os.path.join(base_path, 'databases', 'fog_database.db')
db_path_user = os.path.join(base_path, 'databases', 'user_database.db')

# Connexion à la base de données SQLite (la base sera créée si elle n'existe pas)
conn_with_bdd_fog = sqlite3.connect(db_path_fog)
conn_with_bdd_user = sqlite3.connect(db_path_user)


cursor_fog = conn_with_bdd_fog.cursor()
cursor_user = conn_with_bdd_user.cursor()

#---------------------------------------------------------------------------------------------------------


def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result
    
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


# Setup d'un utilisateur et attribution des clés
gid = "bob"
user_attributes1 = ['STUDENT@UT', 'PHD@UT']
user_attributes2 = ['STUDENT@OU']
user_keys1 = maabe.multiple_attributes_keygen(public_parameters, secret_key1, gid, user_attributes1)
user_keys2 = maabe.multiple_attributes_keygen(public_parameters, secret_key2, gid, user_attributes2)
user_keys = {'GID': gid, 'keys': merge_dicts(user_keys1, user_keys2)}


#--------------------------------------------------------------------------------------------------------

def decrypt_token_for_action():
    decrypted_message = None  # Initialisation de la variable

	
    # Récupération du chemin de fichier depuis la base de données
    cursor_fog.execute('SELECT * FROM obj_abe_keys_table WHERE action_name = ?', ("action1",)) 
    rows = cursor_fog.fetchall()  
    

    if rows:
        for row in rows:
            key_value = row[3]
            # Lire le fichier et afficher le contenu
            orig_cipher = bytesToObject(key_value, group)
            print("key_value:", key_value) 
            
            # Déchiffrement avec MA-ABE
            decrypted_message = maabe.decrypt(public_parameters, user_keys, orig_cipher)
    else:
        print("Aucun résultat trouvé pour l'action spécifiée.")
     
    return decrypted_message
            
#--------------------------------------------------------------------------------------------------------
# Création de la table pour stocker les chemins des fichiers si elle n'existe pas
cursor_user.execute('''
CREATE TABLE IF NOT EXISTS access_token_user_table (
    id INTEGER PRIMARY KEY,
    obj_id INTEGER,
    action_name TEXT UNIQUE,
    key_value TEXT UNIQUE
)
''')

def store_access_token(token, action, id_obj):
    # Sérialisation du message
    serialized_message = objectToBytes(token, group)
    print("have been serialized: ",serialized_message)
    print("token: ",token)
    
    # Récupération du chemin de fichier depuis la base de données
    cursor_user.execute('SELECT * FROM access_token_user_table WHERE action_name = ?', ("action1",)) 
    rows = cursor_user.fetchone() 
    
    print("Rows: ",rows)
    
    if rows:
        print("key found in database")
    else:
        cursor_user.execute('INSERT INTO access_token_user_table (obj_id, action_name, key_value) VALUES (?, ?, ?)', 
                            (id_obj, action, serialized_message))
        
        print("have been successfully stored")
        
        # Commit des changements dans la base de données
        conn_with_bdd_user.commit()


#--------------------------------------------------------------------------------------------------------    
def check_if_equal(token1):
    # Récupération du chemin de fichier depuis la base de données
    cursor_user.execute('SELECT * FROM access_token_user_table WHERE action_name = ?', ("action1",)) 
    rows = cursor_user.fetchall()  

    if rows:  # Indentation correcte ici
        for row in rows:
            key_value = row[3]
            
            orig_cipher = bytesToObject(key_value, group)
            
            print("stored token:",orig_cipher)
            
            if orig_cipher == token1:
               return True
            
     
    return False

#--------------------------------------------------------------------------------------------------------

#Run tests    
decrypted_message = decrypt_token_for_action()

print("decrypted_message:", decrypted_message)
#print("public_parameters	:",public_parameters)

print("decrypted_message:", decrypted_message)

store_access_token(decrypted_message,"action1","1")

is_equal = check_if_equal(decrypted_message)
print("equalization founded:",is_equal)


conn_with_bdd_fog.close()
conn_with_bdd_user.close()






