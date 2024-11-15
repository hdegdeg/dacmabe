from hashlib import sha256
import charm.toolbox.symcrypto
import os
import base64
import sqlite3
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.toolbox.pairinggroup import *

#--------------------------------------------------------------------------------------------------------  
# Connexion à la base de données SQLite (la base sera créée si elle n'existe pas)
base_path='/home/charm/workspace/python_projects/dacmabe' 
db_path_user = os.path.join(base_path, 'databases', 'user_database.db')

# Connexion à la base de données SQLite (la base sera créée si elle n'existe pas) 
conn_with_bdd_user = sqlite3.connect(db_path_user)

 
cursor_user = conn_with_bdd_user.cursor()

#--------------------------------------------------------------------------------------------------------    
def get_key():

    group = PairingGroup('SS512')


    # Récupération du chemin de fichier depuis la base de données
    cursor_user.execute('SELECT * FROM access_token_user_table WHERE action_name = ?', ("action1",)) 
    rows = cursor_user.fetchall()  

    if rows:  # Indentation correcte ici
        for row in rows:
            key_value = row[3]
            
            #print("Key_Bytes:",key_value)
            #orig_cipher = bytesToObject(key_value, group)
            

            return key_value
            
     
    return 


#--------------------------------------------------------------------------------------------------------    

stored_key = get_key()
print("key:",stored_key)

hashed_key = sha256(stored_key).digest()
print("hashed_key: ",hashed_key)

"""
key = sha256(b'shameful secret key').digest()
"""
cipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(hashed_key)


session_id = '21345'
ciphertextAssociatedData = cipher.encrypt('Some network PDU.', associatedData=session_id)


result=cipher.decrypt(ciphertextAssociatedData, associatedData=session_id)
print(result)
