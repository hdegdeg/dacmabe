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

    
group = PairingGroup('SS512')

debug = False
maabe = MaabeRW15(group)
public_parameters = maabe.setup()


# Définition des attributs
attributes1 = ['ONE', 'TWO']
attributes2 = ['THREE', 'FOUR']

# Configuration de l'authentification et génération des clés
(public_key1, secret_key1) = maabe.authsetup(public_parameters, 'UT')
(public_key2, secret_key2) = maabe.authsetup(public_parameters, 'OU')

# Dictionnaire des clés publiques
public_keys = {'UT': public_key1, 'OU': public_key2}


#--------------------------------------------------------------------------------------------------------

def store_public_params_with_functions(params, public_keys, secret_key1, secret_key2):
    
    # Vérifie et crée le dossier "/authority_params" s'il n'existe pas
    directory = "authority_params"
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    # Convertir les valeurs en texte, y compris les fonctions `H` et `F` en chaînes de caractères
    params_serializable = {
        k: v if not callable(v) else "" for k, v in params.items()
    }
    
    # Sérialiser et stocker les paramètres dans des fichiers
    serialized_message = objectToBytes(params_serializable, group)
    with open(os.path.join(directory, "public_params_auth.json"), 'wb') as file:
        file.write(serialized_message)
    
    with open(os.path.join(directory, "public_keys.json"), 'wb') as file:
        file.write(objectToBytes(public_keys, group))
    	
    with open(os.path.join(directory, "secret_key1.json"), 'wb') as file:
        file.write(objectToBytes(secret_key1, group))
    	
    with open(os.path.join(directory, "secret_key2.json"), 'wb') as file:
        file.write(objectToBytes(secret_key2, group))
    	
    

#-----------------------------------------------------------------------------------------------------------------
def generate_keys_for_user(gid):
	gid = "bob"
	user_attributes1 = ['STUDENT@UT', 'PHD@UT']
	user_attributes2 = ['STUDENT@OU']
	user_keys1 = maabe.multiple_attributes_keygen(public_parameters, secret_key1, gid, user_attributes1)
	user_keys2 = maabe.multiple_attributes_keygen(public_parameters, secret_key2, gid, user_attributes2)

store_public_params_with_functions(public_parameters,public_keys,secret_key1,secret_key2)



