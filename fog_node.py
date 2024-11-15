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
import random
from typing import List, Tuple

class FogNode:
    def __init__(self, group: str, scheme=MaabeRW15):
        """
        Initialisation du nœud Fog avec le schéma MA-ABE et une base de données SQLite.
        """

        # Définir le chemin de la base de données
        self.base_path = '/home/charm/workspace/python_projects/dacmabe'
        db_path = os.path.join(self.base_path, 'databases', 'fog_database.db')


        # Initialisation du groupe et du schéma MA-ABE
        self.group = PairingGroup(group)
        self.maabe = scheme(self.group)

        # Appel de la fonction
        self.public_parameters, self.public_keys = self.get_public_params()

        

        # S'assurer que le dossier existe
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        # Connexion à la base de données SQLite
        try:
            self.conn_with_bdd_fog = sqlite3.connect(db_path)
            self.cursor_fog = self.conn_with_bdd_fog.cursor()
            self.init_bdd()  # Initialiser la base de données
        except sqlite3.Error as e:
            print(f"Erreur lors de la connexion à la base de données : {e}")
            raise

    def init_bdd(self):
        """
        Initialise la table pour stocker les clés ABE si elle n'existe pas.
        """
        try:
            self.cursor_fog.execute('''
            CREATE TABLE IF NOT EXISTS obj_abe_keys_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                obj_id INTEGER NOT NULL,
                action_name TEXT UNIQUE NOT NULL,
                rvo TEXT UNIQUE NOT NULL,
                key_value TEXT NOT NULL
            )
            ''')

            self.cursor_fog.execute('''
            CREATE TABLE IF NOT EXISTS obj_primes_table (
                obj_id INTEGER PRIMARY KEY ,
                prime TEXT UNIQUE NOT NULL,
            )
            ''')
            
            self.conn_with_bdd_fog.commit()
            print("Table 'obj_abe_keys_table' initialisée.")
        except sqlite3.Error as e:
            print(f"Erreur lors de la création de la table : {e}")
            raise

    def close_connection(self):
        """
        Ferme la connexion à la base de données.
        """
        if self.conn_with_bdd_fog:
            self.conn_with_bdd_fog.close()
            print("Connexion à la base de données fermée.")
    
    def get_public_params(self):
        with open(os.path.join(self.base_path, 'authority_params/public_params_auth.json'),'r') as file:
            params = file.read()
            orig_params = bytesToObject(params, self.group)

            # Remplacer les lambdas fictives H et F par des lambdas fonctionnelles
            orig_params['H'] = lambda x: self.group.hash(x, G2)
            orig_params['F'] = lambda x: self.group.hash(x, G2)
        
        with open(os.path.join(self.base_path, 'authority_params/public_keys.json'), 'r') as file:
            public_keys = file.read()
            orig_public_keys = bytesToObject(public_keys, self.group)
            
            
        return orig_params, orig_public_keys


    def generate_token_for_action(self,actions, id_obj,access_policy):
        PRIME = randprime(10**100, 10**101)
        result_dict={}

        # Parcourir la liste des actions
        for action in actions:
            # Génération du message aléatoire
            message1 = self.group.random(GT)
            # Générer une valeur aléatoire de 256 bits
            RVO = random.getrandbits(256)
            
            # Chiffrement du message avec MA-ABE
            cipher_text = self.maabe.encrypt(self.public_parameters, self.public_keys, message1, access_policy)

            serialized_message = objectToBytes(cipher_text, self.group)

            print("have ben seralized")
            
            # Stocker le chemin du fichier dans la base de données
            self.cursor_fog.execute(
            'INSERT INTO obj_abe_keys_table (obj_id, action_name, key_value, rvo) VALUES (?, ?, ?, ?)',
            (id_obj, f"{id_obj}_{action}", serialized_message, RVO)
            )

            # Ajouter au dictionnaire le tuple (message1, RVO)
            self.cursor_fog.execute(
                'INSERT INTO obj_abe_keys_table (obj_id, action_name, key_value, rvo) VALUES (?, ?, ?, ?)',
                (id_obj, f"{id_obj}_{action}", serialized_message, RVO)
            )

            # Ajouter au dictionnaire le tuple (message1, RVO)
            result_dict[action] = (message1, RVO)

        self.cursor_fog.execute(
                'INSERT INTO obj_primes_table (obj_id,prime) VALUES (?, ?)',
                (id_obj, PRIME)
            )
        
        # Commit des changements dans la base de données
        self.conn_with_bdd_fog.commit()

        return result_dict, PRIME

#-----------------------------------------------------------CREATE SHARE FOR USER----------------------------------------------------    

    def generate_coefficients(secret: int, fixed_share: Tuple[int, int], PRIME) -> List[int]:

        """
        Génère les coefficients du polynôme de Shamir en fixant une part spécifique.
        """
        x_fixed, y_fixed = fixed_share
        # Le terme constant est le secret
        c0 = secret
        # Le coefficient suivant est calculé pour que f(x_fixed) = y_fixed
        c1 = (y_fixed - c0) % PRIME
        return PRIME,[c0, c1]

    def create_shares(self,secret: int, fixed_share: Tuple[int, int], total_shares: int) -> List[Tuple[int, int]]:
        """
        Génère les parts du secret en fixant une part et en générant les autres dynamiquement.
        """
        coefficients = self.generate_coefficients(secret, fixed_share)
        shares = [fixed_share]
        for x in range(1, total_shares + 1):
            if x == fixed_share[0]:
                continue  # Sauter la part fixe
            # Évaluer le polynôme à x
            y = sum(coeff * (x**exp) for exp, coeff in enumerate(coefficients)) % PRIME
            shares.append((x, y))
        return shares

    def get_credential_of_action(self, action, id_obj):
    
        # Récupération du chemin de fichier depuis la base de données
        self.cursor_fog.execute('SELECT * FROM obj_abe_keys_table WHERE action_name = ?', (action,)) 
        rows = self.cursor_fog.fetchone()  

        if rows:
            for row in rows:
                Token = row[3]
                RVO =  row[4]
        else:
            print("Aucun résultat trouvé pour l'action spécifiée.")

        self.cursor_fog.execute('SELECT * FROM obj_primes_table WHERE id_obj = ?', (id_obj,)) 
        rows = self.cursor_fog.fetchone()  

        if rows:
            for row in rows:
                PRIME = row[2]
        else:
            print("Aucun résultat trouvé pour l'action spécifiée.")
        
        return Token,RVO,PRIME
    
    

    def generate_credential_for_action(self,action):
        self.get_token_of_action(action)

        
        print()
#------------------------------------------------------------------------------------------------------------------------------------
def main():
    fog = FogNode('SS512', MaabeRW15)
    print("Nœud Fog initialisé avec succès.")
    fog.generate_token_for_action( actions=["action1","action2","action3"],id_obj=5 ,access_policy='(STUDENT@UT or PROFESSOR@OU) and (STUDENT@UT or MASTERS@OU)' )
    # Crée une instance de FogNode
    try:
        print("")
    except Exception as e:
        print(f"Erreur lors de l'initialisation du nœud Fog : {e}")
    finally:
        if 'fog' in locals():
            fog.close_connection()


if __name__ == "__main__":
    print("Le script démarre...")
    main()

#test git