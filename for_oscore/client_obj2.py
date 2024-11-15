import sys
from pathlib import Path

# Ajouter le chemin du dossier `aiocoap` au chemin de recherche de Python
aiocoap_path = Path("/home/charm/workspace/python_projects/aiocoap")
sys.path.insert(0, str(aiocoap_path))
sys.path.append('/home/charm/workspace/python_projects/aiocoap/contrib/oscore-plugtest')


import aiocoap
import asyncio

from aiocoap.oscore import BaseSecurityContext
from aiocoap.credentials import CredentialsMap
from aiocoap.numbers.codes import Code
from aiocoap.oscore import BaseSecurityContext
from plugtest_common import *
from aiocoap.oscore_sitewrapper import OscoreSiteWrapper
from aiocoap.credentials import CredentialsMap 
from aiocoap.cli.common import server_context_from_arguments, add_server_arguments

# Création du client OSCORE
async def main():
    # Charger les credentials et le contexte de sécurité
    contextdir = Path("/home/charm/workspace/python_projects/dacmabe/client_credentials")
    credentials = CredentialsMap()

    # Charger les secrets à partir des fichiers de contexte
    credentials[':b'] = get_security_context('b', contextdir / "b")  # Le secret de 'client1'

    # Créer un client avec OSCORE
    protocol = await aiocoap.Context.create_client_context()

    # Préparer la requête
    request = aiocoap.Message(code=aiocoap.POST, uri="coap://localhost/check-day")
    request.payload = b"dimanche"  # Message à envoyer au serveur

    # Appliquer le contexte de sécurité OSCORE sur la requête
    request.oscore_context = credentials[':b']  # Application du contexte de sécurité pour OSCORE

    # Vérifier les données brutes avant l'envoi
    print("Message avant envoi (payload brut) :")
    print(request.payload)

    # Envoyer la requête avec OSCORE
    response = await protocol.request(request).response

    print("Réponse du serveur :", response.payload.decode('utf-8'))

if __name__ == "__main__":
    asyncio.run(main())
