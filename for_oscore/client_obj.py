import sys
from pathlib import Path

# Ajouter le chemin du dossier `aiocoap` au chemin de recherche de Python
aiocoap_path = Path("/home/charm/workspace/python_projects/aiocoap")
sys.path.insert(0, str(aiocoap_path))


import aiocoap
import asyncio

async def main():
    # Création du contexte client
    protocol = await aiocoap.Context.create_client_context()

    # Préparation du message
    request = aiocoap.Message(code=aiocoap.POST, uri="coap://localhost/check-day")
    request.payload = b"dimanche"

    # Envoi de la requête
    response = await protocol.request(request).response

    print("Réponse du serveur :", response.payload.decode('utf-8'))

if __name__ == "__main__":
    asyncio.run(main())


"""
async def main():
    protocol = await Context.create_client_context()
    msg = Message(code=GET, uri="coap://localhost/other/separate")
    response = await protocol.request(msg).response
    print(response.payload)

asyncio.run(main())
"""