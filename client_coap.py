import sys
from pathlib import Path

# Ajouter le chemin du dossier `aiocoap` au chemin de recherche de Python
aiocoap_path = Path("/home/charm/workspace/python_projects/aiocoap")
sys.path.insert(0, str(aiocoap_path))

# Importer les classes et fonctions nécessaires
from aiocoap import *
import asyncio


async def main():
    protocol = await Context.create_client_context()
    msg = Message(code=GET, uri="coap://localhost/other/separate")
    response = await protocol.request(msg).response
    print(response.payload)

asyncio.run(main())
