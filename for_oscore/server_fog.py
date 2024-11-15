import sys
from pathlib import Path

# Ajouter le chemin du dossier `aiocoap` au chemin de recherche de Python
aiocoap_path = Path("/home/charm/workspace/python_projects/aiocoap")
sys.path.insert(0, str(aiocoap_path))

import asyncio
from aiocoap import *
from aiocoap import Context, Message, resource
from aiocoap.numbers.codes import Code
from aiocoap.oscore import BaseSecurityContext

class DayOfWeekResource(resource.Resource):
    async def render_post(self, request):
        # Déchiffrer le message et lire le jour reçu
        day_received = request.payload.decode('utf-8')
        print(f"Jour reçu : {day_received}")
        
        # Vérifier si le jour est dimanche
        if day_received.lower() == "dimanche":
            response_payload = "True"
        else:
            response_payload = "False"
        
        return Message(payload=response_payload.encode('utf-8'), code=Code.CONTENT)

async def main():
    root = resource.Site()
    root.add_resource(['check-day'], DayOfWeekResource())
    """
    context = await Context.create_server_context(root)
    print("Serveur Fog en écoute...")
    await asyncio.get_running_loop().create_future()
    """
    

    # Création du contexte de sécurité
    context = await Context.create_server_context(root)
    context.oscore = BaseSecurityContext()  # Assurez-vous de spécifier le bon répertoire de clés

    
    print("Serveur Fog en écoute...")
    await asyncio.get_running_loop().create_future()
if __name__ == "__main__":
    asyncio.run(main())
