import sys
from pathlib import Path

# Ajouter le chemin du dossier `aiocoap` au chemin de recherche de Python
aiocoap_path = Path("/home/charm/workspace/python_projects/aiocoap")
sys.path.insert(0, str(aiocoap_path))
sys.path.append('/home/charm/workspace/python_projects/aiocoap/contrib/oscore-plugtest')

import asyncio
from aiocoap import *
from aiocoap import Context, Message, resource
from aiocoap.numbers.codes import Code
from aiocoap.oscore import BaseSecurityContext
from plugtest_common import *
from aiocoap.oscore_sitewrapper import OscoreSiteWrapper
from aiocoap.credentials import CredentialsMap 
from aiocoap.cli.common import server_context_from_arguments, add_server_arguments


class DayOfWeekResource(resource.Resource):
    async def render_post(self, request):
        
        print("Payload: ",request.payload)
        print("end payload---------------------------------------------------------")
        
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
    # Création du site avec la ressource
    root = resource.Site()
    root.add_resource(['check-day'], DayOfWeekResource())

    # Charger les secrets pré-partagés pour OSCORE
    server_credentials = CredentialsMap()
    contextdir = Path("/home/charm/workspace/python_projects/dacmabe/server")  # Spécifiez le répertoire contenant les fichiers de contexte
    server_credentials[':b'] = get_security_context('b', contextdir / "b")  # Le secret de 'file'

    # Activer OSCORE avec les identifiants de sécurité
    root = OscoreSiteWrapper(root, server_credentials)

    # Créer le contexte de serveur
    context = await Context.create_server_context(root)

    print("Serveur Fog en écoute avec OSCORE activé...")
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())