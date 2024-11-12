import sys
from pathlib import Path

# Ajouter le chemin du dossier `aiocoap` au chemin de recherche de Python
aiocoap_path = Path("/home/charm/workspace/python_projects/aiocoap")
sys.path.insert(0, str(aiocoap_path))

import asyncio
from aiocoap import Context, Message, resource
from aiocoap.oscore import SecurityContext, ServerSecurityContext

# Clé statique pour OSCORE (par exemple 16 octets)
STATIC_KEY = b'SECRETOSCOREKEY12'  # Utilisez une clé de 16, 24, ou 32 octets

class FogServer(resource.Resource):
    async def render_post(self, request):
        # Déchiffrer le message avec OSCORE
        jour = request.payload.decode('utf-8')
        
        # Vérifier le jour et préparer la réponse
        if jour.lower() == "dimanche":
            response = "True"
        else:
            response = "False"
        
        return Message(payload=response.encode('utf-8'))

async def main():
    # Contexte de sécurité du serveur
    security_context = ServerSecurityContext({b'fixed-id': SecurityContext(STATIC_KEY, None)})

    # Création de la ressource FogServer
    root = resource.Site()
    root.add_resource(['message'], FogServer())
    
    # Configuration et démarrage du serveur CoAP avec OSCORE
    context = await Context.create_server_context(root, oscore_contexts=[security_context])

    print("Serveur Fog en écoute...")
    await asyncio.get_running_loop().create_future()  # Garder le serveur en exécution

if __name__ == "__main__":
    asyncio.run(main())
