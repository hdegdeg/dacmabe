import random
from typing import List, Tuple

# Nombre premier pour le champ fini
PRIME = 74090201509400935663578247995981991143165808252774049261150693121321224971355577324060154417375390949

def generate_coefficients(secret: int, fixed_share: Tuple[int, int]) -> List[int]:
    """
    Génère les coefficients du polynôme de Shamir en fixant une part spécifique.
    """
    x_fixed, y_fixed = fixed_share
    # Le terme constant est le secret
    c0 = secret
    # Le coefficient suivant est calculé pour que f(x_fixed) = y_fixed
    c1 = (y_fixed - c0) % PRIME
    return [c0, c1]

def create_shares(secret: int, fixed_share: Tuple[int, int], total_shares: int) -> List[Tuple[int, int]]:
    """
    Génère les parts du secret en fixant une part et en générant les autres dynamiquement.
    """
    coefficients = generate_coefficients(secret, fixed_share)
    shares = [fixed_share]
    for x in range(1, total_shares + 1):
        if x == fixed_share[0]:
            continue  # Sauter la part fixe
        # Évaluer le polynôme à x
        y = sum(coeff * (x**exp) for exp, coeff in enumerate(coefficients)) % PRIME
        shares.append((x, y))
    return shares

def reconstruct_secret(shares: List[Tuple[int, int]]) -> int:
    """
    Reconstruit le secret en utilisant les parts fournies.
    """
    def _lagrange_interpolation(x: int, x_s: List[int], y_s: List[int]) -> int:
        """
        Effectue l'interpolation de Lagrange pour retrouver le secret.
        """
        def _basis(j: int) -> int:
            num = 1
            den = 1
            for m in range(len(x_s)):
                if m != j:
                    num = (num * (x - x_s[m])) % PRIME
                    den = (den * (x_s[j] - x_s[m])) % PRIME
            return num * pow(den, -1, PRIME) % PRIME  # Inverse modulaire

        result = 0
        for j in range(len(y_s)):
            result = (result + y_s[j] * _basis(j)) % PRIME
        return result

    x_s, y_s = zip(*shares)
    return _lagrange_interpolation(0, x_s, y_s)

# Paramètres
secret = 333333333
total_shares = 5
threshold = 2

# Définir une part fixe
fixed_x = 1
RVO1 = 123456789
fixed_share = (fixed_x, RVO1)

# Générer les parts
shares = create_shares(secret, fixed_share, total_shares)
print("Shares:", shares)

# Sélectionner des parts pour reconstruire le secret
selected_shares = shares[:2]

print("explication: ",selected_shares)
recovered_secret = reconstruct_secret(selected_shares)
print("Recovered Secret:", recovered_secret)

# Vérification
assert recovered_secret == secret, "Le secret reconstruit ne correspond pas au secret initial !"
