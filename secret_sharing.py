import random
from typing import List, Tuple
from sympy import randprime


PRIME = 74090201509400935663578247995981991143165808252774049261150693121321224971355577324060154417375390949  # Nombre premier pour le champ fini

def generate_coefficients(secret: int, threshold: int) -> List[int]:
    coefficients = [secret % PRIME]
    for _ in range(threshold - 1):
        coefficients.append(random.randint(1, PRIME - 1))
        print("cofficients  :",coefficients)
    return coefficients

def create_shares(secret: int, total_shares: int, threshold: int) -> List[Tuple[int, int]]:
    coefficients = generate_coefficients(secret, threshold)
    shares = []
    for x in range(1, total_shares + 1):
        y = sum(coeff * (x**exp) for exp, coeff in enumerate(coefficients)) % PRIME
        shares.append((x, y))
    return shares

def reconstruct_secret(shares: List[Tuple[int, int]], threshold: int) -> int:
    def _lagrange_interpolation(x: int, x_s: List[int], y_s: List[int]) -> int:
        def _basis(j: int) -> int:
            num = 1
            den = 1
            for m in range(len(x_s)):
                if m != j:
                    num = (num * (x - x_s[m])) % PRIME
                    den = (den * (x_s[j] - x_s[m])) % PRIME
            return num * pow(den, -1, PRIME) % PRIME  # Modulo inverse

        result = 0
        for j in range(len(y_s)):
            result = (result + y_s[j] * _basis(j)) % PRIME
        return result

    if len(shares) < threshold:
        raise ValueError("Not enough shares to reconstruct the secret!")
    x_s, y_s = zip(*shares)
    return _lagrange_interpolation(0, x_s, y_s)


secret = 1234545454
total_shares = 3
threshold = 2

shares = create_shares(secret, total_shares, threshold)
print("Shares:", shares)

# Sélectionner 3 parts pour reconstruire le secret
selected_shares = shares[:threshold]
recovered_secret = reconstruct_secret(selected_shares, threshold)
print("Recovered Secret:", recovered_secret)

"""
# Générer un nombre premier entre 10^100 et 10^101
prime = randprime(10**100, 10**101)
print("Grand nombre premier généré :", prime)
"""