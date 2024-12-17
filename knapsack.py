"""Ранцевая криптосистема"""

import random
from math import gcd
from sympy import mod_inverse


def generate_superincreasing_sequence(length):
    """Генерирует супервозрастающую последовательность."""
    seq = []
    total = 0
    for _ in range(length):
        next_val = total + random.randint(1, 10)
        seq.append(next_val)
        total += next_val
    return seq


def generate_knapsack_with_backdoor(bit_length=16):
    """
    Генерирует ключи для ранцевой криптосистемы с бэкдором.

    params:
    bit_length: Длина открытого ключа (размер ранца).
    return:
    Кортеж содержащий (открытый ключ, закрытый ключ, скрытые параметры для бэкдора).
    """
    # Генерация супервозрастающей последовательности (скрытый ключ)
    private_key = generate_superincreasing_sequence(bit_length)

    # Генерация модуля (M) и мультипликативно обратимого числа (W)
    total_sum = sum(private_key)
    modulus = total_sum + random.randint(1, 10)  # Выбираем модуль больше суммы
    while True:
        multiplier = random.randint(2, modulus - 1)
        if gcd(multiplier, modulus) == 1:
            break
    inverse_multiplier = mod_inverse(multiplier, modulus)

    # Генерация открытого ключа (путём шифрования приватного ключа)
    public_key = [(w * multiplier) % modulus for w in private_key]

    # Сохранение скрытых параметров (для бэкдора)
    backdoor_params = {
        "modulus": modulus,
        "multiplier": multiplier,
        "inverse_multiplier": inverse_multiplier
    }

    return public_key, private_key, backdoor_params


def encrypt_knapsack(plaintext, public_key):
    """Шифрует сообщение с использованием ранцевой криптосистемы."""
    binary = [int(b) for b in bin(plaintext)[2:].zfill(len(public_key))]
    return sum(b * pk for b, pk in zip(binary, public_key))


def decrypt_knapsack(ciphertext, private_key, backdoor_params):
    """Расшифровывает сообщение, используя скрытые параметры (бэкдор)."""
    modulus = backdoor_params["modulus"]
    inverse_multiplier = backdoor_params["inverse_multiplier"]
    modified_ciphertext = (ciphertext * inverse_multiplier) % modulus

    plaintext_bits = []
    for w in reversed(private_key):
        if modified_ciphertext >= w:
            plaintext_bits.append(1)
            modified_ciphertext -= w
        else:
            plaintext_bits.append(0)

    return int("".join(map(str, reversed(plaintext_bits))), 2)


def recover_private_key_knapsack(public_key, backdoor_params):
    """
    Восстанавливает приватный ключ из публичного ключа и скрытых параметров (бэкдора).

    params:
    public_key: Список элементов публичного ключа.
    backdoor_params: Словарь с параметрами бэкдора:
        - "modulus": Модуль M, использованный при создании публичного ключа.
        - "multiplier": Множитель W, использованный при создании публичного ключа.
        - "inverse_multiplier": Обратный множитель W^-1 mod M.

    return:
    Список, представляющий приватный ключ.
    """
    modulus = backdoor_params["modulus"]
    inverse_multiplier = backdoor_params["inverse_multiplier"]

    # Восстанавливаем элементы приватного ключа
    private_key = [(pk * inverse_multiplier) % modulus for pk in public_key]

    return private_key


def string_to_numeric(message):
    """
    Преобразует строку в числовое представление, используя ASCII.
    Каждому символу соответствует 8-битное бинарное представление.
    """
    binary_string = ''.join(format(ord(c), '08b') for c in message)
    return int(binary_string, 2)


def numeric_to_string(numeric, bit_length):
    """
    Преобразует числовое представление обратно в строку.
    Число разбивается на группы по 8 бит, и каждая группа преобразуется в символ.
    """
    binary_string = bin(numeric)[2:].zfill(bit_length)
    chars = [chr(int(binary_string[i:i + 8], 2))
             for i in range(0, len(binary_string), 8)]
    return ''.join(chars)


def test_knapsack():
    message = "test"

    # Генерация ключей
    user_pub, user_priv, backdoor_params =\
        generate_knapsack_with_backdoor(len(message)*8)
    print("Пользовательский Public Key:", user_pub)
    print("Пользовательский Private Key:", user_priv)
    print("Backdoor Param:", backdoor_params)

    # Восстановление ключей
    recovered_priv = recover_private_key_knapsack(
        user_pub, backdoor_params)
    print("Восстановленый Private Key:", recovered_priv)

    # Шифрование сообщения
    ciphertext = encrypt_knapsack(string_to_numeric(message), user_pub)
    print("Зашифрованное Сообщение:", ciphertext)

    # Расшифровка сообщения с восстановленным ключом
    recovered_message = decrypt_knapsack(
        ciphertext, recovered_priv, backdoor_params)
    print("Расшифрованное сообщение:", numeric_to_string(recovered_message,
                                                         len(message)*8))


test_knapsack()
