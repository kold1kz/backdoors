import random
import numpy as np
from math import gcd


def generate_superincreasing_sequence(length):
    # Генерация супервозрастающей последовательности
    seq = []
    total = 0
    for _ in range(length):
        next_val = total + random.randint(1, 10)
        seq.append(next_val)
        total += next_val
    return seq


def chaotic_sequence(length, r=3.9, x0=0.5):
    # Генерация хаотической последовательности
    sequence = [x0]
    for _ in range(length - 1):
        sequence.append(r * sequence[-1] * (1 - sequence[-1]))
    return [int(x * 1e6) for x in sequence]


def genetic_algorithm_optimize(population_size, generations, private_key):
    # Генетический алгоритм для оптимизации параметров
    population = [
        {"modulus": sum(private_key) + random.randint(1, 100),
         "multiplier": random.randint(2, 100)}
        for _ in range(population_size)
    ]

    def fitness(params):
        modulus = params["modulus"]
        multiplier = params["multiplier"]
        if gcd(multiplier, modulus) != 1:
            return 0
        inverse_multiplier = pow(multiplier, -1, modulus)
        public_key = [(w * multiplier) % modulus for w in private_key]
        recovered_key = [(pk * inverse_multiplier) %
                         modulus for pk in public_key]
        return sum(1 for a, b in zip(private_key, recovered_key) if a == b)

    for _ in range(generations):
        population = sorted(population, key=fitness, reverse=True)
        best = population[:population_size // 2]
        offspring = []
        for i in range(len(best) - 1):
            parent1 = best[i]
            parent2 = best[i + 1]
            child = {
                "modulus": (parent1["modulus"] + parent2["modulus"]) // 2,
                "multiplier": (parent1["multiplier"] + parent2["multiplier"]) // 2
            }
            if random.random() < 0.1:
                child["modulus"] += random.randint(-5, 5)
                child["multiplier"] += random.randint(-1, 1)
            offspring.append(child)
        population = best + offspring

    return population[0]


def project_to_hyperplane(vector, projection_matrix):
    # Преобразование ключей в многомерное пространство
    return np.dot(projection_matrix, vector)


def generate_hybrid_keys(bit_length=16, population_size=20, generations=50):
    # Генерация ключей
    private_key = generate_superincreasing_sequence(bit_length)
    best_params = genetic_algorithm_optimize(
        population_size, generations, private_key)
    modulus = best_params["modulus"]
    multiplier = best_params["multiplier"]
    inverse_multiplier = pow(multiplier, -1, modulus)

    chaos = chaotic_sequence(bit_length)

    projection_matrix = np.random.randint(1, 10, (bit_length, bit_length))
    private_key_projected = project_to_hyperplane(
        private_key, projection_matrix)

    public_key = [((w * multiplier) + chaos[i]) %
                  modulus for i, w in enumerate(private_key_projected)]

    backdoor_params = {
        "modulus": modulus,
        "multiplier": multiplier,
        "inverse_multiplier": inverse_multiplier,
        "chaos": chaos,
        "projection_matrix": projection_matrix
    }

    return public_key, private_key, backdoor_params


def string_to_numeric(message):
    """Конвертирует строку в числовое представление."""
    return int.from_bytes(message.encode('utf-8'), 'big')


def numeric_to_string(number, bit_length):
    """Конвертирует число обратно в строку."""
    byte_length = (bit_length + 7) // 8  # Рассчитываем длину в байтах
    return number.to_bytes(byte_length, 'big').decode('utf-8', errors='ignore')


def encrypt_hybrid(plaintext, public_key):
    """Шифрует сообщение с использованием публичного ключа."""
    binary = [int(b) for b in bin(plaintext)[2:].zfill(len(public_key))]
    return sum(int(b) * int(pk) for b, pk in zip(binary, public_key))


def decrypt_hybrid(ciphertext, private_key, backdoor_params):
    """
    Расшифровывает сообщение с использованием приватного ключа (супервозрастающей последовательности).
    """
    modulus = backdoor_params["modulus"]
    inverse_multiplier = backdoor_params["inverse_multiplier"]

    # Применяем обратный множитель
    modified_ciphertext = (ciphertext * inverse_multiplier) % modulus

    # Расшифровка с использованием супервозрастающей последовательности
    plaintext_bits = []
    for w in reversed(private_key):
        if modified_ciphertext >= w:
            plaintext_bits.append(1)
            modified_ciphertext -= w
        else:
            plaintext_bits.append(0)

    # Преобразуем биты обратно в число
    plaintext_binary = ''.join(map(str, reversed(plaintext_bits)))
    try:
        return int(plaintext_binary, 2)
    except ValueError:
        print("Ошибка при преобразовании битов в число.")
        return None


def recover_private_key(public_key, backdoor_params):
    """
    Восстанавливает приватный ключ из публичного ключа и скрытых параметров.
    """
    modulus = backdoor_params["modulus"]
    inverse_multiplier = backdoor_params["inverse_multiplier"]
    chaos = backdoor_params["chaos"]
    projection_matrix = backdoor_params["projection_matrix"]

    # Убираем шум с каждого элемента публичного ключа
    adjusted_public_key = [
        (int(pk) - int(ch)) % modulus for pk, ch in zip(public_key, chaos)
    ]

    # Применяем обратный множитель для восстановления спроецированного приватного ключа
    recovered_key_projected = [
        (apk * inverse_multiplier) % modulus for apk in adjusted_public_key
    ]

    # Преобразуем из многомерного пространства
    try:
        projection_matrix_inv = np.linalg.pinv(
            projection_matrix)  # Псевдообратная матрица
        recovered_private_key = (
            np.dot(projection_matrix_inv, recovered_key_projected)
            .round()
            .astype(int)
        )
    except Exception as e:
        print("Ошибка при восстановлении приватного ключа:", e)
        return []

    # Убираем отрицательные значения (возможные из-за ошибок округления)
    recovered_private_key = [max(0, key) for key in recovered_private_key]

    # Сравниваем длину с публичным ключом, если нужно — обрезаем
    if len(recovered_private_key) > len(public_key):
        recovered_private_key = recovered_private_key[:len(public_key)]

    # Проверка на наличие нулевых значений
    if any(x <= 0 for x in recovered_private_key):
        print("Внимание: восстановленный ключ содержит некорректные значения!")

    return recovered_private_key


def decrypt_with_private_key(ciphertext, private_key):
    """
    Расшифровывает сообщение с использованием приватного ключа (супервозрастающей последовательности).
    :param ciphertext: Зашифрованное сообщение.
    :param private_key: Приватный ключ (супервозрастающая последовательность).
    :return: Расшифрованное сообщение в виде числа.
    """
    # Храним сумму, из которой вычитаем элементы приватного ключа
    remaining_sum = ciphertext

    # Восстанавливаем бинарное сообщение
    plaintext_bits = []

    # Идём по приватному ключу в обратном порядке
    for key_element in reversed(private_key):
        if remaining_sum >= key_element:
            plaintext_bits.append(1)
            remaining_sum -= key_element
        else:
            plaintext_bits.append(0)

    # Переворачиваем порядок битов (они собраны в обратном порядке)
    plaintext_bits.reverse()

    # Преобразуем биты в число
    plaintext_binary = ''.join(map(str, plaintext_bits))
    return int(plaintext_binary, 2)  # Конвертируем бинарное число в целое


def test_knapsack_plus():
    message = 'Hi' 

    # Генерация ключей
    user_pub, user_priv, backdoor_params = generate_hybrid_keys(
        bit_length=len(message) * 8
    )
    print("Пользовательский Public Key:", user_pub)
    print("Пользовательский Private Key:", user_priv)
    print("Backdoor Param:", backdoor_params)

    # Шифрование сообщения
    plaintext = string_to_numeric(message)
    ciphertext = encrypt_hybrid(plaintext, user_pub)
    print("Зашифрованное Сообщение:", ciphertext)

    # востановление пока не работает как и восстановление приватного по публичному

    # Восстановление ключей
    # recovered_priv = recover_private_key(user_pub, backdoor_params)
    # print("Восстановленный Private Key:", recovered_priv)

    # # Проверка восстановления приватного ключа
    # if recovered_priv == user_priv:
    #     print("Приватный ключ восстановлен корректно.")
    # else:
    #     print("Ошибка восстановления приватного ключа.")

    # Расшифровка сообщения

    # recovered_message = decrypt_hybrid(
    #     ciphertext, user_priv, backdoor_params)
    # print(recovered_message)
    # recovered_message = decrypt_with_private_key(ciphertext, user_priv)
    # print("Расшифрованное сообщение:", numeric_to_string(
    #     recovered_message, len(message) * 8))


# Запуск теста
test_knapsack_plus()
