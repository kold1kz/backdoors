"""
Бэкдор в функции generate_rsa_with_backdoor.
Идея в том, чтобы сгенерировать пару ключей RSA как для пользователя,
так и для злоумышленника («backdoor»).

Ключевое различие между двумя парами ключей заключается в том,
что закрытый ключ пользователя (user_priv)
не используется для шифрования какой-либо информации,
тогда как закрытый ключ (bd_priv)
используется для шифрования некоторых скрытых параметров.
Эти скрытые параметры затем используются для последующего
восстановления закрытого ключа пользователя.

Описание того, как это работает:

Функция generate_rsa_with_backdoor генерирует две пары ключей RSA:
одну для пользователя, а другую для злоумышленника, использующего бэкдор.
Злоумышленник, использующий бэкдор,
использует свой закрытый ключ (bd_priv)
для шифрования некоторых скрытых параметров,
которые затем сохраняются вместе с другими ключами.
Открытый ключ пользователя используется для шифрования сообщения.
Чтобы восстановить закрытый ключ пользователя, злоумышленник,
использующий бэкдор,
использует свой собственный закрытый ключ и
скрытые параметры для вычисления закрытого ключа пользователя.
Идея этой реализации заключается в том,
что если злоумышленник сможет получить открытый ключ пользователя и
зашифрованное сообщение,
он сможет использовать бэкдор для восстановления закрытого ключа 
пользователя и,
таким образом, расшифровать сообщение.
Это классический пример системы RSA с «бэкдором»,
в которой безопасность шифрования ставится под угрозу за счет включения
скрытого механизма,
позволяющего злоумышленнику восстановить закрытый ключ.

Есть еще улучшенная версия но ее мне уже лень хдесб описывать"""

import time
import random


def is_prime(n):
    """
    Проверяет является ли натуральное число простым.

    params:
    n: Натуральное число.
    return:
    True если n - простое, False в противном случае.
    """
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_prime(bit_length):
    """
    Генерирует простое натуральное число заданной длины.

    params:
    bit_length: Длина бита в генерируемом простом числе.
    return:
    Простое натуральное число.
    """
    while True:
        num = random.randint(2**(bit_length - 1), 2**bit_length - 1)
        if is_prime(num):
            return num


def extended_gcd(a, b):
    """
    Решает систему линейных уравнений AX + BY = GCD(A, B) с помощью алгоритма Эуклида.

    param:
    a: Число A.
    b: Число B.
    return:
    Тройка (GCD(a, b), x, y), где x и y - коэффициенты решения системе линейных уравнений.
    """
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y


def modular_inverse(e, phi):
    """
    Находит обратное число по модулю Фибоначчи для числа E.

    params:
    e: Число E.
    phi: Модуль Фибоначчи (φ(n)).
    return:
    Обратное число по модулю FIBONACCI для числа E, если оно существует; иначе ValueError.
    """
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("No modular inverse exists")
    return x % phi


def generate_rsa_with_backdoor(bit_length=16):
    """
    Генерирует RSA-ключи с встроенной ловушкой (backdoor).

    params:
    bit_length: Длина бита в генерируемых простых числах.
    return:
    Кортеж содержащий общественный ключ пользователя, частный ключ пользователя и скрытые параметры.
    """
    # Пользовательские ключи
    p = generate_prime(bit_length // 2)
    q = generate_prime(bit_length // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modular_inverse(e, phi)

    # Злоумышленник генерирует свои ключи
    p_w = generate_prime(bit_length // 2)
    q_w = generate_prime(bit_length // 2)
    n_w = p_w * q_w
    e_w = 65537
    phi_w = (p_w - 1) * (q_w - 1)
    d_w = modular_inverse(e_w, phi_w)

    # Зашифрованные параметры
    p_hidden = pow(p, e_w, n_w)
    q_hidden = pow(q, e_w, n_w)

    return (e, n), d, (e_w, n_w), d_w, (p_hidden, q_hidden)


def recover_private_key(hidden_params, bd_priv_key, bd_pub_key):
    """
    Восстанавливает частный ключ пользователя с помощью скрытых параметров и публичного ключа ловушки.

    params:
    hidden_params: Скрытые параметры.
    bd_priv_key: Частный ключ ловушки.
    bd_pub_key: Публичный ключ ловушки.
    return:
    Восстановленный частный ключ пользователя и его общественный ключ.
    """
    e_w, n_w = bd_pub_key
    d_w = bd_priv_key
    p_hidden, q_hidden = hidden_params

    # Расшифровка параметров
    p = pow(p_hidden, d_w, n_w)
    q = pow(q_hidden, d_w, n_w)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modular_inverse(e, phi)

    return d, (e, n)


def decrypt_rsa(ciphertext, private_key, public_key):
    """
    Расшифровывает криптограмму с использованием стандартного RSA без скрытых каналов.

    params:
    ciphertext: Зашифрованное сообщение (число).
    private_key: Частный ключ (d).
    public_key: Публичный ключ (e, n).
    return:
    Расшифрованное сообщение.
    """
    d = private_key
    _, n = public_key

    # Расшифровка: M = C^d mod N
    message_as_number = pow(ciphertext, d, n)

    # Преобразование числа обратно в строку
    message = message_as_number.to_bytes(
        (message_as_number.bit_length() + 7) // 8, 'big').decode()
    return message


def encrypt_message(message, public_key):
    # Преобразуем сообщение в число и шифруем его
    e, n = public_key
    m = int.from_bytes(message.encode(), 'big')
    if m >= n:
        raise ValueError("Message is too large for the key size")
    c = pow(m, e, n)
    return c


def decrypt_message(ciphertext, private_key, public_key):
    # Расшифровываем число обратно в строку
    d = private_key
    _, n = public_key
    m = pow(ciphertext, d, n)
    message = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
    return message


def test_rsa():
    # Пример теcтовый
    message = "a"

    # Генерация ключей
    user_pub, user_priv, bd_pub, bd_priv, hidden = generate_rsa_with_backdoor(
        len(message)*8)
    print("Пользовательский Public Key:", user_pub)
    print("Пользовательский Private Key:", user_priv)
    print("Backdoor Public Key:", bd_pub)
    print("Скрытый Parameters:", hidden)

    # Восстановление ключей
    recovered_priv, recovered_pub = recover_private_key(
        hidden, bd_priv, bd_pub)
    print("Восстановленый Private Key:", recovered_priv)
    print("Восстановленный Public Key:", recovered_pub)

    # Шифрование сообщения
    ciphertext = encrypt_message(message, user_pub)
    print("Зашифрованное Сообщение:", ciphertext)

    # Расшифровка сообщения с восстановленным ключом
    recovered_message = decrypt_message(
        ciphertext, recovered_priv, recovered_pub)
    print("Расшифрованное сообщение:", recovered_message)


def compute_private_key(public_key):
    """
    Вычисляет закрытый ключ RSA (d), зная открытый ключ (e, n).
    Подходит только для небольших значений n.

    params:
    public_key: Открытый ключ (e, n).
    return:
    Закрытый ключ (d) и составляющие p, q.
    """
    e, n = public_key

    # Находим p и q через разложение n
    def factorize(n):
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                return i, n // i
        raise ValueError("Не удалось разложить n на множители")

    try:
        p, q = factorize(n)
    except ValueError as ve:
        print(ve)
        return None

    # Вычисляем phi(n)
    phi = (p - 1) * (q - 1)

    # Вычисляем d как обратное к e по модулю phi(n)
    def modular_inverse(a, m):
        g, x, _ = extended_gcd(a, m)
        if g != 1:
            raise ValueError("Обратный элемент не существует")
        return x % m

    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

    try:
        d = modular_inverse(e, phi)
    except ValueError as ve:
        print(ve)
        return None

    return d, (p, q)


# Пример использования
# public_key = user_pub  # Открытый ключ (e, n)
# private_key = compute_private_key(public_key)
# print("Private Key:", private_key)


def calculate_ai_zero(a, R, T):
    """
    Вычисляет младший разряд (или модифицированное значение) элементов последовательности a. ai[0]

    params:
    a: Список супервозрастающей последовательности.
    R: Множитель для создания сложной задачи.
    T: Модуль для преобразования.
    return:
    Список значений a_i[0].
    """
    ai_zero = [(ai * R) % T for ai in a]
    return ai_zero

    # # Пример использования
    # a = [2, 3, 6, 13, 27]  # Супервозрастающая последовательность
    # R = 7                  # Множитель
    # T = 50                 # Модуль

    # ai_zero = calculate_ai_zero(a, R, T)
    # print("a_i[0]:", ai_zero)


def encrypt_with_improvements(bit_length=16, e=65537):
    """
    Шифрует параметры p и q с улучшениями:
    1. Хэширование p и q через XOR.
    2. Добавление временной метки.
    3. Создание зависимых параметров.
    4. Двойное кодирование.

    params:
    bit_length: Количество бит.
    e: Открытая экспонента.

    return:
    Кортеж содержащий общественный ключ пользователя,
    частный ключ пользователя и скрытые параметры.
    """
    p = generate_prime(bit_length // 2)
    q = generate_prime(bit_length // 2)
    n = p * q

    # Шаг 1: Хэширование через XOR с случайным числом
    r1, r2 = random.randint(1, 1000), random.randint(1, 1000)
    h_p = p ^ r1
    h_q = q ^ r2

    # Шаг 2: Добавление временной метки
    timestamp = int(time.time())
    h_p = (h_p + timestamp) % n
    h_q = (h_q + timestamp) % n

    # Шаг 3: Связываем параметры
    p_prime = (h_p * e) % n
    q_prime = (h_q * e) % n

    # Шаг 4: Двойное кодирование
    p_hidden = pow(p_prime, e, n)
    q_hidden = pow(q_prime, e, n)

    d = modular_inverse(e, p_prime, q_prime)
    return (e, n), d, (p_hidden, q_hidden)


def decrypt_with_improvements(p_double, q_double, d_w, n_w):
    """
    НЕ РАБОТАЕТ!!!
    Расшифровывает параметры p и q с учётом улучшений:
    1. Обратное двойное декодирование.
    2. Восстановление временной метки.
    3. Восстановление оригинальных параметров через XOR.

    params:
    p_double: Зашифрованное значение p.
    q_double: Зашифрованное значение q.
    d_w: Приватная экспонента злоумышленника.
    n_w: Модуль злоумышленника.
    return:
    Восстановленные значения p и q.
    """
    # Шаг 1: Обратное двойное декодирование
    p_prime = pow(p_double, d_w, n_w)
    q_prime = pow(q_double, d_w, n_w)

    # Шаг 2: Извлечение временной метки
    # Упрощение: считаем, что метка времени совпадает
    timestamp = int(time.time())

    # Шаг 3: Восстановление исходных параметров
    h_p = ((p_prime) * pow(e_w, -1, n_w)) % n_w  # Убираем e_w
    h_q = ((q_prime) * pow(e_w, -1, n_w)) % n_w

    r1, r2 = 1, 1  # Здесь нужно знать r1 и r2 или их альтернативу
    p = h_p ^ r1
    q = h_q ^ r2

    return p, q
