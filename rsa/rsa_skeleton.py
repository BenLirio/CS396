import random

# For the lab, complete modexp(), RSA_enc(), and RSA_dec().
# HW 2 will allow you to submit the fully completed code from the lab,
#   as well as egcd(), mulinv(), and keygen(), for extra credit on the
#   assignment.
# You must work independently since this assignment will be part of HW 2.

# test constants
test_p = 23
test_q = 47
test_e =  35
test_d = 347
message = "Hello world!"

lmap = lambda f, xs: list(map(f, xs))

def calc_n(p, q):
    # do not modify!
    return p * q

def calc_phi(p, q):
    # do not modify!
    return (p - 1) * (q - 1)

def modexp(b, e, m):
    assert m > 0, "modulus must be positive"
    out = 1
    while e > 0:
        if e & 1:
            out *= b
            out %= m
        b *= b
        b %= m
        e >>= 1
    return out

def check_modexp():
    for [b, e, m] in [   
                [2, 3, 5],
                [12, 4, 19],
                [7, 8, 9],
                [0, 1, 2],
                [1, 0, 3],
            ]:
        assert b**e % m == modexp(b, e, m)



def RSA_enc(plaintext, key):
    enc_chr = lambda c: modexp(ord(c), key[1], key[0])
    return lmap(enc_chr, plaintext)

def RSA_dec(ciphertext, key):
    dec_chr = lambda c: chr(modexp(c, key[1], key[0]))
    return ''.join(lmap(dec_chr, ciphertext))

def test():
    # do not modify!
    n       = calc_n(test_p, test_q)
    private = [n, test_d]
    public  = [n, test_e]
    
    print("Public key:", public)
    print("Private key:", private)
    
    ciphertext = RSA_enc(message, public)
    plaintext  = RSA_dec(ciphertext,private)

    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", plaintext)

# === Below this comment is the portions of this assignment that contribute to HW 2 ===

def egcd(b, n):
    if n < b: return egcd(n, b) # so that b <= n
    assert b >= 0, "egcd only supports non-negative numbers"
    if b == 0: return (n, 0, 1)
    
    # this is the optimized algorithm from Wikipedia
    (s, old_s, r, old_r) = (0, 1, n, b)

    while r != 0:
        quotient = old_r // r
        (old_r, r) = (r, old_r - quotient * r)
        (old_s, s) = (s, old_s - quotient * s)

    if b != 0:
        t = (old_r - old_s * b) // n
    else:
        t = 0
    
    return (old_r, old_s, t)

def egcd_check():
    for [a, b, c] in [
                [2, 3, 1],
                [12, 4, 4],
                [7, 8, 1],
                [0, 1, 1],
                [1, 0, 1],
            ]:
        assert egcd(a, b)[0] == c, "egcd(%d, %d) != %d" % (a, b, c)
        #assert egcd(a, b) == (c, 1, 0), \
            #f"expected egcd({a}, {b}) to equal ({c}, 1, 0), got {egcd(a, b)}"

def mulinv(e, n):
    assert e >= 0, "mulinv only supports non-negative numbers"
    assert n > 0, "mulinv only supports a positive modulus"
    (_, d, _) = egcd(e, n)
    return d%n

def mulinv_check():
    for [a, b] in [
            [12, 4],
            [1, 0],
        ]:
        try:
            mulinv(a, b)
            assert False, "Expected exception"
        except:
            pass
    for [a, b, c] in [
                [2, 3, 2],
                [7, 8, 7],
                [0, 1, 0],
            ]:
        assert mulinv(a, b) == c, "mulinv(%d, %d) != %d" % (a, b, c)



def checkprime(n, size):
    # do not modify!
    # determine if a number is prime
    if n % 2 == 0 or n % 3 == 0: return False
    i = 0

    # fermat primality test, complexity ~(log n)^4
    while i < size:
        if modexp(random.randint(1, n - 1), n - 1, n) != 1: return False
        i += 1

    # division primality test
    i = 5
    while i * i <= n:
        if n % i == 0: return False
        i += 2
        if n % i == 0: return False
        i += 4
    return True

def primegen(size):
    # do not modify!
    # generates a <size> digit prime
    if(size == 1): return random.choice([2, 3, 5, 7])
    lower = 10 ** (size - 1)
    upper = 10 ** size - 1
    p = random.randint(lower, upper)
    p -= (p % 6)
    p += 1
    if p < lower: p += 6
    elif p > upper: p -= 6
    q = p - 2
    while p < upper or q > lower:
        if p < upper:
            if checkprime(p, size): return p
            p += 4
        if q > lower:
            if checkprime(q, size): return q
            q -= 4
        if p < upper:
            if checkprime(p, size): return p
            p += 2
        if q > lower:
            if checkprime(q, size): return q
            q -= 2
        

def keygen(size):
    # generate a random public/private key pair
    # size is the digits in the rsa modulus, approximately. must be even, >2
    # return a tuple of tuples, [[n, e], [n, d]]
    # Complete this for HW 2 extra credit
    assert(size % 2 == 0 and size > 2) # keep this line!
    
    # generate two primes
    (p, q) = (primegen(size), primegen(size))

    # calculate n and phi(n)
    (n, phi) = (calc_n(p, q), calc_phi(p, q))

    # get e and d
    while True:
        e = random.randint(2, n - 1)
        (g, s, t) = egcd(e, phi)
        if g == 1:
            d = mulinv(e, phi)
            if d < 0:
                d += phi
            break

    # return pair
    return [[n, e], [n, d]]

def customkeytest(text, size):
    keypair = keygen(size)
    
    print("Public key:",keypair[0])
    print("Private key:",keypair[1])
    
    ciphertext = RSA_enc(text, keypair[0])
    plaintext  = RSA_dec(ciphertext, keypair[1])

    print("Original message:", text)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", plaintext)

if __name__ == '__main__':
    check_modexp()
    egcd_check()
    mulinv_check()
    test()
    customkeytest("Foo bar baz", 8)
