#------------------------------------------------------------------------------------------------
# Names: Chris Rose & Saira Herrera
# Course: CIS 475 Intro to Cryptography
# Assignement: Final Project - RSA chat program Cryptosystem
#
#              RSAClient.py: A program that sends: RSA public keys; n, e.
#                            And encrypted cipher texts to the server.
#                            The program recives a 128 AES key from the server,
#                            this key is decrypted using private key d. Server and
#                            client can then chat privately.
#
# Due: Friday, May 14 2021
#------------------------------------------------------------------------------------------------

import math
import socket
from Crypto.Cipher import AES
from random import randrange, getrandbits
from Crypto.Util.Padding import pad, unpad


# !!!!!!!!!!!!!!!!!!!!!!!!! ALGORITHMS NECCESSARY TO PROPERLY ENCRYPT RSA !!!!!!!!!!!!!!!!!!!!!!!!

# Greates common divisor algorithm
def gcd(a, b):
    if(b == 0):
        return a
    else:
        return gcd(b, a%b)

# Primality test algorithm
def isprime(n, k=128):
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True

# Generates prime candidates
def generate_prime_candidate(length):
    # generate random bits
    n = getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    n |= (1 << length - 1) | 1
    return n

# Generates prime numbers of length 1024
def generate_prime_number(length = 1024):
    n = 4
    # keep generating while the primality test fail
    while not isprime(n, 128):
        n = generate_prime_candidate(length)
    return n

# Prulerizer algorithm
def pulverizer(A, B, phi):
    Q , R = divmod(A, B)
    x1 = 1
    y1 = 0
    x2 = 0
    y2 = 1
    while (R != 0):
        A = B
        B = R
        tempx2 = x2
        tempy2 = y2
        x2 = x1 - (Q * x2)
        y2 = y1 - (Q * y2)
        x1 = tempx2
        y1 = tempy2
        Q , R = divmod(A, B)
    if (y2 < 0):
        return phi - abs(y2)
    return y2

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ACQUIRING VARIABLES !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# Generate p, q, n, & phi
p = generate_prime_number()
q = generate_prime_number()
n = p * q
phi = (p - 1) * (q -1)

# Generate e
GCDcheck = 0
e = 284184701247
while GCDcheck == 0:
    if gcd(phi, e) != 1:
        e = e + 1
    else:
        GCDcheck = 1

# Generate d
d = pulverizer(phi, e, phi) % phi

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! DECRYPTING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# Decrypts AES key using private key d
# k**d % n
def decrypt(encrypted_key):
    decrypted_key = pow(encrypted_key, d, n)
    return decrypted_key

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! RSA CHAT PROGRAM !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# Create socket for client
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to port 1234
clientSocket.connect(('0.0.0.0', 1234))

# Send encodeded public keys
print("\n*** Sending n and e ***\n")
print('Public key: (' + str(n) + ", " + str(e)+ ')' + '\n')
clientSocket.send((str(n) + " " + str(e)).encode())

# Get data of encrypted AES key from server
data = clientSocket.recv(4096)
# Decode the AES key to get the byte value as a string.
encrypted_key = data.decode()
# Decrypt key by using integer value of decoded AES key string.
decrypted_key = decrypt(int(encrypted_key))
# Save value of AES key as bytes
key = decrypted_key.to_bytes(16, 'big')
print("\n*** Received AES key ***\n")
print('\n' + 'AES Key: ' + str(key) + '\n')
# To keep track of the ongoing conversation
connection = True

while connection == True:
    # Get cipher text and cipher iv from user as encoded string
    cipherText_and_iv = (clientSocket.recv(4096)).decode()
    # Split string that contains cipher text and iv
    decoded_data = cipherText_and_iv.split('||')
    # Save values of cipher text and iv from split array
    cipher_text = eval(decoded_data[0])
    print("\n*** What people like Eve will see ***\n")
    print('\n' + "Cipher: " + str(cipher_text) + '\n')
    iv = eval(decoded_data[1])

    # Create cipher using iv from server
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # Decrypt and unpad plaintext
    plaintext = unpad(cipher.decrypt(cipher_text), AES.block_size)
    # Decode the plain text to turn it back into string data
    chat = plaintext.decode()
    # Print chat string data
    print('Message from Server: ' + chat + '\n')

    # Creating the cipher text
    send_cipher = AES.new(key, AES.MODE_CBC)
    # Prompt user to send plain text
    plainText_to_server = input("Enter Message to Server: ").encode()
    # Encrypt user's plain text
    cipher_text_to_server = send_cipher.encrypt(pad(plainText_to_server, AES.block_size))
    # Send cipher text and cipher iv as encoded string to server
    clientSocket.send((str(cipher_text_to_server) + '||' +  str(send_cipher.iv)).encode())

    # if the client says the keywork 'bye'
    if plainText_to_server.decode() == 'bye':
        # Close socket
        clientSocket.close()
        # Let the client know that is now disconnected
        print('\n' + 'You disconnected')
        # Conversation is over
        connection = False
