#----------------------------------------------------------------------------------------------------
# Names: Chris Rose & Saira Herrera
# Course: CIS 475 Intro to Cryptography
# Assignement: Final Project - RSA chat program Cryptosystem
#
#              RSAServer.py: A program that receives: RSA public keys; n, e.
#                            And encrypted cipher texts sent by the client. The program generates
#                            a random 128 AES key and sends it to the client,
#                            this key then allows the client to decrypt the encrypted messages sent
#                            by the server. Server and client can then chat privately.
#
#
#
# Due: Friday, May 14 2021
#------------------------------------------------------------------------------------------------------

import socket
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ENCRYPTING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# Encrypts messages to client using AES key and public keys
# key**e % n
def encrypt(random_key, n, e):
    encrypted_message = pow(random_key, e, n)
    return encrypted_message

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! SERVER CHAT PROGRAM !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# Create socket for the server
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind to local port 1234
serverSocket.bind(('0.0.0.0',1234))
print("Started server on port 1234")
# Listen for message from client
serverSocket.listen(5)

# Create random 128 bit key to use for AES
random_key = random.getrandbits(128)
# Allow server to accept message from client
conn, addr = serverSocket.accept()
# Save data sent by client
data = conn.recv(4096)
# Decode data into string
decoded_data = data.decode()
# Split string at space to seperate n and e
public_keys = decoded_data.split(' ')
# Save n
n = public_keys[0]
# Save e
e = public_keys[1]
# Let the client know you received the public keys
print("\n*** Received n and e ***\n")
print('Public keys: (' + str(n) + ", " + str(e) + ')')

# Encrypt random 128 bit AES key using n and e
encrypted_random_key = encrypt(int(random_key), int(n), int(e))
# Send encrypted key to client
print("\n*** Sending encrypted AES key ***\n")
print(str(encrypted_random_key).encode())
conn.send(str(encrypted_random_key).encode())

# Save the random key as bytes
key = random_key.to_bytes(16, 'big')
# To keep track of the ongoing conversation
connection = True

while connection == True:
    # Create cipher using key as bytes.
    cipher = AES.new(key, AES.MODE_CBC)
    # Set plain text.
    plaintext = input("Message to Client: ").encode()
    # Encrypt plain text.
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Send cipher text and cipher iv as encoded string to client.
    conn.send((str(ciphertext) + '||' +  str(cipher.iv)).encode())


    # Get value of cipher text and cipher iv from user as encoded string
    cipherText_and_iv = (conn.recv(4096)).decode()
    # Split string that contains cipher text and iv
    decoded_data = cipherText_and_iv.split('||')
    # Save values of cipher text and iv from split array
    cipherText_from_client = eval(decoded_data[0])
    print("\n*** What people like Eve will see ***\n")
    print('\n' + 'Cipher: ' + str(cipherText_from_client) + '\n')
    iv = eval(decoded_data[1])

    # Create cipher using iv from server
    cipher_from_client = AES.new(key, AES.MODE_CBC, iv=iv)
    # Decrypt and unpad plaintext
    plainText_from_client = unpad(cipher_from_client.decrypt(cipherText_from_client), AES.block_size)
    # Decode the plain text to turn it back into string value
    chat = plainText_from_client.decode()
    # Print final string value
    print('Message from Client: ' + chat + '\n')

    if chat == 'bye':
        # Close socket and notify server
        conn.close()
        print('Client disconnected')
        # Conversation is over
        connection = False
