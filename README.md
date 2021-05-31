# RSA-ChatProgram.

Included Files: RSAServer.py, RSAClient.py located on RSAProject folder.

---

### ``RSAServer.py/RSAClient.py`` usage
> NOTE: it is REQUIRED that you install "pycryptodocome" or another similar library in order to be able to implement AES.
> Here is an useful link to install pycryptodome https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

---

# Problem:

Follow the given scenario:

Import AES into RSAServer and RSAClient. Client will implement RSA encryption method to generate
public keys (n, e). Client will share these public keys with server. Server picks a 128 bit key.
These key is encrypted and sent to Client, Client then decrypts this key using private key d. Both Server and Client have the key to implement AES. Finally, messages sent between the two are encrypted/decrypted using AES key.

---

### How to run the program:

1. Open two terminals.

2. From whichever terminal you prefer run the server by typing the following command:

> python3 RSAServer.py 

3. No on the other terminal run the following command:

> python3 RSAClient.py

4. You will see client and server interchanging keys, once that is over, from the Server terminal enter a message to the client.

5. Message back to back from terminal to terminal as you like.

6. Terminate the program by typing the keyword 'bye' from the Client terminal.
