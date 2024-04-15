import socket
import threading
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Function to perform Diffie-Hellman key exchange
def diffie_hellman():
    # Shared prime and base (p and g)
    p = 23
    g = 5

    # Private key (a or b or c)
    private_key = random.randint(1, 100)

    # Public key calculation
    public_key = (g ** private_key) % p

    return p, g, public_key, private_key

# Function to derive a key from a shared secret
def derive_key(secret):
    return PBKDF2(secret, b'salt', 16, count=1000000)

# Function to encrypt plaintext using AES encryption
def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext, cipher.iv

# Function to decrypt ciphertext using AES decryption
def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()




# Function to start a client
def start_client(client_name):
    try:
        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('127.0.0.1', 12345))

        # Send client name to server
        client_socket.send(client_name.encode())

        # Perform Diffie-Hellman key exchange
        p, g, public_key, private_key = diffie_hellman()

        # Send public key to server
        client_socket.send(f"PUBLIC_KEY {public_key}".encode())

        # Receive server's public key
        server_public_key = int(client_socket.recv(1024).decode().split()[1])

        # Calculate shared secret
        secret = (server_public_key ** private_key) % p
        derived_key = derive_key(str(secret))

        # Begin secure communication loop
        while True:
            # Get user input
            message = input(f"{client_name}: ")

            # Encrypt message
            ciphertext, iv = encrypt(message, derived_key)

            # Send encrypted message to server
            client_socket.send(str((ciphertext, iv)).encode())

    except Exception as e:
        print(f"Error starting client {client_name}: {e}")

if __name__ == "__main__":
    # Start client A
    start_client("A")



