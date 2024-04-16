import socket
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Client configuration
HOST = '127.0.0.1'
PORT = 5555

# Function to generate RSA key pair and save it in a folder
def generate_and_save_keypair(folder):
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Serialize private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Create folder if it doesn't exist
    if not os.path.exists(folder):
        os.makedirs(folder)
    # Save private key to a PEM file
    with open(os.path.join(folder, 'private_key.pem'), 'wb') as f:
        f.write(private_key_pem)

# Create socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Generate and save RSA key pair for Client A
generate_and_save_keypair('client_a')

# Connect to server
client_socket.connect((HOST, PORT))

# Send client's name to server
client_socket.sendall("Client A".encode('utf-8'))

while True:
    # Send message to server
    message = input("Client A: ")
    client_socket.sendall(message.encode('utf-8'))

# Close the connection
client_socket.close()
