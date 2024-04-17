import socket
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64
# Client configuration
HOST = '127.0.0.1'
PORT = 5555

# Function to generate RSA key pair and save them in a folder
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
    # Serialize public key to PEM format
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Create folder if it doesn't exist
    if not os.path.exists(folder):
        os.makedirs(folder)
    # Save private key to a PEM file
    with open(os.path.join(folder, 'A_private_key.pem'), 'wb') as f:
        f.write(private_key_pem)
    # Save public key to a PEM file
    with open(os.path.join(folder, 'A_public_key.pem'), 'wb') as f:
        f.write(public_key_pem)
    return private_key, public_key

# Function to send message to server
def send_message(server_socket, message):
    if isinstance(message, str):
        server_socket.sendall(message.encode('utf-8'))
    else:
        server_socket.sendall(message)

def receive_message(server_socket):
    data = server_socket.recv(1024)
    return data

def generate_hash(data):
    """Generate a SHA-256 hash of the provided data."""
    hash_algorithm = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_algorithm.update(data)
    return hash_algorithm.finalize()


def exchange_public_key_and_name(server_socket, client_name, public_key):
    # Send client's name and public key to server
    client_info = f"{client_name};{public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}"
    send_message(server_socket, client_info)

    # Receive server's public key
    server_public_key_pem = receive_message(server_socket)

    # Deserialize server's public key from PEM format
    try:
        server_public_key = serialization.load_pem_public_key(
            server_public_key_pem,
            backend=default_backend()
        )

        # No need to decode here, return the deserialized key
        return server_public_key

    except Exception as e:
        print("Error exchanging public keys:", e)
        return None

def save_server_public_key(server_public_key):
    # Save server's public key
    with open(os.path.join('client_a', 'server_public_key.pem'), 'wb') as f:
        f.write(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def save_server_public_key(server_public_key):
    # Save server's public key
    with open(os.path.join('client_a', 'server_public_key.pem'), 'wb') as f:
        f.write(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def generate_hash(data):
    """Generate a SHA-256 hash of the provided data."""
    hash_algorithm = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_algorithm.update(data)
    return hash_algorithm.finalize()

# Function to handle challenge and respond with a signed hash
def handle_challenge_response(server_socket, client_private_key):
    # Receive challenge from server
    challenge = receive_message(server_socket)
    print("Received challenge:", challenge)
    # Sign the challenge with the client's private key
    signature = client_private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Send the signed challenge back to the server
    send_message(server_socket, signature)



def main():
    # Generate and save RSA key pair for Client A
    private_key, public_key = generate_and_save_keypair('client_a')
    # Connect to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    # Exchange public key and client name with server
    server_public_key = exchange_public_key_and_name(client_socket, "A", public_key)
    # Save server's public key
    save_server_public_key(server_public_key)
    # Perform challenge-response authentication
    handle_challenge_response(client_socket, private_key)
    receive_message(client_socket)
    # Close the connection
    client_socket.close()

if __name__ == "__main__":
    main()
