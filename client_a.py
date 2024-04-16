import socket
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

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
    with open(os.path.join(folder, 'private_key.pem'), 'wb') as f:
        f.write(private_key_pem)
    # Save public key to a PEM file
    with open(os.path.join(folder, 'public_key.pem'), 'wb') as f:
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


def respond_to_challenge(client_socket, server_public_key, private_key):
    # Receive challenge from server
    challenge = receive_message(client_socket)

    # Encrypt challenge using server's public key
    encrypted_challenge = server_public_key.encrypt(
        challenge,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Send encrypted challenge to server
    send_message(client_socket, encrypted_challenge)

    # Receive encrypted challenge and signature from server
    encrypted_challenge = receive_message(client_socket)
    signature = receive_message(client_socket)

    # Decrypt challenge using client's private key
    decrypted_challenge = private_key.decrypt(
        encrypted_challenge,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Verify signature using server's public key
    try:
        server_public_key.verify(
            signature,
            decrypted_challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Challenge response verified.")
        send_message(client_socket, "OK")
    except Exception as e:
        print(f"Challenge response verification failed: {e}")
        send_message(client_socket, "Authentication failed")
        client_socket.close()


# Function to respond to challenge from server
def challenge_response(server_socket, private_key):
    # Receive challenge from server
    challenge = receive_message(server_socket)

    # Encrypt challenge using server's public key
    encrypted_challenge = server_public_key.encrypt(
        challenge,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Sign challenge with client's private key
    signature = private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Send encrypted challenge and signature to server
    send_message(server_socket, encrypted_challenge)
    send_message(server_socket, signature)

    # Receive authentication result
    auth_result = receive_message(server_socket)
    if auth_result == "OK":
        print("Authentication successful.")
    else:
        print("Authentication failed.")
        server_socket.close()

# Create socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Generate and save RSA key pair for Client A
private_key, public_key = generate_and_save_keypair('A')

# Connect to server
client_socket.connect((HOST, PORT))

# Exchange public key and client name with server
server_public_key = exchange_public_key_and_name(client_socket, "client_a", public_key)

# Respond to challenge from server
respond_to_challenge(client_socket, server_public_key, private_key)

# Close the connection
client_socket.close()
