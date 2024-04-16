import socket
import threading
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Server configuration
HOST = '127.0.0.1'
PORT = 5555

# Function to handle client connections
def handle_client(client_socket, client_name, client_public_key):
    while True:
        # Receive data from client
        data = receive_message(client_socket)
        if not data:
            break
        print(f'{client_name} says: {data}')

        # Broadcast the received message to all other clients
        for c in clients:
            if c[0] != client_socket:
                send_message(c[0], f'{client_name} says: {data}')

    # If client disconnects, remove it from the list
    clients.remove((client_socket, client_name))
    client_socket.close()

def send_message(client_socket, message):
    if isinstance(message, str):
        client_socket.sendall(message.encode('utf-8'))
    else:
        client_socket.sendall(message)

def receive_message(client_socket):
    data = client_socket.recv(1024)
    if isinstance(data, bytes):
        return data.decode('utf-8')
    else:
        return data

def exchange_public_keys(client_socket):
    # Read server's private key from PEM file
    with open("server//server_private_key.pem", 'rb') as f:
        server_private_key_bytes = f.read()

    # Deserialize server's private key
    server_private_key = serialization.load_pem_private_key(
        server_private_key_bytes,
        password=None,  # No password protection
        backend=default_backend()
    )

    # Receive client's name and public key
    client_info = receive_message(client_socket)
    client_name, client_public_key_pem = client_info.split(";")

    # Deserialize client's public key from PEM format
    try:
        client_public_key = serialization.load_pem_public_key(
            client_public_key_pem.encode(),
            backend=default_backend()
        )

        # Save client's public key
        with open(os.path.join('server', f'{client_name}_public_key.pem'), 'wb') as f:
            f.write(client_public_key_pem.encode())

        # Send server's public key to the client
        with open(os.path.join('server', 'server_public_key.pem'), 'rb') as f:
            server_public_key_bytes = f.read()
        client_socket.sendall(server_public_key_bytes)

        return client_name, client_public_key

    except Exception as e:
        print("Error exchanging public keys:", e)
        return None, None


# Function to authenticate client using challenge-response mechanism
def authenticate_client(client_socket, client_name, client_public_key):
    # Receive challenge from client
    challenge = os.urandom(16)
    send_message(client_socket, challenge)

    # Receive encrypted challenge and signature from client
    encrypted_challenge = receive_message(client_socket)
    signature = receive_message(client_socket)

    # Decrypt challenge using server's private key
    decrypted_challenge = server_private_key.decrypt(
        encrypted_challenge,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Verify signature using client's public key
    try:
        client_public_key.verify(
            signature,
            decrypted_challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"{client_name} authenticated successfully.")
        send_message(client_socket, "OK")
        # Respond with a challenge to the client
        challenge_response(client_socket, client_public_key)
    except Exception as e:
        print(f"Authentication failed: {e}")
        send_message(client_socket, "Authentication failed")
        client_socket.close()

def respond_to_challenge(client_socket, server_private_key):
    try:
        # Receive challenge from client
        encrypted_challenge = receive_message(client_socket)

        # Decrypt challenge using server's private key
        decrypted_challenge = server_private_key.decrypt(
            encrypted_challenge,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Respond with decrypted challenge
        send_message(client_socket, decrypted_challenge)

    except ValueError as e:
        print("Error decrypting challenge:", e)
        send_message(client_socket, "Error: Challenge decryption failed")
        client_socket.close()

    except Exception as e:
        print("Unexpected error during challenge response:", e)
        send_message(client_socket, "Error: Unexpected error during challenge response")
        client_socket.close()

# Function to respond with a challenge to the client
def challenge_response(client_socket, client_public_key):
    # Generate challenge
    challenge = os.urandom(16)

    # Encrypt challenge using client's public key
    encrypted_challenge = client_public_key.encrypt(
        challenge,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Sign challenge with server's private key
    signature = server_private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Send encrypted challenge and signature to the client
    send_message(client_socket, encrypted_challenge)
    send_message(client_socket, signature)

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
    with open(os.path.join(folder, 'server_private_key.pem'), 'wb') as f:
        f.write(private_key_pem)
    # Save public key to a PEM file
    with open(os.path.join(folder, 'server_public_key.pem'), 'wb') as f:
        f.write(public_key_pem)
    return private_key, public_key

def main():
    # Generate and save RSA key pair for the server
    global server_private_key, server_public_key
    server_private_key, server_public_key = generate_and_save_keypair('server')

    # Create socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(3)
    print(f'Server listening on {HOST}:{PORT}')

    while True:
        # Accept incoming connections
        client_socket, addr = server_socket.accept()
        print(f'Connection from {addr} has been established.')

        # Exchange public keys with client
        client_name, client_public_key = exchange_public_keys(client_socket)

        # Authenticate client
        authenticate_client(client_socket, client_name, client_public_key)

        # Add client to the list
        clients.append((client_socket, client_name))

        # Respond to challenge
        respond_to_challenge(client_socket, server_private_key)

        # Start a new thread to handle client communication
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_name, client_public_key))
        client_thread.start()

# List to keep track of connected clients
clients = []

if __name__ == "__main__":
    main()
