import socket
import threading
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64

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

    # Print the number of clients connected
    print(f"Number of clients connected: {len(clients)}")


def send_message(client_socket, message):
    try:
        # Try sending the message as is
        client_socket.sendall(message)
    except AttributeError:
        # If message is not bytes, encode it as utf-8
        encoded_message = message.encode('utf-8')
        client_socket.sendall(encoded_message)
    except Exception as e:
        print("Error sending message:", e)


def receive_message(client_socket):
    try:
        data = client_socket.recv(4096)
        # Try decoding the received data as utf-8
        decoded_data = data.decode('utf-8')
        return decoded_data
    except UnicodeDecodeError:
        # If utf-8 decoding fails, return the raw data
        return data
    except Exception as e:
        print("Error receiving message:", e)


def generate_hash(data):
    """Generate a SHA-256 hash of the provided data."""
    hash_algorithm = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_algorithm.update(data)
    return hash_algorithm.finalize()

def exchange_public_keys(client_socket):
    try:
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
        
        print("Key exchanged successfully")
        return client_name, client_public_key

    except ValueError:
        print("Invalid public key received.")
    except TypeError:
        print("Invalid encoding received.")
    except Exception as e:
        print("Error exchanging public keys:", e)
    
    return None, None


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

def generate_hash(data):
    """Generate a SHA-256 hash of the provided data."""
    hash_algorithm = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_algorithm.update(data)
    return hash_algorithm.finalize()

def authenticate_client(client_socket, client_public_key):
    try:
        # Generate a random challenge
        challenge = os.urandom(4)
        print(f"Challenge: {challenge}")
        # Send the challenge to the client
        send_message(client_socket, challenge)

        # Receive the response from the client
        response = receive_message(client_socket)
        # Verify the response by decrypting the received signature
        if verify_response(challenge, response, client_public_key):
            print("Client authenticated successfully.")
            send_message(client_socket, b"Authentication successful")
            return True
        else:
            print("Authentication failed: Invalid response from client.")
            send_message(client_socket, b"Authentication failed")
            return False

    except Exception as e:
        print(f"Error during authentication: {e}")
        send_message(client_socket, b"Authentication failed")
        return False

def verify_response(challenge, response, client_public_key):
    try:
        # Verify the response by using the client's public key
        client_public_key.verify(
            response,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Response verified successfully.")
        return True

    except Exception as e:
        print(f"Error verifying client response: {e}")
        return False





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
        # Authenticate the client
        if authenticate_client(client_socket, client_public_key):
            # Start a new thread to handle client communication
            print(f"Client {client_name} authenticated successfully.")
            # Add the authenticated client to the list
            clients.append((client_socket, client_name, client_public_key))
            client_thread = threading.Thread(target=handle_client, args=(client_socket,client_name, client_public_key))
            client_thread.start()

# List to keep track of connected clients
clients = []

if __name__ == "__main__":
    main()
