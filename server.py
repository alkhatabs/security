import socket
import threading
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Server configuration
HOST = '127.0.0.1'
PORT = 5555

# Function to handle client connections
def handle_client(client_socket, client_name):
    while True:
        # Receive data from client
        data = client_socket.recv(1024).decode('utf-8')
        if not data:
            break
        print(f'{client_name} says: {data}')

        # Broadcast the received message to all other clients
        for c in clients:
            if c != client_socket:
                c.sendall(f'{client_name} says: {data}'.encode('utf-8'))

    # If client disconnects, remove it from the list
    clients.remove(client_socket)
    client_socket.close()

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

# Main function to run the server
def main():
    # Generate and save RSA key pair for the server
    generate_and_save_keypair('server')

    # Create socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(3)
    print(f'Server listening on {HOST}:{PORT}')

    while True:
        # Accept incoming connections
        client_socket, addr = server_socket.accept()
        print(f'Connection from {addr} has been established.')

        # Receive client's name
        client_name = client_socket.recv(1024).decode('utf-8')
        print(f'{client_name} has joined the chat.')

        # Add client to the list
        clients.append(client_socket)

        # Start a new thread to handle client communication
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_name))
        client_thread.start()

# List to keep track of connected clients
clients = []

if __name__ == "__main__":
    main()
