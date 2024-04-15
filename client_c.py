import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import base64

# Load client's RSA private key
with open('client_c_private.pem', 'r') as f:
    client_private_key = RSA.import_key(f.read())

# Load server's public key
with open('server_public.pem', 'r') as f:
    server_public_key = RSA.import_key(f.read())

# Socket setup
HOST = '127.0.0.1'
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

def authenticate_to_server():
    # Send public key certificate to server
    client_socket.sendall("Client C certificate".encode())

def receive_challenge():
    return client_socket.recv(1024).decode()

def generate_response(challenge):
    signature = client_private_key.sign(challenge.encode(), '')
    return signature

def send_response(response):
    client_socket.sendall(response)

def generate_session_key():
    # Perform Diffie-Hellman key exchange
    # Generate private key
    private_key = get_random_bytes(16)
    # Send public key to server
    client_socket.sendall(private_key)
    # Receive server's public key
    server_public_key = client_socket.recv(1024)
    # Derive shared secret
    shared_secret = pow(int.from_bytes(server_public_key, 'big'), int.from_bytes(private_key, 'big'), p)
    # Derive session key using shared secret
    session_key = scrypt(shared_secret.to_bytes(16, 'big'), salt=b'salt', key_len=16, N=2**14, r=8, p=1)
    return session_key

def encrypt_message(message, session_key):
    cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return (cipher.nonce, ciphertext, tag)

def decrypt_message(nonce, ciphertext, tag, session_key):
    cipher = AES.new(session_key, AES.MODE_GCM, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

def send_session_confirmation(session_key):
    confirmation_message = encrypt_message("Session established", session_key)
    client_socket.sendall(json.dumps(confirmation_message).encode())

def receive_session_confirmation():
    confirmation_message = json.loads(client_socket.recv(1024).decode())
    decrypted_message = decrypt_message(confirmation_message[0], confirmation_message[1], confirmation_message[2], session_key)
    if decrypted_message == "Session established":
        return True
    else:
        return False

def send_message(message, session_key):
    encrypted_message = encrypt_message(message, session_key)
    client_socket.sendall(json.dumps(encrypted_message).encode())

def receive_message(session_key):
    encrypted_message = json.loads(client_socket.recv(1024).decode())
    decrypted_message = decrypt_message(encrypted_message[0], encrypted_message[1], encrypted_message[2], session_key)
    return decrypted_message

authenticate_to_server()
challenge = receive_challenge()
response = generate_response(challenge)
send_response(response)
session_key = generate_session_key()
send_session_confirmation(session_key)
if receive_session_confirmation():
    print("Session established with server.")
    while True:
        message = input("Enter message: ")
        send_message(message, session_key)
        received_message = receive_message(session_key)
        print("Received:", received_message)
else:
    print("Session establishment failed.")
