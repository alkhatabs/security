import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

# Serialize RSA public key
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Deserialize RSA public key
def deserialize_public_key(serialized_key):
    return serialization.load_pem_public_key(serialized_key, backend=default_backend())

# Function to send encrypted message to the server
def send_encrypted_message(host, port, message, public_key):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    try:
        # Encrypt message with the recipient's public key
        cipher_text = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Send encrypted message to the server
        client_socket.sendall(cipher_text)
        print("Encrypted message sent to server:", cipher_text.hex())

        # Receive response from the server
        response = client_socket.recv(4096)
        if response:
            print("Response from server:", response.hex())
        else:
            print("No response received from server")
    except Exception as e:
        print("Error:", e)
    finally:
        client_socket.close()

if __name__ == "__main__":
    # Define server address and port
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 12345

    # Generate RSA key pair for the client
    private_key = generate_rsa_key_pair()
    public_key = private_key.public_key()

    # Serialize the public key
    serialized_public_key = serialize_public_key(public_key)

    # Deserialize public keys of A, B, and C
    public_key_A = deserialize_public_key(serialized_public_key)
    public_key_B = deserialize_public_key(serialized_public_key)
    public_key_C = deserialize_public_key(serialized_public_key)

    # Messages to be sent
    message_AB = "Message from A to B"
    message_BC = "Message from B to C"
    message_CA = "Message from C to A"

    # Send encrypted messages
    send_encrypted_message(SERVER_HOST, SERVER_PORT, message_AB, public_key_B)
    send_encrypted_message(SERVER_HOST, SERVER_PORT, message_BC, public_key_C)
    send_encrypted_message(SERVER_HOST, SERVER_PORT, message_CA, public_key_A)
