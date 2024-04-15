import socket
import rsa
import os


SERVER_IP = '127.0.0.1'  # Change this to your server's IP address
SERVER_PORT = 12345  # Change this to your server's port


def generate_certificate(client_name, client_public_key, server_private_key):
    # Ensure client_name is a string
    client_name = client_name.decode()
    # Combine client name and public key for signing
    data_to_sign = client_name.encode() + client_public_key
    # Sign the data to create a certificate
    signature = rsa.sign(data_to_sign, server_private_key, 'SHA-256')
    # Return the certificate
    return data_to_sign + b'|' + signature

def verify_certificate(certificate, public_key):
    # Split the certificate into data and signature
    data, signature = certificate.split(b'|')
    # Verify the signature using the public key
    try:
        rsa.verify(data, signature, public_key)
        return True
    except rsa.VerificationError:
        return False
    
def save_certificate_to_pem(certificate, filename):
    with open(filename, 'wb') as f:
        f.write(certificate)
        
def generate_key_pair():
    # Generate a new RSA key pair
    public_key, private_key = rsa.newkeys(512)  # Adjust key size as needed
    with open('public_key_A', 'wb') as f:
        f.write(public_key.save_pkcs1())
    with open('private_key_A', 'wb') as f:
        f.write(private_key.save_pkcs1())
    return public_key, private_key

def send_message(connection, message):
    connection.sendall(message)

def receive_message(connection):
    data = connection.recv(1024)
    return data

def main():
    # Generate client's key pair and save them in PEM files
    client_public_key, client_private_key = generate_key_pair()
    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    # receive server's public key
    server_public_key = receive_message(client_socket)
    server_public_key = rsa.PublicKey.load_pkcs1(server_public_key)

    # Set the client name directly
    client_name = "A"

    # Encrypt the client's name using the server's public key
    encrypted_client_name = rsa.encrypt(client_name.encode(), server_public_key)

    # Send the encrypted client name to the server
    send_message(client_socket, encrypted_client_name )

    # Receive the server's response
    server_response = receive_message(client_socket)
    if server_response == b'Access Granted':
        print("Access granted by the server.")

        # Close the initial connection
        client_socket.close()

        # Establish a direct connection to the server
        direct_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        direct_socket.connect((SERVER_IP, SERVER_PORT))
        print("Direct connection to the server established.")

        # Receive and process messages from the server
        while True:
            server_message = receive_message(direct_socket)
            if server_message:
                print("Received message from server:", server_message.decode())
            else:
                print("Connection closed by server.")
                break
    else:
        print("Access denied by the server.")

if __name__ == '__main__':
    main()
