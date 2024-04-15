import socket
import rsa


SERVER_IP = '127.0.0.1'  # Change this to your server's IP address
SERVER_PORT = 12345  # Change this to your server's port


def encrypt_large_text(message, public_key):
    # Define the chunk size based on the key size
    chunk_size = rsa.common.byte_size(public_key.n) - 42
    encrypted_chunks = []

    # Encrypt message in chunks
    for i in range(0, len(message), chunk_size):
        chunk = message[i:i + chunk_size]
        encrypted_chunk = rsa.encrypt(chunk.encode(), public_key)
        encrypted_chunks.append(encrypted_chunk)

    # Return the encrypted chunks
    return encrypted_chunks

def decrypt_large_text(encrypted_chunks, private_key):
    decrypted_chunks = []

    # Decrypt each chunk
    for encrypted_chunk in encrypted_chunks:
        decrypted_chunk = rsa.decrypt(encrypted_chunk, private_key).decode()
        decrypted_chunks.append(decrypted_chunk)

    # Combine decrypted chunks into the original message
    return ''.join(decrypted_chunks)

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
    # Generate a new RSA key pair with 512 bits
    public_key, private_key = rsa.newkeys(512)
    with open('public_key_s', 'wb') as f:
        f.write(public_key.save_pkcs1())
    with open('private_key_s', 'wb') as f:
        f.write(private_key.save_pkcs1())
    return public_key, private_key

def save_public_key_to_pem(public_key, filename):
    with open(filename, 'wb') as f:
        f.write(public_key.save_pkcs1())

def send_message(connection, message):
    connection.sendall(message)

def receive_message(connection):
    data = connection.recv(1024)
    return data

def encrypt_message(message, public_key):
    # Encrypt the message using RSA public key
    encrypted_message = encrypt_large_text(message, public_key)
    return encrypted_message

def decrypt_message(encrypted_message, private_key):
    # Decrypt the message using RSA private key
    decrypted_message = decrypt_large_text(encrypted_message, private_key)
    return decrypted_message

def main():
    # Generate server's key pair
    server_public_key, server_private_key = generate_key_pair()

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address
    server_address = (SERVER_IP, SERVER_PORT)
    print('Starting server on %s port %s' % server_address)
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(1)
    # Dictionary to store client public keys
    client_public_keys = {}
    while True:
        print('Waiting for a connection...')
        connection, client_address = server_socket.accept()

        try:
            print('Connection from', client_address)

            # Send server's public key to the client
            send_message(connection, server_public_key.save_pkcs1())

            # Receive the client's encrypted name
            encrypted_data = receive_message(connection)
            decrypted_data = decrypt_message(encrypted_data, server_private_key)
            # Split the decrypted data into client name and public key
            client_name, client_public_key = decrypted_data.split(b'|')
            # Save client's public key to the dictionary
            client_public_keys[client_name.decode()] = rsa.PublicKey.load_pkcs1(client_public_key)
            # Generate client's certificate
            client_certificate = generate_certificate(client_name, client_public_key, server_private_key)

            # Save client's certificate to a PEM file
            save_certificate_to_pem(client_certificate, f'client_{client_name.decode()}_certificate.pem')
            print("Received encrypted data from client:", encrypted_data)
            print("Decrypted client name:", client_name)

            # Send "Access Granted" message to the client
            send_message(connection, b'Access Granted')

        finally:
            # Clean up the connection
            connection.close()

if __name__ == '__main__':
    main()
