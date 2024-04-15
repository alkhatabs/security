import threading
import socket
from cryptography.fernet import Fernet
import base64

alias = input('Choose an alias >>> ')
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 59000))

# Retrieve the key from the server's response
server_response = client.recv(1024).decode('utf-8')
print("Server Response:", server_response)  # Print server response for debugging
if server_response.startswith('Key: '):
    key = base64.urlsafe_b64decode(server_response.split('Key: ')[1].strip())
    cipher_suite = Fernet(key)
else:
    print("Invalid server response. Unable to retrieve key.")
    exit()

def client_receive():
    while True:
        try:
            message = client.recv(1024)
            decrypted_message = cipher_suite.decrypt(message).decode('utf-8')
            if decrypted_message == "alias?":
                client.send(alias.encode('utf-8'))
            else:
                print(decrypted_message)
        except:
            print('Error!')
            client.close()
            break

def client_send():
    while True:
        message = input("")
        encrypted_message = cipher_suite.encrypt(message.encode())
        client.send(encrypted_message)

receive_thread = threading.Thread(target=client_receive)
receive_thread.start()

send_thread = threading.Thread(target=client_send)
send_thread.start()
