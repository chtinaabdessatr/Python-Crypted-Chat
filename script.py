import socket
import threading
import sys
import signal
import logging
from cryptography.fernet import Fernet
import base64
import hashlib

# Function to generate key based on password
def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Function to encrypt message
def encrypt_message(key, message):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

# Function to decrypt message
def decrypt_message(key, encrypted_message):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# Function to handle receiving messages
def receive_messages(sock, key):
    while True:
        try:
            encrypted_message = sock.recv(1024)
            if encrypted_message:
                #print(f"\nEncrypted message received: {encrypted_message}")
                decrypted_message = decrypt_message(key, encrypted_message)
                print(f"{decrypted_message}")
                # Log messages
                encrypted_log.info(encrypted_message)
                plain_log.info(decrypted_message)
            else:
                break
        except Exception as e:
            print("An error occurred:", e)
            break

# Function to handle sending messages
def send_messages(sock, key, user_name):
    while True:
        try:
            message = input()
            if message:
                full_message = f"{user_name}: {message}"
                encrypted_message = encrypt_message(key, full_message)
                #print(f"Encrypted message to send: {encrypted_message}")
                sock.sendall(encrypted_message)
                # Log messages
                encrypted_log.info(encrypted_message)
                plain_log.info(full_message)
        except EOFError:
            break

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    print("\nShutting down...")
    sys.exit(0)

# Main function to handle the chat application
def main():
    # Prompt for user inputs
    user_name = input("Enter your user name: ")
    port = int(input("Enter the port number: "))
    password = input("Enter the password for encryption: ")
    address = input("Enter the IP address of the other client: ")
    mode = input("Enter the mode (server/client): ").lower()
    
    key = generate_key(password)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if mode == 'server':
        sock.bind((address, port))
        sock.listen(1)
        print("Waiting for a connection...")
        connection, client_address = sock.accept()
        print("Connected to:", client_address)
    else:
        sock.connect((address, port))
        connection = sock
        print("Connected to the server")

    # Set up signal handling
    signal.signal(signal.SIGINT, signal_handler)

    receive_thread = threading.Thread(target=receive_messages, args=(connection, key))
    send_thread = threading.Thread(target=send_messages, args=(connection, key, user_name))

    receive_thread.start()
    send_thread.start()

    receive_thread.join()
    send_thread.join()

    connection.close()

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    plain_log = logging.getLogger('plain')
    plain_handler = logging.FileHandler('plain_log.txt')
    plain_formatter = logging.Formatter('%(asctime)s - %(message)s')
    plain_handler.setFormatter(plain_formatter)
    plain_log.addHandler(plain_handler)
    
    encrypted_log = logging.getLogger('encrypted')
    encrypted_handler = logging.FileHandler('encrypted_log.txt')
    encrypted_formatter = logging.Formatter('%(asctime)s - %(message)s')
    encrypted_handler.setFormatter(encrypted_formatter)
    encrypted_log.addHandler(encrypted_handler)

    main()
