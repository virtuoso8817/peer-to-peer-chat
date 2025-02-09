import socket
from encryption import encrypt_message, decrypt_message

HOST = "127.0.0.1"  # Localhost
PORT = 12345        # Port number

# Create a socket (IPv4, TCP)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))  # Bind to the address
server_socket.listen(5)           # Listen for connections

print(f"Server is listening on {HOST}:{PORT}...")

client_socket, client_address = server_socket.accept()
print(f"Connected to {client_address}")

while True:


    encypted_message = client_socket.recv(1024).decode()  # Receive message
    if not encypted_message:
        break  # Exit if the client disconnects

    message = decrypt_message(encypted_message)  # Decrypt message
    print(f"Client: {message}")

    response = input("You(Server):")  # Response message
    encrypted_response = encrypt_message(response)  # Encrypt response
    client_socket.send(encrypted_response.encode())  # Send response

client_socket.close()  # Close connection
server_socket.close()
