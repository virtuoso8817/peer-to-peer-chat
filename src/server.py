import socket
import threading
import tkinter as tk
from tkinter import messagebox
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

# Tkinter UI Setup
root = tk.Tk()
root.title("Server Chat")
root.geometry("400x500")
root.configure(bg="#f0f0f0")

font_style = ("Arial", 12)

# Header Label
header = tk.Label(root, text="Server Chat", font=("Arial", 16, "bold"), bg="#FF5733", fg="white", pady=10)
header.pack(fill=tk.X)

# Chat History
chat_frame = tk.Frame(root, padx=10, pady=5, bg="#f0f0f0")
chat_frame.pack(fill=tk.BOTH, expand=True)

chat_history = tk.Text(chat_frame, height=15, width=50, font=font_style, wrap=tk.WORD)
chat_history.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(chat_frame, command=chat_history.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
chat_history.config(yscrollcommand=scrollbar.set)

# Text Entry Box
entry_frame = tk.Frame(root, bg="#f0f0f0", padx=10, pady=5)
entry_frame.pack(fill=tk.X)

entry = tk.Entry(entry_frame, font=font_style, width=30)
entry.pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill=tk.X)


# Function to send messages from server
def send_message():
    def send():
        try:
            message = entry.get()
            if not message:
                messagebox.showwarning("Warning", "Message cannot be empty!")
                return

            encrypted_message = encrypt_message(message)
            client_socket.send(encrypted_message.encode())  # Send message to client

            # Display message in chat history
            chat_history.insert(tk.END, f"Server: {message}\n", "server_message")
            entry.delete(0, tk.END)

        except Exception as e:
            messagebox.showerror("Error", f"Error sending message: {e}")

    threading.Thread(target=send, daemon=True).start()

send_button = tk.Button(entry_frame, text="Send", font=font_style, bg="#FF5733", fg="white", command=send_message)
send_button.pack(side=tk.RIGHT, padx=5)

# Function to receive messages from the client
def receive_messages():
    while True:
        try:
            response = client_socket.recv(1024).decode()
            if not response:
                break

            decrypted_response = decrypt_message(response)
            chat_history.insert(tk.END, f"Client: {decrypted_response}\n", "client_message")

        except:
            break

# Start a thread to receive messages
threading.Thread(target=receive_messages, daemon=True).start()

# Text Color Formatting
chat_history.tag_config("server_message", foreground="red")   # Server messages in red
chat_history.tag_config("client_message", foreground="green")  # Client messages in green

root.mainloop()


