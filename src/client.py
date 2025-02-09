import socket
import tkinter as tk
from tkinter import messagebox
import threading
from encryption import encrypt_message, decrypt_message  # Import encryption functions

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 12345))


def send_message():
    def send():
        try:
            message = entry.get()
            if not message:
                messagebox.showwarning("Warning", "Message cannot be empty!")
                return

            # Try sending message
            try:
                encrypted_message = encrypt_message(message)  # Encrypt user input
                client_socket.send(encrypted_message.encode())  # Send user input to server
            except BrokenPipeError:
                messagebox.showerror("Error", "Connection lost! Please restart the client.")
                return

            # Try receiving server response
            try:
                response = client_socket.recv(1024).decode()  # Receive response
                decrypt_response = decrypt_message(response)  # Decrypt response
            except ConnectionResetError:
                messagebox.showerror("Error", "Server closed the connection unexpectedly!")
                return

            # Display messages in chat
            chat_history.insert(tk.END, f"You: {message}\n", "user_message")
            chat_history.insert(tk.END, f"Server: {decrypt_response}\n", "server_message")

            entry.delete(0, tk.END)  # Clear input field

        except Exception as e:
            messagebox.showerror("Error", f"Unexpected Error: {e}")

    threading.Thread(target=send, daemon=True).start()


def receive_messages():
    while True:
        try:
            response = client_socket.recv(1024).decode()
            if not response:
                break
            decrypted_response = decrypt_message(response)  # Decrypt incoming message
            chat_history.insert(tk.END, f"Server: {decrypted_response}\n", "server_message")
        except:
            break





threading.Thread(target=receive_messages, daemon=True).start()

# Tkinter UI
root = tk.Tk()
root.title(" Chat Client")
root.geometry("400x500")
root.configure(bg="#f0f0f0")

# Styling
font_style = ("Arial", 12)

# Header Label
header = tk.Label(root, text="Client Chat", font=("Arial", 16, "bold"), bg="#4CAF50", fg="white", pady=10)
header.pack(fill=tk.X)

# Chat History (Text Box)
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

send_button = tk.Button(entry_frame, text="Send", font=font_style, bg="#4CAF50", fg="white", command=send_message)
send_button.pack(side=tk.RIGHT, padx=5)

# Text Color Formatting
chat_history.tag_config("user_message", foreground="blue")
chat_history.tag_config("server_message", foreground="green")

root.mainloop()






