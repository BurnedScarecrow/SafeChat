# import required modules
import secrets
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox

from lib.rsa.rsa import RSA
from lib.aes.aes import AES

HOST = '127.0.0.1'
PORT = 1234

DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
WHITE = "white"
FONT = ("Helvetica", 17)
BUTTON_FONT = ("Helvetica", 15)
SMALL_FONT = ("Helvetica", 13)

# Creating a socket object
# AF_INET: we are going to use IPv4 addresses
# SOCK_STREAM: we are using TCP packets for communication
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

rsa = RSA()
global aes
aes = 0

public, private = rsa.generate_keypair(
    rsa.p, rsa.q, 2**4)  # 8 is the keysize (bit-length) value.
print("Public Key: ", public)
print("Private Key: ", private)


def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message + '\n')
    message_box.config(state=tk.DISABLED)


def connect():

    # try except block
    try:

        # Connect to the server
        client.connect((HOST, PORT))

        # Send to server public key

        print("Successfully connected to server")
        add_message("[SERVER] Successfully connected to the server")

        print("Exchange keys")

    except:
        messagebox.showerror("Unable to connect to server",
                             f"Unable to connect to server {HOST} {PORT}")

    username = username_textbox.get()
    if username != '':
        client.sendall(username.encode())
    else:
        messagebox.showerror("Invalid username", "Username cannot be empty")

    threading.Thread(target=listen_for_messages_from_server,
                     args=(client, )).start()

    username_textbox.config(state=tk.DISABLED)
    username_button.config(state=tk.DISABLED)
    first_message = "S "+str(public[0])+" "+str(public[1])
    client.sendall(first_message.encode())


def send_message():
    message = message_textbox.get()

    if message != '':
        plaintext = aes.text2hex(message)
        encrypted = aes.encrypt(plaintext)
        print("Encrypted message:", message, encrypted)
        ready_message = "A " + str(encrypted)
        client.sendall(ready_message.encode())
        message_textbox.delete(0, len(message))
    else:
        messagebox.showerror("Empty message", "Message cannot be empty")


root = tk.Tk()
root.geometry("600x600")
root.title("Messenger Client")
root.resizable(False, False)

root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=4)
root.grid_rowconfigure(2, weight=1)

top_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
top_frame.grid(row=0, column=0, sticky=tk.NSEW)

middle_frame = tk.Frame(root, width=600, height=400, bg=MEDIUM_GREY)
middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

bottom_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

username_label = tk.Label(
    top_frame, text="Enter username:", font=FONT, bg=DARK_GREY, fg=WHITE)
username_label.pack(side=tk.LEFT, padx=10)

username_textbox = tk.Entry(
    top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
username_textbox.pack(side=tk.LEFT)

username_button = tk.Button(
    top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=connect)
username_button.pack(side=tk.LEFT, padx=15)

message_textbox = tk.Entry(bottom_frame, font=FONT,
                           bg=MEDIUM_GREY, fg=WHITE, width=38)
message_textbox.pack(side=tk.LEFT, padx=10)

message_button = tk.Button(bottom_frame, text="Send", font=BUTTON_FONT,
                           bg=OCEAN_BLUE, fg=WHITE, command=send_message)
message_button.pack(side=tk.LEFT, padx=10)

message_box = scrolledtext.ScrolledText(
    middle_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=WHITE, width=67, height=26.5)
message_box.config(state=tk.DISABLED)
message_box.pack(side=tk.TOP)


def listen_for_messages_from_server(client):

    while 1:

        message = client.recv(2048).decode('utf-8')
        if message != '':
            if message[0] == "S" and message[1] == " ":
                encoded = message[2:-1:1].split(" ")
                print("Recieved encoded RSA message:", encoded)
                encrypted = [int(numeric_string)
                             for numeric_string in encoded]
                decrypted = rsa.decrypt(encrypted, private)
                print("Decrypded:", decrypted)
                global aes
                aes = AES(int.from_bytes(
                    decrypted.encode(), "big", signed=False))

            elif message[0] == "A" and message[1] == " ":
                message = message[2:]
                username = message.split("~")[0]
                content = message.split('~')[1]

                hex = aes.decrypt(int(content.encode()))
                text = aes.hex2text(hex)

                add_message(f"[{username}] {text}")

            elif message[0:6:1] == "SERVER":
                username = message.split("~")[0]
                content = message.split('~')[1]
                add_message(f"[{username}] {content}")

            else:
                print(message)
                add_message(message)

        else:
            messagebox.showerror(
                "Error", "Message recevied from client is empty")

# main function


def main():

    root.mainloop()


if __name__ == '__main__':
    main()
