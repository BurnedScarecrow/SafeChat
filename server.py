# Import required modules
from pydoc import cli
import socket
import threading
from lib.rsa.rsa import RSA
from lib.aes.aes import AES

HOST = '127.0.0.1'
PORT = 1234  # You can use any port between 0 to 65535
LISTENER_LIMIT = 5
active_clients = []  # List of all currently connected users

# secret = 0xfedcba9876543210fedcba9876543210
secret = "_secret_32_bit__"
secret = "_our_secret_key_"

global aes
aes = AES(int.from_bytes(
    secret.encode(), "big", signed=False))


# Function to listen for upcoming messages from a client
def listen_for_messages(client, username):

    while 1:

        message = client.recv(2048).decode('utf-8')
        if message != '':
            print("Recieved :", type(message), message)

            if message[0] == 'S':
                msg = message.split(" ")
                public = (int(msg[1]), int(msg[2]))
                print("Public key is:", public)
                print("Send secret")
                rsa = RSA()
                encrypted_msg = rsa.encrypt(secret, public)
                print(encrypted_msg)
                print(''.join(map(lambda x: str(x), encrypted_msg)))
                client.sendall(
                    ("S " + ''.join(map(lambda x: str(x)+" ", encrypted_msg))).encode())

            if message[0] == "A":
                chipertext = message[2:]
                global aes
                hex = aes.decrypt(int(chipertext.encode()))
                print("Decrypted (HEX bytes):", type(hex), hex)
                text = aes.hex2text(hex)
                print("Decrypted (plaintext):", text)
                final_msg = "A " + username + '~' + chipertext
                send_messages_to_all(final_msg)

        else:
            print(f"The message send from client {username} is empty")
            client.close()


# Function to send message to a single client
def send_message_to_client(client, message):
    client.sendall(message.encode())

# Function to send any new message to all the clients that
# are currently connected to this server


def send_messages_to_all(message):

    for user in active_clients:

        send_message_to_client(user[1], message)

# Function to handle client


def client_handler(client):

    # Server will listen for client message that will
    # Contain the username
    while 1:

        username = client.recv(2048).decode('utf-8')
        if username != '':
            active_clients.append((username, client))
            prompt_message = "SERVER~" + f"{username} added to the chat"
            send_messages_to_all(prompt_message)
            break
        else:
            print("Client username is empty")

    threading.Thread(target=listen_for_messages,
                     args=(client, username, )).start()

# Main function


def main():

    # Creating the socket class object
    # AF_INET: we are going to use IPv4 addresses
    # SOCK_STREAM: we are using TCP packets for communication
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Creating a try catch block
    try:
        # Provide the server with an address in the form of
        # host IP and port
        server.bind((HOST, PORT))
        print(f"Running the server on {HOST} {PORT}")
    except:
        print(f"Unable to bind to host {HOST} and port {PORT}")

    # Set server limit
    server.listen(LISTENER_LIMIT)

    # This while loop will keep listening to client connections
    while 1:

        client, address = server.accept()
        print(f"Successfully connected to client {address[0]} {address[1]}")

        threading.Thread(target=client_handler, args=(client, )).start()


if __name__ == '__main__':
    main()
