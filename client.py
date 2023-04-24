import socket
import threading
import logging
from server import con_accept, host, port, disconnect


class ChatClient:
    def __init__(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger = logging.getLogger(__name__)
        self.username = None

    def start(self):
        if not self.connect():
            return
        while True:
            if self.login():
                break

        receive_thread = threading.Thread(target=self.receive)
        receive_thread.daemon = True
        receive_thread.start()
        self.send()

    def connect(self):
        self.client.settimeout(5)

        try:
            self.client.connect((host, port))
        except (ConnectionRefusedError, socket.timeout):
            self.logger.error(f'Unable to connect to {host}:{port}')
            return False

        self.client.settimeout(None)

        return True

    def login(self):
        self.username = input('Please enter a username: ')
        password = input('Please enter a password: ')
        self.username = self.username.lower().title()  # username not case-sensitive, title for formatting

        self.client.recv(1024)  # wait for username request
        self.client.send(self.username.encode('utf-8'))
        self.client.recv(1024)  # wait for password request
        self.client.send(password.encode('utf-8'))

        msg = self.client.recv(1024).decode('utf-8')

        if msg == con_accept:
            self.logger.info(f'Successfully logged in as {self.username}')
            return True
        else:
            self.logger.info(f'Login failed: {msg}')
            return False

    def send(self):
        try:
            while True:
                msg = input()

                if msg.startswith('!'):
                    self.client.send(msg.encode('utf-8'))

                    if msg == disconnect:
                        break
                else:
                    self.client.send(f'{self.username}: {msg}'.encode('utf-8'))

        except OSError:
            self.logger.error('Unable to send message. User lost connection with the server')

        finally:
            self.client.close()

    def receive(self):
        try:
            while True:
                msg = self.client.recv(1024).decode('utf-8')

                if not msg:
                    break

                print(msg)

        except ConnectionResetError:
            self.logger.error('Connection lost!')

        except ConnectionAbortedError:
            self.logger.info('Disconnecting...')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    chat_client = ChatClient()
    chat_client.start()
