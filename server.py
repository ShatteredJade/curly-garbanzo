import socket
import threading
import logging

# host address:port
host = '127.0.0.1'
port = 50505

# server msgs
req_user = 'USER'
req_pass = 'PASS'
con_accept = 'ACCEPT'

# cmds
disconnect = '!disconnect'
kick = '!kick '
ban = '!ban '


class ServerHost:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.logger = logging.getLogger(__name__)
        self.accounts = {'Archaon': 'admin'}
        self.clients = {}
        self.admins = ['Archaon']
        self.banned = []

    def receive(self):
        self.server.listen(5)
        self.logger.info('Server is listening...')

        while True:
            client, addr = self.server.accept()
            f_addr = f'{addr[0]}:{addr[1]}'
            self.logger.info(f'Connected with {f_addr}')

            client_thread = threading.Thread(target=self.handle, args=(client, f_addr))
            client_thread.start()

    def handle(self, client, f_addr):
        self.logger.info(f'Attempting login with {f_addr}...')
        while True:
            access, username = self.login(client, f_addr)
            if access:
                break

        try:
            while True:
                self.handle_message(client, username)  # receive and vet messages

        except ConnectionResetError:
            self.logger.error(f'Lost connection with {username} ({f_addr})')
            self.logoff(client, username)

        except OSError:
            self.logger.info(f'Closed connection with {username} ({f_addr})')

    def handle_message(self, client, username):
        msg = client.recv(1024).decode('utf-8')

        # check if msg is a command
        if msg.startswith('!'):
            self.commands(msg, client, username)
        else:
            self.broadcast(msg)

    def login(self, client, f_addr):
        try:
            # gather login data
            username, password = self.login_data(client, f_addr)

            # check login data in order to accept/deny connection
            access, msg = self.con_access(username, password)

            if access:
                self.clients[username] = client  # add to logged in clients
                self.logger.info(f'Accepted login with {f_addr} as {username}')
            else:
                self.logger.info(f'Refused login with {f_addr} ({msg})')

            client.send(msg.encode('utf-8'))  # accept or deny connection

            return access, username

        except ConnectionResetError:
            self.logger.error(f'Connection lost with {f_addr} while attempting login')
            return

    def login_data(self, client, f_addr):
        client.send(req_user.encode('utf-8'))
        self.logger.info(f'Requesting username from {f_addr}')
        username = client.recv(1024).decode('utf-8')

        client.send(req_pass.encode('utf-8'))
        self.logger.info(f'Requesting password from {f_addr}')
        password = client.recv(1024).decode('utf-8')

        return username, password

    def con_access(self, username, password):
        # if new user, add to existing accounts and accept connection
        if username not in self.accounts:
            self.accounts[username] = password
            return True, con_accept

        if password != self.accounts.get(username):
            return False, 'Wrong password'

        if username in self.clients.keys():
            return False, 'User already logged in'

        if username in self.banned:
            return False, 'User has been banned'

        # existing user, correct password, not logged in. accept connection.
        return True, con_accept

    def logoff(self, client, username):
        del self.clients[username]
        client.close()
        self.broadcast(f'{username} has logged off!')

    def broadcast(self, msg):
        for client in self.clients.values():
            client.send(msg.encode('utf-8'))

    def commands(self, msg, client, username):
        if msg == disconnect:
            self.logger.info(f'{username} requested logout...')
            self.logoff(client, username)
            return

        if username in self.admins:
            if msg.startswith(kick):
                self.kick(client, username, msg)
                return

            elif msg.startswith(ban):
                self.ban(client, username, msg)
                return

        self.logger.error(f"{username} requested an invalid command '{msg}'")
        client.send(f"Invalid command '{msg}'".encode('utf-8'))

    def kick(self, client, username, msg):
        user_kick = msg[len(kick):]  # Find the selected username to kick
        self.logger.info(f'{username} requested to kick {user_kick}')

        try:
            # find the associated client socket for the user being kicked
            client_kick = self.clients.get(user_kick)

            del self.clients[user_kick]
            client_kick.send(f'You have been kicked by admin {username}'.encode('utf-8'))
            client_kick.close()

            self.logger.info(f'Successfully kicked {user_kick}')
            self.broadcast(f'{username} has kicked user {user_kick}')

        except KeyError:
            error = f'Could not kick {user_kick}, user does not exist or is not logged in'
            self.logger.error(error)
            client.send(error.encode('utf-8'))

    def ban(self, client, username, msg):
        user_ban = msg[len(ban):]  # find the selected username to ban
        self.logger.info(f'{username} requested to ban {user_ban}')

        try:
            # find the associated client socket for the user being banned
            client_ban = self.clients.get(user_ban)

            self.banned.append(user_ban)
            del self.clients[user_ban]
            client_ban.send(f'You have been banned by admin {username}'.encode('utf-8'))
            client_ban.close()

            self.logger.info(f'Successfully banned {user_ban}')
            self.broadcast(f'{username} has banned user {user_ban}')

        except KeyError:
            error = f'Could not ban {user_ban}, user does not exist'
            self.logger.error(error)
            client.send(error.encode('utf-8'))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    server_host = ServerHost()
    server_host.receive()
