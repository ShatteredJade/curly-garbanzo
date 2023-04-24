import socket
import threading
import logging
import bcrypt
import sqlite3
import time

# IMPLEMENT HASHING W/ SALTING AND PEPPERING

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
unban = '!unban '

# roles
admin = 'admin'
user = 'user'
banned = 'banned'


class ServerHost:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.logger = logging.getLogger(__name__)
        self.clients = {}
        self.create_db()

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
            # call command, if it fails send an error msg
            if not self.commands(msg, client, username):
                self.logger.error(f"{username} requested an invalid command '{msg}'")
                client.send(f"Invalid command '{msg}'".encode('utf-8'))
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
        if not self.check_acct(username):
            self.create_acct(username, password)
            return True, con_accept

        if not self.check_pass(username, password):
            return False, 'Wrong password'

        if username in self.clients.keys():
            return False, 'User already logged in'

        if self.check_role(username, banned):
            return False, 'User has been banned'

        # existing user, correct password, not logged in. accept connection.
        return True, con_accept

    def logoff(self, client, username):
        del self.clients[username]
        client.close()
        self.broadcast(f'{username} has logged off!')

    def force_logoff(self, username, user_target, cond):
        if cond == kick:
            action = 'kicked'
        else:
            action = 'banned'

        client_target = self.clients.get(user_target)  # find associated client for kick target
        del self.clients[user_target]
        client_target.send(f'You have been {action} by admin {username}'.encode('utf-8'))
        client_target.close()

    def broadcast(self, msg):
        for client in self.clients.values():
            client.send(msg.encode('utf-8'))

    def commands(self, msg, client, username):
        if msg == disconnect:
            self.logger.info(f'{username} requested logout...')
            self.logoff(client, username)
            return True

        # if user is not an admin, return before checking admin cmds
        if not self.check_role(username, admin):
            return False

        # isolate and format target username
        seperator_index = msg.find(' ')
        user_target = msg[seperator_index + 1:]
        user_target = user_target.lower().title()

        return self.admin_commands(client, username, user_target, msg)

    def admin_commands(self, client, username, user_target, msg):
        # for commands that require db access
        connection = sqlite3.connect('userdata.db')
        cursor = connection.cursor()

        if msg.startswith(kick):
            success, action = self.kick(client, username, user_target)

        elif msg.startswith(ban):
            success, action = self.ban(client, username, user_target, connection, cursor)

        elif msg.startswith(unban):
            success, action = self.unban(client, username, user_target, connection, cursor)

        else:
            return False

        if success:
            self.cmd_broadcast(username, user_target, action)

        return True

    def cmd_broadcast(self, username, user_target, action):
        msg = f'{username} has {action} user {user_target}'
        self.logger.info(msg)
        self.broadcast(msg)

    def kick(self, client, username, user_kick):
        self.logger.info(f'{username} requested to kick {user_kick}')

        # if user is logged in, remove client and send kick msg
        try:
            self.force_logoff(username, user_kick, kick)
        except KeyError:
            error = f'Could not kick {user_kick}, user does not exist or is not logged in'
            self.logger.error(error)
            client.send(error.encode('utf-8'))
            return False

        return True, 'kicked'

    def ban(self, client, username, user_ban, connection, cursor):
        self.logger.info(f'{username} requested to ban {user_ban}')

        # check if target user exists
        if not self.target_check(client, user_ban, ban):
            return False

        cursor.execute(f"""
        UPDATE accounts
        SET role = '{banned}'
        WHERE username = '{user_ban}'
        """)

        connection.commit()

        # if user is logged in, remove client and send ban msg
        try:
            self.force_logoff(username, user_ban, ban)
        except KeyError:
            pass

        return True, 'banned'

    def unban(self, client, username, user_unban, connection, cursor):
        self.logger.info(f'{username} requested to unban {user_unban}')

        # check if acct exists and if they're banned
        if not self.target_check(client, user_unban, unban):
            return False

        cursor.execute(f"""
                UPDATE accounts
                SET role = '{user}'
                WHERE username = '{user_unban}'
                """)

        connection.commit()

        return True, 'unbanned'

    def target_check(self, client, user_target, cond):
        if cond == unban:
            action = 'unban'
        else:
            action = 'ban'

        if not self.check_acct(user_target):
            error = f'Could not {action} {user_target}, user does not exist'
            self.logger.error(error)
            client.send(error.encode('utf-8'))
            return False

        if cond == unban and not self.check_role(user_target, banned):
            error = f'Could not unban {user_target}, user is not banned'
            self.logger.error(error)
            client.send(error.encode('utf-8'))
            return False

        return True

    def create_db(self):
        connection = sqlite3.connect('userdata.db')
        cursor = connection.cursor()

        try:
            cursor.execute('''
            CREATE TABLE accounts (
                username TEXT,
                password TEXT,
                role TEXT
            )
            ''')

            cursor.execute("""
            INSERT INTO accounts VALUES
                ('Archaon', 'pass', 'admin') 
            """)

            connection.commit()

        except sqlite3.OperationalError:
            return

    def create_acct(self, username, password):
        connection = sqlite3.connect('userdata.db')
        cursor = connection.cursor()

        cursor.execute(f"""
        INSERT INTO accounts VALUES
            ('{username}', '{password}', 'user')
        """)

        connection.commit()

    def check_acct(self, username):
        connection = sqlite3.connect('userdata.db')
        cursor = connection.cursor()

        cursor.execute(f"""
        SELECT username FROM accounts
            WHERE username = '{username}'
        """)

        username = cursor.fetchone()

        connection.commit()

        if username:
            return True
        return False

    def check_pass(self, username, password):
        connection = sqlite3.connect('userdata.db')
        cursor = connection.cursor()

        cursor.execute(f"""
        SELECT password FROM accounts
            WHERE username = '{username}'
        """)

        data = cursor.fetchone()

        connection.commit()

        if data[0] == password:
            return True
        return False

    def check_role(self, username, cond):
        connection = sqlite3.connect('userdata.db')
        cursor = connection.cursor()

        cursor.execute(f"""
        SELECT role FROM accounts
            WHERE username = '{username}'
        """)

        role = cursor.fetchone()

        connection.commit()

        if role[0] == cond:
            return True
        return False


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    server_host = ServerHost()
    server_host.receive()
