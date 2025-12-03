# Libraries
import logging
from logging.handlers import RotatingFileHandler
import socket  # create servers and clients that communicate via tcp or udp
import paramiko
import threading

# Constants
logging_format = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
SSH_BANNER = "SSH-2.0-OpenSSH_8.6p1 Ubuntu-4ubuntu0.5"
host_key = paramiko.RSAKey(filename='server.key')
# Loggers and Logging files

# creating a funnel logger which is a main logger that centrelizes everything
# creating a logger named FunnelLogger
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)  # for general logging informations
# send funnel logs to a file named system.log and rotate it if it reaches 2000bytes (we can keep up to 4 log files archived)
funnel_handler = RotatingFileHandler(
    'system.log', maxBytes=2000, backupCount=4)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# creating a credentials logger which is a child logger that is only used to log login or passwords attempts
credentials_logger = logging.getLogger('FunnelLogger')
credentials_logger.setLevel(logging.INFO)
credentials_handler = RotatingFileHandler(
    'cmd_system.log', maxBytes=2000, backupCount=4)
credentials_handler.setFormatter(logging_format)
credentials_logger.addHandler(credentials_handler)

# Emulated shell


def emulatedShell(channel, client_ip):
    try:
        channel.send(b'backup-shell$ ')
        command = b""
        while True:
            char = channel.recv(1)
            channel.send(char)
            if not char:
                channel.close()
                break

            command += char

            response = b''
            if char in (b'\r', b'\n'):
                cmd = command.strip().lower()

                parts = cmd.split()
                base = parts[0] if parts else b''

                if cmd == b'exit':
                    response = b'\nSee you later!\n'
                    channel.send(response)
                    channel.close()
                    break
                elif cmd == b'help':
                    response = (b'\nAvailable: help exit pwd whoami ls cat echo id uname date '
                                b'who w ps netstat ifconfig tail head less echo sudo passwd wget curl '
                                b'touch mkdir rm history uptime version\n')
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                elif cmd == b'clear':
                    response = b'\n' + b'\r\n' * 50
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                elif base == b'echo':
                    arg = b' '.join(parts[1:]) if len(parts) > 1 else b''
                    response = b'\n' + arg + b'\r\n'
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                elif cmd == b'pwd':
                    response = b'\n/home/backup\r\n'
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                elif cmd == b'whoami' or cmd == b'id':
                    if cmd == b'whoami':
                        response = b'\nbackupuser\r\n'
                    else:
                        response = b'\nuid=1001(backupuser) gid=1001(backup)\n'
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                elif cmd == b'uname -a':
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                    response = b'\nLinux backup-shell 5.15.0-xyz #1 SMP Tue Oct 7 00:00:00 UTC 2025 x86_64 GNU/Linux\r\n'
                elif cmd == b'date':
                    response = b'\nTue Oct  7 14:00:00 UTC 2025\r\n'
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                elif cmd in (b'who', b'w'):
                    response = b'\nbackupuser pts/0        2025-10-07 13:50 (:0)\r\n'
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                elif cmd.startswith(b'ps'):
                    response = b'\n  PID USER     COMMAND\n 1234 backupuser python3 emulatedShell\n 2345 root      sshd: root@pts/0\n'
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                elif base in (b'netstat', b'ifconfig'):
                    response = b'\neth0: inet 192.0.2.10  netmask 255.255.255.0  broadcast 192.0.2.255\r\n'
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                elif base in (b'tail', b'head', b'less'):
                    # show fake file excerpt
                    response = b'\n--- file snippet ---\nLine 1\nLine 2\nLine 3\r\n'
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                elif base == b'cat':
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                    # support cat <filename>
                    if len(parts) > 1 and parts[1] == b'jumpbox1.conf':
                        response = b'\nAuthorized access only. Contact admin@corp.local\r\n'
                    else:
                        response = b'\n' + \
                            (b' '.join(parts[1:]) if len(
                                parts) > 1 else b'') + b'\r\n'
                elif base == b'sudo':
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                    # simulate password prompt
                    response = b'\n[sudo] password for backupuser: \r\n'
                elif cmd == b'passwd':
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                    response = b'\nEnter new UNIX password: \r\nRetype new UNIX password: \npasswd: password updated successfully\r\n'
                elif base in (b'wget', b'curl'):
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                    response = b'\n--2025-10-07--  http://example.com/file\nSaved to: file (1234 bytes)\r\n'
                elif base in (b'touch', b'mkdir', b'rm'):
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                    # pretend success
                    response = b'\n' + (b'created' if base != b'rm' else b'removed') + \
                        b' ' + (parts[1] if len(parts) > 1 else b'') + b'\r\n'
                elif cmd == b'history':
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                    response = b'\n  1 ls\n  2 cat jumpbox1.conf\n  3 whoami\r\n'
                elif cmd == b'uptime':
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                    response = b'\n 14:00:00 up 3 days,  2:13,  1 user,  load average: 0.00, 0.01, 0.05\r\n'
                elif cmd in (b'version', b'--version', b'-v'):
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                    response = b'\nemulatedShell version 1.0.0\r\n'
                elif cmd == b'ls':
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                    response = b'\njumpbox1.conf  README.md\r\n'
                else:
                    response = b"\n" + command.strip() + b'\r\n'
                    credentials_logger.info(
                        f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                channel.send(response)
                channel.send(b'backup-shell$ ')
                command = b""
    except Exception:
        try:
            channel.close()
        except Exception:
            pass

# SSH server + Sockets


class Server(paramiko.ServerInterface):
    # initializing the server object
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted connection with ' +
                           f'username: {username}, ' + f'password: {password}')
        credentials_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    # approves the client’s request to open an interactive shell
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    # Approves the client’s request for a pseudo-terminal (PTY), so the shell looks normal
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    # Approves a one-off command execution
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True


def client_handle(client, address, username, password):
    client_ip = address[0]
    print(f"{client_ip} has connected to the server.")

    transport = None
    try:
        # pass the connected client socket into transport
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip,
                        input_username=username, input_password=password)

        transport.add_server_key(host_key)  # adding a host key

        transport.start_server(server=server)  # starting the server

        channel = transport.accept(timeout=50)  # wait for a channel for 50s

        if channel is None:
            print("No channel was opened")
            return

        standard_banner = "Welcome to backup-shell. Unauthorized access is prohibited.\\r\\n\\r\\n"

        channel.send(standard_banner.encode())
        emulatedShell(channel, client_ip=client_ip)
    except Exception as error:
        print(error)
        print("Exception in client_handle:")
    finally:
        try:
            if transport is not None:
                transport.close()
        except Exception as e:
            print("Error closing transport:", e)
        try:
            client.close()
        except Exception as e:
            print("Error closing client socket:", e)


def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100)
    print(f'SSH server is listening on port {port}')

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(
                target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()
        except Exception as error:
            print(error)


#honeypot('127.0.0.1', 2223, username=None, password=None)