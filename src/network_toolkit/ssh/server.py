import os
import paramiko
import sys
import threading

from network_toolkit.common import create_tcp_listener


class Server (paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == 'brett') and (password == 'sekret'):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

def main():
    cwd = os.path.dirname(os.path.realpath(__file__))
    host_key = paramiko.RSAKey(filename=os.path.join(cwd, 'test_rsa.key'))

    server = '192.168.1.207'
    ssh_port = 2222
    try:
        sock = create_tcp_listener(server, ssh_port, backlog=100)
        print('[*] Listening for connection ...')
        client, addr = sock.accept()
    except Exception as e:
        print('[-] Listen failed: ' + str(e))
        sys.exit(1)
    else:
        print('[+] Got a connection!', client, addr)

    bhSession = paramiko.Transport(client)
    bhSession.add_server_key(host_key)
    server = Server()
    bhSession.start_server(server=server)

    chan = bhSession.accept(20)
    if chan is None:
        print('*** No channel.')
        sys.exit(1)

    print('[+] Authenticated!')
    print(chan.recv(1024))
    chan.send('Welcome to bh_ssh')
    try:
        while True:
            command = input('Enter command: ')
            if command != 'exit':
                chan.send(command)
                r = chan.recv(8192)
                print(r.decode())
            else:
                chan.send('exit')
                print('exiting')
                bhSession.close()
                break
    except KeyboardInterrupt:
        bhSession.close()


if __name__ == '__main__':
    main()
