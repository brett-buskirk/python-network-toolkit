from network_toolkit.common import create_tcp_client


def main():
    target_host = "www.google.com"
    target_port = 80

    # Create a socket object and connect it to the target
    client = create_tcp_client(target_host, target_port)

    # Send some data
    client.send(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")

    # Receive some data
    response = client.recv(4096)

    print(response.decode())
    client.close()


if __name__ == '__main__':
    main()
