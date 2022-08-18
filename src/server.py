# https://github.com/msoulier/tftpy/blob/master/tftpy/TftpServer.py

import tftp
import socket

HOST = "10.10.10.100"
PORT = 4000

def listen(
    listenip=HOST,
    listenport=PORT,
):
    """Start a server listening on the supplied interface and port. This
    defaults to INADDR_ANY (all interfaces) and UDP port 69. You can also
    supply a different socket timeout value, if desired."""

    # listenip = listenip if listenip else '0.0.0.0'
    if not listenip:
        listenip = "0.0.0.0"
    print(f"Server requested on ip {listenip}, port {listenport}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(60)
        sock.bind((listenip, listenport))
        _, listenport = sock.getsockname()
        return sock
    except OSError as err:
        # Reraise it for now.
        raise err
    except sock.timeout:
        print("Connection timed out")
        exit(0)
    except KeyboardInterrupt:
        if sock:
            sock.close()
        print("Failed accept")
        exit(2)

if __name__ == '__main__':
    while True:
        sock = listen()
        # We're already listening so whattodo will receive from some client addresss
        serv_ret_val = tftp.whattodo(sock)
        if serv_ret_val == -2:
            sock.close()
