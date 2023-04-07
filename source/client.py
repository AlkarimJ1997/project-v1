import socket
import argparse
import pickle
import crypt
import sys
import multiprocessing


class CrackerClient:
    IDENTIFIERS = {
        "": "DES",
        "$y$": "yescrypt",
        "$gy$": "gost-yescrypt",
        "$1$": "MD5",
        "$2$": "Blowfish (bcrypt)",
        "$2a$": "Blowfish (bcrypt)",
        "$2b$": "Blowfish (bcrypt)",
        "$2x$": "Blowfish (bcrypt)",
        "$2y$": "Blowfish (bcrypt)",
        "$3$": "NTHASH",
        "$5$": "SHA-256",
        "$6$": "SHA-512",
        "$7$": "scrypt",
        "$md5$": "SunMD5",
    }

    KEYBOARD_ERR = "\n\nKeyboard interrupt detected. Exiting..."
    CONNECTION_REFUSED_ERR = "\nConnection refused. No server found at the specified address and port."

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.tries = 0
        self.found = False

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
        except ConnectionRefusedError:
            print(self.CONNECTION_REFUSED_ERR)
            sys.exit(1)

    def identify_algo(self, identifier):
        return self.IDENTIFIERS.get(identifier, "Unknown")

    def receive_data(self):
        try:
            header = self.sock.recv(4)

            if not header:
                return None

            message_size = int.from_bytes(header, "big")
            data = self.sock.recv(message_size)

            return pickle.loads(data) if data else None
        except ConnectionResetError:
            self.sock.close()
            sys.exit(0)

    def send_data(self, data):
        try:
            self.sock.sendall(pickle.dumps(data))
        except BrokenPipeError:
            pass

    def wait(self):
        self.sock.settimeout(None)

        while True:
            msg = self.receive_data()

            if msg == "NEXT":
                self.send_data(self.tries)
                return

            if msg == "FIN":
                self.sock.close()
                return

    def worker(self, user, user_info):
        self.tries = 0

        while True:
            self.sock.settimeout(None)
            server_data = self.receive_data()

            if not server_data:
                break

            identifier, salt, hash, entry = user_info.values()
            self.sock.settimeout(0)

            for password in server_data:
                print(f"Trying {password} for {user}")
                self.tries += 1

                if crypt.crypt(password, f"{identifier}{salt}") == entry:
                    # Send the password back to the server
                    self.send_data({"password": password, "algorithm": self.identify_algo(identifier), "salt": salt, "hash": hash, "tries": self.tries})
                    self.found = True
                    return

                # Check for a NEXT or FIN message
                try:
                    msg = self.receive_data()

                    if msg == "NEXT":
                        self.send_data(self.tries)
                        return True

                    if msg == "FIN":
                        self.send_data(self.tries)
                        self.sock.close()
                        sys.exit(0)
                except BlockingIOError:
                    pass

            # Send a need more passwords message back to the server
            self.sock.sendall(pickle.dumps("MORE"))

    def run(self):
        try:
            self.user_info = self.receive_data()

            if not self.user_info:
                print("No user info received")
                return

            for user in self.user_info:
                self.found = False
                self.send_data("ACK")
                self.worker(user, self.user_info[user])

                if self.found:
                    self.wait()
        except KeyboardInterrupt:
            print(self.KEYBOARD_ERR)


def main():
    parser = argparse.ArgumentParser(description="Password Cracker Client")
    parser.add_argument("-s", "--server", help="Server to connect to", required=True)
    parser.add_argument("-p", "--port", help="Port to connect to", type=int, required=True)
    args = parser.parse_args()

    # If args.server is not a valid IP address, throw an error
    try:
        socket.inet_aton(args.server)
    except OSError:
        parser.error("Invalid IP address")
    
    # If args.port is not a valid port, throw an error
    if args.port < 0 or args.port > 65535:
        parser.error("Invalid port")

    # Run the client
    processes = []

    try:
        for _ in range(multiprocessing.cpu_count()):
            p = multiprocessing.Process(target=CrackerClient(args.server, args.port).run)
            p.start()
            processes.append(p)

        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print(CrackerClient.KEYBOARD_ERR)

        for p in processes:
            p.terminate()


if __name__ == "__main__":
    main()
