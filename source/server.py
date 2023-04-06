import string
import itertools
import argparse
import queue
import time
import os
import socket
import psutil
import select
import pickle
import itertools


class Cracker:
    ALPHABET = string.ascii_letters
    ALPHA_NUM = ALPHABET + string.digits
    CHARS = ALPHA_NUM + string.punctuation

    DICT_PATH = os.path.join(os.path.dirname(__file__), "dictionaries")

    # Output Messages
    NO_USERS = [
        "\n+--------------------------------+\n",
        "| No users were cracked.         |\n",
        "+--------------------------------+\n",
    ]

    DOESNT_EXIST = [
        "\n+---------------------------------------+\n",
        "| No users to crack. Exiting...         |\n",
        "+---------------------------------------+\n",
    ]

    CRACKED_HEADING = [
        "\n+--------------------+\n",
        "| Cracked users:     |\n",
        "+--------------------+\n",
    ]

    KEYBOARD_ERR = "\n\nKeyboard interrupt detected. Exiting..."

    def __init__(self, file, users, alpha, alpha_num, port):
        # Command line arguments
        self.file = file
        self.users = users

        # Variables
        self.crack_dict = {}
        self.users_found = {}
        self.client_tries = 0

        self.define_character_set(alpha, alpha_num)

        # Get IPv4 address and start server
        self.get_ip_address()
        self.start_server(port)

    def get_ip_address(self):
        addrs = psutil.net_if_addrs()
        for addr in addrs:
            if addr != "lo":
                self.host = addrs[addr][0].address
                break

    def start_server(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, port))
        self.sock.listen(5)

        print("\n+---------------------------------------------+")
        print(f"|Server started at {self.host} on port {port}  |")
        print("+---------------------------------------------+\n")

    def define_character_set(self, alpha, alpha_num):
        if alpha:
            self.CHARACTER_SET = self.ALPHABET
        elif alpha_num:
            self.CHARACTER_SET = self.ALPHA_NUM
        else:
            self.CHARACTER_SET = self.CHARS

    def parse_shadow(self, file):
        with open(file, "r") as shadow:
            for line in shadow:
                line = line.strip()

                if not line or line.startswith(("!", "*")):
                    continue

                # Line format -> user:$identifier$salt$hash:metadata
                user, line = line.split(":")[0], line.split(":")[1]

                if user not in self.users:
                    continue

                if not line.startswith("$"):
                    self.crack_dict[user] = {
                        "identifier": "",
                        "salt": line[:2],
                        "hash": line[2:],
                    }
                    self.crack_dict[user]["entry"] = "{identifier}{salt}{hash}".format(**self.crack_dict[user])
                    continue

                identifier, line = line.split("$")[1], line.split("$")[2:]

                # Blowfish (bcrypt) has a different format
                if identifier in ("2", "2a", "2b", "2x", "2y"):
                    salt, hash = f"{line[0]}$" + line[1][:22], line[1][22:]

                    self.crack_dict[user] = {
                        "identifier": f"${identifier}$",
                        "salt": salt,
                        "hash": hash,
                    }
                    self.crack_dict[user]["entry"] = "{identifier}{salt}{hash}".format(**self.crack_dict[user])
                    continue

                # SunMD5 has a different format
                if identifier == "md5":
                    self.crack_dict[user] = {
                        "identifier": f"${identifier}$",
                        "salt": line[0],
                        "hash": line[1],
                    }
                    self.crack_dict[user]["entry"] = "{identifier}{salt}${hash}".format(**self.crack_dict[user])
                    continue

                if len(line) > 2:
                    salt, hash = f"{line[0]}${line[1]}", line[2]
                else:
                    salt, hash = line[0], line[1]

                self.crack_dict[user] = {
                    "identifier": f"${identifier}$",
                    "salt": f"{salt}$",
                    "hash": hash,
                }
                self.crack_dict[user]["entry"] = "{identifier}{salt}{hash}".format(**self.crack_dict[user])

    def display_cracked_users(self):
        if not any(self.users_found.values()):
            print("".join(self.NO_USERS))
            return

        print("".join(self.CRACKED_HEADING), end="")

        # Remove any non-found users from output
        self.users_found = {user: self.users_found[user] for user in self.users_found if self.users_found[user]}

        for user in self.users_found:
            dict = self.users_found[user].pop("dictionary", None)

            password, algo, salt, hash, tries, time = self.users_found[user].values()

            print("\n+" + "-" * (18) + "+")
            print("| User: " + f"{user:<{11}}" + "|")
            print("+" + "-" * (18) + "+\n")

            print(f"| Password: {password}")
            print(f"| Algorithm: {algo}")
            print(f"| Salt: {salt}")
            print(f"| Hash: {hash}")
            print(f"| Time: {time} seconds")
            print(f"| Tries: {tries:,}")

            if dict:
                print(f"| Dictionary: {dict}")

        print("\n+--------------------+\n")

    def generate_passwords(self):
        for length in itertools.count(1):
            for password in itertools.product(self.CHARACTER_SET, repeat=length):
                yield "".join(password)

    def encode_bytes(self, data):
        data_bytes = pickle.dumps(data)
        header = len(data_bytes).to_bytes(4, "big")

        return header + data_bytes

    def accumulate_tries(self, socket):
        data = socket.recv(1024)
        tries = pickle.loads(data)

        self.client_tries += tries
    
    def notify_all_clients(self, sockets, user):
        for socket in sockets:
            socket.sendall(self.encode_bytes("NEXT"))
            self.accumulate_tries(socket)
        
        self.users_found[user]["tries"] = self.client_tries
        self.client_tries = 0

    def handle_client_disconnect(self, distribution_queue, client_tasks, socket):
        client = socket.getpeername()

        print(f"Connection from {client[0]} has been terminated!")

        if client_tasks[client]:
            distribution_queue.put(client_tasks[client])

        socket.close()
        client_tasks.pop(client)
    
    def close(self, sockets):
        for socket in sockets:
            socket.sendall(self.encode_bytes("FIN"))
            socket.close()
        
        self.sock.close()

    def brute_force(self):
        try:
            fds = [self.sock]
            users_list = list(self.crack_dict.keys())
            client_tasks = {}

            while not all(self.users_found.values()):
                user = users_list.pop(0)
                found = False
                password_generator = self.generate_passwords()
                distribution_queue = queue.LifoQueue()
                total_time = 0
                start_time = time.time()

                while not found:
                    ready_sockets, _, _ = select.select(fds, [], [], 0.1)

                    for socket in ready_sockets:
                        # Accept a new connection
                        if socket == self.sock:
                            client, address = self.sock.accept()
                            fds.append(client)

                            print(f"Connection from {address[0]} has been established!")
                            start_time = time.time()
                            client_tasks[address] = None

                            # Send the dictionary to the client of any remaining users to be cracked
                            remaining = {user: self.crack_dict[user] for user in self.crack_dict if not self.users_found[user]}
                            bytes = self.encode_bytes(remaining)
                            client.sendall(bytes)
                            continue

                        # Receive data from a connected client
                        data = socket.recv(1024)

                        # Client has disconnected
                        if not data:
                            self.handle_client_disconnect(distribution_queue, client_tasks, socket)
                            fds.remove(socket)

                            if len(fds) == 1:
                                end_time = time.time() - start_time
                                total_time += end_time

                            continue

                        # Client needs more passwords
                        if pickle.loads(data) in ["ACK", "MORE"]:
                            if distribution_queue.empty():
                                passwords = list(itertools.islice(password_generator, 100))
                            else:
                                passwords = distribution_queue.get()

                            client_tasks[socket.getpeername()] = passwords
                            bytes = self.encode_bytes(passwords)

                            socket.sendall(bytes)
                            continue

                        # Client has found the password
                        end_time = time.time() - start_time
                        total_time += end_time

                        self.users_found[user] = pickle.loads(data)
                        self.users_found[user]["time"] = total_time

                        found = True
                        break

                # If there are still more users to crack, notify all clients to move on to the next user
                if not all(self.users_found.values()):
                    self.notify_all_clients(fds[1:], user)
            
            # Close all sockets
            self.close(fds[1:])
        except KeyboardInterrupt:
            print(self.KEYBOARD_ERR)
            self.close(fds[1:])

    def run(self):
        try:
            self.parse_shadow(self.file)
            self.users_found = {user: {} for user in self.users}

            if not self.crack_dict:
                print("".join(self.DOESNT_EXIST))
                return
            
            self.brute_force()
        except KeyboardInterrupt:
            print(self.KEYBOARD_ERR)
        except FileNotFoundError:
            print("\nFile not found. Please check the path to the shadow file.\n")
        except PermissionError:
            print("\nPermission denied. You do not have adequate permissions to read the shadow file.")
            print("Try running the program as root.\n")
        finally:
            self.display_cracked_users()


def main():
    parser = argparse.ArgumentParser(description="Password Cracker")
    parser.add_argument("-f", "--file", help="Path to shadow file", required=True)
    parser.add_argument("--alpha", help="Use only alphabetical characters.", action="store_true")
    parser.add_argument("--alpha_num", help="Use only alphanumeric characters.", action="store_true")
    parser.add_argument("-p", "--port", help="Port to run server on.", type=int, required=True)
    parser.add_argument("users", nargs="+", help="List of users to find passwords for.")
    args = parser.parse_args()

    if args.alpha and args.alpha_num:
        parser.error("You must specify only 1 character set (--alpha or --alpha_num). Use -h for more info.")

    # Run the cracker
    cracker = Cracker(args.file, args.users, args.alpha, args.alpha_num, args.port)
    cracker.run()


if __name__ == "__main__":
    main()
