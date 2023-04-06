import string
import itertools
import argparse
import multiprocessing
import time
import crypt
import os


class Cracker:
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

    EXHAUSTED = [
        "\n+---------------------------------------------------------------------+\n",
        "| All dictionaries have been exhausted. Moving on to brute force...   |\n",
        "+---------------------------------------------------------------------+\n",
    ]

    KEYBOARD_ERR = "\n\nKeyboard interrupt detected. Exiting..."

    def __init__(self, file, users, dict_attack, brute_force, alpha, alpha_num, threads):
        # Command line arguments
        self.file = file
        self.users = users

        # Flags
        self.dict_flag = dict_attack
        self.bf_flag = brute_force

        # Threads
        self.threads = threads

        # Variables
        self.crack_dict = {}
        self.users_found = {}
        self.users_cracked = 0

        self.define_character_set(alpha, alpha_num)

    def identify_algo(self, identifier):
        return self.IDENTIFIERS.get(identifier, "Unknown")

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

    def sort_by_size(self, files):
        return sorted(files, key=lambda x: os.path.getsize(os.path.join(self.DICT_PATH, x)))

    def generate_passwords(self):
        for length in itertools.count(1):
            for password in itertools.product(self.CHARACTER_SET, repeat=length):
                yield "".join(password)

    def generate_wordlist(self, files):
        for file in files:
            with open(os.path.join(self.DICT_PATH, file), "r") as wordlist:
                for line in wordlist:
                    yield line.strip(), file

    def worker(self, queue, user, tries, found, results_queue):
        while True:
            password = queue.get()
            file = None

            if isinstance(password, tuple):
                password, file = password

            if password is None or found.value:
                break

            identifier, salt, hash, entry = self.crack_dict[user].values()

            print(f"Process {os.getpid()} trying {password} for {user}...")
            tries.value += 1

            if crypt.crypt(password, f"{identifier}{salt}") == entry:
                user_data = {
                    "password": password,
                    "algorithm": self.identify_algo(identifier),
                    "salt": salt,
                    "hash": hash,
                    "tries": tries.value,
                }

                if file:
                    user_data["dictionary"] = file

                results_queue.put(user_data)
                found.value = True

                break

    def dictionary_attack(self):
        self.dictionaries = self.sort_by_size(os.listdir(self.DICT_PATH))
        # self.dictionaries = list(filter(lambda x: x == "500-worst-passwords.txt", os.listdir(self.DICT_PATH)))

        processes = []
        found = multiprocessing.Value("b", False)
        results_queue = multiprocessing.Queue()

        try:
            for user in self.crack_dict:
                tries = multiprocessing.Value("i", 0)
                password_queue = multiprocessing.Queue()
                start_time = time.time()

                for _ in range(self.threads):
                    p = multiprocessing.Process(target=self.worker, args=(password_queue, user, tries, found, results_queue))
                    p.start()
                    processes.append(p)

                for password in self.generate_wordlist(self.dictionaries):
                    password_queue.put(password)

                    if found.value:
                        break

                for _ in processes:
                    password_queue.put(None)

                for p in processes:
                    p.join()

                end_time = time.time()

                while not results_queue.empty():
                    self.users_found[user] = results_queue.get()
                    self.users_found[user]["time"] = round(end_time - start_time, 1)

                found.value = False
                processes.clear()

            for p in processes:
                p.terminate()
        except KeyboardInterrupt:
            print(self.KEYBOARD_ERR)

            for p in processes:
                p.terminate()

            self.display_cracked_users()
            os._exit(0)

    def brute_force(self):
        processes = []
        found = multiprocessing.Value("b", False)
        results_queue = multiprocessing.Queue()

        try:
            for user in self.crack_dict:
                tries = multiprocessing.Value("i", 0)
                password_queue = multiprocessing.Queue()
                start_time = time.time()

                for _ in range(self.threads):
                    p = multiprocessing.Process(target=self.worker, args=(password_queue, user, tries, found, results_queue))
                    p.start()
                    processes.append(p)

                for password in self.generate_passwords():
                    password_queue.put(password)

                    if found.value:
                        break

                for _ in processes:
                    password_queue.put(None)

                for p in processes:
                    p.join()

                end_time = time.time()

                while not results_queue.empty():
                    self.users_found[user] = results_queue.get()

                self.users_found[user]["time"] = round(end_time - start_time, 1)

                found.value = False
                processes.clear()
        except KeyboardInterrupt:
            print(self.KEYBOARD_ERR)

            for p in processes:
                p.terminate()

    def run(self):
        try:
            self.parse_shadow(self.file)
            self.users_found = {user: {} for user in self.users}

            if not self.crack_dict:
                print("".join(self.DOESNT_EXIST))
                return

            if self.dict_flag:
                self.dictionary_attack()

                if self.bf_flag:
                    # Check if there are users in users_found that do not have values (i.e. not found)
                    if any(not self.users_found[user] for user in self.users_found):
                        try:
                            print("".join(self.EXHAUSTED))
                            time.sleep(2)

                            # Find which users are not found and remove the rest from the crack_dict
                            users_not_found = [user for user in self.users_found if not self.users_found[user]]
                            self.crack_dict = {user: self.crack_dict[user] for user in self.crack_dict if user in users_not_found}
                        except KeyboardInterrupt:
                            print(self.KEYBOARD_ERR)
                            self.display_cracked_users()
                            os._exit(0)

                        # Run brute force on the remaining users
                        self.brute_force()
            else:
                self.brute_force()

            # Display cracked users and terminate the program
            self.display_cracked_users()
            os._exit(0)
        except FileNotFoundError:
            print("\nFile not found. Please check the path to the shadow file.\n")
        except PermissionError:
            print("\nPermission denied. You do not have adequate permissions to read the shadow file.")
            print("Try running the program as root.\n")


def main():
    parser = argparse.ArgumentParser(description="Password Cracker")
    parser.add_argument("-f", "--file", help="Path to shadow file", required=True)
    parser.add_argument("-d", "--dict_attack", help="Use dictionary attack", action="store_true")
    parser.add_argument("-bf", "--brute_force", help="Use brute force attack", action="store_true")
    parser.add_argument("--alpha", help="Use only alphabetical characters.", action="store_true")
    parser.add_argument("--alpha_num", help="Use only alphanumeric characters.", action="store_true")
    parser.add_argument("-t", "--threads", help="Number of threads to use.", type=int, default=multiprocessing.cpu_count())
    parser.add_argument("users", nargs="+", help="List of users to find passwords for.")
    args = parser.parse_args()

    if args.alpha and args.alpha_num:
        parser.error("You must specify only 1 character set (--alpha or --alpha_num). Use -h for more info.")

    if args.threads < 1:
        parser.error("You must specify at least 1 thread.")

    # Run the cracker
    cracker = Cracker(args.file, args.users, args.dict_attack, args.brute_force, args.alpha, args.alpha_num, args.threads)
    cracker.run()


if __name__ == "__main__":
    main()
