import getpass
import socket
import time
import threading

PORT = 50599
HOST = '127.0.0.1'
BUFFER_SIZE = 8192

class Client:
    def __init__(self):
        self.sock = None
        self.token = None
    
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")
        return True
    
    def send(self, payload):
        msg = f"LEN:{len(payload)}\n{payload}"
        self.sock.send(msg.encode())
        
        data = b""
        while True:
            chunk = self.sock.recv(BUFFER_SIZE)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                nl = data.find(b"\n")
                if nl > 4:
                    try:
                        length = int(data[4:nl])
                        if len(data) >= nl + 1 + length:
                            return data[nl+1:nl+1+length].decode()
                    except:
                        pass
        return data.decode()
    
    def profile(self):
        if not self.token:
            print("Login first")
            return

        resp = self.send(
            f"PROFILE {self.token}"
        )

        print(resp)
    
    def register(self, user, pwd):
        resp = self.send(f"REGISTER {user} {pwd}")
        print(f"[REGISTER] {resp}")
        return resp.startswith("OK")
    
    def login(self, username, password):
        response = self.send(
        f"LOGIN {username} {password}"
        )
        print(f"[LOGIN] {response}")
        if response.startswith("OK") and "Token:" in response:
            self.token = response.split("Token:")[1].strip()
            return True
        return False

    def logout(self):
        if self.token:
            resp = self.send(f"LOGOUT {self.token}")
            print(f"[LOGOUT] {resp}")
            self.token = None
            return True
        return False
    
    def protected(self):
        if self.token:
            resp = self.send(f"PROTECTED {self.token}")
            print(f"[PROTECTED] {resp}")
            return True
        print("[PROTECTED] Not logged in")
        return False
    
    def status(self):
        resp = self.send("STATUS")
        print(f"[STATUS] {resp}")
        return resp
    
    def close(self):
        if self.sock:
            self.sock.close()
            print("[+] Connection closed")

def test_concurrent(n=10):
    print(f"\n--- Testing {n} concurrent clients ---")

    threads = []
    results = []

    def run(cid):
        c = None

        try:
            c = Client()
            c.connect()

            username = f"user{cid}"
            password = f"User@{cid}123"

            # Register
            c.register(username, password)

            # Login
            c.login(username, password)

            # Check if login succeeded
            if c.token:
                c.protected()
                c.logout()
                results.append((cid, "SUCCESS"))
            else:
                results.append((cid, "FAILED"))

        except Exception as e:
            results.append((cid, f"FAILED: {e}"))

        finally:
            if c:
                c.close()

    # Start threads
    for i in range(n):
        t = threading.Thread(target=run, args=(i,))
        t.start()
        threads.append(t)

    # Wait for all threads
    for t in threads:
        t.join()

    # Count successes
    success = len(
        [r for r in results if r[1] == "SUCCESS"]
    )

    print("\n===== CONCURRENT TEST RESULTS =====")

    for cid, result in sorted(results):
        print(f"Client {cid}: {result}")

    print(f"\nResult: {success}/{n} clients succeeded")

def main():
    c = Client()

    try:
        c.connect()

        while True:
            print("\n========== MENU ==========")
            print("1. Register")
            print("2. Login")
            print("3. Protected Command")
            print("4. Logout")
            print("5. Profile")
            print("6. Status")
            print("7. Run 10 Concurrent Clients")
            print("8. Exit")
            print("==========================")

            choice = input("Select option: ")

            if choice == "1":
                user = input("Username: ")
                pwd = getpass.getpass("Password: ")
                c.register(user, pwd)

            elif choice == "2":
                user = input("Username: ")
                pwd = getpass.getpass("Password: ")
                c.login(user, pwd)

            elif choice == "3":
                c.protected()

            elif choice == "4":
                c.logout()

            elif choice == "5":
                c.profile()

            elif choice == "6":
                c.status()

            elif choice == "7":
                test_concurrent(10)

            elif choice == "8":
                break

            else:
                print("Invalid option")

    finally:
        c.close()


if __name__ == "__main__":
    main()
