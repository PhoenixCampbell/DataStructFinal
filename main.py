import hashlib
import itertools
import string
import time
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from tkinter import simpledialog

HASH_ALGORITHMS = {
    "MD5": hashlib.md5,
    "SHA-1": hashlib.sha1,
    "SHA-256": hashlib.sha256,
    "SHA-512": hashlib.sha512,
    "SHA-224": hashlib.sha224,
    "SHA-384": hashlib.sha384,
}


class PassCrackApp:
    def __init__(self, master):
        self.master = master
        master.title("Password Cracker")
        master.geometry("400x200")
        master.resizable(True, True)
        master.configure(bg="#222222")

        self.hash_algorithm = tk.StringVar()
        self.hash_algorithm.set("MD5")
        self.dictionary_file = "rockyou.txt"
        self.max_length = 30

        self.label_hash_algorithm = tk.Label(
            self.master, text="Select Hash Algorithm:", bg="#222222", fg="white"
        )
        self.label_hash_algorithm.grid(row=0, column=0, padx=10, pady=5)

        self.option_menu_hash_algorithm = tk.OptionMenu(
            self.master, self.hash_algorithm, *HASH_ALGORITHMS.keys()
        )
        self.option_menu_hash_algorithm.config(
            indicatoron=True,
            compound="right",
            bg="#222222",
            fg="white",
            activebackground="#222222",
            activeforeground="white",
        )
        self.option_menu_hash_algorithm.grid(row=0, column=1, padx=10, pady=5)

        self.label_dictionary_file = tk.Label(
            self.master, text="Dictionary File:", bg="#222222", fg="white"
        )
        self.label_dictionary_file.grid(row=1, column=0, padx=10, pady=5)

        self.button_browse = tk.Button(
            self.master,
            text="Browse",
            command=self.browse_dictionary_file,
            bg="#222222",
            fg="white",
            activebackground="#222222",
            activeforeground="white",
        )
        self.button_browse.grid(row=1, column=1, padx=10, pady=5)

        self.label_max_length = tk.Label(
            self.master, text="Max Length for Brute Force:", bg="#222222", fg="white"
        )
        self.label_max_length.grid(row=2, column=0, padx=10, pady=5)

        self.entry_max_length = tk.Entry(self.master, bg="#222222", fg="white")
        self.entry_max_length.grid(row=2, column=1, padx=10, pady=5)
        self.entry_max_length.insert(0, "30")

        self.button_crack_password = tk.Button(
            self.master,
            text="Crack Password",
            command=self.crack_password,
            bg="#222222",
            fg="white",
            activebackground="#222222",
            activeforeground="white",
        )
        self.button_crack_password.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        self.create_widgets()

    def create_widgets(self):
        self.label_hash_algorithm = tk.Label(self.master, text="Select Hash Algorithm:")
        self.label_hash_algorithm.grid(row=0, column=0, padx=10, pady=5)

        self.option_menu_hash_algorithm = tk.OptionMenu(
            self.master, self.hash_algorithm, *HASH_ALGORITHMS.keys()
        )
        self.option_menu_hash_algorithm.grid(row=0, column=1, padx=10, pady=5)

        self.label_dictionary_file = tk.Label(self.master, text="Dictionary File:")
        self.label_dictionary_file.grid(row=1, column=0, padx=10, pady=5)

        self.button_browse = tk.Button(
            self.master, text="Browse", command=self.browse_dictionary_file
        )
        self.button_browse.grid(row=1, column=1, padx=10, pady=5)

        self.label_max_length = tk.Label(
            self.master, text="Max Length for Brute Force:"
        )
        self.label_max_length.grid(row=2, column=0, padx=10, pady=5)

        self.entry_max_length = tk.Entry(self.master)
        self.entry_max_length.grid(row=2, column=1, padx=10, pady=5)
        self.entry_max_length.insert(0, "30")

        self.button_crack_password = tk.Button(
            self.master, text="Crack Password", command=self.crack_password
        )
        self.button_crack_password.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    def browse_dictionary_file(self):
        filename = filedialog.askopenfilename(title="Select Dictionary File")
        if filename:
            self.dictionary_file = filename

    def crack_password(self):
        hash_algorithm = HASH_ALGORITHMS[self.hash_algorithm.get()]
        max_length = int(self.entry_max_length.get())

        while True:
            password_hash = simpledialog.askstring(
                "Enter Password Hash", "Enter the password hash:"
            )
            if not password_hash:
                return

            cracked_password = self.dictionary_attack(password_hash, hash_algorithm)
            if cracked_password:
                messagebox.showinfo(
                    "Password Cracked",
                    f"Password cracked using dictionary attack: {cracked_password}",
                )
                continue  # *Skip brute force attack if dictionary attack was successful

            cracked_password, attempts = self.brute_force_attack(
                password_hash, max_length, hash_algorithm
            )
            if cracked_password:
                messagebox.showinfo(
                    "Password Cracked",
                    f"Password cracked using brute force attack: {cracked_password}",
                )
            else:
                messagebox.showinfo(
                    "Brute Force Attack Failed", "Brute force attack failed."
                )

    def dictionary_attack(self, hash_value, dictionary_file):
        with open(self.dictionary_file, "r", encoding="utf-8", errors="ignore") as file:
            for word in file:
                word = word.strip()
                hashed_word = hashlib.md5(word.encode()).hexdigest()
                if hashed_word == hash_value:
                    return word
        return None

    def brute_force_attack(self, hash_value, max_length, hash_algorithm):
        characters = string.ascii_uppercase + string.ascii_lowercase + string.digits
        attempts = 0

        for length in range(1, max_length + 1):
            for combination in itertools.product(characters, repeat=length):
                password = "".join(combination)
                hashed_password = hashlib.md5(password.encode()).hexdigest()
                attempts += 1
                if hashed_password == hash_value:
                    return password, attempts
                if attempts % 10000 == 0:
                    print("Attempts made:", attempts)
                    time.sleep(10)
        return None, attempts


def main():
    root = tk.Tk()
    app = PassCrackApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
