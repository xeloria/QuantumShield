import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk, simpledialog
import os
import threading
import hashlib
import webbrowser  # Added for clickable links
from kyber import Kyber512

class QuantumShield:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("QuantumShield - Quantum-Resistant Encryption")
        self.root.geometry("570x300")
        self.root.resizable(False, False)

        # Stop event and thread management
        self.stop_event = threading.Event()
        self.active_thread = None

        # Styling
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#F2F2F2")
        style.configure("TLabel", font=("Segoe UI", 10), background="#F2F2F2")
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=5)
        style.configure("TEntry", padding=5)
        style.map("TButton", background=[("active", "#D1D1D1")])

        # Main Frame
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill="both", expand=True)

        # File Selection Section
        file_frame = ttk.LabelFrame(self.main_frame, text="File Selection")
        file_frame.pack(fill="x", pady=10)

        # Input File
        ttk.Label(file_frame, text="Input File:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.input_entry = ttk.Entry(file_frame, width=50)
        self.input_entry.grid(row=0, column=1, padx=5, pady=5)
        self.input_button = ttk.Button(file_frame, text="Browse", command=self.browse_input_file)
        self.input_button.grid(row=0, column=2, padx=5, pady=5)

        # Output Location
        ttk.Label(file_frame, text="Output Location:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.output_entry = ttk.Entry(file_frame, width=50)
        self.output_entry.grid(row=1, column=1, padx=5, pady=5)
        self.output_button = ttk.Button(file_frame, text="Browse", command=self.browse_output_directory)
        self.output_button.grid(row=1, column=2, padx=5, pady=5)

        # Actions Section
        action_frame = ttk.LabelFrame(self.main_frame, text="Actions")
        action_frame.pack(fill="x", pady=10)

        self.key_gen_button = ttk.Button(action_frame, text="Generate Key", command=self.generate_key)
        self.key_gen_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.encrypt_button = ttk.Button(action_frame, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.decrypt_button = ttk.Button(action_frame, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        self.stop_button = ttk.Button(action_frame, text="Stop", command=self.stop_process)
        self.stop_button.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        self.about_button = ttk.Button(action_frame, text="About", command=self.show_about)
        self.about_button.grid(row=0, column=4, padx=5, pady=5, sticky="ew")
        
        # Adjust column weights for consistent button spacing
        for i in range(5):
            action_frame.columnconfigure(i, weight=1)

        # Status Bar
        self.status_bar = ttk.Label(self.main_frame, text="", anchor="center", font=("Segoe UI", 10, "italic"), foreground="blue")
        self.status_bar.pack(fill="x", pady=(5, 0))

    def browse_input_file(self):
        file_path = filedialog.askopenfilename()
        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, file_path)

    def browse_output_directory(self):
        directory_path = filedialog.askdirectory()
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, directory_path)

    def stop_process(self):
        """Stops the current encryption/decryption process and terminates the thread."""
        if self.active_thread and self.active_thread.is_alive():
            self.stop_event.set()
            self.active_thread.join(timeout=2)
            self.active_thread = None  # Clean up the thread reference
        self.status_bar.config(text="Process stopped.")

    def generate_key(self):
        try:
            # Generate a key pair
            public_key, private_key = Kyber512.keygen()
            with open("public_key.key", "wb") as pub_file:
                pub_file.write(public_key)
            with open("private_key.key", "wb") as priv_file:
                priv_file.write(private_key)

            self.status_bar.config(text="Key generated successfully.")
        except Exception as e:
            self.status_bar.config(text=f"Error: {str(e)}")
            
    def show_about(self):
        """Displays information about the tool with a clickable GitHub link."""
        about_window = tk.Toplevel(self.root)
        about_window.title("About QuantumShield")
        about_window.geometry("430x330")
        about_window.resizable(False, False)

        tk.Label(
            about_window, 
            text="QuantumShield - Quantum-Resistant Encryption Tool",
            font=("Segoe UI", 12, "bold")
        ).pack(pady=(10, 5))

        tk.Label(
            about_window,
            text="Version: 1.0.0\nAuthor: Xeloria",
            font=("Segoe UI", 10)
        ).pack(pady=(5, 0))

        # Create a clickable link
        github_label = tk.Label(
            about_window, 
            text="GitHub: https://github.com/xeloria", 
            font=("Segoe UI", 10, "italic"), 
            fg="blue", 
            cursor="hand2"
        )
        github_label.pack(pady=(5, 10))
        
        # Bind the label to open the link in a browser
        github_label.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/xeloria"))

        tk.Label(
            about_window,
            text=(
                "Purpose: Encrypt and decrypt files using quantum-resistant cryptography.\n\n"
                "Usage:\n"
                "- Generate Keys: Create public and private keys.\n"
                "- Encrypt: Secure your file with the public key.\n"
                "- Decrypt: Use the private key to retrieve your file.\n\n"
                "Disclaimer: Ensure keys and passwords are stored securely. Improper use may lead to data loss."
            ),
            font=("Segoe UI", 10),
            wraplength=350,  # Ensures text wraps neatly in the window
            justify="left"
        ).pack(pady=(5, 10))

    def initialize_progress(self, total_chunks):
        """Reusable method to create and return a progress bar."""
        progress = ttk.Progressbar(self.main_frame, orient="horizontal", length=400, mode="determinate")
        progress.pack(pady=10)
        progress["maximum"] = total_chunks
        return progress

    def prompt_password(self, callback):
        """Prompt for a password and ensure it runs on the main thread."""
        def ask():
            password = simpledialog.askstring("Password", "Enter a password for encryption/decryption:", show="*")
            if password:
                callback(hashlib.sha256(password.encode()).digest())
            else:
                callback(None)
        self.root.after(0, ask)

    def start_thread(self, target_function, *args):
        """Start a new thread for encryption or decryption."""
        self.active_thread = threading.Thread(target=target_function, args=args, daemon=True)
        self.active_thread.start()

    def encrypt_file(self):
        def perform_encryption(password_hash):
            if not password_hash:
                self.status_bar.config(text="Encryption canceled: No password provided.")
                return
            try:
                self.status_bar.config(text="Encrypting... Please wait.")
                self.stop_event.clear()
                input_file_path = self.input_entry.get()
                output_directory_path = self.output_entry.get()

                if not os.path.exists(input_file_path):
                    self.status_bar.config(text="Invalid input file.")
                    return
                
                # If output location is empty, use the input file directory
                if not output_directory_path.strip():
                    output_directory_path = os.path.dirname(input_file_path)

                original_file_name = os.path.basename(input_file_path)
                output_file_name = os.path.join(output_directory_path, f"{original_file_name}.qenc")

                with open("public_key.key", "rb") as pub_file:
                    public_key = pub_file.read()
                ciphertext, shared_secret = Kyber512.enc(public_key)
                combined_secret = bytes(a ^ b for a, b in zip(shared_secret, password_hash))

                with open("key_ciphertext.bin", "wb") as ct_file:
                    ct_file.write(ciphertext)

                metadata = original_file_name.encode("utf-8")
                encrypted_metadata = bytearray(
                    [metadata[i] ^ combined_secret[i % len(combined_secret)] for i in range(len(metadata))]
                )
                metadata_length = len(encrypted_metadata).to_bytes(4, byteorder="big")

                with open(input_file_path, "rb") as input_file:
                    file_data = input_file.read()

                chunk_size = 1024 * 64
                total_chunks = len(file_data) // chunk_size + 1
                progress = self.initialize_progress(total_chunks)

                encrypted_data = bytearray()
                for i in range(total_chunks):
                    if self.stop_event.is_set():
                        self.status_bar.config(text="Encryption stopped.")
                        progress.destroy()
                        return

                    start = i * chunk_size
                    end = start + chunk_size
                    chunk = file_data[start:end]
                    encrypted_chunk = bytearray(
                        [chunk[j] ^ combined_secret[(start + j) % len(combined_secret)] for j in range(len(chunk))]
                    )
                    encrypted_data.extend(encrypted_chunk)
                    progress.step(1)
                    self.root.update_idletasks()

                with open(output_file_name, "wb") as output_file:
                    output_file.write(metadata_length + encrypted_metadata + encrypted_data)

                progress.destroy()
                self.status_bar.config(text=f"File encrypted successfully as {output_file_name}.")
            except Exception as e:
                self.status_bar.config(text=f"Error: {str(e)}")

        self.prompt_password(lambda password_hash: self.start_thread(perform_encryption, password_hash))

    def decrypt_file(self):
        def perform_decryption(password_hash):
            if not password_hash:
                self.status_bar.config(text="Decryption canceled: No password provided.")
                return
            try:
                self.status_bar.config(text="Decrypting... Please wait.")
                self.stop_event.clear()
                input_file_path = self.input_entry.get()
                output_directory_path = self.output_entry.get()

                if not os.path.exists(input_file_path):
                    self.status_bar.config(text="Invalid input file.")
                    return
                
                # If output location is empty, use the input file directory
                if not output_directory_path.strip():
                    output_directory_path = os.path.dirname(input_file_path)

                with open("private_key.key", "rb") as priv_file:
                    private_key = priv_file.read()
                with open("key_ciphertext.bin", "rb") as ct_file:
                    ciphertext = ct_file.read()
                shared_secret = Kyber512.dec(ciphertext, private_key)
                combined_secret = bytes(a ^ b for a, b in zip(shared_secret, password_hash))

                with open(input_file_path, "rb") as input_file:
                    metadata_length = int.from_bytes(input_file.read(4), byteorder="big")
                    encrypted_metadata = input_file.read(metadata_length)
                    decrypted_metadata = bytearray(
                        [encrypted_metadata[i] ^ combined_secret[i % len(combined_secret)] for i in range(len(encrypted_metadata))]
                    )
                    try:
                        original_file_name = decrypted_metadata.decode("utf-8")
                    except UnicodeDecodeError:
                        self.status_bar.config(text="Error: Failed to decode file name. Invalid password or corrupted file.")
                        return

                    encrypted_data = input_file.read()

                chunk_size = 1024 * 64
                total_chunks = len(encrypted_data) // chunk_size + 1
                progress = self.initialize_progress(total_chunks)

                decrypted_data = bytearray()
                for i in range(total_chunks):
                    if self.stop_event.is_set():
                        self.status_bar.config(text="Decryption stopped.")
                        progress.destroy()
                        return

                    start = i * chunk_size
                    end = start + chunk_size
                    chunk = encrypted_data[start:end]
                    decrypted_chunk = bytearray(
                        [chunk[j] ^ combined_secret[(start + j) % len(combined_secret)] for j in range(len(chunk))]
                    )
                    decrypted_data.extend(decrypted_chunk)
                    progress.step(1)
                    self.root.update_idletasks()

                output_file_path = os.path.join(output_directory_path, original_file_name)
                with open(output_file_path, "wb") as output_file:
                    output_file.write(decrypted_data)

                progress.destroy()
                self.status_bar.config(text=f"File decrypted successfully as {output_file_path}.")
            except Exception as e:
                self.status_bar.config(text=f"Error: {str(e)}")

        self.prompt_password(lambda password_hash: self.start_thread(perform_decryption, password_hash))

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = QuantumShield()
    app.run()
