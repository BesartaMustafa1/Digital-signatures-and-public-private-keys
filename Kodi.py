import numpy as np 
from sympy import Matrix 
import random
import tkinter as tk
from tkinter import messagebox

# Matrica të paracaktuara për gradë të ndryshme
matrix_rank = {
    2: [np.array([[12, 1], [1, 11]]), np.array([[13, 1], [16, 17]])],
    3: [np.array([[7, 16, 16], [17, 13, 7], [11, 10, 1]]), np.array([[3, 10, 20], [22, 21, 13], [7, 9, 14]])],
    4: [np.array([[7, 3, 19, 21], [1, 11, 15, 16], [25, 25, 22, 15], [7, 18, 12, 23]]),
        np.array([[18, 15, 22, 23], [17, 1, 24, 22], [24, 21, 25, 11], [9, 10, 17, 10]])]
}

def char_to_num(char):
    """Konverton një karakter në vlerë numerike bazuar në mapimet e paracaktuara."""
    if char == ' ':
        return 62  # Cakto një numër unik për hapësirën
    elif 'A' <= char <= 'Z':
        return ord(char) - ord('A')  # Konverton shkronjat e mëdha në numra 0-25
    elif 'a' <= char <= 'z':
        return ord(char) - ord('a') + 26  # Konverton shkronjat e vogla në numra 26-51
    elif '0' <= char <= '9':
        return ord(char) - ord('0') + 52  # Konverton numrat në karaktere 52-61
    else:
        return 63  # Konverton karakteret e panjohura në 63 ('X')

def num_to_char(num):
    """Konverton një numër në karakter bazuar në mapimet e paracaktuara."""
    if num == 62:
        return ' '  # Kthen hapësirën
    elif 0 <= num <= 25:
        return chr(num + ord('A'))  # Kthen shkronjat e mëdha nga 0-25
    elif 26 <= num <= 51:
        return chr(num - 26 + ord('a'))  # Kthen shkronjat e vogla nga 26-51
    elif 52 <= num <= 61:
        return chr(num - 52 + ord('0'))  # Kthen numrat nga 52-61
    else:
        return 'X'  # Kthen karakterin 'X' për vlera të tjera

def pad_message(message, block_size):
    """Mbush mesazhin për të siguruar që gjatësia e tij të jetë shumëfish i madhësisë së bllokut."""
    padding_length = (block_size - len(message) % block_size) % block_size
    return message + ' ' * padding_length  # Shton hapësira në fund të mesazhit

def mod_inv(matrix, modulus):
    """Llogarit inverzin modular të matricës me një modulus të caktuar."""
    det = int(np.round(np.linalg.det(matrix)))  # Llogarit determinantën e matricës dhe e rrumbullakos
    det_inv = pow(det, -1, modulus)  # Llogarit inverzin modular të determinantës
    matrix_mod_inv = det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % modulus  # Llogarit inverzin modular të matricës
    return matrix_mod_inv

def message_to_vector(message, block_size):
    """Konverton mesazhin e mbushur në një vektor të vlerave numerike."""
    padded_message = pad_message(message, block_size)  # Mbush mesazhin për të qenë shumëfish i madhësisë së bllokut
    return np.array([char_to_num(c) for c in padded_message if c is not None])  # Konverton çdo karakter në vlerë numerike

def encrypt(message, matrix):
    """Enkripton mesazhin duke përdorur matricën e dhënë."""
    if matrix.shape[0] != matrix.shape[1]:
        raise ValueError("Matrica e enkriptimit duhet të jetë katrore.")  # Kontrollo nëse matrica është katrore
    block_size = len(matrix)  # Merr madhësinë e bllokut nga gjatësia e një dimensioni të matricës
    message_vector = message_to_vector(message, block_size)  # Konverto mesazhin në vektor numerik
    encrypted_message = ""

    # Për çdo bllok të vektorit të mesazhit:
    for i in range(0, len(message_vector), block_size):
        block_vector = message_vector[i:i + block_size]  # Merr një bllok të vektorit të mesazhit
        encrypted_vector = np.dot(matrix, block_vector) % 64  # Enkripto bllokun duke e shumëzuar me matricën dhe duke marrë mbetjen me mod 64
        encrypted_message += ''.join(num_to_char(int(i)) for i in encrypted_vector)  # Konverto numrat e enkriptuar në karaktere dhe shto në mesazhin e enkriptuar

    return encrypted_message  # Kthe mesazhin e enkriptuar

def decrypt(encrypted_message, matrix):
    if matrix.shape[0] != matrix.shape[1]:  # Kontrollo nëse matrica është katrore.
        raise ValueError("The decryption matrix must be square.")
    block_size = len(matrix)  # Merr madhësinë e bllokut nga gjatësia e një dimensioni të matricës.
    message_vector = message_to_vector(encrypted_message, block_size)  # Konverto mesazhin e enkriptuar në një vektor mesazhesh duke përdorur madhësinë e bllokut.
    decrypted_message = ""  # Inicializo një string për mesazhin e dekriptuar.
    matrix_inv = mod_inv(matrix, 64)  # Llogarit inverzin modular të matricës me mod 64.

    for i in range(0, len(message_vector), block_size):  # Për çdo bllok të vektorit të mesazhit:
        block_vector = message_vector[i:i + block_size]  # Merr një bllok të vektorit të mesazhit.
        decrypted_vector = np.dot(matrix_inv, block_vector) % 64  # Dekripto bllokun duke e shumëzuar me inverzin e matricës dhe duke marrë mbetjen me mod 64.
        decrypted_message += ''.join(num_to_char(int(i)) for i in decrypted_vector)  # Konverto numrat e dekriptuar në karaktere dhe shto në mesazhin e dekriptuar

    return decrypted_message

class MatrixCipherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Matrix Cipher")
        self.encryption_matrix = None  

        self.message_label = tk.Label(root, text="Enter your message:")
        self.message_label.pack()

        self.message_entry = tk.Text(root, height=10, width=50)
        self.message_entry.pack()

        self.rank_label = tk.Label(root, text="Choose the matrix rank (2, 3, or 4):")
        self.rank_label.pack()

        self.rank_entry = tk.Entry(root)
        self.rank_entry.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.pack()

        self.matrix_label = tk.Label(root, text="Used Matrix:")
        self.matrix_label.pack()

        self.matrix_text = tk.Text(root, height=4, width=50)
        self.matrix_text.pack()

        self.encrypted_message_label = tk.Label(root, text="Encrypted Message:")
        self.encrypted_message_label.pack()

        self.encrypted_message_text = tk.Text(root, height=10, width=50)
        self.encrypted_message_text.pack()
        self.encrypted_message_text.config(state=tk.DISABLED)

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.pack()

        self.decrypted_message_label = tk.Label(root, text="Decrypted Message:")
        self.decrypted_message_label.pack()

        self.decrypted_message_text = tk.Text(root, height=10, width=50)
        self.decrypted_message_text.pack()
        self.decrypted_message_text.config(state=tk.DISABLED)

        self.restart_button = tk.Button(root, text="Restart", command=self.restart_program)
        self.restart_button.pack()

    def display_matrix(self, matrix):
        matrix_str = '\n'.join([' '.join(map(str, row)) for row in matrix])
        self.matrix_text.delete(1.0, tk.END)
        self.matrix_text.insert(tk.END, f"{matrix_str}\nDimensions: {matrix.shape}")

    def encrypt_message(self):
        try:
            rank = int(self.rank_entry.get())
            if rank not in matrix_rank:
                raise ValueError("Invalid rank")
            self.encryption_matrix = random.choice(matrix_rank[rank])
            self.display_matrix(self.encryption_matrix)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return
        
        message = self.message_entry.get("1.0", tk.END).strip()
        try:
            encrypted_message = encrypt(message, self.encryption_matrix)
            self.encrypted_message_text.config(state=tk.NORMAL)
            self.encrypted_message_text.delete(1.0, tk.END)
            self.encrypted_message_text.insert(tk.END, encrypted_message)
            self.encrypted_message_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_message(self):
        encrypted_message = self.encrypted_message_text.get(1.0, tk.END).strip()
        try:
            if self.encryption_matrix is None:
                raise ValueError("No matrix available. Please encrypt a message first.")
            decrypted_message = decrypt(encrypted_message, self.encryption_matrix)
            self.decrypted_message_text.config(state=tk.NORMAL)
            self.decrypted_message_text.delete(1.0, tk.END)
            self.decrypted_message_text.insert(tk.END, decrypted_message)
            self.decrypted_message_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def restart_program(self):
        self.encryption_matrix = None
        self.message_entry.delete("1.0", tk.END)
        self.rank_entry.delete(0, tk.END)
        self.matrix_text.delete(1.0, tk.END)
        self.encrypted_message_text.config(state=tk.NORMAL)
        self.encrypted_message_text.delete(1.0, tk.END)
        self.encrypted_message_text.config(state=tk.DISABLED)
        self.decrypted_message_text.config(state=tk.NORMAL)
        self.decrypted_message_text.delete(1.0, tk.END)
        self.decrypted_message_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = MatrixCipherGUI(root)
    root.mainloop()
