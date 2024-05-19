#Librarit numpy dhe sympy per te menaxhuar dhe manipuluar matrica
import numpy as np  #perdoret per llogaritje shkencore
from sympy import Matrix #perdoret per te manipuluar dhe kryer veprime me matrica (me simbole)
import random
#Librarit per gui:
import tkinter as tk
from tkinter import messagebox

# I definojme disa matrica te ndryshme
matrix_rank = {
    2: [np.array([[12, 1], [1, 11]]), np.array([[13, 1], [16, 17]])],
    3: [np.array([[7, 16, 16], [17, 13, 7], [11, 10, 1]]), np.array([[21, 5, 1], [23, 22, 25], [19, 14, 24]])],
    4: [np.array([[7, 3, 19, 21], [1, 11, 15, 16], [25, 25, 22, 15], [7, 18, 12, 23]]), np.array([[18, 15, 22, 23], [17, 1, 24, 22], [24, 21, 25, 11], [9, 10, 17, 10]])]

}

def char_to_num(char):
    #shendrrimi i karaktereve ne numra
    if char == ' ':
        return 62 
    elif 'A' <= char <= 'Z': #Merr karakteret(shkronjat) prej A deri ne Z (UPPERCASE)
        return ord(char) - ord('A') #I rendit dhe u jep vlere karaktereve SHEMBULL A=0, B=1, ... Z=25
    elif 'a' <= char <= 'z': #Merr karakteret(shkronjat) prej a deri ne z (lowercase)
        return ord(char) - ord('a') + 26 #I rendit dhe u jep vlere karaktereve SHEMBULL a=26, B=27, ... Z=51
    elif '0' <= char <= '9': #Merr karakteret(numrat) prej 0 deri ne Z (UPPERCASE)
        return ord(char) - ord('0') + 52 #I rendit dhe u jep vlere karaktereve SHEMBULL 0=52, 1=23, ... Z=61
    else:
        return 63  #Per karakteret tjera e kthen "X"

def num_to_char(num):
    #Shendrrimi i numrave ne karaktere
    #Logjika e njejt me "char_to_num" vetem se i rikthen nga numrat e caktuar ne karakteret origjinale 
     if num == 62:
        return ' '
     elif 0 <= num <= 25:
        return chr(num + ord('A'))
     elif 26 <= num <= 51:
        return chr(num - 26 + ord('a'))
     elif 52 <= num <= 61:
        return chr(num - 52 + ord('0'))
     else:
        return 'X'
    
def pad_message(message, block_size):
    #Siguron qe mesazhi te kete padding ne menyre te duhur, ndan mesashin ne baze te inputit te userit
    # (2, 3 ose 4) nese blloku i fundit ka karaktere me pak se inputi i userit e ben padding ate me shkronjen "A"
    padding_length = (block_size - len(message) % block_size) % block_size
    return message + 'A' * padding_length

def mod_inv(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, modulus)
    matrix_mod_inv = det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
    return matrix_mod_inv

def message_to_vector(message, block_size):
    """Convert the padded message to a vector of numerical values."""
    padded_message = pad_message(message, block_size)
    return np.array([char_to_num(c) for c in padded_message if c is not None])

def encrypt(message, matrix):
    if matrix.shape[0] != matrix.shape[1]:
        raise ValueError("The encryption matrix must be square.")
    block_size = len(matrix)
    message_vector = message_to_vector(message, block_size)
    encrypted_message = ""

    for i in range(0, len(message_vector), block_size):
        block_vector = message_vector[i:i + block_size]
        encrypted_vector = np.dot(matrix, block_vector) % 64
        encrypted_message += ''.join(num_to_char(int(i)) for i in encrypted_vector)

    return encrypted_message

def decrypt(encrypted_message, matrix):
    if matrix.shape[0] != matrix.shape[1]: # Kontrollo nëse matrica është katrore.
        raise ValueError("The decryption matrix must be square.")
    block_size = len(matrix)  # Merr madhësinë e bllokut nga gjatësia e një dimensioni të matricës.
    message_vector = message_to_vector(encrypted_message, block_size)  # Konverto mesazhin e enkriptuar në një vektor mesazhesh duke përdorur madhësinë e bllokut.
    decrypted_message = "" # Inicializo një string për mesazhin e dekriptuar.
    matrix_inv = mod_inv(matrix, 64)  # Llogarit inverzin modular të matricës me mod 64.

    for i in range(0, len(message_vector), block_size):   # Për çdo bllok të vektorit të mesazhit:
        block_vector = message_vector[i:i + block_size]   # Merr një bllok të vektorit të mesazhit.
        decrypted_vector = np.dot(matrix_inv, block_vector) % 64   # Dekripto bllokun duke e shumëzuar me inverzin e matricës dhe duke marrë mbetjen me mod 64.
        decrypted_message += ''.join(num_to_char(int(i)) for i in decrypted_vector) # Konverto numrat e dekriptuar në karaktere dhe shto në mesazhin e dekriptuar.

    return decrypted_message

class MatrixCipherGUI: # krijimi i ndërfaqeve grafike të përdoruesit
    def __init__(self, root):
        self.root = root
        self.root.title("Matrix Cipher")

        self.message_label = tk.Label(root, text="Enter your message:")
        self.message_label.pack()

        self.message_entry = tk.Entry(root, width=50)
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

        self.encrypted_message_text = tk.Text(root, height=2, width=50)
        self.encrypted_message_text.pack()

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.pack()

        self.decrypted_message_label = tk.Label(root, text="Decrypted Message:")
        self.decrypted_message_label.pack()

        self.decrypted_message_text = tk.Text(root, height=2, width=50)
        self.decrypted_message_text.pack()

    def display_matrix(self, matrix):
        matrix_str = '\n'.join([' '.join(map(str, row)) for row in matrix])
        self.matrix_text.delete(1.0, tk.END)
        self.matrix_text.insert(tk.END, f"{matrix_str}\nDimensions: {matrix.shape}")


    def encrypt_message(self):
        message = self.message_entry.get()
        try:
            rank = int(self.rank_entry.get())
            if rank not in matrix_rank:
                raise ValueError("Invalid rank")
            matrix = random.choice(matrix_rank[rank])
            encrypted_message = encrypt(message, matrix)
            self.encrypted_message_text.delete(1.0, tk.END)
            self.encrypted_message_text.insert(tk.END, encrypted_message)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_message(self):
        encrypted_message = self.encrypted_message_text.get(1.0, tk.END).strip()
        try:
            rank = int(self.rank_entry.get())
            if rank not in matrix_rank:
                raise ValueError("Invalid rank")
            matrix = random.choice(matrix_rank[rank])
            decrypted_message = decrypt(encrypted_message, matrix)
            self.decrypted_message_text.delete(1.0, tk.END)
            self.decrypted_message_text.insert(tk.END, decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = MatrixCipherGUI(root)
    root.mainloop()
