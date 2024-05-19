# Third project
This project was completed by sophomore students from the Faculty of Electrical and Computer Engineering at the University of "Hasan Prishtina", under the expert guidance of Prof. Dr. Blerim Rexha and Ass. Mërgim Hoti, as part of our coursework in Data Security.
### Authors 

- [Auron Musliu](https://github.com/Auronmussliu1)
- [Aurore Smirqaku](https://github.com/auroresmirqakuu)
- [Avdi Shabani](https://github.com/AvdiShabani)
- [Ardit Bajmrami](https://github.com/ArditBajrami1)
- [Besarta Mustafa](https://github.com/BesartaMustafa1)
## Code Explanation
This encryption uses the Hill Cipher method. Hill Cipher is a symmetric encryption algorithm that uses matrix algebra to encrypt and decrypt messages. It is a classic block cipher that transforms a set of characters into another set using matrix operations.
### Dependencies
numpy: For numerical operations and matrix manipulation.
sympy: For handling matrix inversions.
tkinter: For creating the graphical user interface (GUI).
### Matrix Cipher Components
#### Character Conversion Functions:

char_to_num(char): Converts characters to numerical values.
num_to_char(num): Converts numerical values back to characters.
### Message Padding:
pad_message(message, block_size): Pads the message to ensure its length is a multiple of the block size.
Matrix Inversion Modulo:

mod_inv(matrix, modulus): Computes the modular inverse of a matrix.
Message to Vector Conversion:

message_to_vector(message, block_size): Converts the padded message to a vector of numerical values.
### Encryption and Decryption:

encrypt(message, matrix): Encrypts the message using the provided matrix.
decrypt(encrypted_message, matrix): Decrypts the message using the provided matrix.
Graphical User Interface (GUI):

### MatrixCipherGUI: A class to create the GUI for encryption and decryption.
Predefined Matrices
Matrices are predefined for different ranks (2, 3, and 4), which are used for encryption and decryption.

Here is an overview of the Hill Cipher implemented in these codes:

Hill Cipher uses a matrix (the key) to encrypt and decrypt messages.
The message is divided into blocks of the same size as the matrix.
Each block is multiplied by the key matrix to create the encrypted message.
Decryption is performed using the modular inverse of the key matrix.
These steps are clearly reflected in the provided codes, ensuring that messages are correctly encrypted and decrypted using the Hill method.

Description of Key Functions:
Encryption:
python
Copy code
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
Decryption:
python
Copy code
def decrypt(encrypted_message, matrix):
    if matrix.shape[0] != matrix.shape[1]:
        raise ValueError("The decryption matrix must be square.")
    block_size = len(matrix)
    message_vector = message_to_vector(encrypted_message, block_size)
    decrypted_message = ""
    matrix_inv = mod_inv(matrix, 64)

    for i in range(0, len(message_vector), block_size):
        block_vector = message_vector[i:i + block_size]
        decrypted_vector = np.dot(matrix_inv, block_vector) % 64
        decrypted_message += ''.join(num_to_char(int(i)) for i in decrypted_vector)

    return decrypted_message
This code is an implementation of the Hill method for encryption and decryption, using matrix algebra to transform messages.