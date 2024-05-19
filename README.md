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
