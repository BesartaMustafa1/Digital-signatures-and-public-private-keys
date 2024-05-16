#Librarit numpy dhe sympy per te menaxhuar dhe manipuluar matrica
import numpy as np  #perdoret per llogaritje shkencore
from sympy import Matrix #perdoret per te manipuluar dhe kryer veprime me matrica (me simbole)
import random

# I definojme disa matrica te ndryshme
matrix_rank = {
    2: [np.array([[12, 1], [1, 11]]), np.array([[13, 1], [16, 17]])],
    3: [np.array([[7, 16, 16], [17, 13, 7], [11, 10, 1]]), np.array([[21, 5, 1], [23, 22, 25], [19, 14, 24]])],
    4: [np.array([[7, 3, 19, 21], [1, 11, 15, 16], [25, 25, 22, 15], [7, 18, 12, 23]]), np.array([[18, 15, 22, 23], [17, 1, 24, 22], [24, 21, 25, 11], [9, 10, 17, 10]])]

}

def char_to_num(char):
    #shendrrimi i karaktereve ne numra
    if 'A' <= char <= 'Z': #Merr karakteret(shkronjat) prej A deri ne Z (UPPERCASE)
        return ord(char) - ord('A') #I rendit dhe u jep vlere karaktereve SHEMBULL A=0, B=1, ... Z=25
    elif 'a' <= char <= 'z': #Merr karakteret(shkronjat) prej a deri ne z (lowercase)
        return ord(char) - ord('a') + 26 #I rendit dhe u jep vlere karaktereve SHEMBULL a=26, B=27, ... Z=51
    elif '0' <= char <= '9': #Merr karakteret(numrat) prej 0 deri ne Z (UPPERCASE)
        return ord(char) - ord('0') + 52 #I rendit dhe u jep vlere karaktereve SHEMBULL 0=52, 1=23, ... Z=61
    else:
        return ord('X') - ord('A')  #Per karakteret tjera e kthen "X"

def num_to_char(num):
    #Shendrrimi i numrave ne karaktere
    #Logjika e njejt me "char_to_num" vetem se i rikthen nga numrat e caktuar ne karakteret origjinale 
    if 0 <= num <= 25:
        return chr(num + ord('A'))
    elif 26 <= num <= 51:
        return chr(num - 26 + ord('a'))
    elif 52 <= num <= 61:
        return chr(num - 52 + ord('0'))
    else:
        return None
    
def pad_message(message, block_size):
    #Siguron qe mesazhi te kete padding ne menyre te duhur, ndan mesashin ne baze te inputit te userit
    # (2, 3 ose 4) nese blloku i fundit ka karaktere me pak se inputi i userit e ben padding ate me shkronjen "A"
    padding_length = (block_size - len(message) % block_size) % block_size
    return message + 'A' * padding_length