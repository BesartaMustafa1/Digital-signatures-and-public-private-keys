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