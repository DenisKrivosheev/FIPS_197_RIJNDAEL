
def xor_strings(s1, s2):
    # перетворюємо рядки в байтові рядки
    #convert strings into byte strings
    b1 = bytes.fromhex(s1)
    b2 = bytes.fromhex(s2)
    
    # виконуємо операцію XOR для кожної пари відповідних байтів
    # we perform an XOR operation for each pair of corresponding bytes
    result = bytes([a ^ b for a, b in zip(b1, b2)])
    
    # перетворюємо результат у рядок шістнадцяткових чисел
    #convert the result into a string of hexadecimal numbers
    return result.hex().upper()

def transpon_matrix(s):
    state_matrix = [s[i:i+2] for i in range(0, len(s), 2)]
    state_matrix = [state_matrix[i:i+4] for i in range(0, len(state_matrix), 4)]
    state_matrix = [[state_matrix[j][i] for j in range(len(state_matrix))] for i in range(len(state_matrix[0]))]
    for row in state_matrix:
        print(row)
    
    print('-----------------------------------')
    return state_matrix


s1 = "53756E73657473206F76657220736561"
print('-----addrow 1 ----')
print('State S0:')
transpon_matrix(s1)
s2 = "000102030405060708090A0B0C0D0E0F"
print('State R0:')
transpon_matrix(s2)
result = xor_strings(s1, s2)
state_matrix = [result[i:i+2] for i in range(0, len(result), 2)]
state_matrix = [state_matrix[i:i+4] for i in range(0, len(state_matrix), 4)]
state_matrix = [[state_matrix[j][i] for j in range(len(state_matrix))] for i in range(len(state_matrix[0]))]
print('State S0 to R0 = State S1:')
 
for row in state_matrix:
    print(row)



def to_text_fromhex(s):
    hex_bytes = bytes.fromhex(s)
    # Convert bytes to text (assuming utf-8 encoding)
    text = hex_bytes.decode('utf-8')
    print(text)


print("--------byteSub---------")
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
def ByteSub(s1, S_BOX):
    output = ""
    for i in range(0, len(s1), 2):
        byte = int(s1[i:i+2], 16)
        output += "{:02X}".format(S_BOX[byte])
    return output

s2 = ByteSub(result, S_BOX)
state2_matrix = [s2[i:i+2] for i in range(0, len(s2), 2)]
state2_matrix = [state2_matrix[i:i+4] for i in range(0, len(state2_matrix), 4)]
state2_matrix = [[state2_matrix[j][i] for j in range(len(state2_matrix))] for i in range(len(state_matrix[0]))]
print('State S1 Bytesub = State S2:')
for row in state2_matrix:
    print(row)
state2_string = ''.join([''.join(row) for row in state2_matrix])



print("-----shiftRow-----")
def shift_rows(state_matrix):
    # зсув рядка 1 на 1 байт вправо
    state_matrix[1] = state_matrix[1][1:] + state_matrix[1][:1]

    # зсув рядка 2 на 2 байти вправо
    state_matrix[2] = state_matrix[2][2:] + state_matrix[2][:2]

    # зсув рядка 3 на 3 байти вправо
    state_matrix[3] = state_matrix[3][3:] + state_matrix[3][:3]

    state_string = ''.join([''.join(row) for row in state_matrix])
    return state_string

s3 = shift_rows(state2_matrix)

def printMatrix_fromRow(s):
    matrix = [[s[i:i+2] for i in range(j, j+8, 2)] for j in range(0, len(s), 8)]
    # Вывести матрицу
    for row in matrix:
        print(row)

    print('-----------------------------------')
    return matrix

print('State S2 shiftrow = State S3:')
printMatrix_fromRow(s3)



print("----------mixcolumn-------")
def mix_column(state):
    # Матриця для перемноження
    mix_matrix = [[0x02, 0x03, 0x01, 0x01],
                  [0x01, 0x02, 0x03, 0x01],
                  [0x01, 0x01, 0x02, 0x03],
                  [0x03, 0x01, 0x01, 0x02]]

    # Перемноження матриць
    new_state = []
    for i in range(4):
        new_column = []
        for j in range(4):
            result = 0
            for k in range(4):
                # Множення елементів матриці на State
                val = int(state[k][j], 16)
                mix_val = mix_matrix[i][k]
                product = 0
                if mix_val == 0x02:
                    product = val << 1
                    if product >= 0x100:
                        product ^= 0x11B
                elif mix_val == 0x03:
                    product = (val << 1) ^ val
                    if product >= 0x100:
                        product ^= 0x11B
                else:
                    product = val
                result ^= product
            new_column.append(hex(result)[2:].zfill(2))
        new_state.append(new_column)

    return new_state

# Конвертування рядка у матрицю стану
state_matrix = [s1[i:i+2] for i in range(0, len(s1), 2)]
state_matrix = [state_matrix[i:i+4] for i in range(0, len(state_matrix), 4)]
state_matrix = [[state_matrix[j][i] for j in range(len(state_matrix))] for i in range(len(state_matrix[0]))]
# Застосування операції MixColumn
print('State S3:')
state_matrix4 = mix_column(printMatrix_fromRow(s3))
print("State S3 mixcolumn = State S4:")
# Виведення результату
for row in state_matrix4:
    print(row)



print("----------------------------------")

state4_string = ''.join([''.join(row) for row in state_matrix4])
print('ignore it:')
stage4_transporent = transpon_matrix(state4_string)
state4_string_tranporent = ''.join([''.join(row) for row in stage4_transporent])


R1 = "D6AA74FDD2AF72FADAA678F1D6AB76FE" 
stageSstar= xor_strings(state4_string_tranporent, R1)
print('State S4 addrow to R1 = State*:')
transpon_matrix(stageSstar)
codded = ''.join([''.join(row) for row in stageSstar])
print('codded message:',codded)
byte_string = bytes.fromhex(codded)
# Decode the bytes using the Latin-1 encoding
text_string = byte_string.decode('latin-1')
# Print the output
print(text_string)



#S_line = "6c4c0a85de77f4ddce5e7b9153304f2e"
#sunsets over sea
#S_line = "DE66CBFF542F42DF59E2E145B2EF7515"
#-------------------------------------------------------------------------------------------------------------------------
print("here started task 7 , you must change S_line ")
S_line = "2d2920b92d78bb3aa96cbf0b1edef553"

print('-----addrow in step 7 ------')
print("State S line")
printMatrix_fromRow(S_line)
print("R1")
transpon_matrix(R1)
print("State S line to R1 = state 4 line: ")
state4_line =transpon_matrix(xor_strings(S_line,R1))
state4_line_string = ''.join([''.join(row) for row in state4_line])


#generate a sbox_inv from AES


#Зворотне перетворення InvMixColumn(State) from AES ALGORITHM має вигляд
print("----- Inversemixcolumn----")

def gf_add(a, b):
    """Add two numbers in GF(2^8)."""
    return a ^ b

def gf_mul(a, b):
    """Multiply two numbers in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p % 256

def imc1(a, b, c, d):
    """Apply the inverse MixColumns operation on a single column of the state matrix."""
    hf = gf_add(gf_mul(C1, a), gf_mul(C2, b))
    hf = gf_add(hf, gf_add(gf_mul(C3, c), gf_mul(C4, d)))
    return hf

def imc4(a, b, c, d):
    """Apply the inverse MixColumns operation on all columns of the state matrix."""
    a1 = imc1(a, b, c, d)
    b1 = imc1(b, c, d, a)
    c1 = imc1(c, d, a, b)
    d1 = imc1(d, a, b, c)
    return a1, b1, c1, d1

# Define the constants used in the MixColumns operation.
C1 = 0x0e
C2 = 0x0b
C3 = 0x0d
C4 = 0x09
def hex_to_int_matrix(hex_matrix):
    return [[int(hex_value, 16) for hex_value in row] for row in hex_matrix]
print("State S line 4:")
input_matrix = printMatrix_fromRow(state4_line_string)
#= [['BA', '0C', '14', '85'], ['E6', 'D8', 'F8', '9B'], ['7E', '86', '03', '39'], ['78', '27', '60', 'D0']]
output_matrix = hex_to_int_matrix(input_matrix)
# Transpose the matrix
input_matrix = [[output_matrix[j][i] for j in range(4)] for i in range(4)]
# Apply inv_mix_column on each column
output_matrix = [[hex(x)[2:].zfill(2) for x in imc4(column[0], column[1], column[2], column[3])] for column in input_matrix]
# Transpose the matrix back to original form
output_matrix = [[output_matrix[j][i] for j in range(4)] for i in range(4)]
s5 = ''
for row in output_matrix:
    for value in row:
        s5 += value
print('State S line 4 invmixcolumn = State S line 3:')
printMatrix_fromRow(s5)



print('------inv shift row------')  
def inv_shift_rows(state):
    """
    Perform AES inverse ShiftRows operation on the given state.

    Args:
    state: 4x4 matrix of integers representing the current state of the AES encryption.

    Returns:
    4x4 matrix of integers representing the state after performing inverse ShiftRows operation.
    """

    # Create a new empty 4x4 matrix
    result = [[0] * 4 for i in range(4)]

    # Copy the elements from the input state to the result matrix
    for row in range(4):
        for col in range(4):
            result[row][col] = state[row][col]

    # Apply the inverse shift rows operation
    for row in range(4):
        for i in range(row):
            # Rotate the row to the right
            temp = result[row][3]
            for col in range(3, 0, -1):
                result[row][col] = result[row][col - 1]
            result[row][0] = temp

    return result
print('state s line 3 ')
printMatrix_fromRow(s5)
# Example usage
hex_string = s5
hex_pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
# Convert each pair of characters back to an integer in hex format using list comprehension
hex_matrix = [[int(pair, 16) for pair in hex_pairs[i:i+4]] for i in range(0, len(hex_pairs), 4)]
state = hex_matrix
result = inv_shift_rows(state)
hex_matrix = [[hex(element) for element in row] for row in result]
# Print the resulting matrix
hex_matrix = [[hex(element)[2:].zfill(2) for element in row] for row in result]
# Concatenate the hex values in each row and join them into a single string
hex_string = ''.join([''.join(row) for row in hex_matrix])
# Print the resulting hex string
print('State line 3 to State line 2=')
printMatrix_fromRow(hex_string)



print('------inversebytesub----')
sbox_inv = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

def inversbytesub(input_string, sbox_inv):
    input_bytes = bytes.fromhex(input_string)
    output_bytes = bytearray(len(input_bytes))
    for i in range(len(input_bytes)):
        output_bytes[i] = sbox_inv[input_bytes[i]]
    return output_bytes.hex()
print("State S line 2")
s444 = printMatrix_fromRow(hex_string)
s44rev = ''.join([''.join(row) for row in s444])
print("to State S line 1 =")
printMatrix_fromRow(inversbytesub(s44rev, sbox_inv))


print('--------last add round key--------')
print('State S line 1')
state_last = printMatrix_fromRow(inversbytesub(s44rev, sbox_inv))
state_last_string = ''.join([''.join(row) for row in state_last])
#s2 = R0 
s2 = "000102030405060708090A0B0C0D0E0F"
print("---ignore it---")
revers = transpon_matrix(state_last_string)
revers_s = ''.join([''.join(row) for row in revers])
print('R0 ')
transpon_matrix(s2)
print("addrow State S line 1 to R0 = ")
transpon_matrix(xor_strings(revers_s, s2))
print('state 0 =',xor_strings(revers_s, s2),'to text:')
to_text_fromhex(xor_strings(revers_s, s2))

