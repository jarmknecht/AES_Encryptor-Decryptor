#!/usr/bin/python

import binascii
import sys
import os

class AES:
    def __init__(self):
        self.mod = 0x011b
        self.carry_bit = 0x100
        self.nb = 4
        self.bits_inByte = 8

        self.Sbox = [
            [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 ] ,
            [ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 ] ,
            [ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 ] ,
            [ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 ] ,
            [ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 ] ,
            [ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf ] ,
            [ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 ] ,
            [ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 ] ,
            [ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 ] ,
            [ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb ] ,
            [ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 ] ,
            [ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 ] ,
            [ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a ] ,
            [ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e ] ,
            [ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf ] ,
            [ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]
            ]

        self.InvSbox = [
            [ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb ] ,
            [ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb ] ,
            [ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e ] ,
            [ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 ] ,
            [ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 ] ,
            [ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 ] ,
            [ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 ] ,
            [ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b ] ,
            [ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 ] ,
            [ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e ] ,
            [ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ] ,
            [ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 ] ,
            [ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f ] ,
            [ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef ] ,
            [ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 ] ,
            [ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d ]
            ]

        self.Rcon = [ 0x00000000,
                  0x01000000, 0x02000000, 0x04000000, 0x08000000,
                  0x10000000, 0x20000000, 0x40000000, 0x80000000,
                  0x1B000000, 0x36000000, 0x6C000000, 0xD8000000,
                  0xAB000000, 0x4D000000, 0x9A000000, 0x2F000000,
                  0x5E000000, 0xBC000000, 0x63000000, 0xC6000000,
                  0x97000000, 0x35000000, 0x6A000000, 0xD4000000,
                  0xB3000000, 0x7D000000, 0xFA000000, 0xEF000000,
                  0xC5000000, 0x91000000, 0x39000000, 0x72000000,
                  0xE4000000, 0xD3000000, 0xBD000000, 0x61000000,
                  0xC2000000, 0x9F000000, 0x25000000, 0x4A000000,
                  0x94000000, 0x33000000, 0x66000000, 0xCC000000,
                  0x83000000, 0x1D000000, 0x3A000000, 0x74000000,
                  0xE8000000, 0xCB000000, 0x8D000000]


    def ffAdd(self, x, y):
        return (x ^ y) & 0xFF

    def xtime(self, x):
        x = x << 1
        if (x & self.carry_bit) == self.carry_bit:  # this mean there is a carry bit and need to xor it by mod
            x = x ^ self.mod
        return x

    def ffMultiply(self, x, y):
        next_byte = x
        xtime_bytes = []

        for i in range(self.bits_inByte):  # eight is the size of polynomial 8 bits in 1 byte
            xtime_bytes.append(next_byte)
            next_byte = self.xtime(next_byte)

        product = 0

        for j in range(self.bits_inByte): # eight is the size of polynomial 8 bits in 1 byte
            # Whenever we see a 1 that means the polynomial has a coefficient there
            # and needs to be xored with xtime_bytes made from x
            if (y & 0x01) == 0x01:
                product = product ^ xtime_bytes[j]
            y = y >> 1  # move right down all the bits
        return product

    def keyExpansion(self, key, nr, nk):
        word = []

        for i in range(nk):
            word.append((key >> (32 * (nk - i - 1))) & 0xFFFFFFFF)

        for i in range(nk, self.nb * (nr + 1)):
            temp = word[i - 1]
            if (i % nk) == 0:
                temp = self.rotWord(temp)
                temp = self.subWord(temp)
                rcon = self.Rcon[i // nk]
                temp = temp ^ rcon
            elif (nk > 6) and (i % nk == 4):
                temp = self.subWord(temp)
            word.append(word[i - nk] ^ temp)

        return word

    def subByte(self, byte):
        x = (byte & 0xF0) >> 4  # gets the x coord of sbox
        y = (byte & 0x0F)  # gets the y coord of sbox
        return self.Sbox[x][y]

    def subBytes(self, state):
        newState = [[], [], [], []]
        for x in range(self.nb): #number rows in state (4)
            for y in range(self.nb): #number cols in state (4)
                newState[x].append(self.subByte(state[x][y]))

        return newState

    def subWord(self, word):
        bytes = []
        newWord = 0
        bytes.append((word & 0xFF000000) >> 24)
        bytes.append((word & 0x00FF0000) >> 16)
        bytes.append((word & 0x0000FF00) >> 8)
        bytes.append(word & 0x000000FF)

        for byte in bytes:
            newWord = (newWord << self.bits_inByte) + self.subByte(byte)

        return newWord

    def rotWord(self, word):
        topByte = (word & 0xFF000000) >> 24
        word = (word & 0x00FFFFFF)
        word = word << self.bits_inByte
        newWord = word | topByte

        return newWord

    def shiftRow(self, row, numShift):
        return row[numShift:] + row[:numShift]

    def shiftRows(self, state):
        newState = [[], [], [], []]

        for x in range(self.nb): # how many rows are in the state which is 4
            newState[x] = self.shiftRow(state[x], x)

        return newState

    def mixColumns(self, state):
        newState = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]

        for y in range(self.nb): # how many columns there are in the state which is 4
            newState[0][y] = self.ffAdd(self.ffAdd(
                    self.ffAdd(self.ffMultiply(0x02, state[0][y]), self.ffMultiply(0x03, state[1][y]))
                    , state[2][y]),
            state[3][y])

            newState[1][y] = self.ffAdd(state[0][y],
                self.ffAdd(self.ffAdd(self.ffMultiply(0x02, state[1][y]), self.ffMultiply(0x03, state[2][y])),
                           state[3][y]))

            newState[2][y] = self.ffAdd(
            self.ffAdd(state[0][y], state[1][y]),
            self.ffAdd(self.ffMultiply(0x02, state[2][y]), self.ffMultiply(0x03, state[3][y])))

            newState[3][y] = self.ffAdd(
            self.ffAdd(self.ffMultiply(0x03, state[0][y]), state[1][y]),
            self.ffAdd(state[2][y], self.ffMultiply(0x02, state[3][y])))

        return newState

    def getKey(self, word, round):
        keyState = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]

        for x in range(self.nb): # num rows in keyState
            for y in range(self.nb): # num cols in keyState
                keyState[x][y] = (word[round * self.nb + y] >> ((3 - x) * self.bits_inByte)) & 0xFF
        return keyState

    def toMatrix(self, bytes):
        matrix = [[], [], [], []]
        for i in range(16): # there are 16 bytes in the plaintext
            matrix[i % 4].append((bytes >> ((16 - i - 1) * self.bits_inByte)) & 0xFF)
            # 16-1 is 15 so most moving is 15, then its a byte so times by 8 it will be in the least most byte now
        return matrix

    def toBytes(self, matrix):
        bytes = 0
        for y in range(self.nb):
            for x in range(self.nb):
                bytes = (bytes << self.bits_inByte) + matrix[x][y]
        return bytes

    def addRoundKey(self, state, word, round):
        newState = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]

        key = self.getKey(word, round)

        for x in range(self.nb):  # rows in state are 4
            for y in range(self.nb):  # cols in state are 4
                newState[x][y] = self.ffAdd(state[x][y], key[x][y])

        return newState

    def invShiftRows(self, state):
        newState = [[], [], [], []]

        for x in range(self.nb): # how many rows are in the state which is 4
            newState[x] = self.shiftRow(state[x], self.nb - x)

        return newState

    def invSubByte(self, byte):
        x = (byte & 0xF0) >> 4  # gets the x coord of sbox
        y = (byte & 0x0F)  # gets the y coord of sbox
        return self.InvSbox[x][y]

    def invSubBytes(self, state):
        newState = [[], [], [], []]
        for x in range(self.nb):  # number rows in state (4)
            for y in range(self.nb):  # number cols in state (4)
                newState[x].append(self.invSubByte(state[x][y]))

        return newState

    def invMixColumns(self, state):
        newState = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]

        for y in range(self.nb):  # how many columns there are in the state which is 4
            newState[0][y] = self.ffAdd(self.ffAdd(self.ffMultiply(0x0e, state[0][y]), self.ffMultiply(0x0b, state[1][y])),
            self.ffAdd(self.ffMultiply(0x0d, state[2][y]), self.ffMultiply(0x09, state[3][y])))

            newState[1][y] = self.ffAdd(self.ffAdd(self.ffMultiply(0x09, state[0][y]), self.ffMultiply(0x0e, state[1][y])),
            self.ffAdd(self.ffMultiply(0x0b, state[2][y]), self.ffMultiply(0x0d, state[3][y])))

            newState[2][y] = self.ffAdd(self.ffAdd(self.ffMultiply(0x0d, state[0][y]), self.ffMultiply(0x09, state[1][y])),
            self.ffAdd(self.ffMultiply(0x0e, state[2][y]), self.ffMultiply(0x0b, state[3][y])))

            newState[3][y] = self.ffAdd(self.ffAdd(self.ffMultiply(0x0b, state[0][y]), self.ffMultiply(0x0d, state[1][y])),
            self.ffAdd(self.ffMultiply(0x09, state[2][y]), self.ffMultiply(0x0e, state[3][y])))

        return newState

    def cipher(self, plaintext, cipherKey, nk, nr):

        #print("=========================================================")

        word = self.keyExpansion(cipherKey, nr, nk)
        state = self.toMatrix(plaintext)
        state = self.addRoundKey(state, word, 0)  # round zero

        for round in range(1, nr):
            state = self.subBytes(state)
            state = self.shiftRows(state)

            state = self.mixColumns(state)

            state = self.addRoundKey(state, word, round)


        round = nr
        state = self.subBytes(state)

        state = self.shiftRows(state)

        state = self.addRoundKey(state, word, round)

        return state

    def invCipher(self, ciphertext, cipherKey, nk, nr):
        word = self.keyExpansion(cipherKey, nr, nk)
        state = self.toMatrix(ciphertext)

        state = self.addRoundKey(state, word, nr)  # round nr (last round of key)

        for round in range(nr - 1, 0, -1):

            state = self.invShiftRows(state)

            state = self.invSubBytes(state)

            state = self.addRoundKey(state, word, round)

            state = self.invMixColumns(state)

        round = 0
        state = self.invShiftRows(state)

        state = self.invSubBytes(state)

        state = self.addRoundKey(state, word, round)

        return state


if __name__ == "__main__":
    aes = AES()

    if len(sys.argv) < 3:
        print("USAGE: <file to encrypt> <size of encryption key>")
        exit(-1)

    plaintext = sys.argv[1]

    print("File to encrypt: ", plaintext)

    key_bit_size = int(sys.argv[2])

    print("Key bit size: ", key_bit_size)

    if (key_bit_size == 128):
        nk = 4
        nr = 10
    elif (key_bit_size == 192):
        nk = 6
        nr = 12
    elif (key_bit_size == 256):
        nk = 8
        nr = 14
    else:
        print("Incorrect key size for AES encryption")
        exit(-1)

    key_byte_size = int(int(key_bit_size) / 8)

    print("Key byte size: ", key_byte_size)

    key = os.urandom(key_byte_size)
    print("Key: ", key.hex())

    key_file = open('key.txt', 'w')
    key_file.write(key.hex())
    key_file.close()

    print("Opening file for reading...")

    if not(os.path.exists(plaintext)):
        print("File does not exist")
        exit(-1)

    if not (os.path.isfile(plaintext)):
        print("Is not a file. Can't encrypt")
        exit(-1)

    file = open(plaintext, "rb")
    contents = (file.read())
    file.close()
    #print("LENGTH: ", contents.__len__())
    #print(contents.hex())
    num_of_blocks = int((contents.__len__()) / 16)
    #print("Number of blocks: ", num_of_blocks) # this will provide how many blocks total to put through encryption
    remainder = int((contents.__len__()) % 16)  # checks if there is a remainder and if so will provide the padding needed to get to 16 bytes
    byte_array = list(contents)
    #print("Remainder: ", remainder)
    if not remainder == 0:
        num_of_blocks = num_of_blocks + 1
        number_of_padded_bytes = 16 - remainder

        for i in range(number_of_padded_bytes):
            byte_array.append(00)
      #  print("Number of padded bytes: ", number_of_padded_bytes)

  #  print("Total number of blocks: ", num_of_blocks)

    #print(byte_array)

    #print("rem: ", byte_array.__len__() % 16)

    block = bytes(byte_array)

    starting_index = 0

    print("Encrypting...")
    for i in range(num_of_blocks):
        byte_block = block[starting_index: starting_index + 16]
        #print("Byte Block ", i, byte_block)

        encryption = aes.cipher(int.from_bytes(byte_block, byteorder='big'), int.from_bytes(key, byteorder='big'), nk, nr)
        encryption_bytes = "%.32x" % aes.toBytes(encryption)

        if i == 0:
            enc_file = open('ciphertext.txt.enc', 'wb')
        else:
            enc_file = open('ciphertext.txt.enc', 'ab')
        enc_file.write(binascii.unhexlify(encryption_bytes))
        enc_file.close()
        starting_index = starting_index + 16

    print("Decrypting...")
    starting_index = 0
    enc_file = open("ciphertext.txt.enc", "rb")
    enc_contents = (enc_file.read())
    enc_file.close()

    byte_array = list(enc_contents)

    print(byte_array)

    print("rem: ", byte_array.__len__() % 16)

    block = bytes(byte_array)

    for i in range(num_of_blocks):
        byte_block = block[starting_index: starting_index + 16]
        print("Byte Block ", i, byte_block)
        decryption = aes.invCipher(int.from_bytes(byte_block, byteorder='big'), int.from_bytes(key, byteorder='big'), nk, nr)
        decrypted_bytes = "%.32x" % aes.toBytes(decryption)

        if i == 0:
            dcrpt_file = open('decryptedtext.txt', 'wb')
        else:
            dcrpt_file = open('decryptedtext.txt', 'ab')
        dcrpt_file.write(binascii.unhexlify(decrypted_bytes))
        dcrpt_file.close()
        starting_index = starting_index + 16

    print("Saving as decryptedtext.txt")
    print("DONE!")