import os
import sys
import aes_constants as constants

class AES:
    def __init__(self, key, keysize):
        self.keysize = keysize                 
        self.state = []
        self.col_count = self.keysize // constants.BITS_PER_BYTE // constants.ROW_COUNT
        self.__generate_key_array(key)

        self.round_subkeys = self.__generate_round_subkeys()


    def encrypt_file(self, inputfile, outfile, operation):
        last_block = False
        self.previous_encrypted_block = constants.CBC_INITIALIZATION_VECTOR

        while not last_block:
            self.state = AES.__create_matrix(4, 4)

            byte_count = self.__read_chunk_into_state(inputfile, 16)

            last_block = (byte_count < 16)
            
            if last_block:
                # fill the rest of the block with 0's and add count at end
                self.state[3][3] = 16 - byte_count

            if operation == 'cbc':
                for r_idx in range(len(self.state)):
                    for c_idx in range(len(self.state)):
                        self.state[r_idx][c_idx] ^= self.previous_encrypted_block[r_idx][c_idx]

            current_roundkey = 0
            self.__add_roundkey(current_roundkey)

            # do algorithm
            for _ in range(constants.ROUNDS_PER_KEYSIZE[self.keysize] - 2):
                current_roundkey += 1
                self.__sub_bytes(constants.SUB_BYTES)
                self.__shift_rows()
                self.__mix_columns()
                self.__add_roundkey(current_roundkey)

            current_roundkey += 1
            self.__sub_bytes(constants.SUB_BYTES)
            self.__shift_rows()
            self.__add_roundkey(current_roundkey)

            self.__write_chunk_to_file(outfile, self.state)
            self.previous_encrypted_block = self.state
            

    def decrypt_file(self, inputfile, outfile, operation):
        self.previous_encrypted_block = AES.__create_matrix(4, 4)
        for r_idx in range(len(self.previous_encrypted_block)):
            for c_idx in range(len(self.previous_encrypted_block)):
                self.previous_encrypted_block[r_idx][c_idx] = constants.CBC_INITIALIZATION_VECTOR[r_idx][c_idx]

        self.next_previous_encrypted_block = AES.__create_matrix(4, 4)

        while True:
            self.state = AES.__create_matrix(4, 4)
            byte_count = self.__read_chunk_into_state(inputfile, 16)

            if operation == 'cbc':
                for r_idx in range(len(self.state)):
                    for c_idx in range(len(self.state)):
                        self.next_previous_encrypted_block[r_idx][c_idx] = self.state[r_idx][c_idx]
            
            if byte_count == 0:
                outfile.seek(-1, 2)
                bytes_to_remove = outfile.read(1)
                outfile.seek(-1 * int.from_bytes(bytes_to_remove, sys.byteorder), 2)
                outfile.truncate()
                return

            current_roundkey = constants.ROUNDS_PER_KEYSIZE[self.keysize] - 1
            self.__add_roundkey(current_roundkey)

            # do algorithm
            for _ in range(constants.ROUNDS_PER_KEYSIZE[self.keysize] - 2):
                current_roundkey -= 1
                self.__inv_shift_rows()
                self.__sub_bytes(constants.SUB_BYTES_INVERSE)
                self.__add_roundkey(current_roundkey)
                self.__inv_mix_columns()

            current_roundkey -= 1
            self.__inv_shift_rows()
            self.__sub_bytes(constants.SUB_BYTES_INVERSE)
            self.__add_roundkey(current_roundkey)

            if operation == 'cbc':
                for r_idx in range(len(self.state)):
                    for c_idx in range(len(self.state)):
                        self.state[r_idx][c_idx] ^= self.previous_encrypted_block[r_idx][c_idx]
                temp = self.previous_encrypted_block
                self.previous_encrypted_block = self.next_previous_encrypted_block
                self.next_previous_encrypted_block = temp

            self.__write_chunk_to_file(outfile, self.state)


    def __read_chunk_into_state(self, input, chunk_size):
        chunk = input.read(chunk_size)
        byte_count = len(chunk)  
        for byte_idx in range(byte_count):
            self.state[byte_idx % 4][byte_idx // 4] = chunk[byte_idx]
        return byte_count


    def __write_chunk_to_file(self, output, chunk):
        to_write = []
        for row in range(4):
            for col in range(4):
                to_write.append(chunk[col][row])

        output.write(bytearray(to_write))


    def __generate_key_array(self, key):
        self.key_array = AES.__create_matrix(constants.ROW_COUNT, self.col_count)

        key_bytes = bytearray(key)

        index = 0
        for col in range(self.col_count):
            for row in range(constants.ROW_COUNT):
                self.key_array[row][col] = key_bytes[index]
                index = index + 1
           

    def __sub_bytes(self, sub_bytes_array):
        for row in range(constants.ROW_COUNT):
            for col in range (self.col_count):
                current_val = self.state[row][col]
                self.state[row][col] = sub_bytes_array[current_val]


    def __shift_rows(self):
        for row_idx in range(1, constants.ROW_COUNT):
            row = self.state[row_idx]
            for _ in range(row_idx):
                row.append(row.pop(0))


    def __inv_shift_rows(self):
        for row_idx in range(1, constants.ROW_COUNT):
            row = self.state[row_idx]
            for _ in range(row_idx):
                row.insert(0, row.pop())


    def __mix_columns(self):
        for i in range(constants.ROW_COUNT):
            col = AES.__get_col(self.state, i)
            mixed_col = AES.__gen_modular_product(col)
            for r in range(len(mixed_col)):
                self.state[r][i] = mixed_col[r][0]


    def __inv_mix_columns(self):
        for i in range(constants.ROW_COUNT):
            col = AES.__get_col(self.state, i)
            mixed_col = AES.__gen_inverse_modular_product(col)
            for r in range(len(mixed_col)):
                self.state[r][i] = mixed_col[r][0]


    def __add_roundkey(self, round_idx):
        key_column_start_idx = round_idx * self.col_count
        for row in range(4):
            for col in range(4):
                self.state[row][col] ^= self.round_subkeys[row][key_column_start_idx + col]


    def __generate_round_subkeys(self):
        word_size = 32
        key_words = self.keysize // word_size
        total_col = 4 * constants.ROUNDS_PER_KEYSIZE[self.keysize]

        round_subkeys = AES.__create_matrix(constants.ROW_COUNT, total_col)

        for current_col in range(total_col):
            if current_col < key_words:
                AES.__put_col(round_subkeys, current_col, AES.__get_col(self.key_array, current_col))
            elif current_col >= key_words and current_col % key_words == 0:
                previous_key_col = AES.__get_col(round_subkeys, current_col - key_words)

                col_to_sub = AES.__get_col(round_subkeys, current_col - 1)
                col_to_rotate = AES.__sub_word(col_to_sub)
                rotated_col = AES.__rot_word(col_to_rotate)

                rcon_col = [[constants.RC[current_col // key_words]], [0], [0], [0]]

                finished_col = AES.__xor_word(previous_key_col, AES.__xor_word(rotated_col, rcon_col))

                AES.__put_col(round_subkeys, current_col, finished_col)
            elif current_col >= key_words and key_words > 6 and current_col % key_words == 4:
                previous_key_col = AES.__get_col(round_subkeys, current_col - key_words)

                col_to_sub = AES.__get_col(round_subkeys, current_col - 1)
                subbed_col = AES.__sub_word(col_to_sub)

                finished_col = AES.__xor_word(previous_key_col, subbed_col)

                AES.__put_col(round_subkeys, current_col, finished_col)
            else:
                previous_key_col = AES.__get_col(round_subkeys, current_col - key_words)

                other_previous_key_col = AES.__get_col(round_subkeys, current_col - 1)

                finished_col = AES.__xor_word(previous_key_col, other_previous_key_col)

                AES.__put_col(round_subkeys, current_col, finished_col)

        return round_subkeys


    @staticmethod
    def __rot_word(col):
        col.append(col.pop(0))
        return col


    @staticmethod
    def __sub_word(col):
        for row in col:
            row[0] = constants.SUB_BYTES[row[0]]
        return col

    
    @staticmethod
    def __xor_word(col_a, col_b):
        for i in range(len(col_a)):
            col_a[i][0] ^= col_b[i][0]
        
        return col_a


    @staticmethod 
    def __create_matrix(num_rows, num_cols):
        out_mat = []
        for _ in range(num_rows):
            row = []
            for _ in range(num_cols):
                row.append(0)
            out_mat.append(row)
        return out_mat


    @staticmethod
    def __get_col(mat_a, col_idx):
        col = []

        for row in mat_a:
            col.append([row[col_idx]])

        return col


    @staticmethod
    def __put_col(mat_a, col_idx, col):
        for row_idx in range(len(mat_a)):
            mat_a[row_idx][col_idx] = col[row_idx][0]

        return mat_a


    @staticmethod
    def __gen_modular_product(byte_list):
        a0b0 = AES.__pow_2_shift(byte_list[0][0], 0x02)
        a0b1 = AES.__pow_2_shift(byte_list[1][0], 0x02)
        a0b2 = AES.__pow_2_shift(byte_list[2][0], 0x02)
        a0b3 = AES.__pow_2_shift(byte_list[3][0], 0x02)

        a1b0 = byte_list[0][0]
        a1b1 = byte_list[1][0]
        a1b2 = byte_list[2][0]
        a1b3 = byte_list[3][0]
        
        a2b0 = byte_list[0][0]
        a2b1 = byte_list[1][0]
        a2b2 = byte_list[2][0]
        a2b3 = byte_list[3][0]
        
        a3b0 = AES.__pow_2_shift(byte_list[0][0], 0x02) ^ byte_list[0][0]
        a3b1 = AES.__pow_2_shift(byte_list[1][0], 0x02) ^ byte_list[1][0]
        a3b2 = AES.__pow_2_shift(byte_list[2][0], 0x02) ^ byte_list[2][0]
        a3b3 = AES.__pow_2_shift(byte_list[3][0], 0x02) ^ byte_list[3][0]

        result = []

        # 03 01 01 02
        # d0 =        a0b0 + a3b1 + a2b2 + a1b3
        result.append([a0b0 ^ a3b1 ^ a2b2 ^ a1b3])
        # d1 =        a1b0 + a0b1 + a3b2 + a2b3
        result.append([a1b0 ^ a0b1 ^ a3b2 ^ a2b3])
        # d2 =        a2b0 + a1b1 + a0b2 + a3b3
        result.append([a2b0 ^ a1b1 ^ a0b2 ^ a3b3])
        # d3 =        a3b0 + a2b1 + a1b2 + a0b3
        result.append([a3b0 ^ a2b1 ^ a1b2 ^ a0b3])
        return result


    @staticmethod
    def __gen_inverse_modular_product(byte_list):
        a0b0 = AES.__pow_2_shift(byte_list[0][0], 0x08) ^ AES.__pow_2_shift(byte_list[0][0], 0x04) ^ AES.__pow_2_shift(byte_list[0][0], 0x02)
        a0b1 = AES.__pow_2_shift(byte_list[1][0], 0x08) ^ AES.__pow_2_shift(byte_list[1][0], 0x04) ^ AES.__pow_2_shift(byte_list[1][0], 0x02)
        a0b2 = AES.__pow_2_shift(byte_list[2][0], 0x08) ^ AES.__pow_2_shift(byte_list[2][0], 0x04) ^ AES.__pow_2_shift(byte_list[2][0], 0x02)
        a0b3 = AES.__pow_2_shift(byte_list[3][0], 0x08) ^ AES.__pow_2_shift(byte_list[3][0], 0x04) ^ AES.__pow_2_shift(byte_list[3][0], 0x02)

        a1b0 = AES.__pow_2_shift(byte_list[0][0], 0x08) ^ byte_list[0][0]
        a1b1 = AES.__pow_2_shift(byte_list[1][0], 0x08) ^ byte_list[1][0]
        a1b2 = AES.__pow_2_shift(byte_list[2][0], 0x08) ^ byte_list[2][0]
        a1b3 = AES.__pow_2_shift(byte_list[3][0], 0x08) ^ byte_list[3][0]
        
        a2b0 = AES.__pow_2_shift(byte_list[0][0], 0x08) ^ AES.__pow_2_shift(byte_list[0][0], 0x04) ^ byte_list[0][0]
        a2b1 = AES.__pow_2_shift(byte_list[1][0], 0x08) ^ AES.__pow_2_shift(byte_list[1][0], 0x04) ^ byte_list[1][0]
        a2b2 = AES.__pow_2_shift(byte_list[2][0], 0x08) ^ AES.__pow_2_shift(byte_list[2][0], 0x04) ^ byte_list[2][0]
        a2b3 = AES.__pow_2_shift(byte_list[3][0], 0x08) ^ AES.__pow_2_shift(byte_list[3][0], 0x04) ^ byte_list[3][0]
        
        a3b0 = AES.__pow_2_shift(byte_list[0][0], 0x08) ^ AES.__pow_2_shift(byte_list[0][0], 0x02) ^ byte_list[0][0]
        a3b1 = AES.__pow_2_shift(byte_list[1][0], 0x08) ^ AES.__pow_2_shift(byte_list[1][0], 0x02) ^ byte_list[1][0]
        a3b2 = AES.__pow_2_shift(byte_list[2][0], 0x08) ^ AES.__pow_2_shift(byte_list[2][0], 0x02) ^ byte_list[2][0]
        a3b3 = AES.__pow_2_shift(byte_list[3][0], 0x08) ^ AES.__pow_2_shift(byte_list[3][0], 0x02) ^ byte_list[3][0]

        result = []

        # 03 01 01 02
        # d0 =        a0b0 + a3b1 + a2b2 + a1b3
        result.append([a0b0 ^ a3b1 ^ a2b2 ^ a1b3])
        # d1 =        a1b0 + a0b1 + a3b2 + a2b3
        result.append([a1b0 ^ a0b1 ^ a3b2 ^ a2b3])
        # d2 =        a2b0 + a1b1 + a0b2 + a3b3
        result.append([a2b0 ^ a1b1 ^ a0b2 ^ a3b3])
        # d3 =        a3b0 + a2b1 + a1b2 + a0b3
        result.append([a3b0 ^ a2b1 ^ a1b2 ^ a0b3])
        return result


    @staticmethod
    def __pow_2_shift(byte, shift):
        if shift == 1:
            return byte
        byte = byte << 1
        if (byte & 0x100):
            byte = byte ^ 0x11b
        return AES.__pow_2_shift(byte, shift >> 1)
