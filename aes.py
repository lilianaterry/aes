import os
import sys
import aes_constants as constants

class AES:
    def __init__(self, key, keysize):
        self.keysize = keysize                 
        self.state = []
        self.col_count = self.keysize // constants.BITS_PER_BYTE // constants.STATE_SIZE
        self.__generate_key_array(key)

        self.round_subkeys = self.__generate_round_subkeys()
        val = 0
        for col in range(len(self.round_subkeys[0])):
        	hexvals = "%d:" % val	
        	for row in range(len(self.round_subkeys)):
        		hexvals += " %x" % self.round_subkeys[row][col]
        	print(hexvals)
        	val += 1

    def encrypt_file(self, inputfile, outfile, operation):
        last_block = False
        self.previous_encrypted_block = constants.CBC_INITIALIZATION_VECTOR

        while not last_block:
            self.state = AES.__create_matrix(constants.STATE_SIZE, constants.STATE_SIZE)

            byte_count = self.__read_chunk_into_state(inputfile, 16)

            last_block = (byte_count < 16)
            
            if last_block:
                # Fill the rest of the block with 0's and add count at end.
                self.state[3][3] = 16 - byte_count

            if operation == 'cbc':
                for r_idx in range(len(self.state)):
                    for c_idx in range(len(self.state)):
                        self.state[r_idx][c_idx] ^= self.previous_encrypted_block[r_idx][c_idx]

            current_roundkey = 0
            self.__add_roundkey(current_roundkey)

            # Perform the encryption as described in the NIST document
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

        # Sets up storage of previous encrypted block for later use if cbc mode is active.
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
            
            # Remove the padding from the end of the encryption so we only get the necessary data.
            if byte_count == 0:
                outfile.seek(-1, 2)
                bytes_to_remove = outfile.read(1)
                outfile.seek(-1 * int.from_bytes(bytes_to_remove, sys.byteorder), 2)
                outfile.truncate()
                return

            current_roundkey = constants.ROUNDS_PER_KEYSIZE[self.keysize] - 1
            self.__add_roundkey(current_roundkey)

            # Perform the decryption as described in the NIST document
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
        self.key_array = AES.__create_matrix(constants.STATE_SIZE, self.col_count)

        key_bytes = bytearray(key)

        index = 0
        for col in range(self.col_count):
            for row in range(constants.STATE_SIZE):
                self.key_array[row][col] = key_bytes[index]
                index = index + 1
           

    def __sub_bytes(self, sub_bytes_array):
        for row in range(constants.STATE_SIZE):
            for col in range (constants.STATE_SIZE):
                current_val = self.state[row][col]
                self.state[row][col] = sub_bytes_array[current_val]


    def __shift_rows(self):
        for row_idx in range(1, constants.STATE_SIZE):
            row = self.state[row_idx]
            for _ in range(row_idx):
                row.append(row.pop(0))


    def __inv_shift_rows(self):
        for row_idx in range(1, constants.STATE_SIZE):
            row = self.state[row_idx]
            for _ in range(row_idx):
                row.insert(0, row.pop())


    def __mix_columns(self):
        for i in range(constants.STATE_SIZE):
            col = AES.__get_col(self.state, i)
            mixed_col = AES.__gen_modular_product(col)
            for r in range(len(mixed_col)):
                self.state[r][i] = mixed_col[r][0]


    def __inv_mix_columns(self):
        for i in range(constants.STATE_SIZE):
            col = AES.__get_col(self.state, i)
            mixed_col = AES.__gen_inverse_modular_product(col)
            for r in range(len(mixed_col)):
                self.state[r][i] = mixed_col[r][0]


    def __add_roundkey(self, round_idx):
        key_column_start_idx = round_idx * constants.STATE_SIZE
        for row in range(4):
            for col in range(4):
                self.state[row][col] ^= self.round_subkeys[row][key_column_start_idx + col]


    # Generates the expanded key needed for encryption and decryption roundkey operations(based on the key_expansion 
    # psuedocode from the given NIST document).
    def __generate_round_subkeys(self):
        word_size = 32
        key_words = self.keysize // word_size
        total_col = 4 * constants.ROUNDS_PER_KEYSIZE[self.keysize]

        round_subkeys = AES.__create_matrix(constants.STATE_SIZE, total_col)

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
    def gfield_calc(byte, prod):
        i = 7
        runningSum = 0x0
        # Determine which powers of 2 sum to prod.
        while i >= 0:
            bit = ((prod >> i) & 0x1)
            if bit == 0x1:
                byteTemp = byte
                shift = 0x1 << i
                # Perform an iterative implementation of xtimes on the byte
                # related to the power of 2 found in the prod number.
                while shift > 0:
                    if shift == 1:
                        break
                    byteTemp = byteTemp << 1
                    if byteTemp & 0x100:
                        byteTemp = byteTemp ^ 0x11b
                    shift = shift >> 1
                runningSum ^= byteTemp  # "Add" the xtimes result into the running sum
            i -= 1
        return runningSum


    # Performs the calculations necessary to "mix" one column(used for encryption).
    @staticmethod
    def __gen_modular_product(byte_list):

        result = [[0x0], [0x0], [0x0], [0x0]]

        for row in range(len(constants.NORMAL_GENMOD)):
            for byte in range(len(byte_list)):
                result[row][0] ^= AES.gfield_calc(byte_list[byte][0], constants.NORMAL_GENMOD[row][byte])
        
        return result


    # Perfoms the calculations necessary to "inverse mix" one column(used for decryption).
    @staticmethod
    def __gen_inverse_modular_product(byte_list):

        result = [[0x0], [0x0], [0x0], [0x0]]

        for row in range(len(constants.INVERSE_GENMOD)):
            for byte in range(len(byte_list)):
                result[row][0] ^= AES.gfield_calc(byte_list[byte][0], constants.INVERSE_GENMOD[row][byte])
        
        return result
