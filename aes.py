class AES:
    ROW_COUNT = 4
    MIX_MATRIX = [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ]
    BITS_PER_BYTE = 8

    def __init__(self, key, keysize):
        self.key = key
        self.keysize = keysize                 
        self.state = []
        self.col_count = self.keysize // AES.BITS_PER_BYTE // AES.ROW_COUNT
        self.key_array = AES.__create_matrix(AES.ROW_COUNT, self.col_count)

        key_bytes = bytearray(key)

        index = 0
        for col in range(self.col_count):
            for row in range(AES.ROW_COUNT):
                self.key_array[row][col] = key_bytes[index]
                index = index + 1

    def encrypt_file(self, inputfile, outfile):
        pass


    def decrypt_file(self, inputfile, outfile):
        pass


    def __sub_bytes(self):
        pass


    def __shift_rows(self):
        pass


    def __mix_columns(self):
        for i in range(AES.COL_COUNT):
            col = AES.__get_col(self.state, i)
            mixed_col = AES.__matrix_multiply(AES.MIX_MATRIX, col)
            for r in range(len(mixed_col)):
                self.state[r][i] = mixed_col[r][0]


    def __add_roundkey(self):
        pass


    @staticmethod
    def __matrix_multiply(mat_a, mat_b):
        out_m = len(mat_a)
        out_n = len(mat_b[0])

        out_mat = AES.__create_matrix(out_m, out_n)

        for out_r in range(out_m):
            for out_c in range(out_n):
                for other_val in range(len(mat_a[0])):
                    out_mat[out_r][out_c] ^= AES.__mult(mat_a[out_r][other_val], mat_b[other_val][out_c])

        return out_mat

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
    def __mult(int_a, int_b):
        pass


    @staticmethod
    def __get_col(mat_a, col_idx):
        col = []

        for row in mat_a:
            col.append([row[col_idx]])

        return col
