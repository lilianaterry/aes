
class AES:
    sub_matrix = [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ]


    def __init__(self, key, keysize):
        self.key = key
        self.keysize = keysize                 


    def encrypt_file(self, inputfile, outfile):
        pass


    def decrypt_file(self, inputfile, outfile):
        pass


    def __sub_bytes(self):
        pass


    def __shift_rows(self):
        pass


    def __mix_columns(self):
        pass


    def __add_roundkey(self):
        pass


    @staticmethod
    def __matrix_multiply(mat_a, mat_b):
        out_m = len(mat_a)
        out_n = len(mat_b[0])

        out_mat = []
        for _ in range(out_m):
            row = []
            for _ in range(out_n):
                row.append(0)
            out_mat.append(row)

        for out_r in range(out_m):
            for out_c in range(out_n):
                for other_val in range(len(mat_a[0])):
                    out_mat[out_r][out_c] ^= AES.__mult(mat_a[out_r][other_val], mat_b[other_val][out_c])

        return out_mat


    @staticmethod
    def __mult(int_a, int_b):
        pass
