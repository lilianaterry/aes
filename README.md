# AES (CS 361)

## Running
This program can be run by doing the following:

`python3 program.py --keysize {128, 256} --keyfile {path to key} --inputfile {path to file to encrypt or decrypt} --outputfile {path of file to write to} --mode {encrypt, decrypt}`

Further help can be found by running the help command:

`python3 program.py --help`

If you would like to use CBC mode for increased security, add the `--operation` flag with a value of `cbc`.

## About the algorithm
The AES portion of the program lives in the `aes.py` file.

For both encryption and decryption, the file is read in 16 bytes at a time and stored in the state variable where AES will be performed on that block. During this process, if the mode is set to CBC, the preceding encrypted block will also be stored and used in the encryption/decryption process.

### Major algorithm portions

#### Key generation
The algorithm for this was generated based on the function defined [here](https://en.wikipedia.org/wiki/Rijndael_key_schedule).

It uses the `key_words` value as the number of words in each key (number of bytes divided by 4).

The key expansion is treated as a 4 x (4 * number of rounds) matrix which is filled in column by column until the entire key has been generated.

It then follows the following pattern:
1. If the column index to generate is less than `key_words`, take the value directly from the input key. This causes the first roundkey to be the original key provided by the user.
2. If we are generating the first column of a roundkey other than the original key, we use the column immediately preceding the column we are generating, substitute the values using our substitution table, rotate the column once, and XOR it first with the first column from the previous key and then XOR it with the RCON matrix that is described in the Wikipedia article.
3. If our keysize is bigger than 192 bits, we're past the original key, and we're on the 5th column of a roundkey, we get the immediately preceding column, substitute the values using our table, and XOR it with the matching column from the previous roundkey key.
4. If the column falls into none of these categories, we get the matching column from the previous roundkey and XOR it with the immediately preceding column.

Once this operation is complete, we can get the 4 x 4 matrix for a given round that starts at [0, 4 * round index] (row-major order).

#### AddRoundkey

#### SubBytes

#### ShiftRows

#### MixColumns
