import unittest

from sha256 import SHA256

class TestCode(unittest.TestCase):
    def test_file_runs(self):
        self.assertEqual(1, 1)

    def test_str_to_bin(self):
        input_str = 'tests'
        output_bin = '0111010001100101011100110111010001110011'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.str_to_bin(input_str), output_bin)

    def test_rot_r(self):
        input_str = ''
        A = '01110100'
        n = 3
        A_shifted = '10001110'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.rot_r(A,n), A_shifted)

    def test_rot_r_n_greater_than_lenA(self):
        input_str = ''
        A = '01110100'
        n = 15
        A_shifted = '11101000'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.rot_r(A,n), A_shifted)

    def test_sh_r(self):
        input_str = ''
        A = '01110100'
        n = 3
        A_shifted = '00001110'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.sh_r(A,n), A_shifted)

    def test_sh_r_n_greater_than_lenA(self):
        input_str = ''
        A = '01110100'
        n = 9
        A_shifted = '00000000'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.sh_r(A,n), A_shifted)

    def test_AND(self):
        input_str = ''
        A = '01110100'
        B = '01110111'
        result = '01110100'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.AND(A,B), result)

    def test_AND_non_equal_length(self):
        input_str = ''
        A =            '01110100'
        B =      '01110111000101'
        result = '00000001000100'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.AND(A,B), result)

    def test_XOR(self):
        input_str = ''
        A =      '01110100'
        B =      '01110111'
        result = '00000011'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.XOR(A,B), result)

    def test_XOR_non_equal_length(self):
        input_str = ''
        A =            '01110100'
        B =      '01110111000101'
        result = '01110110110001'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.XOR(A,B), result)

    def test_COMPlement(self):
        input_str = ''
        A =      '01110100'
        result = '10001011'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.COMP(A), result)

    def test_add_trunc(self):
        input_str = ''
        A =      '01110100'
        B =      '01110100'
        result = '0011101000'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.add_trunc([A, B]), result)

    def test_add_trunc_long_inputs(self):
        input_str = ''
        A =      '11110100011101000111010001110100'
        B =      '11110100011101000111010001110100'
        result = '11101000111010001110100011101000'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.add_trunc([A, B]), result)

    def test_add_trunc_RedBlockBlue_T2(self):
        input_str = ''
        A =      '11001110001000001011010001111110'
        B =      '00111010011011111110011001100111'
        result = '00001000100100001001101011100101'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.add_trunc([A, B]), result)

    def test_ch(self):
        input_str = ''
        A =      '01110100'
        B =      '00110111'
        C =      '11101011'
        result = '10111111'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.ch(A, B, C), result)

    def test_maj(self):
        input_str = ''
        A =      '01110100'
        B =      '00110111'
        C =      '11101011'
        result = '01110111'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.maj(A, B, C), result)

    def test_S0(self):
        input_str = ''
        A =      '01110100011101000111010001110100'
        result = '01101111011011110110111101101111'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.S0(A), result)

    def test_S1(self):
        input_str = ''
        A =      '01110100011101000111010001110100'
        result = '01100101011001010110010101100101'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.S1(A), result)

    def test_s0(self):
        input_str = ''
        A =      '01110100011101000111010001110100'
        result = '11111011011110110111101101111011'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.s0(A), result)

    def test_s1(self):
        input_str = ''
        A =      '01110100011101000111010001110100'
        result = '10110100101010011010100110101001'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.s1(A), result)

    def test_Ki(self):
        input_str = ''
        i =      0
        result = '01000010100010100010111110011000'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.Ki(i), result)

    def test_Ki_again(self):
        input_str = ''
        i =      16
        result = '11100100100110110110100111000001'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.Ki(i), result)

    def test_pad_msg_less_than_448(self):
        input_str = ''
        A = '11100100100110110110100111000001'
        result = '11100100100110110110100111000001100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.pad_msg(A), result)

    def test_pad_msg_between_448_and_512(self):
        input_str = ''
        A = '1' + '0'*498 + '1'
        result = A + '1' + '0'*11 + '0'*448 + '0000000000000000000000000000000000000000000000000000000111110100' 
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.pad_msg(A), result)

    def test_pad_msg_between_greater_than_512(self):
        input_str = ''
        A = '1' + '0'*550 + '1'
        result = A + '1' + '0'*(448 - (553-512)) + '0000000000000000000000000000000000000000000000000000001000101000' 
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.pad_msg(A), result)

    def test_get_block_i_less_than_17(self):
        input_str = ''
        M = '1' + '0'*510 + '1'
        i = 0
        result = '10000000000000000000000000000000' 
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.get_block_decomp(M)[i], result)

    def test_get_block_i_equal_16(self):
        input_str = ''
        M = '1' + '0'*510 + '1'
        i = 15
        result = '00000000000000000000000000000001' 
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.get_block_decomp(M)[i], result)

    def test_get_block_i_greater_than_16(self):
        input_str = ''
        M = '0' + '1'*510 + '0'
        i = 16

        term1 =  '00000000001111111111111111111111'
        term2 =  '11111111111111111111111111111111'
        term3 =  '00011111111111111111111111111111'
        term4 =  '01111111111111111111111111111111'

        t12   = '100000000001111111111111111111110'
        t34   = '010011111111111111111111111111110'
        result=  '10100000001111111111111111111100' 
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.get_block_decomp(M)[i], result)

    def test_H0i(self):
        input_str = ''
        i =      0
        result = '01101010000010011110011001100111'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.H0i(i), result)

    def test_H0i_again(self):
        input_str = ''
        i =      5
        result = '10011011000001010110100010001100'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.H0i(i), result)

    def test_get_hash(self):
        input_str = 'abc'
        result = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.get_hash(), result)

    def test_get_hash_leading_zero(self):
        input_str = 'abc1234567890123456789012'
        result = '02947128ed6bc91ce44f2747abd78d1f963822ebb1a9816a94bf2aba8e390424'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.get_hash(), result)

    def test_get_hash_440_bits(self):
        input_str = '0000000000000000000000000000000000000000000000000000000'
        result = '9f8ef876f51f5313c91cc3f6b8119af09d8bbdd72098fa149b2780eb3591d6be'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.get_hash(), result)

    def test_get_hash_448_bits(self):
        input_str = '00000000000000000000000000000000000000000000000000000000'
        result = 'bd03ac1428f0ea86f4b83a731ffc7967bb82866d8545322f888d2f6e857ffc18'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.get_hash(), result)

    def test_get_hash_multi_blocks(self):
        input_str = '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        result = 'b74aa3803524ebbc58fd5abc6dfe4b6d0c5d8081f247ada1c44ddb06486a5717'
        sha256 = SHA256(input_str)
        self.assertEqual(sha256.get_hash(), result)




        

    

  


if __name__ == '__main__':

    unittest.main()