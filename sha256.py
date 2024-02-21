
class SHA256():
    def __init__(self, input_str: str, result_type = 1):
        self.input_str = input_str
        self.result_type = result_type
        self.prime_numbers = self.get_prime_numbers(64)
        

    def get_prime_numbers(self, i: int) -> list[str]:
        prime_numbers = []
        curr_num = 2
        while len(prime_numbers) < i:
            prime = True
            for num in prime_numbers:
                if curr_num % num == 0:
                    prime = False
            
            prime_numbers += [curr_num] if prime else []
            curr_num +=1
        return prime_numbers

    def str_to_bin(self, A: str) -> str:
        return ''.join(bin(ord(x))[2:].zfill(8) for x in A)
    
    def pad_inputs(self, A: str, B: str) -> str:
        max_len = max(len(A), len(B))
        return A.zfill(max_len), B.zfill(max_len)
    
    def AND(self, A: str, B: str) -> str:
        A, B = self.pad_inputs(A, B)
        return ''.join('1' if A[n] == B[n] == '1' else '0' for n in range(len(A)))
    
    def XOR(self, A: str, B: str) -> str:
        A, B = self.pad_inputs(A, B)
        return ''.join('1' if A[n] != B[n] else '0' for n in range(len(A)))
        
    def COMP(self, A: str) -> str:
        return ''.join('1' if n == '0' else '0' for n in A)

    def rot_r(self, A: str, n: int) -> str:
        n %= len(A)
        return A[-n:] + A[:-n]
    
    def sh_r(self, A: str, n: int) -> str:
        n = min(n, len(A))
        return '0'*n + A[:-n]
    
    def add_trunc(self, num_list: list[str]) -> str:
        result = ''
        for num in num_list:
            A, B = self.pad_inputs(num, result)
            result = ''
            overflow = '0'
            for i in range(-1,-len(A)-1,-1):
                arr = [overflow, A[i], B[i]]
                result = min(set(arr), key=arr.count) + result
                overflow = max(set(arr), key=arr.count)

            result = (overflow + result)[-32:]

        return result
    
    def ch(self, A: str, B: str, C: str) -> str:
        return self.XOR(self.AND(A, B), self.AND(self.COMP(A), C))
    
    def maj(self, A: str, B: str, C: str) -> str:
        return self.XOR(self.XOR(self.AND(A, B), self.AND(A, C)), self.AND(B, C))
    
    def S0(self, A: str) -> str:
        return self.XOR(self.XOR(self.rot_r(A,2),self.rot_r(A,13)),self.rot_r(A,22))

    def S1(self, A: str) -> str:
        return self.XOR(self.XOR(self.rot_r(A,6),self.rot_r(A,11)),self.rot_r(A,25))

    def s0(self, A: str) -> str:
        return self.XOR(self.XOR(self.rot_r(A,7),self.rot_r(A,18)),self.sh_r(A,3))

    def s1(self, A: str) -> str:
        return self.XOR(self.XOR(self.rot_r(A,17),self.rot_r(A,19)),self.sh_r(A,10))

    def Ki(self, i: int) -> str:
        result = int((self.prime_numbers[i]**(1/3) % 1) * 2**32)
        return bin(result)[2:].zfill(32)
    
    def pad_msg(self, A: str) -> str:
        n = 448 - ((len(A)+1) % 512)
        n = 512 + n if n < 0 else n
        return A + '1' + '0'*n + bin(len(A))[2:].zfill(64)
    
    def get_block_decomp(self, M: str) -> list[str]:
        W = ['-999'] * 64
        for i in range(64):
            if i < 16:
                W[i] = M[i*32:(i+1)*32]
            else:
                W[i] = self.add_trunc([self.s1(W[i-2]), W[i-7], 
                                       self.s0(W[i-15]), W[i-16]])
        return W
    
    def H0i(self, i: int) -> str:
        result = int((self.prime_numbers[i]**(1/2) % 1) * 2**32)
        return bin(result)[2:].zfill(32)

    def hash_comp(self, M: str) -> str:
        prev_H = [self.H0i(0), self.H0i(1), self.H0i(2), self.H0i(3), 
                  self.H0i(4), self.H0i(5), self.H0i(6), self.H0i(7)]
        for i in range(0,len(M),512):
            Mi = M[i:i+512]
            W = self.get_block_decomp(Mi)
            a, b, c, d = prev_H[0], prev_H[1], prev_H[2], prev_H[3] 
            e, f, g, h = prev_H[4], prev_H[5], prev_H[6], prev_H[7]
            for j in range(64):
                T1 = self.add_trunc([h, self.S1(e), self.ch(e,f,g), self.Ki(j), W[j]])
                T2 = self.add_trunc([self.S0(a), self.maj(a,b,c)])
                h = g
                g = f
                f = e
                e = self.add_trunc([d, T1])
                d = c
                c = b
                b = a 
                a = self.add_trunc([T1, T2])
                
            prev_H = [self.add_trunc([prev_H[0],a]),
                      self.add_trunc([prev_H[1],b]),
                      self.add_trunc([prev_H[2],c]),
                      self.add_trunc([prev_H[3],d]),
                      self.add_trunc([prev_H[4],e]),
                      self.add_trunc([prev_H[5],f]),
                      self.add_trunc([prev_H[6],g]),
                      self.add_trunc([prev_H[7],h])]
            
        return  prev_H[0] + prev_H[1] + prev_H[2] + prev_H[3] + \
                prev_H[4] + prev_H[5] + prev_H[6] + prev_H[7]

    def bin_to_hex(self, A: str) -> str:
        return (hex(int(A,2))[2:]).zfill(64)

    def get_hash(self) -> str:
        A = self.str_to_bin(self.input_str)
        M = self.pad_msg(A)
        bin_result = self.hash_comp(M)
        return self.bin_to_hex(bin_result) if self.result_type else bin_result

if __name__ == "__main__":
    while True:
        input_str = input("input_str:")
        result_type = input("result_type: hex (0) binary (1):")
        sha256 = SHA256(input_str = input_str, result_type= result_type)
        print(sha256.get_hash())

    