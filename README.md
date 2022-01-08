# Cryptography
Mainly for operation record
***
# 第一次大作业
## Programming Assignment AES
>In this assignment, you must decrypt a challenge ciphertext generated using AES in CBC-mode with PKCS #5 padding. (Note: technically this is PKCS #7 padding, since the block size of AES is 16 bytes. But the padding is done in exactly the same way as PKCS #5 padding.) To do so, you will be given access to a server that will decrypt any ciphertexts you send it (using the same key that was used to generate the challenge ciphertext)...but that will only tell you whether or not decryption results in an error! 
>
>All the files needed for this assignment are available here, including a README file that should explain everything. 
>
>Note that this assignment requires the ability to perform basic networking. Because we do not assume students necessarily know this, we have provided stub code for doing basic networking in C, Java, Ruby, and Python, but you are welcome to use any language of your choice as long as you are able to write code for basic networking functionality in that language. (Students may feel free to post stub code in other languages for the networking component on the discussion boards.) 
>
>The first step in this project is to send the challenge ciphertext to the server, and verify that you receive back a "no error" message. Once you can do that, the rest is "just" crypto... 
>
>The plaintext, when converted to ASCII, is readable English text, and so you should be able to tell once you have been successful. Once you have successfully recovered the plaintext (in ASCII).

对于题目描述，解释一下解密的原理和注意点：

Padding的含义是“填充”，在解密时，如果算法发现解密后得到的结果，它的填充方式不符合规则，那么表示输入数据有问题，对于解密的类库来说，往往便会抛出一个异常，提示Padding不正确。

此题使用AES对称加密，并采用CBC模式（密码分组连接模式），具体形式如下图所示：
![image](https://user-images.githubusercontent.com/57308439/148498209-c3bd097f-30f7-4657-b273-97119d3e4fa3.png)

此外，这里用到了padding oracle的相关概念：

假如说此时我们按8字节为一个明文分组，分到最后发现最后一组缺了一个字节，程序不会填一些随机数，亦或者将不够的位数全填零。CBC模式最后的填充方法，就是缺了一位就填一个0x01,缺了两位就填两个0x02,缺了三位就填三个0x03,以此往后类推缺n个就填n个0x0n。哪怕当明文正好时分组的整数倍时，也会填充8个0x08，即使是整数倍也要填充。这样就导致了无论我们明文的长度是多少，我们CBC模式加密是都会在明文的最后进行填充，以确保分段的长度是8的整数倍。

形象化如下所示：

![image](https://user-images.githubusercontent.com/57308439/148498521-5b01c883-6eb8-40d5-94a2-ec06c845a827.png)

至于加解密流程，Dan Boneh老师的课也讲得挺清楚的，具体可以去coursera查看
加密：
![image](https://user-images.githubusercontent.com/57308439/148498821-b76e31a4-6b2d-40ce-aa45-4a1f5ad89475.png)
解密：
![image](https://user-images.githubusercontent.com/57308439/148498830-0e2e9f64-ed7f-4ee3-99a1-a96e9bbe3e42.png)

根据题目要求，不难编写出主程序
```c
#include "oracle.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
unsigned char ciphertext[3][16]={
  {159,11,19,148,72,65,168,50,178,66,27,158,175,109,152,54},
  {129,62,201,217,68,165,200,52,122,124,166,154,163,77,141,192},
  {223,112,227,67,196,0,10,42,227,88,116,206,117,230,76,49}
};
unsigned char ctext[32], plaintext[48], xor_iv[16];
void solve(int p) {
  int i, j, k, ret;
  memset(ctext, 0, sizeof(ctext) );
  for (i=0; i<16; ++i) ctext[16+i] = ciphertext[p][i];
  for (i=0; i<16; ++i) {
    for (j=0; j<i; ++j) ctext[15-j] = xor_iv[15-j] ^ (i+1);
    for (j=0; j<256; ++j) {
      ctext[15-i] = j;
      ret = Oracle_Send(ctext, 2);
      if (ret == 1) {
        xor_iv[15-i] = j ^ (i+1);
        plaintext[16*p+15-i] = xor_iv[15-i] ^ ciphertext[p-1][15-i];
        break;
      }
    }
  }
}
int main(int argc, char *argv[]) {
  int i, ret;
  Oracle_Connect();
  for (i=1; i<3; ++i) solve(i);
  freopen("plaintext.txt", "w", stdout);
  for (i=16; i<48; ++i) printf("%c", plaintext[i]);
  fclose(stdout);
  Oracle_Disconnect();
}
```
最后连接服务器:

![image](https://user-images.githubusercontent.com/57308439/148499311-0994f1de-e000-44c7-821d-26c3f2e782b1.png)

解密结果：
<h3>Yay ! You get an A. =)</h3>

***

# 第二次大作业
## 1. cryptopals Byte-at-a-time ECB decryption (Harder)
>This attack is the same as the challenge #12, but with some required initial work, offsets and padding to apply.
>
>We first need to find out how long the prefix is. We do this by generating 2 blocks of fixed data (e.g. [0xA] * 32) and gradually increasing the size of the fixed data until we find 2 neighbour duplicate blocks in the ciphertext. This indicates that we have fully padded the last block of the prefix and that we have produced two blocks of our own input after that. To make sure that we don't just have identical blocks because the prefix happened to end with our fixed value (therefore fooling us into thinking that we have padded 1 more byte than we really have), we can try with 2 different fixed values, e.g. [0] * 32 and [1] * 32.
>
>Then, one can use the index where the duplicate blocks begin to find where the first block after the prefix starts. With that information, we can find the amount of padding that was required to pad the prefix to a multiple of blocksize through len(fixed_data) - 2 * blocksize. The length of the prefix is then index of first of the duplicates - padding length.
>
>With the length of the prefix, we just use our algorithm from challenge #12, but prefixing our input with some padding to pad the prefix to a blocksize multiple. We also need to offset any index in the produced ciphertext by the amount of blocks in the prefix.

这道题其实有个前置题，叫Byte-at-a-time ECB decryption (Simple)，可以先从此题入手。
(使用ECB模式加密，加密过程很简单，不多赘述,见图）
![image](https://user-images.githubusercontent.com/57308439/148503327-21df4cc4-c607-4423-9bf1-3cd3b7d3d19f.png)



对于Harder版本，首先列一个简单的思路：
* 首先将相同的字符串字节传入函数1，从传入1个字节（A）开始，然后AA,AAA...直到找到密文的块的大小
* 测试加密模式是否为ECB
* 知道块的大小后，设计一个恰好少1字节的输入块（例如，如果块大小为8字节，则输入“ AAAAAAA”）
* 找到前缀长度
* 一次一个byte解密target-byte

总而言之，加密函数加密的内容就是随机前缀+可控字符串+未知字符串

具体代码：
```python
from binascii import a2b_base64
from Crypto.Cipher import AES
from os.path import commonprefix
import random
import string

BLOCK_SIZE = 16

def bytes_to_str(byte_list: bytes) -> str:
    return "".join(filter(lambda x: x in string.printable, "".join(map(chr, byte_list))))

def generate_random_bytes(num_bytes: int) -> bytes:
    return bytes([random.randint(0, 255) for _ in range(num_bytes)])

def pkcs7_padding(byte_string: bytes, block_length: int) -> bytes:
    num_to_pad = block_length - (len(byte_string) % block_length)
    return byte_string + bytes([num_to_pad]) * num_to_pad

def aes_in_ecb_mode(byte_string: bytes, key: bytes, encrypt: bool = False) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    if encrypt:
        return cipher.encrypt(byte_string)
    else:
        return cipher.decrypt(byte_string)

def detect_aes_in_ecb_mode(byte_string: bytes,
                           block_length: int) -> bool:
    byte_blocks = [byte_string[i*block_length: (i+1)*block_length]
                   for i in range(int(len(byte_string) / block_length))]
    unique_blocks = set(byte_blocks)
    return len(unique_blocks)/len(byte_blocks) < 1

GLOBAL_KEY = generate_random_bytes(BLOCK_SIZE)
UNKNOWN_STRING = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

MAX_SIZE = BLOCK_SIZE * 10
RANDOM_BYTES = generate_random_bytes(random.randint(1, int(MAX_SIZE/2)))

def ecb_encryption_oracle_harder(byte_string: bytes)->bytes:
    unknown_string = a2b_base64(UNKNOWN_STRING)
    plain_text = RANDOM_BYTES + byte_string + unknown_string
    return aes_in_ecb_mode(pkcs7_padding(plain_text, BLOCK_SIZE), GLOBAL_KEY, encrypt=True)

def find_block_size(encryptor):
    length_output = len(encryptor(b'A'*0))
    for i in range(1, MAX_SIZE):
        new_length_output = len(encryptor(b'A'*i))
        block_size = new_length_output - length_output
        if block_size != 0:
            break
        length_output = new_length_output
    return length_output, block_size

def find_num_random_blocks(encryptor, length_output, block_size):
    common_prefix_length = len(commonprefix([encryptor(b''), encryptor(b'A')]))
    for num_random_blocks in range(int(length_output/block_size)):
        if common_prefix_length < block_size * num_random_blocks:
            break
    return num_random_blocks

def find_string_lengths(encryptor, block_size, num_random_blocks):
    encrypted_strings =[]
    for i in range(block_size):
        encrypted_strings.append(encryptor(b'A'*i))
        random_string_length = len(commonprefix(encrypted_strings))
        unknown_string_length = len(encrypted_strings[0]) - random_string_length
        if len(encrypted_strings) > 1 and random_string_length >= block_size * num_random_blocks and random_string_length % block_size == 0:
            min_addition = i-1
            break
        encrypted_strings = [encrypted_strings[-1]]
    return min_addition, random_string_length, unknown_string_length

def byte_at_a_time_ecb_decryption_harder(encryptor)->bytes:
    length_output, block_size = find_block_size(encryptor)
    num_random_blocks = find_num_random_blocks(encryptor, length_output, block_size)
    min_addition, random_string_length, unknown_string_length = find_string_lengths(encryptor, block_size, num_random_blocks)

    if not detect_aes_in_ecb_mode(encryptor(b'A'*MAX_SIZE), block_size):
        return b'Not ECB Mode'

    num_blocks = int(unknown_string_length/block_size)
    unknown_string = b''
    input_block = b'A'*(block_size + min_addition)
    for block_number in range(num_blocks):
        unknown_string_block = b''
        for n in range(min_addition + block_size - 1, min_addition - 1, -1):
            input_block = input_block[1:]
            last_byte_dict = {encryptor(input_block + bytes([b]))[random_string_length: random_string_length + block_size]: bytes([b]) for b in range(256)}
            offset = (block_size * block_number) + random_string_length
            one_byte_short = encryptor(b'A'*n)[offset: offset + block_size]
            if one_byte_short not in last_byte_dict:
                break
            last_byte = last_byte_dict[one_byte_short]
            unknown_string_block += last_byte
            input_block += last_byte
        unknown_string += unknown_string_block
        input_block = b'A'*min_addition + unknown_string_block
    return unknown_string

for line in bytes_to_str(byte_at_a_time_ecb_decryption_harder(ecb_encryption_oracle_harder)).split("\n"):
    print(line)
```
解密结果：

![image](https://user-images.githubusercontent.com/57308439/148503457-f7a0de4e-dffd-42bd-aaaa-57976eaf7b51.png)



## 2. PKCS#7 padding validation
>We get the last byte of the plaintext as n and make sure that the last n bytes of the plaintext are equal to n. If it is not the case, raise an exception.

要求实现一个函数，可以检测一段明文是否为pkcs#7填充，如果是话则去掉填充，不是的话则报异常.
总体很简单，代码如下：

```python
def checkPKCS7padding(string):
    l = len(string)
    c = string[l-1]
    paddingCount = ord(c)
    for i in range(paddingCount):
        if string[l-1-i] != c:
            print ("invalid!")
            return False
    print ("valid!")
    return True

string1="ICE ICE BABY\x04\x04\x04\x04"
checkPKCS7padding(string1)
string2="ICE ICE BABY\x05\x05\x05\x05"
checkPKCS7padding(string2)
string3="ICE ICE BABY\x01\x02\x03\x04"
checkPKCS7padding(string3)
```
运行结果：

![image](https://user-images.githubusercontent.com/57308439/148646901-ee324437-01ae-4fbb-ab5f-e873d0eecf6d.png)


## 3. CBC bit flipping attacks
>Start out by encrypting a normal token for a block of 16 bytes. This will be where we will inject our crafted block. Call this encrypted block current_block.
>
>We want to inject target = ";admin=true;abc=".
>
>We know that the plaintext block following our input is: next_plain = ";comment2=%20lik".
>
>When decrypting with CBC, the following is done: next_plain = next_block_pre_xor ^ current_block
>
>We can calculate next_block_pre_xor = next_plain ^ current_block.
>
>We want next_block_pre_xor ^ crafted_block to yield target, so we choose: crafted_block = target ^ next_block_pre_xor.
>
>Then, all we need is to swap current_block with our crafted_block to get admin access. The decryption of current_block will yield scrambled plaintext, but it is not a problem since it only modifies comment1.

此题涉及的知识为CBC翻转攻击

CBC翻转攻击技术可以通过修改密文来操纵解密后的明文。其原理就是如果对初始化向量中的任意比特进行反转，则明文分组中相应的比特也会反转，其原因是第一个明文分组会和初始化向量进行异或运算

具体图解如下：

![image](https://user-images.githubusercontent.com/57308439/148504246-c90c78b8-62fb-4011-b495-41e0aa9cae0b.png)

这里主要介绍一下CBC翻转攻击的关键函数，以便后期自我回顾加深

首先得到块长度和前缀长度，接着计算需要添加多少字节到前缀，才能使得其长度为块长度整数倍，接着计算要添加多少字节到明文才能使得其长度为块长度整数倍。然后将明文加长1个块长度（用?填充），对其加密。使用异或的方法，我们可以通过更改明文之前的块的字节来生成所需的字节。最后将伪造的密文片段放在一起，组成完整的密文

```python
def test():
    input_string = b'A' * AES.block_size * 2
    ciphertext = cbc_encrypt(input_string)
    required = pad(b";admin=true;", AES.block_size)
    inject = bytes([r ^ ord('A') for r in required])
    extra = len(ciphertext) - len(inject) - 2 * AES.block_size
    inject = bytes(2 * AES.block_size) + inject + bytes(extra)
    crafted = bytes([x ^ y for x, y in zip(ciphertext, inject)])
    if check(crafted):
        print("Admin Found")
    else:
        print("Admin Not Found")
```

完整代码如下：

```python
from Crypto.Cipher import AES
from Crypto import Random
import re


def pad(value, size):
    if len(value) % size == 0:
        return value
    padding = size - len(value) % size
    padValue = bytes([padding]) * padding
    return value + padValue

#这里参考了博客的做法，魔术方法好用
class InvalidPaddingError(Exception):
    def __init__(self, paddedMsg, message="has invalid PKCS#7 padding."):
        self.paddedMsg = paddedMsg
        self.message = message
        super().__init__(self.message)
    def __repr__(self):
        return f"{self.paddedMsg} {self.message}"


def valid_padding(paddedMsg, block_size):
    if len(paddedMsg) % block_size != 0:
        return False
    last_byte = paddedMsg[-1]
    if last_byte >= block_size:
        return False
    padValue = bytes([last_byte]) * last_byte
    if paddedMsg[-last_byte:] != padValue:
        return False
    if not paddedMsg[:-last_byte].decode('ascii').isprintable():
        return False
    return True


def remove_padding(paddedMsg, block_size):
    if not valid_padding(paddedMsg, block_size):
        raise InvalidPaddingError
    last_byte = paddedMsg[-1]
    unpadded = paddedMsg[:-last_byte]
    return unpadded



QUOTE = {b';': b'%3B', b'=': b'%3D'}
KEY = Random.new().read(AES.block_size)
IV = bytes(AES.block_size)


def cbc_encrypt(input_text):
    prepend = b"comment1=cooking%20MCs;userdata="
    append = b";comment2=%20like%20a%20pound%20of%20bacon"
    for key in QUOTE:
        input_text = re.sub(key, QUOTE[key], input_text)
    plaintext = prepend + input_text + append
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def check(ciphertext):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = cipher.decrypt(ciphertext)
    print(f"Plaintext: {plaintext}")
    if b";admin=true;" in plaintext:
        return True
    return False


def test():
    input_string = b'A' * AES.block_size * 2
    ciphertext = cbc_encrypt(input_string)
    required = pad(b";admin=true;", AES.block_size)
    inject = bytes([r ^ ord('A') for r in required])
    extra = len(ciphertext) - len(inject) - 2 * AES.block_size
    inject = bytes(2 * AES.block_size) + inject + bytes(extra)
    crafted = bytes([x ^ y for x, y in zip(ciphertext, inject)])
    if check(crafted):
        print("Admin Found")
    else:
        print("Admin Not Found")


if __name__ == "__main__":
    test()
```

解密结果：

![image](https://user-images.githubusercontent.com/57308439/148506129-c0bf8f45-1182-4658-a92b-82e2a0621367.png)

## 4. MTC3 AES key — encoded in the machine readable zone of a European ePassport
>![image](https://user-images.githubusercontent.com/57308439/148506396-1032b5fd-6f11-4fdc-aaba-9b36956eb5d1.png)

此题设计步骤较多，我将分步进行解析：

### 第一步
观察到此人护照有?，需要自我破译，根据所提供的护照校验位信息：

![image](https://user-images.githubusercontent.com/57308439/148506512-a818af89-cadd-4033-bbe1-77c5bbd3972e.png)

通过如下代码：

```python
origin = [1,1,1,1,1,6]
rule = [7,3,1,7,3,1]
t = 0
for i in range(0,6):
    t = t + origin[i]*rule[i]
    res = t % 10
```
得知？= 7

### 第二步：
目标：获取密钥种子

根据如下规则：

![image](https://user-images.githubusercontent.com/57308439/148506789-cea6bb41-fd1c-4a0c-878d-4a0bcbb32fea.png)

通过如下代码：

```python
new_res = "12345678<8<<<1110182<111116" + str(res) + "<<<<<<<<<<<<<<<4"
# 12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4
result = new_res[0:10] + new_res[13:20] + new_res[21:28]
#12345678<811101821111167
hex_result = hashlib.sha1(result.encode()).hexdigest()
# 十进制先变为二进制散列再换成十六进制
key_seed = hex_result[:32]  # 取前16位
print(key_seed)   #a095f0fdfe51e6ab3bf5c777302c473e
```
得到种子密钥：

![image](https://user-images.githubusercontent.com/57308439/148506955-816377ed-778a-4b9a-9a09-9b5580918c09.png)

### 第三步
求解Ka与Kb

查询证件访问秘钥相关规则，如下图：

![image](https://user-images.githubusercontent.com/57308439/148507028-a8208410-4874-4616-8ba2-fe0cb6e79890.png)

根据文件规则，不难求解

通过如下代码：

```python
c = '00000001'
D = key_seed + c
hex_D = hashlib.sha1(codecs.decode(D, "hex")).hexdigest()
# 十六进制先变为二进制散列再换成十六进制
ka = hashlib.sha1(codecs.decode(D, "hex")).hexdigest()[:16]
kb = hashlib.sha1(codecs.decode(D, "hex")).hexdigest()[16:32]
```

### 第四步
Ka和Kb奇偶校验生成最终的key

通过如下代码：
```python
def check(x):
    k = []
    a = bin(int(x, 16))[2:]
    for i in range(0, len(a), 8):
        k.append(a[i:i + 7])
        if (a[i:i + 7].count("1")) % 2 == 0:
            k.append('1')
        else:
            k.append('0')
    a1 = hex(int(''.join(k), 2))
    # print("this is " + x + "---" +a1)
    return a1[2:]

k_1 = check(ka)
k_2 = check(kb)
key = k_1 + k_2
print("key =",key)
```

求得key

![image](https://user-images.githubusercontent.com/57308439/148507232-06528b00-0c1f-4fdf-898f-c97f654c98b2.png)

### 第五步
最终先解密base64编码，将其与key解密

注意：由于题目中提到初始化矢量即IV为零，因此将IV设置为’0’*32

通过如下收尾代码：
```python
IV = '0'*32
b4code = "9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI"
cipher = base64.b64decode(b4code)
m = AES.new(binascii.unhexlify(key), AES.MODE_CBC, binascii.unhexlify(IV))
print(m.decrypt(cipher))
```
得到最终解密的的明文

![image](https://user-images.githubusercontent.com/57308439/148507359-8f2f4228-532c-45e0-bb96-0ac14d813487.png)
<h3>Herzlichen Glueckwunsch. Sie haben die Nuss geknackt. Das Codewort lautet: Kryptographie!</h3>

# 第三次大作业
## 首届（2016）全国高校密码数学挑战赛 赛题三 — RSA 加密体制破译
>RSA 密码算法是使用最为广泛的公钥密码体制。该体制简单且易
于实现，只需要选择 5 个参数即可（两个素数𝑝和𝑞、模数𝑁 = 𝑝𝑞、加
密指数𝑒和解密指数𝑑）。设𝑚为待加密消息，RSA 体制破译相当于已 知𝑚𝑒 mod 𝑁，能否还原𝑚的数论问题。目前模数规模为 1024 比特的
RSA 算法一般情况下是安全的，但是如果参数选取不当，同样存在被
破译的可能。
>
>有人制作了一个 RSA 加解密软件（采用的 RSA 体制的参数特点描
述见密码背景部分）。已知该软件发送某个明文的所有参数和加密过
程的全部数据（加密案例文件详见附件 3-1）。Alice 使用该软件发送
了一个通关密语，且所有加密数据已经被截获，请问能否仅从加密数
据恢复该通关密语及 RSA 体制参数？如能请给出原文和参数，如不能
请给出已恢复部分并说明剩余部分不能恢复的理由？

### 前置知识与说明
#### RSA
* 每个使用者，任意选择两个大素数𝑝和𝑞，并求出其乘积𝑁 = pq。
* 令𝜑(𝑁) = (𝑝 − 1)(𝑞 − 1),选择整数𝑒，使得GCD(𝑒,𝜑(𝑁)) = 1，并求出𝑒模𝜑(𝑁)的逆元𝑑，即𝑒𝑑 ≡ 1 mod 𝜑(𝑁)
* 将数对(𝑒, 𝑁)公布为公钥，𝑑保存为私钥

Bob 欲传递明文𝑚给 Alice，则 Bob 首先由公开途径找出 Alice 的公钥(𝑒, 𝑁)，Bob 计算加密的信息𝑐为:

>𝑐 ≡ 𝑚^𝑒 mod 𝑁

Bob 将密文𝑐传送给 Alice。随后 Alice 利用自己的私钥𝑑解密：

>c^e ≡ (𝑚^𝑒)𝑑 ≡ 𝑚^𝑒𝑑 ≡ 𝑚 mod N

#### 事项说明
* 模数𝑁 = 𝑝𝑞规模为 1024 比特，其中𝑝，𝑞为素数；
* 素数𝑝由某一随机数发生器生成；
* 素数𝑞可以随机选择，也可以由上述中的随机数发生器产生；
* 可以对文本加密，每次加密最多 8 个明文字符；
* 明文超过 8 个字符时，对明文分片，每个分片不超过 8 个字符；
* 分片明文填充为 512 比特消息后再进行加密，填充规则为高位添加 64 比特标志位，随后加上 32 比特通信序号，再添加若干个 0，最后 64 比特为明文分片字符对应的 ASCII 码（注：填充方式参见加密案例，但注意每次通信的标志位可能变化）；
* 分片加密后发送一个加密帧数据，帧数据文件名称为 FrameXX，其中 XX 表示接收序号，该序号不一定等于通信序号；
* 帧数据的数据格式如下，其中数据都是 16 进制表示，结构如下1024bit模数N | 1024bit加密指数e | 1024bit密文 m^e mod N；
* 由于 Alice 初次使用该软件，可能会重复发送某一明文分片。

相关例子如下：

![image](https://user-images.githubusercontent.com/57308439/148543234-f105f4cd-71f5-4e7f-a8b5-205ca53f7998.png)


#### 相关背景
RSA 的安全性是基于大整数素因子分解的困难性，而大整数因子分解问题是数学上的著名难题。数域筛法是目前 RSA 攻击的首选算法。 在 1999 年，一台 Cray 超级电脑用了 5 个月时间分解了 512 比特长的密钥。在 512 比特 RSA 算法破解 10 年之后，即 2009 年 12 月 9 日，768比特 RSA 算法即 232 数位数字的 RSA-768 被分解。分解一个 768 比特RSA 密钥所需时间是 512 位的数千倍，而 1024 比特所需时间则是 768比特的一千多倍，因此在短时间内 1024 比特仍然是安全的。除此之外，目前对于 RSA 算法的攻击主要有以下方式:选择密文攻击、公共模数攻击、低加密密指数攻击、低解密指数攻击、定时攻击等等，详细的 RSA 安全分析参见有关文献。

### 1. 解密方法分类
老师在群里发了一张破译图辅助完成大作业（开点小外挂

![`{J4B5(X1@SPB90JUEL~BWU](https://user-images.githubusercontent.com/57308439/148518030-b38dc263-16eb-4ee7-865d-4fa351bcb27a.jpg)

既然老师给了思路，就根据图中的内容对各种Frame进行分类（把列出上表的过程自己实现一遍。

题目给出了21个明文分片的加密结果。针对任意待加密明文，以8字符为单位长度进行划分，得到的结果随后进行相关填充，注意在填充过程中需要加入通信序号，可以通过通信序号进行片段还原。具体填充与加密过程可以参考过程及相关文件。根据文档，可以对提供的Frame0-Frame20进行密文解析，分离出重要参数模数n，加密指数e和密文c，脚本如下：

```python
for i in range(21):
    with open("/Users/mac/Desktop/RSA大礼包/frame_set/Frame"+str(i), "r") as f:
        tmp = f.read()
        ns.append(tmp[0:256])
        es.append(tmp[256:512])
        cs.append(tmp[512:768])
```

对解析得到的参数进行分析，分析方法如下：
* 遍历所有的模数N，判断是否存在模数相同的加密片段
* 遍历寻找任意两个模数N的公因子，如果得到不为1的公因子则可以成功分解这两个模数
* 遍历所有加密指数e，寻找低加密指数及对应的加密对
* 剩下的片段采用费马分解和Pollard p-1分解进行尝试
* 常规方法使用完如果还有剩余片段，可以采用猜测攻击的方法。当然，针对猜测攻击的结果需要进行游程计算，以验证结果的精确性。

编写相关脚本
```python
from math import gcd
n = []
e = []
c = []
for i in range(21):
    with open("Frame"+str(i), "r") as f:
        tmp = f.read()
        n.append(tmp[0:256])
        e.append(tmp[256:512])
        c.append(tmp[512:768])

with open("split_frame.txt", "w") as s:
    for i in range(21):
        s.write("Frame" + str(i) + ":" + "\n")
        s.write("n=" + n[i] + "\n")
        s.write("e=" + e[i] + "\n")
        s.write("c=" + c[i] + "\n")
        s.write("\n")

def find_same():
    same = "Same Frame_n = "
    for i in range(21):
        if n.count(n[i]) > 1:
            same += (str(i) + "/")
    print(same[:-1])

def find_gcd():
    for i in range(20):
        gcdd = "gcd_n = "
        for j in range(i+1,21):
            if gcd(int(n[i],base=16),int(n[j],base=16)) != 1 and int(n[i],base=16) != int(n[j],base=16):
                gcdd += (str(i)+"/"+str(j))
        if(gcdd[8:]!=""):
            print(gcdd)

def find_e():
    low = "low_e = "
    for i in range(21):
        if int(e[i],base=16) <= 16:
            low += (str(i)+"/")
    print(low[:-1])

if __name__ == "__main__":
    find_same()
    find_gcd()
    find_e()
```

得到结果：

![image](https://user-images.githubusercontent.com/57308439/148518814-9057a844-5e70-470f-89e0-a53c410c4849.png)

得出初步结论：
* Frame0和Frame4的模数N相同，可以使用公共模数攻击的方法
* Frame1和Frame18的模数N具有公共因子，可以通过因数碰撞法还原明文
* Frame3，Frame7，Frame8，Frame11，Frame12，Frame15，Frame16和Frame20采用低加密指数广播攻击解密
* 其余还有待探索，先进行下一步工作在做详细分析。

### 2. 低加密指数攻击
>相关原理如下:
>
>![image](https://user-images.githubusercontent.com/57308439/148519918-256fb02a-411b-4167-a3b1-34da5f34bdfa.png)

经过观察相应Frame各自的e时，还可以继续细分为：
* Frame3，Frame8，Frame12，Frame16和Frame20采用低加密指数e=5进行攻击
* Frame7，Frame11，Frame15采用低加密指数e=3进行攻击

#### e=3 的情况
若 c ≡ m^3 mode N
则可以计算如下公式

![image](https://user-images.githubusercontent.com/57308439/148521628-f32465f8-362f-4c8e-ac7a-9e2899c8fecb.png)

对此，可以从小到大枚举K，依次开三次根号，知道开出整数为止。

#### e=5 的情况
同理e=3的解密过程

#### 实现过程
首先找到各自的frame数据（其实我当时可以弄列表，更简易）

本次攻击涉及到的知识点有Euclid算法与中国剩余定理（具体内容信息安全数学基础已经掌握透了，不再赘述）

具体代码：
```python
import gmpy2
import binascii

# Frame7/11/15 采用采用低加密指数e=3进行加密
# Frame3/8/12/16/20 采用低加密指数e=5进行加密

# 求逆元
def euclid(a, b):
  if a == 0:
    return (b, 0, 1)
  else:
    g, y, x = euclid(b % a, a)
    return (g, x - (b // a) * y, y)

#中国剩余定理
def chinese_remainder_theorem(items):
    N = 1
    for a, n in items:
        N *= n
        result = 0
    for a, n in items:
        m = N//n
        d, r, s = euclid(n, m)
        if d != 1:
            N = N//n
            continue
        result += a*s*m
    return result % N, N

def e_3():
    frames = [{"c": 0xB1E7F916884F9D17DFFCB8EF1A93D61E3DA73E066CE8B71F09BB8EF61C833300CB472854FF642F540DB232DED17095F4FDDCA6CCCC27628EA781F546863FA431B9057FA7DC1AA41C127FB22B113E512B14926CA0C361DD6DAAEBC3F2E9CE51D012F40173CF88F07752CAAABA06AE53C4DBD559F50EED636A0A2E65D6BD835BD0, "n": 0xDD1B58FF0DE86CD28DFFB60CC1EE0EFA3250D58264B3DA9CEAA5B5C17C728741F728C462C347DCB707BA7EE8672295F5A750C19D48AE23A32FC21E76F3188B85008E4EC1A66371BBB0825E558E876D80FA59E7099AF25B0B298131277E634772F24EE0ED1BACD3BA6F8D8E443D5AE16FAF6AA7DBAA59F91F763E4EAFD7D7F5CD},
              {"c": 0x9A597210DA69760A66B063FA125DC17DC2038EC720CAE6D0B1599EC25B9A19F328BC55882EE9ED05FC9BD90276B0F7F1D227946FFD77081DF6E08976EBF57A3BB21AC13FE25A742A0C137E007BD8787A42683D81ADC28450051B44617C2081D5ACA3141DC2C848F1401CEA94DA7D11142BB2406306B299953D1C28259521EA11, "n": 0x9FEDDC9C122AA836E9A04FE9358A118B358C7BC6F3ABDE4E035E2BCB15B52950DB1D23449EA62F83406FB591ED39564FD0E2DAD0954156037BB32C9C23C49DA83E2E85BC09A9B6FD75E2F55129044FA0F996895E8BF5E53D88938E4A3366649E97961BE5B7B4095476D013D2E9F6FE75DC21295747BF371AE346355A5ADBD93F},
              {"c": 0x4A6972B03F96CC30DE3F60DA66C71842E600320964A69EC818047B219506A12F3E4D522B40B10EB3F630A068C908186F29BF782360E35262A4CECCAD554F57D1721DB61B260AC6C5FBCB020AC326562048B0FC9270AFE51C63F5F27A9A3CFD78B5971D5CBF7FBF20E23CA7B429121BD0BB9AE0552D6907C659E2B450B01675D7, "n": 0xD2611805B6839FD983F2C574BDAD1C50A4FB9FAB35F3BB643F90A9FBB0B84AF1D042E35E821564FCA783F1A2AF41349BB3E1C159B20EA6A0DB9E70597CB5C0780EF6CD78481AEAC0DF65A8DE35A8B5021FCE55332C5B2ADAEDCF80963BD6FFF773CAB55D73637C9BD667148FB1359782D38C41CBB43FA5FD56F424F842D8683D}]
    items = []
    for i in range(3):
        items += [(frames[i]["c"], frames[i]["n"])]
    x, y = chinese_remainder_theorem(items)
    m = gmpy2.iroot(x, 3)[0]
    result = binascii.a2b_hex(hex(m)[-16:])
    return result

def e_5():
    frames = [{"c": 0x76CBCAF659936784799208C3EE2420B7BBFDBB9AA8D7C89874C11314DF5DECD3AA97F3DA89851A043AF16E6570E7D03A4F3225D49E552FAA2FB9F6A19AE95BA73ECD6E7CC05CD9C03E03E06F829042DBA4C1A91F39AC0CAD516C8DE7FB45939A2038C24C13F7F62A20040473D8F3D8339A4B30A65715F98A43CC3293E51190D5, "n": 0x8365D1FF23709FAAEF6330AECA9C848B292E0872C5C41E8CBE9D0780F32EBFC5FCC7947BD666F06AA619F952AFB8D7C08B9211960D1916235D8AB3A60DEC45B1EF5CC21848E56D5235717186EAD51AE22A5661BDFDC42E31F9181F6AB1D070FDEBB078A9980D7A0571B587130A1D3056CBA40CBBA287CD5031838BAB893B476B},
              {"c": 0x246F3344F2C341FDA293ECB4214C14D57164CB37FB364ED14B2FE3D10C94D2365155959B481085379A9C85B9FCB86C7E3676B2BFD98DF7055D7E474CFEE6CE3529980A3FA0C537AF9C375E606E89B19D34FC801200DB462538E2E9FE80803A8EF02F662D0E5AC9C35DCE7A758B9EFD6D5FEA73BD9649C9B651E5AA5F1D96A773, "n": 0x9288E1EEF599EA72113D950723A8FC0ADD096C7312D8E78911FE64A4322C4FEC96FD70B345AA5A345481FB91D8549998A90E2429DCAF1EEEC863F396479A0BBD121E36B0EFAC8D002FC95B58B5879DD75251B5CEFCBE90BF50669742821BE2E89B3831FD6F0F3EAB310E5BF3FC66D702D5FF1581EE1DEFF161EFCA359063C6AB},
              {"c": 0x3F312B5FDA3A9AA43DE2697FA001EE909DFE677AA6A48BEAF84991FF7D423596B5CC230DB4E5BE42E7C886E1FA6B39002B148F670C3B162816EFCC6341A96D3CDCF849A35B866EFB9E5F5C48DF9BBD3F065FFA3E0961EB2393C6F2689B72603B21A2E1C674EE2A1A6534CA01F5606B062FB53CA9C3EB1BEC80AC6849B090A7EF, "n": 0x808B8F96E7255B3F169EE854ABE0CD0AC7A4AE1B388CBC9A234E225842208A435842C254A55855B867F3FCA78E3887C8D1663B501A5D4D5E32F3EF84847F45651A5E2FC8A091E12E2B4DB7AB41113D258E2200FFB2BBF8B7C38B0049B3E2E60C65EB8B6375F03A40DC9F9AB01FEC60E09DC8CA3644A83738BDA0CFDB2B5ABB3D},
              {"c": 0x224CD570EAF4D650AA24D51127E1657D201C8483AA690D48D58CA56AE86EA517DF43F9F130CC7CA75C8868623BA145189E2D16326A82A437516530D130161552D016ADB2D8746DC92D30F2A4D90A50A63AF038B0449CF2A3442BA6696B6485A46D47545591AADB1C68E901745D4F9231627C9E0C0A52CC7439CC45B21AE51AEE, "n": 0x811F75BEAD6F0C3EA1560CFA4BFD4762F1DA3A30E22644AB16B1BEA5A6A1AF14F0C3C2E63865FD29241246C1473892232DAB6224AF1600F73340CBCA7BF5AF01EA1FA007E46064CE2F8DD92A9E7FA9F16CFEEE5A6CF67683BCD97F1E7E1BA73A9F86A8E4D7496393AC9727D10530A76B03B3A23321E8BDD756FCE265494F6D35},
              {"c": 0x210B2C8CA031259D2EF22A2561B23B794B3740382BD0A89EF7DB9E62463C8649EF5983EB94CFF6F0D6A1881A0D4E190EF8A1ACC20DA5DA71AE31705A5501B6856C151449DFC76B7026A9FAB74AA4B41C7F58ECCDC35777866C117D3BE1E37A4576E34C90DF7B8146F1BDF841D1362287A4922CB9A80221EC165E48F0BFFD4EDE, "n": 0x8178408D7E1155B9F5B0665A3EDFE279189567AAC333CA33A7304AE1BB9C9A921735888FB7BC9B41550817B1C0D42B2AB0304546709648F45147180AD5FC839FB8F90B2D30772718A7B45E6204CE7886122874759F93C198CE61D10555F03C13FD83E639A637D849C846D5589029533E567E12FD992D690EC5EF38569327FC8D}]
    items = []
    for i in range(5):
        items += [(frames[i]["c"], frames[i]["n"])]
    x, y = chinese_remainder_theorem(items)
    m = gmpy2.iroot(x, 5)[0]
    result = binascii.a2b_hex(hex(m)[-16:])
    return result

print("Frame7:  ", e_3())
print("Frame11: ", e_3())
print("Frame15: ", e_3())

print("\n")

print("Frame3:  ", e_5())
print("Frame8:  ", e_5())
print("Frame12: ", e_5())
print("Frame16: ", e_5())
print("Frame20: ", e_5())
```

运行结果：

![image](https://user-images.githubusercontent.com/57308439/148522411-640f8ce3-3b41-43f9-8c1f-3ed47d95f97b.png)

发现e=3的Frame无法成功解密，均为不可识别的乱码，故需要使用其他方法破解Frame7、Frame11和Frame15，这里先暂时按下不表。

### 3. 公共模数攻击

>参考原理如下：
>
>![image](https://user-images.githubusercontent.com/57308439/148538592-fc2fa0bb-07a1-4f60-9c24-f76107eb5609.png)

具体实施来说，就是攻击者截获c1和c2后，通过扩展欧几里得算法便可以求出明文

相关代码如下：
```python
import gmpy2
import binascii

# 欧几里得算法
def euclid(a, b):
  if a == 0:
    return (b, 0, 1)
  else:
    g, y, x = euclid(b % a, a)
    return (g, x - (b // a) * y, y)

# 公共模数攻击
def same_modules():
    # 寻找公共模数
    n = 0x803F734ED9E3A3FBDEF8E3540B7B676FB66D15D2E5139840CB3CD06E62634C00A48EA2BF9BC3D7A709DBB47BE7E27DFB2C0E5B81254E6C326691471AE6DDC4A35539018BA6305DAFF1C480F195118B1310C546C31FE62C7AEC2A947013AC2897D00FD60E7B792DD499315341895BD1D1C9AA923E9373E1E01E2856B4FC8C6893
    e0 = 0x42A04A989C5800528EF687C978355E9C4AFD410A9DD4B08CCA7669C747CCE5446D5E85022CA2A2C383C28E85AD038C37CED2E18BD88529BD2480E20191958497C61823378CA06DE01C8B6FB148C9BC935E433EFCD960A1BF841FD60599811941A122CB1A323A76367EE78D71870B7134881CA077518C809013AE8EC6BAECD519
    c0 = 0x45446FC78AC9AA9F2E38197D44B76F0C2A7DED354615D906608016E9F884FA51E20893FA0AEAF5975E28A68FBCD9BA469EA00263F812523EEC79E0CF967190317BEF53EE8FF29AF4411A238E7FCE148AE7603C9A1DEC4EEAC1E41AD5FB8725FD3DCE4C058DB10F279B3EC1FA3EBC6584547D29501CCA52851148344316073E6B
    e4 = 0xD8BFFCDD82504C05A241E26742F0A867B162E5ECBF185E66F0A5FCA1801A2C3A2A562549D433C600E3A4085C123535AA7AD14D55C0B3765C55C5B78B946517C14438AD876EC0F7AC22792988BB6CD7837AA64334EB5F7C668D570CBF8134B7F7E87EEFA95179CA11BEDCDF420EB6DF9178C0A3B489A07B86EBCA6ADF96982D0D
    c4 = 0x1BDAF2DBCEC34D6602C949E9B53876A4D8B62FA69DD960063B342E5101F92A0F5D88A445D7BDF36F3816AEBD5A98A8F06AB2CD708E363A657665CF05CB1F289EB758E09D11351816DF1EDF4575F01F95EFCE164D62EEE92BCE562B94B451FD9B566E4F8625E0428AD93BC6F8342C089AF2842EA6DEB9ED22D450F062CC7B18A8
    s = euclid(e0, e4)
    s0 = s[1]
    s4 = s[2]
    # 求模反元素
    if s0<0:
        s0 = - s0
        c0 = gmpy2.invert(c0, n)
    elif s4<0:
        s4 = - s4
        c4 = gmpy2.invert(c4, n)

    m = pow(c0,s0,n)*pow(c4,s4,n) % n
    result = binascii.a2b_hex(hex(m)[-16:])
    return result

print("Frame0:", same_modules())
print("Frame4:", same_modules())
```

求解结果：

![image](https://user-images.githubusercontent.com/57308439/148538910-d46bf715-ef4a-4a47-8603-df02c9bb2dc5.png)

### 4. 因数碰撞攻击
>相关原理如下：
>
>如果参数选取不当，p和q在多个rsa加密中出现多次，则生成的不同的n可能会有相同的因子。
>
>假设p相同，q不同，则有
>![image](https://user-images.githubusercontent.com/57308439/148540489-d0820c73-8ed9-4f7b-bb8f-d2296cd99bca.png)
>
>此时便可以很快将他们各自的私钥求解出来。

为此，我们不难构造出碰撞函数及其具体实现代码：

```python
import gmpy2
import binascii

def crash():
    n1 = 0x845334AC0B3EB2239FDF0E3069750901E791CB774AD36941E30D85E5A0FED57749A30DC1F1F4CB191D9863F437C98293E8E8888B963BCF16B691F1D4EEF56C6807440E5FB5EC5B95DF3434DEDA30C60DCB4E77294BE027F984D5E675AEB1CBBE57E8CAF140226EAD6DCD9A9636A0CFF586FA434804CB09D7E8C48DE34EBE9049
    e1 = 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001
    c1 = 0x0251025DC5FB84476581D0F67C640D8927DA6D083627C9C29F3174C17CFE316A6218194DD4BE03D30EF9ECCBB4C609673D853590DD122B151DCFD6D75FD202DC2C758E897BABE0A4CD842FF35D086CF4E34EFBD09E8FF9FBFB4B5254CA2323A463139ABD16E301C37F683579BA624EFBB297B9E6D5A1C68F75EB4BADF9AA198C
    n18 = 0x84FF95E263D30FAD83684CC08B11DAB54F5A0F3D24A8763C47B57750ED2E342022652836E2EBB30A765DC7364F417E4555D1FD72D140EFB72E283007028CC2A4FE97E4FE3B5D272C917E734F8715A0C5BFF2900640D8097425AFA965F9B1566F339F155ACEB59EDE241327813C920A6FB98A6BB9209379F1BBEBCC955949D8BB
    e18 = 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001
    c18 = 0x45D8BD62BBF9966C81722D6D4AD5E6E91FD5258C8B0747CA166237D167D5C881B100D83D73352F18A60914963CA8F7DF9B9211273C8D7EDAC87132AADAC33DEF0BDA6C9EA91750818D869990521C6BA0A10BC1AC2273282FA4AC47EFBEEE99B2D35EBDA2019D1EF8BF24B5017FA8481B372362AAE138043A00D8761BCDCA80BC
    prime = gmpy2.gcd(n1,n18)
    p = prime
    q1 = n1 // p
    q18 = n18 // p
    s1 = (p-1)*(q1-1)
    s18 = (p-1)*(q18-1)
    d1 = gmpy2.invert(e1,s1)
    d18 = gmpy2.invert(e18,s18)
    m1 = pow(c1, d1, n1)
    m18 = pow(c18,d18,n18)
    result1 = binascii.a2b_hex(hex(m1)[-16:])
    result18 = binascii.a2b_hex(hex(m18)[-16:])
    result = result1 + result18
    return result


print("Frame1: ", crash()[:8])
print("Frame18:", crash()[8:])
```

运行结果如下：

![image](https://user-images.githubusercontent.com/57308439/148540732-725fba6a-521f-413e-b356-965cab1c6ab7.png)

### 5. 费马分解法
>相关原理如下：
>
>![image](https://user-images.githubusercontent.com/57308439/148541012-4115c5f8-4843-4dfa-be8b-0717c8524d79.png)

定义函数fermat()，用来爆破剩余未解密的frame，从而列举出p与q相近的样例，最后发现frame10符合

函数代码如下：
```python
def fermat(n, verbose=True):
    n = int(n,base=16)
    a0 = gmpy2.iroot(n,2)[0]+1 # int(ceil(n**0.5))
    count = 0
    b = 0
    while count<1000000:
        a = a0 + count
        v = a*a - n
        if gmpy2.is_square(v):
            b = gmpy2.isqrt(v)
            break
        count += 1
    if (b==0):
        print("error")
    p= a + b
    q= a - b
    return p, q
```

随后根据原理编写实现代码：
```python
import gmpy2
import binascii
import math
from split_frame import n,e,c

# Frame10

def fermat(n, verbose=True):
    n = int(n,base=16)
    a0 = gmpy2.iroot(n,2)[0]+1 # int(ceil(n**0.5))
    count = 0
    b = 0
    while count<1000000:
        a = a0 + count
        v = a*a - n
        if gmpy2.is_square(v):
            b = gmpy2.isqrt(v)
            break
        count += 1
    if (b==0):
        print("error")
    p= a + b
    q= a - b
    return p, q


def frame10(n,c,e):
    p = fermat(n)[0]
    q = fermat(n)[1]
    s = (p-1)*(q-1)
    n = int(n,base=16)
    c = int(c, base=16)
    e = int(e,base=16)
    d = gmpy2.invert(e, s)
    m = pow(c, d, n)
    result = binascii.a2b_hex(hex(m)[-16:])
    return result


if __name__ == "__main__":
#    print(fermat(n[10]))
    print("Frame10: ", frame10(n[10],c[10],e[10]))
```

运行结果如下：

![image](https://user-images.githubusercontent.com/57308439/148541369-fd0f80aa-4456-452c-9833-8a1c7d3bd181.png)

### 6. Pollard p-1分解法
>相关原理如下：
>
>![image](https://user-images.githubusercontent.com/57308439/148541477-26b0145f-356b-4348-a033-d413d9559a40.png)

为此，先编写函数pollard(n)，来找到p-1或q-1能被小素数整除的样例，最后经过爆破发现Frame2,Frame6,Frame19的模数可以使用该方法分解

相关函数如下：
```python
def pollard(n):
    m = 2
    max = 2**20
    for i in range(2,max+1):
        m = pow(m,i,n)
        factor = gmpy2.gcd(m-1,n)
        if (factor>=2) and (factor<=n-1):
            t = n//factor
            n = t*factor
    return factor
```

同样根据原理，我们不难得到最终的解密代码：
```python
import binascii
import gmpy2
from split_frame import n,c,e
import math

# Frame2,Frame6,Frame19
def pollard(n):
    m = 2
    max = 2**20
    for i in range(2,max+1):
        m = pow(m,i,n)
        factor = gmpy2.gcd(m-1,n)
        if (factor>=2) and (factor<=n-1):
            t = n//factor
            n = t*factor
    return factor


def pollard_resolve(n,c,e):
    n = int(n, base=16)
    c = int(c, base=16)
    e = int(e, base=16)
    p = pollard(n)
    q = n // p
    s = (p-1)*(q-1)
    d = gmpy2.invert(e, s)
    m = gmpy2.powmod(c, d, n)
    result = binascii.a2b_hex(hex(m)[-16:])
    return result

if __name__ == "__main__":
#    print(pollard(n[2]))
    print("Frame2:  ", pollard_resolve(n[2],c[2],e[2]))
    print("Frame6:  ", pollard_resolve(n[6],c[6],e[6]))
    print("Frame19: ", pollard_resolve(n[19],c[19],e[19]))
```

运行结果如下(由于需要考虑爆破时间，运行时间较长)：

![image](https://user-images.githubusercontent.com/57308439/148541933-02d961b6-7f7a-4276-a95d-bb74dedc7975.png)

### 7. 整理现有解密内容
>![image](https://user-images.githubusercontent.com/57308439/148542180-b80826a5-873c-4e92-aed1-4353f1308127.png)

### 8. 猜测明文攻击
对于剩下的8个frame，我只能采用猜测明文攻击。

当我们仔细观察现有明文时，不难发现部分明文或暴露出关键信息。

比如：

* Frame0  : 'My secre' 补齐大概率是My secret ...
* Frame1  : '. Imagin' 补齐大概率是. Imagine ... 或 . Imagination ...
* Frame3  : 't is a f' 极有可能与Frame0合并构成My secret is a f...
* Frame19 : 'instein.' 补齐大概率是... Einstein.

至此，可以推测明文为爱因斯坦的一句名言。

通过谷歌搜算关键词，找到相关信息

![image](https://user-images.githubusercontent.com/57308439/148544358-c08959a1-aec8-44c7-86aa-6abc13b2d041.png)

![image](https://user-images.githubusercontent.com/57308439/148544422-dba7f514-92eb-4ace-80cd-c31a2d704c4c.png)

>"LOGIC WILL GET YOU FROM A TO B.  IMAGINATION WILL TAKE YOU EVERYWHERE." –ALBERT EINSTEIN

但是secret没有出现，猜测也只能到此结束。

### 9. 破解随机数生成器
随后在群里翻找答案，看见shallow说过（真是太强了！！

![image](https://user-images.githubusercontent.com/57308439/148544766-faee035c-88e5-49d0-8097-0e08c0f416d0.png)

那就按照他的提示在题目要求里也找到了相关说明，顺便搜了一下随机数生成器在密码学中的相关实现方法。

若能破解这个随机数生成器，便可以获得所有参数以及明文。

最常见的随机数生成器是线性同余， 我先尝试在Frame1中得到的素数进行尝试，求解如下过程：

![image](https://user-images.githubusercontent.com/57308439/148545120-41a4b937-d5c1-4a99-99dd-7af856c4587e.png)

得到a = 365, b = -1

所以Xn = 365Xn-1 - 1 mod 2^16

随后验证其正确性：

由于第二组16bits为1111111010000101，对应十进制数为65157，代入公式求得第三组16bits为58272，转换为二进制数也就是1110001110100000，而通过现有的数据查询第三组16bits正是1110001110100000，验证正确！！！

此外，由于部分N的因子大于512bit，必须修改参数暴力破解

至此，故可以根据这个随机数生成器来对所有的N进行分解：

```python
from gmpy2 import *
import time

N = [
    90058705186558569935261948496132914380077312570281980020033760044382510933070450931241348678652103772768114420567119848142360867111065753301402088676701668212035175754850951897103338079978959810673297215370534716084813732883918187890434411552463739669878295417744080700424913250020348487161014643951785502867,
    92921790800705826977497755832938592891062287903332844896046168726101016067456726822505517352409138948392871113192427210529297191908638888388136391240683157994654207338463678065440899870434887094216772312358731142317774259942199808535233769089985063860828267808621928898445383706310204223006136919334252875849,
    # 90252653600964453524559669296618135272911289775949194922543520872164147768650421038176330053599968601135821750672685664360786595430028684419411893316074286312793730822963564220564616708573764764386830123818197183233443472506106828919670406785228124876225200632055727680225997407097843708009916059133498338129L,
    92270627783020341903769877272635163757611737252302329401876135487358785338853904185572496782685853218459404423868889360808646192858060332110830962463986164014331540336037718684606223893506327126112739408023014900003600028654929488487584130630596342720833061628867179840913592694993869009133576053124769728363,
    90058705186558569935261948496132914380077312570281980020033760044382510933070450931241348678652103772768114420567119848142360867111065753301402088676701668212035175754850951897103338079978959810673297215370534716084813732883918187890434411552463739669878295417744080700424913250020348487161014643951785502867,
    99193711547257063160816850544214924340574358752670644615293764532335872088470223740970673347993652626497557387222167784182876395436088845281840169701654629849214222297784511349059698963212947299142320497759258889425182705042123217476724761095690092179821753840224757786599021225709340258545979566824267620959,
    # 146839643970016464813197409569004275595828791825722617066607993001682901023784267554815946189374651530288894322286859792246413142980277245909181062525398546369553995023529451396820549308690493928593324007689135648753323161394735120908960458860801743476353228970081369439513197105039143930008573928693059198131L,
    155266493936043103849855199987896813716831986416707080645036022909153373110367007140301635144950634879983289720164117794783088845393686109145443728632527874768524615377182297125716276153800765906014206797548230661764274997562670900115383324605843933035314110752560290540848152237316752573471110899212429555149,
    102900163930497791064402577447949741195464555746599233552338455905339363524435647082637326033518083289523250670463907211548409422234391456982344516192210687545692054217151133151915216123275005464229534891629568864361154658107093228352829098251468904800809585061088484485542019575848774643260318502441084765867,
    97767951046154372321400443371234495476461828137251939025051233003462769415459435471728054384852461870179980010660162922547425212869925648424741526671585598167502856111641944825179295197098826911226483155821197251989297102189187139234080795582529077092266799813985026581245196104843272305656744384140745492897,
    93836514358344173762895084384953633159699750987954044414830106276642828025218933012478990865656107605541657809389659063108620208004740646099662700112782252200834393363574089818787717951026690934986964275526538236750596344542450864284576226592039259070002692883820960186403938410354082341916474419847211138467,
    112306066601652819062206435724795595603085908011001671184332227488970057128128821831260649058569739569103298091727188365019228385820143813415009397359257831092635374404034997011441653286642458431865026213129412677064308342580757248577955071384972714557250468686599901682728173096745710849318629959223270431039,
    90267480939368160749458049207367083180407266027531212674879245323647502822038591438536367206422215464489854541063867946215243190345476874546091188408120551902573113507876754578290674792643018845798263156849027209440979746485414654160320058352559498237296080490768064578067282805498131582552189186085941328701,
    # 94390533992358895550704225180484604016029781604622607833044135524814562613596803297695605669157378162035217814540004231075201420796787547733762265959320018107419058832819010681344133011777479722382525797938558181629835768471461434560813554411133962651212455645589624432040989600687436833459731886703583047283L,
    120008876536855131221255979370745233738591934188224528487535120483456214085493237482915446419599357910343450285858995374277365393767669569942204888383426461862651659865189178784473131914234181752055950431093341514138390898892413182538823693941124637301582389014479754627419560568004831093116617428970538503551,
    147733349387696521015664992396355145811249793103958464053225389476050097503928022819269482555955365534137156079172704297584033078453033637103720972881068435459202133846880715879894340131656691631756162323422868846616160423755883726450486845175227682329583615739797782025647376042249605775433971714513081755709,
    90673177193017332602781813187879442725562909473411994052511479411887936365983777106776080722300002656952655125041151156684340743907349108729774157616323863062525593382279143395837261053976652138764279456528493914961780300269591722101449703932139132398288208673556967030162666354552157189525415838326249712949,
    # 111178307033150739104608647474199786251516913698936331430121060587893564405482896814045419370401816305592149685291034839621072343496556225594365571727260237484885924615887468053644519779081871778996851601207571981072261232384577126377714005550318990486619636734701266032569413421915520143377137845245405768733L,
    93394639108667212482180458616036741615058981058942739509025631675767304945732437421192075466824789572910657586684470553691049259504106442090140927782673066834126848556317079995332229262871079799089771973100731889841015960713908117908583988637159206246729697336281050046919985463146705713899703248595045701819,
    # 94154993593274109828418786834159728190797445711539243887409583756844882924221269576486611543668906670821879426307992404721925623741478677756083992902711765865503466687919799394258306574702184666207180530598057989884729154273423032471322027993848437082723045300784582836897839491321003685598931080456249945287L,
    90916739755838083837461026375700330885001446224187511395518230504776419813625940046511904838818660297497622072999229706061698225191645268591198600955240116302461331913178712722096591257619538927050886521512453691902946234986556913039431677697816965623861908091178749411071673467596883926097177996147858865293]

Nd = [
    # 90252653600964453524559669296618135272911289775949194922543520872164147768650421038176330053599968601135821750672685664360786595430028684419411893316074286312793730822963564220564616708573764764386830123818197183233443472506106828919670406785228124876225200632055727680225997407097843708009916059133498338129L,
    146839643970016464813197409569004275595828791825722617066607993001682901023784267554815946189374651530288894322286859792246413142980277245909181062525398546369553995023529451396820549308690493928593324007689135648753323161394735120908960458860801743476353228970081369439513197105039143930008573928693059198131,
    # 94390533992358895550704225180484604016029781604622607833044135524814562613596803297695605669157378162035217814540004231075201420796787547733762265959320018107419058832819010681344133011777479722382525797938558181629835768471461434560813554411133962651212455645589624432040989600687436833459731886703583047283L,
    # 111178307033150739104608647474199786251516913698936331430121060587893564405482896814045419370401816305592149685291034839621072343496556225594365571727260237484885924615887468053644519779081871778996851601207571981072261232384577126377714005550318990486619636734701266032569413421915520143377137845245405768733L,
    94154993593274109828418786834159728190797445711539243887409583756844882924221269576486611543668906670821879426307992404721925623741478677756083992902711765865503466687919799394258306574702184666207180530598057989884729154273423032471322027993848437082723045300784582836897839491321003685598931080456249945287]


def BFFactor(fname, n):  # 细分
    s = time.clock()
    for f16bit in range(1, 65537):
        print
        '\r', f16bit,
        Xn = bin(f16bit)[2:].zfill(16)
        while len(Xn) < 1000:
            Xn += bin((365 * int(Xn[-16:], 2) - 1) % 2 ** 16)[2:].zfill(16)

        while len(Xn) > 980 and int(Xn, 2):
            # print Xn
            if gcd(int(Xn, 2), n) != 1:
                print
                'Frame %s Factor found!' % fname
                print
                'Factor1:', int(Xn, 2)
                print
                'Factor2:', n / int(Xn, 2)
                print
                'Timer:', round(time.clock() - s), 's'
                return ''

            Xn = Xn[:-1]

    return '[!!!]Factor not found!\n'


def FindFactors(fname, n):  # 小于 512bits
    for f16bit in range(1, 65537):
        Xn = bin(f16bit)[2:].zfill(16)
        while len(Xn) < 520:
            # Xn.append(bin((365 * Xn[-1] - 1) % 2**16)[2:])
            Xn += bin((365 * int(Xn[-16:], 2) - 1) % 2 ** 16)[2:].zfill(16)
            # xn = ''.join([bin(i)[2:] for i in Xn])
            if gcd(int(Xn, 2), n) != 1:
                print
                'Frame %s Factor found!' % fname
                print
                'Factor1:', int(Xn, 2)
                print
                'Factor2:', n / int(Xn, 2)
                return ''
    return 'Factor not found!\n'


for fname, n in enumerate(N):
    print
    FindFactors(fname, n)
```

得到如下结果：
```
Frame 0
p=6812427463539231600349464320632373878259506266011361351387035583576132041989251176508636878569037408377298402530520856411137155634830256279629494046731167
q=13219767207586640795571526377541732890465157517028423385812256305169857431521906172089205698188779144534548881591815311408600403492889107894773842719465101

Frame 1
p=7273268163465293471933643674908027120929096536045429682300347130226398442391418956862476173798834057392247872274441320512158525416407044516675402521694747
q=12775796067504534889308793837705093856447186276434607181291462366302734214583227473619414509043813033676998357747882057607288385639737162184366176530607467

Frame 2
p=52484065122572767557293534477361686456679280880304125291106733197354892893647364164212186415880889674435558369420400890814461263958618375991691022752189839
q=1719620105458406433483340568317543019584575635895742560438771105058321655238562613083979651479555788009994557822024565226932906295208262756822275663694111

Frame 3
p=7055398260479522499340383681532186847092995337600547504968011029334785849248198827261592108738030900350146800969715064939422943632175860165796992047655507
q=13078018330994845621552747855429996741129628768867676788710615773048246855802311926334525991481279783903078961691672741494174797757666145632542141818518409

Frame 4
p=6812427463539231600349464320632373878259506266011361351387035583576132041989251176508636878569037408377298402530520856411137155634830256279629494046731167
q=13219767207586640795571526377541732890465157517028423385812256305169857431521906172089205698188779144534548881591815311408600403492889107894773842719465101

Frame 5
p=8534204848837515931975393694743604482233978795239717717444249645500744498481212186170560396980739879301795276459915005215431744867752453542213016868639743
q=11623075998787245402346559750331455079165060117337930034889727146620333293916811257160778523014841986594526205881807563317848049715664071879977965137310113

Frame 6
p=159482692259010816139523195494724350795654007589889398757383554027183924116413427533184220914037106543253535103452324841452565420868944985464229649420240708554088156331324206733727690785373464575525698274552058386560106163093965065830071277465943834308083708065429495092746028681968670036721164931
q=920724637201

Frame 7
p=12406300145307944335209213373018196725715201666535385618794522686524721950743049201561939737652055430279463659191670498628785792792237461236532551241091557
q=12515132804905159708127766136325707992321377113998710477445811836263405233128780498152047439057240132542217905573440500557504942936575400253824837109325257

Frame 8
p=8649620751833675845720949489383858845796447401365353800898878144845175406172676844999275150219630606359684669242320399096050331623719946048021382644892803
q=11896494295276874055593281869319334151651783133808673396575485807068776793606182148494465816391713137317129560972663854384901692609500496853548961122888889

Frame 9
p=9578503710865082752572619447703250581238252879412822133271432204532787671643027893670256331928358458734493559747171810834463456086852684437858903431104943
q=10207017087152588040715048402680785398862222629910637172475793288776252558629748676497021478354292685455714591071372731030921157909006333951719151324136879

Frame 10
p=9686924917554805418937638872796017160525664579857640590160320300805115443578184985934338583303180178582009591634321755204008394655858254980766008932978633
q=9686924917554805418937638872796017160525664579857640590160320300805115443578184985934338583303180178582009591634321755204008394655858254980766008932978699

Frame 11
p=10567461048505039641972710268713128944634687748250712080474984695584136876402672898538333956369978635390580930966654058991315304961329166742263216335895001
q=10627535420870140157264943381237995845188613757283488311986534170673076876359166440468642831586000127005789867628311873382408383407839525066568105400526039

Frame 12
p=6985860474362742689823213380101231514167124463232248283942151780607845942841460091693138693954396501918480507964569322391710334462720533595017918609916463
q=12921454883136991414340641129184178393731045365222406074761149065515779165690863384311170163255060973667442222325395407973824379536104548265452893540473427

Frame 13
p=28159870572597920594563893250499572739237769660647238839011417383170724985058502301163390234256825164330439886062865686161169349465086627567328776299903327
q=3351951982485649274893506249551461531869841455148098344430890360930441007518386744200468574541725856922507964546621512713438470702986642490397676148760429

Frame 14
p=10954856299233465126359914171500305822846165431085183673999109759449706415739193445885099004577509868426540084786683485568001351280541116090063034118634519
q=10954856299233465126359914171500305822846165431085183673999109759449706417636519711881707731622506407722143163847672064459333431572992021257881551867597529

Frame 15
p=12129590228679741504121711843970362493049315734589299243022334854180628199056110072388206407916677887428330057500003256795368137540193144088105889375346813
q=12179582871512776468956891745877445010350618063676813770961929030122878089063984750168929497808121238411849832804023412100455762402728468432020965274841793

Frame 16
p=6998204055345503454608535735199373144581147952412423572966494183179306005216278935510553634487794945379209006773628864213102839984362642462197184843259867
q=12956635227542071202375560927144520333507358619831580670377595997503810379893056493870213428580918250332435506596912071784762831942734238145246920736537647

Frame 17
p=33168227830849222860094691158174263663422336899723339302414624335921937096795361698659264621281924482566876836548283550012466892022559940789243695658550143
q=3351951982485649274893506249551461531869841455148098344430890360930441007518386744200468574541725856922511753810518751644117399610974624147782234049900131

Frame 18
p=7273268163465293471933643674908027120929096536045429682300347130226398442391418956862476173798834057392247872274441320512158525416407044516675402521694747
q=12840807874760119497562989864651565491645077946976950748211992253853323703532620362223764981952516328133916264333884385029280730688894521589959051436522977

Frame 19
p=86725761611859895386396141031497189948984447138542215420462553101081991008304507461163078354877970282649251051457532902955009856009405853917396630017011320500357081664483071782135584899953560478866041032397335990722689211113937797406269980402604895207480485168493674422769645640726941944110986793
q=1085663496559

Frame 20
p=7006433107252813175095285828299335809650512229854304253471035955787617465825842990081320535410435973346940338772266519696972554709877157476961995216696227
q=12976180370825816046330723693051565324091920359016588247467647785104809172783057319885443026117787490599861213721564637212466483142611446237049740392927759
```

当获得所有的p与q时，所有问题都迎刃而解了，编写最终脚本final.py
```python
import re
from gmpy2 import *

Data = []
for i in range(21):
    with open('Frame' + str(i)) as fp:
        data = re.findall('(.{256})(.{256})(.{256})', fp.read().replace('\n', ''))
        Data += data

N = [int(n, 16) for n, e, c in Data if int(e, 16)]
C = [int(c, 16) for n, e, c in Data if int(e, 16)]
E = [int(e, 16) for n, e, c in Data if int(e, 16)]

with open('pq.txt', 'r') as fp:
    data = fp.read()
    p = [int(i) for i in re.findall(r'p=([0-9]+)', data)]
    q = [int(i) for i in re.findall(r'q=([0-9]+)', data)]
    pq = zip(p, q)

cN = [i * j for i, j in pq]
if [i for i in range(21) if cN[i] != N[i]]:
    print
    'You are wrong!!';

else:
    print
    '[!]Well done in pq'

Phi = [(i - 1) * (j - 1) for i, j in pq]

D = [invert(E[i], Phi[i]) for i in range(21)]

M = [('%x' % pow(C[i], D[i], N[i])) for i in range(21)]


for i, m in enumerate(M):
    print
    '  [-]Frame%d' % i
    print
    'p:', '%x' % p[i]
    print
    'q:', '%x' % q[i]
    print
    'n:', '%x' % N[i]
    print
    'e:', '%x' % E[i]
    print
    'd:', '%x' % D[i]
    print
    'm:', m
    print
    'c:', '%x' % C[i]

print
'The Secret is:', ''.join([m.decode('hex')[-8:] for m in sorted(set(M))])
```

运行结果如下
```
Frame0
p: 821273a9e7f4b6e3c1a619ad9ba8ee87167a0bf1069c6c6b948ece755cd0548f8fe2253912440af39c76143ddaf833978e4adf81aaecb27b795e0b05b620ab9f
q: fc68e047c53a33b1b35cba2b6f4eb2351590be4f56a284f9970450b30f36affdebb815576d0a774107acf03b841e5ec51ee0055fa8722a89a554b8c36e06de8d
n: 803f734ed9e3a3fbdef8e3540b7b676fb66d15d2e5139840cb3cd06e62634c00a48ea2bf9bc3d7a709dbb47be7e27dfb2c0e5b81254e6c326691471ae6ddc4a35539018ba6305daff1c480f195118b1310c546c31fe62c7aec2a947013ac2897d00fd60e7b792dd499315341895bd1d1c9aa923e9373e1e01e2856b4fc8c6893
e: 42a04a989c5800528ef687c978355e9c4afd410a9dd4b08cca7669c747cce5446d5e85022ca2a2c383c28e85ad038c37ced2e18bd88529bd2480e20191958497c61823378ca06de01c8b6fb148c9bc935e433efcd960a1bf841fd60599811941a122cb1a323a76367ee78d71870b7134881ca077518c809013ae8ec6baecd519
d: 5b3b2da24b37ced4e91817ca8a52a0ac2d870c23c65d1e7172368544192a6d48c301f947394ae86093905f7949e82247b52f043e7801ea7a3562d6e27687a5f4db1dc4959f5bed65a7b12595dc4775257e03afc86df4311dd150249cb6a74384771ca87c62114130b0d79f4815b39057c452bbdfa38b69537fe874c5a1a542f9
m: 9876543210abcdef0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d79207365637265
c: 45446fc78ac9aa9f2e38197d44b76f0c2a7ded354615d906608016e9f884fa51e20893fa0aeaf5975e28a68fbcd9ba469ea00263f812523eec79e0cf967190317bef53ee8ff29af4411a238e7fce148ae7603c9a1dec4eeac1e41ad5fb8725fd3dce4c058db10f279b3ec1fa3ebc6584547d29501cca52851148344316073e6b

Frame1
p: 8adefe85e3a08b1f5b320649f614da838cc6b64debc82c27f39a5291b8bc640ba3ae5f1590f0a62ff1029fd9e86456936f9618dd73181937f36a0e21250cd21b
q: f3eeca557b30a36f05427f1936a4e7d387d6ac1d65587e774faa9561fb4c4b5b70bebee52c80727f3f12eca96cf457e34ea622ad70a89f87737aa4f12b9c2d6b
n: 845334ac0b3eb2239fdf0e3069750901e791cb774ad36941e30d85e5a0fed57749a30dc1f1f4cb191d9863f437c98293e8e8888b963bcf16b691f1d4eef56c6807440e5fb5ec5b95df3434deda30c60dcb4e77294be027f984d5e675aeb1cbbe57e8caf140226ead6dcd9a9636a0cff586fa434804cb09d7e8c48de34ebe9049
e: 10001
d: 4cca3c76dacfb7711505cca62b8ccf7d5b75302e3a2e159736bc5247bff622cae6e0c8cb142e8aee384e8732e26cfe69f76f7a4e07110e4c900681e0a00bacac93e48ed30df9a75802261b201aba465d7207b191ce41f1ecbebff5f258146b6df8ab7ce45153b823a28d7d1d57bf14310f2db82ff94c9363357b42f0a582be5
m: 9876543210abcdef0000000b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e20496d6167696e
c: 251025dc5fb84476581d0f67c640d8927da6d083627c9c29f3174c17cfe316a6218194dd4be03d30ef9eccbb4c609673d853590dd122b151dcfd6d75fd202dc2c758e897babe0a4cd842ff35d086cf4e34efbd09e8ff9fbfb4b5254ca2323a463139abd16e301c37f683579ba624efbb297b9e6d5a1c68f75eb4badf9aa198c
 
Frame2
p: 3ea18c437be22139df56ae544e1f2232c25b9c75532c15bbfcb087a6680914d4f355b0e779b6087ddb4aa938453329b6f98f91995780017fe3249b0a4d9d28d8f
q: 20d553f6ec8df4dd610278518babe13e0efd87744717f733836c634407d0230e467b622f9787080adde08cb349423bc93efd965375b51f301bd9d9d25c61891f
n: 808627ced38a980d765454ac5dfefc10195f6fef9b35b52b742dbce2419c34080a3ef3e9673fea4dd629ff382155031ea6dcba8372d42c1862f32b2bee47e157fa7150c544635035f366f7d68234f56fa24180eb6a00a0f85c65aaeb455b8ed28f2285376cda786f8c658cfeb3752f3504a7256ea3dbd22eef20267d156fab51
e: 10001
d: 759c4e6951e38de923d35ff8abbb5e664d11ac9912eb3ef298ca1202ea0f4afde0826329bf3619ef487ffdf11b6f73ff64aab073016d6f3c91affc5da31b5bf33746594e57305bff450e943cf79a78cc82c4e7c36ec448fd0f18c07af173e0d339e97117da2f92e1915a74186bd000b3df214b2a24d98716383b717b5e206391
m: 9876543210abcdef0000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000002054686174206973
c: 38702ef6fd51ca1ca834ef495618da956c8f8ad222b99e256ed5e3dd9089e194de67fd427f6132715709830a73b1a1cb582e56d06af8f31bba2851dba1a1c2985b7fc233018e42554c2aabd69a225f9283a164c3aa5479363f89260219f9964738b7c78c5d08618009f3904eb55a6a570e8d4b1701f4bf1b2c99c7887ccff2c9

Frame3
p: 86b6117def3812d7dc8a70c1c32c45bb6b9e7045126032df87f2d40950d43e43c586a00d32880be7f85a1851ab7c7fcb346ec0d5efb0bdefcdc25d9973242a53
q: f9b405a30966666d096869471a3a64b1905cd32b144ef335c290674f4ba2d5f9140489b3543610fd38b8de57020ae84124ac493b691edfc50be0ee5fdd72bb89
n: 8365d1ff23709faaef6330aeca9c848b292e0872c5c41e8cbe9d0780f32ebfc5fcc7947bd666f06aa619f952afb8d7c08b9211960d1916235d8ab3a60dec45b1ef5cc21848e56d5235717186ead51ae22a5661bdfdc42e31f9181f6ab1d070fdebb078a9980d7a0571b587130a1d3056cba40cbba287cd5031838bab893b476b
e: 5
d: 4ed6b132aedd2c99c2d51d35acc44f86b24ed1de76a8df213f2b048091e8d976cade25e3e70a903ffd42c8cb363bb4a6ba2470f3a17573aed1b99efd3b8dc369dc2b3361302a926e62e58e186e7576acb569defb810c9e779bf2ef3e0ccf37a70ae32f58a3fc6b1359fb23730459de93118567ffc5d4e95d34b9bfd1552f6dbd
m:9876543210abcdef0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000007420697320612066
c: 76cbcaf659936784799208c3ee2420b7bbfdbb9aa8d7c89874c11314df5decd3aa97f3da89851a043af16e6570e7d03a4f3225d49e552faa2fb9f6a19ae95ba73ecd6e7cc05cd9c03e03e06f829042dba4c1a91f39ac0cad516c8de7fb45939a2038c24c13f7f62a20040473d8f3d8339a4b30a65715f98a43cc3293e51190d5

Frame4
p: 821273a9e7f4b6e3c1a619ad9ba8ee87167a0bf1069c6c6b948ece755cd0548f8fe2253912440af39c76143ddaf833978e4adf81aaecb27b795e0b05b620ab9f
q: fc68e047c53a33b1b35cba2b6f4eb2351590be4f56a284f9970450b30f36affdebb815576d0a774107acf03b841e5ec51ee0055fa8722a89a554b8c36e06de8d
n: 803f734ed9e3a3fbdef8e3540b7b676fb66d15d2e5139840cb3cd06e62634c00a48ea2bf9bc3d7a709dbb47be7e27dfb2c0e5b81254e6c326691471ae6ddc4a35539018ba6305daff1c480f195118b1310c546c31fe62c7aec2a947013ac2897d00fd60e7b792dd499315341895bd1d1c9aa923e9373e1e01e2856b4fc8c6893
e: d8bffcdd82504c05a241e26742f0a867b162e5ecbf185e66f0a5fca1801a2c3a2a562549d433c600e3a4085c123535aa7ad14d55c0b3765c55c5b78b946517c14438ad876ec0f7ac22792988bb6cd7837aa64334eb5f7c668d570cbf8134b7f7e87eefa95179ca11bedcdf420eb6df9178c0a3b489a07b86ebca6adf96982d0d
d: 7d71af7541f1b1ba8a810def794f3662ee73b7e81ead2b89313e969ff5cd12b40cfed55ea2b5f1572ebf14532b17062a206371be56c78799fd20cf61113cd677537090516953f0aa64afda84c60d8a863d1639446bd3f21d24c60b406308f458640fe0bb8f3fe9ce0bf13060219b9c5da80df8594f32349831863dceaf98293d
m: 9876543210abcdef0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d79207365637265
c: 1bdaf2dbcec34d6602c949e9b53876a4d8b62fa69dd960063b342e5101f92a0f5d88a445d7bdf36f3816aebd5a98a8f06ab2cd708e363a657665cf05cb1f289eb758e09d11351816df1edf4575f01f95efce164d62eee92bce562b94b451fd9b566e4f8625e0428ad93bc6f8342c089af2842ea6deb9ed22d450f062cc7b18a8

Frame5
p: a2f2530963d4554390860f0d758892e7735a77511e7c76cb5f6e0fd592b024efa8c29c9946240153e356219decd8aff7e32ae2e17acc14dbbc3e6465240053ff
q: ddec697b645e1a051920d29f4cb259c903941a031646c1cd5148e3a7951a9611f63c138bdd2e5a952670cdaf4282d35955e476135916045d3898b0b7f4ea31a1
n: 8d41ac379635a2c8ffa55f609be3eb6219c7ad0d3c335ac1f7ae27c3c0510e9acde319a6e00b891bddb05c6b53f62e9321340bc0f19727c0526ac811cc02c7229241045a3d125978c1181264fde49d8a148aad8a8796c12c2ab5e8d7b0f98edac907c092b70d8b36e5bdc47c5801e4225bb508b1f081f5331c9b1324875ea25f
e: 10001
d:34302045853c99c0f31a912b6b4d00c904c74dfb46d39e636d73ad8358095a80fd323b66f8fdaa115e8d6b07c8447b1ea6b4c8e6e71b36778abba2e158636a58a048944b9bdba2755423e0a12081e831ee561fe23e25a31f01829df96e179bf36ee15c6d6f9847b8d75cd19493cb2c97f7da091cb077ab5937d9e47fb0623bc1
m:9876543210abcdef0000000c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000006174696f6e207769
c:251a6449a3e9a4a444238910ed757d0dcf8d825007a94ad9e171d4caf3799b07bb5fc050aab3762ee10e234dfff101d7e551de4f61c824f55c6a4c0e895d48ab46c67a66fdac65f2f60d5a2150fca740940293ff5b2aedae129fabf3840d879ad25f9393ff9a664ffcfa0b2fe484d01994dad68c0d340246c7b63515a96dd034

Frame6
p:f9b6087d1a3861d77f8ad7c19e2c84bb3e9e47459d6061df8af21b098bd45d43f886570d1d881ae75b5a3f51467c7ecbc76e57d53ab0acef90c264996e2409534b56699d94d837f7cb2aaae1a2cc1cdb243eac65cc00dbffaa9232298474d963f226402d8028b907cefa1a71b31c5eeb550e44f55150ef0fd86283
q: d65f770611
n:d11b49bf43234d6595219ab7c21730de0a13a7a01e63831a4d4f8dc5a7e68fca0e9768ef0dabcad036e08e17e4b27c1151df364556d8f93d19565d9f40f095a49c6185f2630671eb5ec1eaa514bec32d93a0f0459b52f1e34d4b9113413403f66619262ef1d3cbb025648c997cd1438de21cfe4bea0c6e00c72ffde587929cb3
f:d11b49bf4229975d18076255ea97a60648757b1b6324e4d307b22d63c85b9daf050b9491c9b3447929c305fcfd5721d20098b9c68b118ae5441bacf2515fd34002f361e90fbb1b81c12d126d1cf39882b1fe2428c02eb336e77f9037418971c43c94b1558de1a56ff7e463e0750249737069e1ecfeb75fbbd1deac2018433420
e: 10001
d:64b69ced76636bd8d5b2f0c4eac98198731bca60657f268b11a0dac5bd818acffa411a9ca1262baba3d69fb2bb1e5556bd1cd2157373ce8f201fa84bc9afbaa2910942362b72760c27cb9a9d5d1d626e48665c6a182e25f922c4c8e424379bc8e558c494ad526a0924bf26efbbcb8f2eff8cafd922d1955573fea8ae88a10da1
m:9876543210abcdef00000007000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020224c6f67696320
c:4333af6b43f36028d8d9650ec3eed3238541ee5c15e626c58c9ec33674a6d08d5b1f2580a1a0b07e9d853536cd994e197889d122701a62bb2a9e79559f3d5281014535f6c54f83ca8d9700eeb67d99af318d20a5150ad46d622a6a12de0a758ee7df75f5d10f2fe2585f2348537787063321ffdac91bb3c3d1d88cbd04a824ed

Frame7
p:ece0bb5f2672d0895354cec3cc06e48ddd082467e6da24d17dfca04b8aee15556a30666f0c427a1915a4dad3fed6571d3458a17736aaf061ba4c9e5bc7bec9e5
q:eef4b1e3a0a60cad12a89987e57a2ef1ed9cc76b538e2175b3d05f8f3ee2a839d944c5f33b76c73d11f89e971d4ac28151eccd7bf85e1e05cd20769f20b29dc9
n:dd1b58ff0de86cd28dffb60cc1ee0efa3250d58264b3da9ceaa5b5c17c728741f728c462c347dcb707ba7ee8672295f5a750c19d48ae23a32fc21e76f3188b85008e4ec1a66371bbb0825e558e876d80fa59e7099af25b0b298131277e634772f24ee0ed1bacd3ba6f8d8e443d5ae16faf6aa7dbaa59f91f763e4eafd7d7f5cd
f: dd1b58ff0de86cd28dffb60cc1ee0efa3250d58264b3da9ceaa5b5c17c728741f728c462c347dcb707ba7ee8672295f5a750c19d48ae23a32fc21e76f3188b8324b8e17edf4a94854a84f609dd065a012fb4fb36608a14c3f7b4314cb49289e3aed9b48ad3f3926447f014d92139c7d1292538e87b50eab7eed139b4ef668e20
e: 3
d:936790aa09459de1b3ffceb32bf409fc218b39019877e713471923d652f704d6a4c5d841d7853dcf5a7c549aef6c63f91a35d668db1ec26cca8169a4a2105d02187b40ff3f870dae31adf95be8aee6ab75235224405c0dd7fa7820ddcdb70697c9e6785c8d4d0c42daa00de6162685361b6e25f05235f1cff48b7bcdf4ef096b
m:9876543210abcdef000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000616d6f7573207361
c:b1e7f916884f9d17dffcb8ef1a93d61e3da73e066ce8b71f09bb8ef61c833300cb472854ff642f540db232ded17095f4fddca6cccc27628ea781f546863fa431b9057fa7dc1aa41c127fb22b113e512b14926ca0c361dd6daaebc3f2e9ce51d012f40173cf88f07752caaaba06ae53c4dbd559f50eed636a0a2e65d6bd835bd0

Frame8
p:a526772deb284807b1fac171ce1cddeb680e5bf51c505e0f1b620ab949c42c735ff6d1bd0a78ed1709caf501526c83fb2cdef88555a0151f1d32a04988140483
q:e324da534856229d59d818f7982af3e1b7cc0ddbc13e85653100dcff17929b293974ea632f26392d8528da07dbfaa371081c8feb320e5df5f650300f85622cb9
n:9288e1eef599ea72113d950723a8fc0add096c7312d8e78911fe64a4322c4fec96fd70b345aa5a345481fb91d8549998a90e2429dcaf1eeec863f396479a0bbd121e36b0efac8d002fc95b58b5879dd75251b5cefcbe90bf50669742821be2e89b3831fd6f0f3eab310e5bf3fc66d702d5ff1581ee1deff161efca359063c6ab
f:9288e1eef599ea72113d950723a8fc0add096c7312d8e78911fe64a4322c4fec96fd70b345aa5a345481fb91d8549998a90e2429dcaf1eeec863f396479a0bbb89d2e52fbc2e225b23f680ef4f3fcc0a32774bfe1f2fad4b0403af8a20c51b4c01cc75dd35701866a21a8ceacdffaf96a1038d11666f7cdc4e6cf9dc82ed9570
e: 5
d:753a4e58c47b21f4da97aa6c1c873008b0d456c2757a52d40e651d5028237323abfdf3c29e21e1c376ce62db1376e146eda4e9bb16f27f256d1cc2de9fae6fc93b0f1dbfc9be81e2832b9a590c3309a1c1f9099818f2f108d002f2d4e70415d667d6c4b0f78ce0521b4870bbd7ffbfabb402d7411ebf9716a523fb16cf24778d
m:9876543210abcdef0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000007420697320612066
c:246f3344f2c341fda293ecb4214c14d57164cb37fb364ed14b2fe3d10c94d2365155959b481085379a9c85b9fcb86c7e3676b2bfd98df7055d7e474cfee6ce3529980a3fa0c537af9c375e606e89b19d34fc801200db462538e2e9fe80803a8ef02f662d0e5ac9c35dce7a758b9efd6d5fea73bd9649c9b651e5aa5f1d96a773

Frame9
p:b6e2c03911449df333765f3dc9f8f697954ada8189eca57bf05eb6058520ce9f98b2b5c92f94d6032246ddcd3d485fa7611a7211a23c4f8b692ef6959270c9af
q:c2e2dc39fd4419f3ff763b3d75f83297214a7681f5eca17b3c5e1205b1208a9fa4b2d1c91b945203ee46b9cde9489ba7ed1a0e110e3c4b8bb52e5295be7085af
n:8b39e72d3c13d48f7773118b19f0d1a0cc592fd8ff12469e1d51aba8869a23297cd62e28bcf885f744bd4a7c53cb5369f941f401ec010da8665b7eb0b17b1839b3f0e49b51a266ddb84899eb302e050e43a284b5051c5b9002ba2b8bf1dd3a22c0bab03a6e780f218852ee086f05e9adf290189439aff15986077d36d271c9a1
f:8b39e72d3c13d48f7773118b19f0d1a0cc592fd8ff12469e1d51aba8869a23297cd62e28bcf885f744bd4a7c53cb5369f941f401ec010da8665b7eb0b17b18383a2b48284319aef6855bff6ff03cdbdf8d0d33b185431498d5fd6380bb9be0e3835528a8234ee71a77c5566d4874ee5ea45b98718937564267aa340b81907a44
e: 10001
d: 4d82b10767f90a4fcd0a8cebca475e0d8d76e1c2874f1f6d8b991a5e3a81b9adb148746e4db676aed0e02985ca08daa9971176cd531ccb03c3e89041c2ad6b307282022c181f465f0ca3c93402a57f2b98158f7ff756ff328f8000537d1f2d36bcb93e674d30f24cb3fd733e68266146e36df312d277b25849ea620b3dd8b799
m: 9876543210abcdef0000000d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c6c2074616b6520
c: 1478d729930a4bac9a114abcf11b6e5267818c936edc70c87cceeae6114ceefd83f0ece19d1dd120470f7d7c22882a57a3df23d467dddeaa86bbb2c1fea07ce8f660440f7a269f2d5c9090c6e8775a553063f8240cc3ced605ae71699affb5740c522eac8c864b207ac691deefe08a66d216fec93961131f786ef9f949f092c8

Frame10
p: b8f4b3e37aa6dead7ca8bb875f7a20f1f79c096b6d8e33755dd0c18ff8e2da39234447f39576193dfbf84097174a3481dbec8f7b925eb005f720589f5ab24fc9
q: b8f4b3e37aa6dead7ca8bb875f7a20f1f79c096b6d8e33755dd0c18ff8e2da39234447f39576193dfbf84097174a3481dbec8f7b925eb005f720589f5ab2500b
n: 85a0ac7e685995d9f8012c3a0249491956697997bbb6e5ddc1b53dc6184a843c3e4eb9b2d97feafad097aa0ff640846287953c88f5a0813fd81ff3ebbdd62d66f4403653dcec64ace99f9faaed4fd35513214ef4b4b9aa910e5923cd87f9330e3599f2cf1ad90efc6bdabbd249d1ac8cf83836fe18399379e712010fc25a3da3
e: 10001
d: 382ad8366df031efa3b2028003940058d91c8e927bc19e0f3f2bca6268b571adccd6d4715bc0cbe94f2260c642d0cd9488beeee9f6acd78719761cd61b3e5a688f87a35c50c33c3b51d1d87a057651c507be3299ad6dd010aa362b20abc0cb5809fdf9dfd9d66abcc77c4dd7cae74e6af396c507aef2a6bf73d5af4204bb7cf1
m: 9876543210abcdef00000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000077696c6c20676574
c: 704a43957ac6d55375fe290ceba686277b617ae3a013ba998c7475f161a72c4c0820f3a6a2d9474df3ce86d6b78b50814f6710daf8338b9880a8ed05cc498098ae299905bdddaf05423765070adf71e8cc43103d8e813a9ea8e5027091360de30d925369df9085066392166961d70e5af868b75fd78227f8e603e5790a89058c

Frame11
p: c9c4ac73dff651bd8a786d1789ca7501d26c03fbacde7885d5a0951f9d32204908148483eec6704d1dc87627759aac910abc4e0b45ae591502f0302fb30239d9
q: caea4fa1888caf9b5ffedd254dc0dabfe252aee962340423e5e6c8ed79e8cfc73eba6f3188dc21ab00ce25b5c3101dcf8022b0799c84283350b6137dc938e4d7
n: 9feddc9c122aa836e9a04fe9358a118b358c7bc6f3abde4e035e2bcb15b52950db1d23449ea62f83406fb591ed39564fd0e2dad0954156037bb32c9c23c49da83e2e85bc09a9b6fd75e2f55129044fa0f996895e8bf5e53d88938e4a3366649e97961be5b7b4095476d013d2e9f6fe75dc21295747bf371ae346355a5adbd93f
e: 3
d: 6a9e9312b6c71acf466adff0ce5c0bb223b2fd2f4d1d3edeace9728763ce1b8b3cbe1783146eca57804a790bf37b8edfe0973c8b0e2b8eacfd221dbd6d2dbe6f1baa5bc46b6f23c3079d1cb83650aa94d88fe450fdecf06288b2cad368324db435da1acad560fa3d90264ff920dd780e362c1c8c43b323e1b5154bc8946b270b
m: 9876543210abcdef00000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000079696e67206f6620
c: 9a597210da69760a66b063fa125dc17dc2038ec720cae6d0b1599ec25b9a19f328bc55882ee9ed05fc9bd90276b0f7f1d227946ffd77081df6e08976ebf57a3bb21ac13fe25a742a0c137e007bd8787a42683d81adc28450051b44617c2081d5aca3141dc2c848f1401cea94da7d11142bb2406306b299953d1c28259521ea11

Frame12
p: 85622cb9c3c41e7369f613bd2478ff17b3ca57010c6cb5fb76de7a85afa0671f0732424982147683f8c6b24d37c888271f9a0e91c4bc800b8faedb155cf0822f
q: f6b6c17ddf3842d74c8a20c1b32c75bbdb9e2045026062dff7f2840940d46e433586500d22883be7685ac8519b7cafcba46e70d5dfb0edef3dc20d9963245a53
n: 808b8f96e7255b3f169ee854abe0cd0ac7a4ae1b388cbc9a234e225842208a435842c254a55855b867f3fca78e3887c8d1663b501a5d4d5e32f3ef84847f45651a5e2fc8a091e12e2b4db7ab41113d258e2200ffb2bbf8b7c38b0049b3e2e60c65eb8b6375f03a40dc9f9ab01fec60e09dc8ca3644a83738bda0cfdb2b5abb3d
e: 5
d: 336b063c5c7557b2d5d929bb77f38537830eac0ae36b7ea40e1f40f01a736a8156811a884223557cf661984305b0365053c27e200a8bb88c14619301ce994ef4a5b54d6d323bccc161ebce11c3c4b68732b09d7d74c5f324eeb0cd7de7c5a044107aca052087cfeefe32733a1ea943925719b785d9b11d4bf9acc2de914f25e5
m: 9876543210abcdef0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000007420697320612066
c: 3f312b5fda3a9aa43de2697fa001ee909dfe677aa6a48beaf84991ff7d423596b5cc230db4e5be42e7c886e1fa6b39002b148f670c3b162816efcc6341a96d3cdcf849a35b866efb9e5f5c48df9bbd3f065ffa3e0961eb2393c6f2689b72603b21a2e1c674ee2a1a6534ca01f5606b062fb53ca9c3eb1bec80ac6849b090a7ef

Frame13
p: 219aa9485c033046d4df82a94b50210fe3748d1a6e6d3168f259899b725a0a51f68e892c541724caf513accd60a409d3c2e8a57e7501126cc50db43f7e2e2795f
q: 4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d7650c08e1f6d
n: 866aa521700cc11b537e0aa52d40843f8dd23469b9b4c5a3c966266dc9682947da3a24b1505c932bd44eb3358290274f0ba295f9d40449b314531725bdb1df55d57d088a5d188994c77362bfe54777d666b8c4d59c0c9c2b4d4e63780fd8d7c637444e0a9ec83a9ed3fa856d5155f6fcb5861f0cb66994ee0ccb615b99d22e73
e: 10001
d: 411bed4aea1cb3794a131692f5fd7751d59f8995e0c768a8b288917ac2817ae57c1687e97fb4a7f12610cd0bd1678432ecbedf88b9232e93d8f77a91e47601684de51e1f91e437806c7ebc31675b66bab717b222e0d3b11d77babdb47d7fa5415959e3b770c38bd26571fab7044e9a4000e27a8f6a28d187f39b91344535f5a9
m: 9876543210abcdef0000000e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000796f752065766572
c: 3b54c09ac3380dd2cd82d1244d9b774a1e9d4b5809e79280e5254d4a41b8f803a7151d6feea62b04b90854a96f1b5284f209fb8dc0bfda39c885c1401f821872f17610cdf5bc8b7d236966b3a749cdd0907716fce3af5e39678efe9b344e2c05ede973f4da393b27f505030e3aa56c6c1022fc0b9ed6454884e41784a3efef5c

Frame14
p: d12a38e118cc5adb8a3e1a65a200f9ff70928029ba74d76318266e2d1628970754fa2871a91c1ceb3b0e32f5a7508d0f1e6251b984c44b7392f688bdf578fc17
q: d12a38e118cc5adb8a3e1a65a200f9ff70928029ba74d76318266e2d1628d708f61cf38bdb569321b9f5c0672e5bfe43a67ef230d650cc03a6a51784b065d2d9
n: aae5f7d640fd102e49217a08e0a4af72ec895d5aba020beaf6f73053f4053d47cb7ebf3d583532abfff50f69508a4dbf2421742dcc2c16ae00e88c237653ec4dcfcd9a918763a9c9de3ce3da1fe2bc94ff93a9a7c261400a6e363c66816fda0e44ee73662cfd2b8bfa926ef2b40f7d41f35b7e89516bc28330b5cf49976b8d7f
e: 10001
d: 2f0ecfe5c1536da7311ff4b889130ff4b74943d97daa9e997e93a64d17be7197596377496f06870371a18b32d6a89eabe94904f2af6bdc7ae169275d8471ab7976740c56bb2afd7646f3b5c083af2bcc9a68a25bc2511041184330dd747ac205d74c0297a10130ec531d5ece6fc413166757e4d86cc084acf0c7d6f734802ae1
m: 9876543210abcdef00000009000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020796f752066726f
c: 32083a7d65ad94e25e193e0740fe348fb5c35d17329d5446015c85f134ba59fe8607941e5fe605243efa6e3638a4ab96bb6faedaab095ddd1ee1757919d82c39865c81f5f7fa3e4e72fc976d8a37e3a5591b6c75ed9b65af8a516b44b06162550347cce972e4ae121f1a595dffd9051d5ddf2cc2bf2d04faee8eab92f57cdd9b

Frame15
p: e79833b7bbeaeca1618c149b60fe4a25b6c08fbff352ebe95b34092306e6d5ed02e824c76fba4c31a1dcc6ab41ced2b56c1012cfd1222d79d5846d33b1b6607d
q: e88c8f9bbffebd25adc0babf42528ee9c234e42345e6a8edd9e8afc79eba4f31e8dc01ab60ce05b52310fdcfe0229079fc840833b0b6f37d2938c4d7a68a72c1
n: d2611805b6839fd983f2c574bdad1c50a4fb9fab35f3bb643f90a9fbb0b84af1d042e35e821564fca783f1a2af41349bb3e1c159b20ea6a0db9e70597cb5c0780ef6cd78481aeac0df65a8de35a8b5021fce55332c5b2adaedcf80963bd6fff773cab55d73637c9bd667148fb1359782d38c41cbb43fa5fd56f424f842d8683d
e: 3
d: 8c40baae79ad153bad4c83a3291e12e06dfd151ccea27ced7fb5c6a7cb25874be02c979456b8edfdc502a1171f80cdbd229680e676b46f15e7bef590fdce804ed48c06c332cb80a68abb3bad0c3a92a1c49096354cc10ead25cc851d0ece91e5b0045f47173cc72360fb8ab85f82cd8cf1fac48576ef03599024a1f3470fb8ab
m: 9876543210abcdef000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000416c626572742045
c: 4a6972b03f96cc30de3f60da66c71842e600320964a69ec818047b219506a12f3e4d522b40b10eb3f630a068c908186f29bf782360e35262a4ceccad554f57d1721db61b260ac6c5fbcb020ac326562048b0fc9270afe51c63f5f27a9a3cfd78b5971d5cbf7fbf20e23ca7b429121bd0bb9ae0552d6907c659e2b450b01675d7

Frame16
p: 859e8245bc6094df41f206099ad4c0431f86f20d1c88ade7f25a8a51357c41cbce6e52d519b09fef07c20f993d242c533256c49d53d88af7222ab5e151cc9fdb
q: f762b6b985c4b873fbf63dbd0678391765ca21010e6c8ffb48dee485d1a0e11ff9324c49c41490830ac65c4d99c84227519a589146bcda0be1aec515fef07c2f
n: 811f75bead6f0c3ea1560cfa4bfd4762f1da3a30e22644ab16b1bea5a6a1af14f0c3c2e63865fd29241246c1473892232dab6224af1600f73340cbca7bf5af01ea1fa007e46064ce2f8dd92a9e7fa9f16cfeee5a6cf67683bcd97f1e7e1ba73a9f86a8e4d7496393ac9727d10530a76b03b3a23321e8bdd756fce265494f6d35
e: 5
d: 674c5e322458d6988111a3fb6ffdd2b58e482e8d81b836ef455afeeaebb48c10c09c9beb605197541cdb6bcdd293a81c24891b508c119a5f5c33d63b965e2599f0e51f3a1b62792f27b7aab664288d458624af7034cdc6e6ce19a69f926536a57984d49e61368f4e14d89654f1d02d8d330204039f75e0a9dc1c52be60750dbd
m: 9876543210abcdef0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000007420697320612066
c: 224cd570eaf4d650aa24d51127e1657d201c8483aa690d48d58ca56ae86ea517df43f9f130cc7ca75c8868623ba145189e2d16326a82a437516530d130161552d016adb2d8746dc92d30f2a4d90a50a63af038b0449cf2a3442ba6696b6485a46d47545591aadb1c68e901745d4f9231627c9e0c0a52cc7439cc45b21ae51aee

Frame17
p: 2794aeba5f8d3c08d879a53b557a1ef1deaebecc4937236aff339c6d47c41273cf08af1e6e21050cf32db7df694e2435e0a287b0764b28eedc67bf9162181c37f
q: 400000000000000000000000000000000000000000000000000000000000000000000000000000000000000297bc784272b16f7b8edff759502b21342f286e63
n: 9e52bae97e34f02361e694ed55e87bc77abafb3124dc8dabfcce71b51f1049cf3c22bc79b8841433ccb6df840f2bd5a6e75a1ce52f54048ff4930e7b103c6a3433a2663bd9cba0e38a35695f927eb2ff7a51939869a113d8a6cb03228c0e5d1466b1ff491129a988efdbc636ab2610caa50925554be758321178f9eb94072c1d
e: 10001
d: 6f02930c24f1f96ed5b657b6120670c3edca2d56c801dd543a6e864bf8fbf2c4dbe57f41d99ec28b8f7eaa3a6e68cde5b951f5f0bcbeac744388d91e70c3ebb1c59690dd8660476c0767b64925fca55c02afc3c9c4e4172df2ba630e59060a3a891dd8c47f41c67475913d15e12203150c1811a66b490de734f6f3569f65121
m: 9876543210abcdef0000000f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000007977686572652e22
c: 1fca302be54fd4b4f8da498ede013bf551c714e321b17465cf55b9980ec12fdf92f4f408c15239fe5eed408248d598510c0e77618eba67321938d487d7286bd9ef539cb2b068fe02617be2954109b3b3da0c76ecf00957894d556acbce10e1ff68a536b82ef0befa92e9fd96264786fab50a3162d2564d8634338e5a6eef5e0

Frame18
p: 8adefe85e3a08b1f5b320649f614da838cc6b64debc82c27f39a5291b8bc640ba3ae5f1590f0a62ff1029fd9e86456936f9618dd73181937f36a0e21250cd21b
q: f52c8fbbed9eca4564601cdf29f2ce09c2d4c84387863a0dc48835e7da5a52515d7c49cb366e9ad5c1b027efefc2d799652434539a560c9dfbd812f70a2a7de1
n: 84ff95e263d30fad83684cc08b11dab54f5a0f3d24a8763c47b57750ed2e342022652836e2ebb30a765dc7364f417e4555d1fd72d140efb72e283007028cc2a4fe97e4fe3b5d272c917e734f8715a0c5bff2900640d8097425afa965f9b1566f339f155aceb59ede241327813c920a6fb98a6bb9209379f1bbebcc955949d8bb
e: 10001
d: 41f02573746273e766bb133272c08b5a50d929acfabbbac2f01a7be9576e0cd1d1bbad5068f8ca6f6977dd08840ac87bbfacb8a7702f6da9b7ec9cc31cf4849b626659aa5842287b950c404089df572d442526b66e20cb1a6c5e07f0ac7e04d680c54ff2c02885a685af6e45123818b3e1957d4da190643ed41d5ab457639101
m: 9876543210abcdef0000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000006d204120746f2042
c: 45d8bd62bbf9966c81722d6d4ad5e6e91fd5258c8b0747ca166237d167d5c881b100d83d73352f18a60914963ca8f7df9b9211273c8d7edac87132aadac33def0bda6c9ea91750818d869990521c6ba0a10bc1ac2273282fa4ac47efbeee99b2d35ebda2019d1ef8bf24b5017fa8481b372362aae138043a00d8761bcdca80bc

Frame19
p: 87ca9b01006c99fb8adefe85e3a08b1f5b320649f614da838cc6b64debc82c27f39a5291b8bc640ba3ae5f1590f0a62ff1029fd9e86456936f9618dd73181937f36a0e21250cd21b907e03a53240a53f9ad2bd690eb4f6a3a6663f6d6e686a47873acdb1455ce42b514eec35c790884f58a25ef96904bab3313629
q: fcc696496f
n: 8614c70089aade50e5a14de1fb8fcf0880046e9494eead3bf600ebe451e335b4c9e21de984912bca15914711a9c359056a2ad0543035e971a2faa387ea53aad48a7016735e2bb60716626cad6cf4f9cc41a59cf31ef07473a1de08a018cab7c6b95bf7ac9f501bd42fcc4c7cd834b6a7723b6abcc9a98146a750a9222cce2cc7
e: 10001
d: 444aa8e158f808be0868f8d5974cec85e864750cd459fdd3648150eda9aed471c1e9c1d9e5264c45375e3fa41679c28d5d61d24fe9cb2e5583b84b7f71e651b9156ef68e2c115880c148355e9ba2367a0355ae99eb3ace56e5b093c827e60bb081b7c9d3dcaa7012c2b72fa9efc513bc8619ebf5f6a6e221d6adb8ca4bcd06c1
m: 9876543210abcdef000000050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000696e737465696e2e
c: 4b6a6a6ce0cd9d8e0df4fbd2a23af3fb45fa587406a3e052231519c4b6b0b606d64dc531a29c0a7510928d4487e7bc3d45cdbadb595ae7d53fbdee70371debcb9a938b94dc0f266326a9df6191e04f82a9cdc067d366926b58a9092f55db22f8d4bcd9777a99f14ed95083d091da69f80f448eff48a21f998bbdc97daea135c1

Frame20
p: 85c6bb4d0cc839277c9aa791e9bc410bbcae0415d1f0532f9a0294d93964d393a8965dddd4186637bc6aa321960cef1be97ee8a5b340923f83d2f2699fb4b3a3
q: f7c23f99ad24dc532256f49dc3d83af7122ae5e1c1cc4fdbdb3e9765db003effd192cd2983746c6389268b2d6f287c07d5fa1571921c51ebcc0eeff52050120f
n: 8178408d7e1155b9f5b0665a3edfe279189567aac333ca33a7304ae1bb9c9a921735888fb7bc9b41550817b1c0d42b2ab0304546709648f45147180ad5fc839fb8f90b2d30772718a7b45e6204ce7886122874759f93c198ce61d10555f03c13fd83e639a637d849c846d5589029533e567e12fd992d690ec5ef38569327fc8d
e: 5
d: 4dae8d21b20a66a2c69d0a3625b987e241f33e3341ebdfb8978360210a2ac324745351efd4a45d273304db04407f4d199ce9c32a438d5ef8fd910e6ce6cab55ef076702a471fa42b9edb41516789311b8ec953186d811254cf1396108db9e5b382033d1e2f3369cf1b39ca9f535f24dcc1030c8a3249e95546d4cd2e4b7b8751
m: 9876543210abcdef0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000007420697320612066
c: 210b2c8ca031259d2ef22a2561b23b794b3740382bd0a89ef7db9e62463c8649ef5983eb94cff6f0d6a1881a0d4e190ef8a1acc20da5da71ae31705a5501b6856c151449dfc76b7026a9fab74aa4b41c7f58eccdc35777866c117d3be1e37a4576e34c90df7b8146f1bdf841d1362287a4922cb9a80221ec165e48f0bffd4ede

The Secret is: My secret is a famous saying of Albert Einstein. That is "Logic will get you from A to B. Imagination will take you everywhere."
```

最终解密的结果为:

<h3>My secret is a famous saying of Albert Einstein. That is "Logic will get you from A to B. Imagination will take you everywhere.</h3>

至此，解密完成。
