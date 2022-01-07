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

