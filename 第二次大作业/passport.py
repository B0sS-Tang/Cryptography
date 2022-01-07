import hashlib
import codecs
import binascii
from Crypto.Cipher import AES
import base64


origin = [1,1,1,1,1,6]
rule = [7,3,1,7,3,1]
t = 0
for i in range(0,6):
    t = t + origin[i]*rule[i]
    res = t % 10
# print(res)   7

new_res = "12345678<8<<<1110182<111116" + str(res) + "<<<<<<<<<<<<<<<4"
# 12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4
result = new_res[0:10] + new_res[13:20] + new_res[21:28]
#12345678<811101821111167
hex_result = hashlib.sha1(result.encode()).hexdigest()
# 十进制先变为二进制散列再换成十六进制
key_seed = hex_result[:32]  # 取前16位
# print(key_seed)   a095f0fdfe51e6ab3bf5c777302c473e

c = '00000001'
D = key_seed + c
hex_D = hashlib.sha1(codecs.decode(D, "hex")).hexdigest()
# 十六进制先变为二进制散列再换成十六进制
ka = hashlib.sha1(codecs.decode(D, "hex")).hexdigest()[:16]
kb = hashlib.sha1(codecs.decode(D, "hex")).hexdigest()[16:32]

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
#print("key =",key)
# ea8645d97ff725a898942aa280c43179
IV = '0'*32
b4code = "9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI"
cipher = base64.b64decode(b4code)
m = AES.new(binascii.unhexlify(key), AES.MODE_CBC, binascii.unhexlify(IV))
print(m.decrypt(cipher))


# b'Herzlichen Glueckwunsch. Sie haben die Nuss geknackt. Das Codewort lautet: Kryptographie!\x01\x00\x00\x00\x00\x00\x00'



