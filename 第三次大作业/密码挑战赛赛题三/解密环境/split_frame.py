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


