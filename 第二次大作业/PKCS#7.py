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
