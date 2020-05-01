#!/usr/bin/env python
#coding: utf-8


import hashlib
from base64 import b64encode, b64decode
import codecs
import binascii
import re
from time import sleep
import sys
import os
from platform import python_version

class CONST(object):
    """[Creating the instance allows the magic __setattr__ method to kick in and intercept attempts to set the FOO variable.
     You could throw an exception here if you wanted to.
      Instantiating the instance over the class name prevents access directly via the class.]

	Arguments:
		object {[type]} -- [description]
	"""
    abc = "abcdefghijklmnopqrstuvwxyz "

    def __setattr__(self, *_):
        raise TypeError
 
 # CONST = CONST()


clearScreen = "clear"
if sys.version_info[0] < 3:
    version = python_version()
    print("\n\033[32m You are using python in the version\033[1;m \033[1m\033[31m%s\033[1;m \033[32mand it is lower than python3 onwards.\033[1;m" % (versao))
    print("\033[32m Please run program with a higher version than python2\033[1;m\n")
    exit(1)


def Presentation():
    os.system(clearScreen)
    print("""\033[31m

___________                                   __  .______________
\_   _____/ ____   ___________ ___.__._______/  |_|   \__    ___/
 |    __)_ /    \_/ ___\_  __ <   |  |\____ \   __\   | |    |   
 |        \   |  \  \___|  | \/\___  ||  |_> >  | |   | |    |   
/_______  /___|  /\___  >__|   / ____||   __/|__| |___| |____|   
        \/     \/     \/       \/     |__|                       

   
                              \033[1mBy: Souradeepta\033[1;m

""")


def Again(choice, call):
    """Repeat a function call again

    Arguments:
            choice {[string]} -- [Input y or n]
            call {[function]} -- [calls the function it originates from]
    """
    choiceSelect = input(choice)
    if choiceSelect == "y" or choiceSelect == "Y":
        call()
    elif choiceSelect == "n" or choiceSelect == "N":
        Begin()
    else:
        Again(choice, call)


def Begin():
    Presentation()
    print("""
	[\033[1;32m*\033[1;m] CHOOSE ONE OF THE OPTIONS BELOW TO CONTINUE:

	\033[31m1\033[1;m) \033[31mENCODE\033[1;m - \033[32mMD5\033[1;m
	\033[31m2\033[1;m) \033[31mENCODE\033[1;m - \033[32mSHA1\033[1;m
	\033[31m3\033[1;m) \033[31mENCODE\033[1;m - \033[32mSHA224\033[1;m
	\033[31m4\033[1;m) \033[31mENCODE\033[1;m - \033[32mSHA256\033[1;m
	\033[31m5\033[1;m) \033[31mENCODE\033[1;m - \033[32mSHA384\033[1;m
	\033[31m6\033[1;m) \033[31mENCODE\033[1;m - \033[32mSHA512\033[1;m
	\033[31m7\033[1;m) \033[31mENCODE\033[1;m - \033[32mBASE64\033[1;m
	\033[31m8\033[1;m) \033[31mENCODE/DECODE\033[1;m - \033[32mBINARY\033[1;m
	\033[31m9\033[1;m) \033[31mENCODE/DECODE\033[1;m - \033[32mHEXADECIMAL\033[1;m
	\033[31m10\033[1;m) \033[31mENCODE/DECODE\033[1;m - \033[32mCEASAR CIPHER\033[1;m
	\033[31m11\033[1;m) \033[31mREVERSE\033[1;m - \033[32mTEXT\033[1;m
	\033[31m12\033[1;m) \033[31mREVERSE\033[1;m - \033[32mWORDS\033[1;m
    \033[31m13\033[1;m) \033[31mENCODE/DECODE\033[1;m - \033[32mCUSTOM\033[1;m
	\033[31m14\033[1;m) EXIT
""")
    appChoice = input("\n\033[1;36m⟫⟫⟫\033[1;m ")
    if appChoice == "1":
        Md5()
    elif appChoice == "2":
        Sha1()
    elif appChoice == "3":
        Sha224()
    elif appChoice == "4":
        Sha256()
    elif appChoice == "5":
        Sha384()
    elif appChoice == "6":
        Sha512()
    elif appChoice == "7":
        Base64()
    elif appChoice == "8":
        Binary()
    elif appChoice == "9":
        Hexadecimal()
    elif appChoice == "10":
        CeasarCipher()
    elif appChoice == "11":
        TextReverse()
    elif appChoice == "12":
        WordsReverse()
     elif appChoice == "12":
        Custom()
    elif appChoice == "14":
        exit(1)
    else:
        Begin()


def Md5():
    Presentation()
    mystring = input(
        "\033[32mENTER THE TEXT YOU WANT TO ENCRYPT IN MD5\033[1;m: ")
    hash_object = hashlib.md5(mystring.encode())
    print("")
    print(hash_object.hexdigest())
    print("")
    Again(
        "\n\033[1;36mDESIRE TO DO ANOTHER ENCRYPTION IN MD5 (y/n) ?:\033[1;m ", Md5)


def Sha1():
    Presentation()
    mystring = input(
        "\033[32mENTER THE TEXT YOU WANT TO ENCRYPT IN SHA1\033[1;m: ")
    hash_object = hashlib.sha1(mystring.encode())
    print("")
    print(hash_object.hexdigest())
    print("")
    Again(
        "\n\033[1;36mDESIRE TO DO ANOTHER ENCRYPTION IN SHA1 (y/n) ?:\033[1;m ", Sha1)


def Sha224():
    Presentation()
    mystring = input(
        "\033[32mENTER THE TEXT YOU WANT TO ENCRYPT IN SHA224\033[1;m: ")
    hash_object = hashlib.sha224(mystring.encode())
    print("")
    print(hash_object.hexdigest())
    print("")
    Again(
        "\n\033[1;36mDESIRE TO DO ANOTHER ENCRYPTION IN SHA224 (y/n) ?:\033[1;m ", Sha224)


def Sha256():
    Presentation()
    mystring = input(
        "\033[32mENTER THE TEXT YOU WANT TO ENCRYPT IN SHA256\033[1;m: ")
    hash_object = hashlib.sha256(mystring.encode())
    print("")
    print(hash_object.hexdigest())
    print("")
    Again(
        "\n\033[1;36mDESIRE TO DO ANOTHER ENCRYPTION IN SHA256 (y/n) ?:\033[1;m ", Sha256)


def Sha384():
    Presentation()
    mystring = input(
        "\033[32mENTER THE TEXT YOU WANT TO ENCRYPT IN SHA384\033[1;m: ")
    hash_object = hashlib.sha384(mystring.encode())
    print("")
    print(hash_object.hexdigest())
    print("")
    Again(
        "\n\033[1;36mDESIRE TO DO ANOTHER ENCRYPTION IN SHA384 (y/n) ?:\033[1;m ", Sha384)


def Sha512():
    Presentation()
    mystring = input(
        "\033[32mENTER THE TEXT YOU WANT TO ENCRYPT IN SHA512\033[1;m: ")
    hash_object = hashlib.sha512(mystring.encode())
    print("")
    print(hash_object.hexdigest())
    print("")
    Again(
        "\n\033[1;36mDESIRE TO DO ANOTHER ENCODE IN SHA512 (y/n) ?:\033[1;m ", Sha512)


def Base64Encode():
    Presentation()
    mystring = str(
        input("\033[32mENTER THE TEXT YOU WANT TO ENCODE IN BASE64\033[1;m: "))
    print("")
    encode = b64encode(mystring.encode('utf-8'))
    decode = encode.decode('utf-8')
    print(decode)
    print("")
    Again(
        "\n\033[1;36mWOULD YOU LIKE TO ENCODE ANOTHER TEXT IN BASE64 (y/n) ?:\033[1;m ", Base64Encode)


def Base64Decode():
    Presentation()
    mystring = str(
        input("\033[32mENTER THE TEXT YOU WANT TO DECODE IN BASE64\033[1;m: "))
    print("")
    try:
        decode = b64decode(mystring).decode('utf-8')
        print(decode)
        print("")
    except:
        print("\n[\033[1;91m!\033[1;m] INCORRECT PADDING")
        sleep(3)
        Base64Decode()
    Again(
        "\n\033[1;36mWOULD YOU LIKE TO TO DECODE ANOTHER TEXT IN BASE64 (y/n) ?:\033[1;m ", Base64Decode)


def Base64():
    Presentation()
    print("""
[\033[1;32m*\033[1;m] CHOOSE ONE OF THE OPTIONS BELOW TO CONTINUE:

\033[31m1\033[1;m) ENCODE - BASE64
\033[31m2\033[1;m) DECODE - BASE64
""")
    appChoice = input("\n\033[1;36m⟫⟫⟫\033[1;m ")
    if appChoice == "1":
        Base64Encode()
    elif appChoice == "2":
        Base64Decode()
    else:
        Base64()


def BinaryEncode(encoding='utf-8', errors='surrogatepass'):
    Presentation()
    try:
        mystring = input(
            "\033[32mENTER THE TEXT YOU WANT TO ENCODE IN BINÁRIO\033[1;m: ")
        print("")
        bits = bin(int(binascii.hexlify(
            mystring.encode(encoding, errors)), 16))[2:]
        print(bits.zfill(8 * ((len(bits) + 7) // 8)))
        print("")
    except:
        print("\n[\033[1;91m!\033[1;m] VALUE ERROR")
        sleep(3)
        BinaryEncode()
    Again(
        "\n\033[1;36mWOULD YOU LIKE TO ENCODE ANOTHER TEXT IN BINÁRIO (y/n) ?:\033[1;m ", BinaryEncode)


def BinaryDecode(encoding='utf-8', errors='surrogatepass'):
    Presentation()
    try:
        Binary = input(
            "\033[32mENTER THE SEQUENCE OF NUMBERS YOU DESIRE TO DECODE IN BINARY\033[1;m: ")
        Binary = Binary.reENTER(" ", "")
        n = int(Binary, 2)
        print("")
        print(int2bytes(n).decode(encoding, errors))
        print("")
    except:
        print("\n\n[\033[1;91m!\033[1;m] VALUE ERROR")
        sleep(3)
        BinaryDecode()
    Again(
        "\n\033[1;36mWISHES TO DECODE ANOTHER SEQUENCE IN BINARY (y/n) ?:\033[1;m ", BinaryDecode)


def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))


def Binary():
    Presentation()
    print("""
[\033[1;32m*\033[1;m] CHOOSE ONE OF THE OPTIONS BELOW TO CONTINUE:

\033[31m1\033[1;m) ENCODE - BINARY
\033[31m2\033[1;m) DECODE - BINARY
""")
    appChoice = input("\n\033[1;36m⟫⟫⟫\033[1;m ")
    if appChoice == "1":
        BinaryEncode()
    elif appChoice == "2":
        BinaryDecode()
    else:
        Binary()


def HexaEncode():
    Presentation()
    mystring = input(
        "\033[32mENTER THE TEXT YOU WANT TO ENCODE IN HEXADECIMAL\033[1;m: ")
    print("")
    encode = binascii.hexlify(bytes(mystring, "utf-8"))
    encode = str(encode).strip("b")
    encode = encode.strip("'")
    encode = re.sub(r'(..)', r'\1 ', encode).strip()
    print(encode)
    print("")
    Again(
        "\n\033[1;36mWANT TO ENCODE ANOTHER TEXT IN HEXADECIMAL (y/n) ?:\033[1;m ", HexaEncode)


def HexaDecode():
    Presentation()
    try:
        mystring = input(
            "\033[32mENTER THE SEQUENCE OF CHARACTERS YOU DESIRE TO DECODE IN HEXADECIMAL\033[1;m: ")
        print("")
        decode = bytes.fromhex(mystring).decode('utf-8')
        print(decode)
        print("")
    except:
        print("\n[\033[1;91m!\033[1;m] VALUE ERROR")
        sleep(3)
        HexaDecode()
    Again(
        "\n\033[1;36mWISHES TO DECODE ANOTHER SEQUENCE IN HEXADECIMAL (y/n) ?:\033[1;m ", HexaDecode)


def Hexadecimal():
    Presentation()
    print("""
[\033[1;32m*\033[1;m] CHOOSE ONE OF THE OPTIONS BELOW TO CONTINUE:

\033[31m1\033[1;m) ENCODE - HEXADECIMAL
\033[31m2\033[1;m) DECODE - HEXADECIMAL
""")
    appChoice = input("\n\033[1;36m⟫⟫⟫\033[1;m ")
    if appChoice == "1":
        HexaEncode()
    elif appChoice == "2":
        HexaDecode()
    else:
        Hexadecimal()


def TextReverseEncode():
    Presentation()
    mystring = input("\033[32mENTER THE TEXT YOU WANT TO REVERSE\033[1;m: ")
    print("")
    print(mystring[::-1])
    print("")
    Again(
        "\n\033[1;36mWANTS TO MAKE ANOTHER REVERSE (y/n) ?:\033[1;m ", TextReverseEncode)


def TextReverseDecode():
    Presentation()
    mystring = input(
        "\033[32mENTER TEXT YOU WANT TO DECODE THE REVERSE\033[1;m: ")
    print("")
    print(mystring[::-1])
    print("")
    Again(
        "\n\033[1;36mWANT TO DECODE ANOTHER REVERSE (y/n) ?:\033[1;m ", TextReverseDecode)


def TextReverse():
    Presentation()
    print("""
[\033[1;32m*\033[1;m] CHOOSE ONE OF THE OPTIONS BELOW TO CONTINUE:

\033[31m1\033[1;m) ENCODE - REVERSE-TEXT
\033[31m2\033[1;m) DECODE - REVERSE-TEXT
""")
    appChoice = input("\n\033[1;36m⟫⟫⟫\033[1;m ")
    if appChoice == "1":
        TextReverseEncode()
    elif appChoice == "2":
        TextReverseDecode()
    else:
        TextReverse()


def WordsReverseEncode():
    Presentation()
    mystring = input("\033[32mENTER THE TEXT YOU WANT TO REVERSE\033[1;m: ")
    print("")
    print(' '.join(mystring.split()[::-1]))
    print("")
    Again("\n\033[1;36mWANTS TO MAKE ANOTHER REVERSE (y/n) ?:\033[1;m ",
          WordsReverseEncode)


def WordsReverseDecode():
    Presentation()
    mystring = input(
        "\033[32mENTER TEXT YOU WANT TO DECODE THE REVERSE\033[1;m: ")
    print("")
    print(' '.join(mystring.split()[::-1]))
    print("")
    Again("\n\033[1;36mWANT TO DECODE ANOTHER REVERSE (y/n) ?:\033[1;m ",
          WordsReverseDecode)


def WordsReverse():
    Presentation()
    print("""
[\033[1;32m*\033[1;m] CHOOSE ONE OF THE OPTIONS BELOW TO CONTINUE:

\033[31m1\033[1;m) ENCODE - REVERSE-WORDS
\033[31m2\033[1;m) DECODE - REVERSE-WORDS
""")
    appChoice = input("\n\033[1;36m⟫⟫⟫\033[1;m ")
    if appChoice == "1":
        WordsReverseEncode()
    elif appChoice == "2":
        WordsReverseDecode()
    else:
        WordsReverse()


def CeasarCipher():
    Presentation()
    print("""
[\033[1;32m*\033[1;m] CHOOSE ONE OF THE OPTIONS BELOW TO CONTINUE:

\033[31m1\033[1;m) ENCODE - CIPHER OF CESAR
\033[31m2\033[1;m) DECODE - CIPHER OF CESAR
""")
    appChoice = input("\n\033[1;36m⟫⟫⟫\033[1;m ")
    if appChoice == "1":
        CeasarCipherEncode()
    elif appChoice == "2":
        CeasarCipherDecode()
    else:
        CeasarCipher()


def cipher(text, key):
    #abc = "abcdefghijklmnopqrstuvwxyz "
    cipher_text = ""

    for letter in text:
        sum = CONST.abc.find(letter) + key
        modulo = int(sum) % len(CONST.abc)
        cipher_text = cipher_text + str(CONST.abc[modulo])

    return cipher_text


def decipher(text, key):
    #abc = "abcdefghijklmnopqrstuvwxyz "
    cipher_text = ""

    for letter in text:
        sum = CONST.abc.find(letter) - key
        modulo = int(sum) % len(CONST.abc)
        cipher_text = cipher_text + str(CONST.abc[modulo])

    return cipher_text


def CeasarCipherEncode():
    Presentation()
    try:
        text = str(input('\n\033[32mTEXT FOR CIPHER\033[1;m: ')).lower()
        key = int(input('\033[32mNUMERICAL KEY\033[1;m: '))
        print("\033[32mRESULT\033[1;m:", cipher(text, key))
        print("")
    except:
        print("\n\n[\033[1;91m!\033[1;m] VALUE ERROR")
        sleep(3)
        CeasarCipherEncode()
    Again(
        "\n\033[1;36mDO ANOTHER ENCODE GIVES CESAR CIPHER (y/n) ?:\033[1;m ", CeasarCipherEncode)


def CeasarCipherDecode():
    Presentation()
    try:
        text = str(input('\n\033[32mTEXT TO BE DECODE\033[1;m: ')).lower()
        key = int(input('\033[32mNUMERICAL KEY\033[1;m: '))
        print("\033[32mRESULT\033[1;m:", decipher(text, key))
        print("")
    except:
        print("\n\n[\033[1;91m!\033[1;m] VALUE ERROR")
        sleep(3)
        CeasarCipherDecode()
    Again(
        "\n\033[1;36mDO ANOTHER DECODE GIVES CESAR CIPHER (y/n) ?:\033[1;m ", CeasarCipherDecode)

def Custom():
     Presentation()
    try:
        text = str(input('\n\033[32mTEXT TO BE DECODE\033[1;m: ')).lower()
        key = int(input('\033[32mNUMERICAL KEY\033[1;m: '))
        print("\033[32mRESULT\033[1;m:", decipher(text, key))
        print("")
    except:
        print("\n\n[\033[1;91m!\033[1;m] VALUE ERROR")
        sleep(3)
        CeasarCipherDecode()
    Again(
        "\n\033[1;36mDESIRE TO DO ANOTHER DECODE GIVES CIPHER OF CESAR (y/n) ?:\033[1;m ", CeasarCipherDecode)
    pass

Begin()
