#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json, sys, getopt, os.path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class encryptdecrypt:
    def __init__(self):
        if os.path.exists("private") and os.path.exists("public"):
            self.__prv =open("private", "r").read()
            self.__pub = open("public", "r").read()
        else:
            new_key = RSA.generate(4096, e=65537)
            self.__prv = new_key.exportKey("PEM")
            fd = open("private", "wb")
            fd.write(self.__prv)
            fd.close()
            self.__pub = new_key.publickey().exportKey("PEM")
            fd = open("public", "wb")
            fd.write(self.__pub)
            fd.close()

    def is_json(self, myjson):
        try:
            json_object = json.loads(myjson)
        except ValueError, e:
            return False
        return True

    def decryptjson(self, data):
        ciper = PKCS1_OAEP.new(RSA.importKey(self.__prv))
        try:
            data = base64.b64decode(data)
        except:
            return False
        size = 512
        offset = 0
        decrypted = ""
        while offset < len(data):
            decrypted += ciper.decrypt(data[offset: offset + size])
            offset += size
        if self.is_json(decrypted.rstrip()):
            return decrypted.rstrip()
        else:
            return False

    def encryptjson(self, data):
        if self.is_json(data):
            ciper = PKCS1_OAEP.new(RSA.importKey(self.__pub))
            size = 470
            offset = 0
            end_loop = False
            encrypted = ""
            while not end_loop:
                chunk = data[offset:offset + size]
                if len(chunk) % size != 0:
                    end_loop = True
                    chunk += " " * (size - len(chunk))
                encrypted += ciper.encrypt(chunk)
                offset += size
            return base64.b64encode(encrypted)
        else:
            return False

    def decryptdict(self, data):
        res = json.loads(self.decryptjson(data))
        if isinstance(res, dict):
            return res
        else:
            return False

    def encryptdict(self, data):
        if isinstance(data, dict):
            return self.encryptjson(json.dumps(data))
        else:
            return False

if len(sys.argv) > 1:
    def usage():
        print "function.py -e '<json>' or function -d <cryptstring>"
        print "function.py --encrypt='<json>' or function --decrypt=<cryptstring>"
    try:
        opts, args = getopt.getopt(sys.argv[1:],"he:d:",["help", "encrypt=", "decrypt="])
    except getopt.GetoptError as err:
        usage()
        print err
    f = encryptdecrypt()
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-e", "--encrypt"):
            res = f.encryptjson(a)
            if res:
                print res
            else:
                print "error JSON"
        elif o in ("-d", "--decrypt"):
            res = f.decryptjson(a)
            if res:
                print res
            else:
                print "error CRYPTSTRING"
