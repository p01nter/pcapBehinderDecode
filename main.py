import base64
import re
from Crypto.Cipher import AES
from scapy.all import *
from Crypto.Util.Padding import unpad
import json

def aes_decrypt(ciphertext, key, iv):
    ciphertext = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')

def dict_b64decode(data):
    for k, v in data.items():
        if is_base64(data[k]):
            value = base64.b64decode(data[k])
            try:
                newdata = json.loads(value)
                dict_b64decode(newdata)
            except:
                print(k, value)

def behinder_decode(msg_type, data, key):
    res = aes_decrypt(data, key.encode(), b'\x00'*16)
    if msg_type == 'response':
        pass
        jsondata = json.loads(res)
        dict_b64decode((jsondata))
        # print(base64.b64decode((jsondata['status'])), base64.b64decode(jsondata['msg']))
    else:
        b64str = re.search(r"assert\|eval\(base64_decode\('([^']+)'\)", res).group(1)
        d64str = base64.b64decode(b64str).decode()
        cmds = re.findall(r'cmd="(.*?)"', d64str)
        if cmds:
            print(base64.b64decode(cmds[0]))

def is_base64(s):
    if isinstance(s, str):
        pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
        if not pattern.match(s):
            return False
        if len(s) % 4 != 0:
            return False
        try:
            decoded = base64.b64decode(s, validate=True)
            return True
        except Exception:
            return False
    return False

def main(file_path,decrypt_key):
    raw_result = {}
    load_layer('http')
    pkts = sniff(offline=file_path,session=TCPSession)

    for pkt in pkts:
        type_http = ''
        conti = False
        try:
            try:
                message = pkt["HTTP"]['HTTPRequest']['Raw'].load.decode('latin1')
                type_http = 'requests'
                conti = True
            except IndexError as identifier:
                pass

            if not conti:
                try:
                    message = pkt["HTTP"]['HTTPResponse']['Raw'].load.decode('latin1')
                    type_http = 'response'
                except IndexError as identifier:
                    continue
            tag = str(pkt['IP'].ack)
            if tag not in raw_result.keys():
                raw_result[tag] = []
                raw_result[tag].append(type_http)
                raw_result[tag].append(message)
            else:
                raw_result[tag][1] += message

        except IndexError as identifier:
            continue

    print("长度为：",len(raw_result))

    for _, value in raw_result.items():
        if is_base64(value[1]):
            behinder_decode(value[0], value[1], decrypt_key)

if __name__ == "__main__":
    decrypt_key = 'e45e329feb5d925b'
    file_path = './web.pcapng'
    print('文件路径：',file_path,' 秘钥为：',decrypt_key)
    main(file_path,decrypt_key)
