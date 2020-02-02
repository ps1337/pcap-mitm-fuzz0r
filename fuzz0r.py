#!/usr/bin/env python2

# pcap based fuzzing adapted from https://github.com/blazeinfosec/pcrappyfuzzer/blob/master/pcrappyfuzzer.py

# to parse the pcap and modify UDP packets on-the-fly
from scapy.all import *
# to send the payload via UDP
from pwnlib.tubes import *
# to invoke radamsa
from subprocess import Popen, PIPE

# for `mitmFuzz` - modify network packets on-the-fly
import netfilterqueue

import random
import time
import os
import binascii

import sys
reload(sys)
sys.setdefaultencoding('utf8')

## Settings ##
VERBOSE = False
# Path to the file replayed via `pcapFuzz`
PCAP_PATH = './testcases/2.pcapng'
# Path to the radamsa binary
RADAMSA_PATH = '/usr/bin/radamsa'

# Host to fuzz
HOST = "10.0.0.14"
# UDP port of the target
PORT = 27015
# Our IP
CLIENT = "10.0.0.2"

# Amount of packets to be sent before fuzzing in mitm mode (`mitmFuzz`)
# (-> Establish connection to server/game first)
MITMFUZZ_PASS = 2200
BITFLIPMODE = True
RADAMSAMODE = True
# How much of the data will be flipped
BITFLIP_FACTOR = 2
# Every X % of all packets will be fuzzed
FUZZ_FACTOR = 10.0
# Sleep X seconds between packets replayed from a pcap
SLEEPTIME = 0.1

SRV = remote.remote(HOST, PORT, typ="udp")


# Flip random bytes
def flip(data):
    l = len(data)
    # amount of bytes to change
    n = int(l * BITFLIP_FACTOR / 100)

    for i in range(0, n):
        r = random.randint(0, l - 1)
        data = data[0:r] + chr(random.randint(0, 255)) + data[r + 1:]
    return data


# Fuzzes `input` and returns the modified value
def hax(input):
    if BITFLIPMODE:
        fuzzed = flip(input)
        input = fuzzed
    if RADAMSAMODE:
        try:

            print("[i] Radamsa input: %s" % str(input))
            cmd = [RADAMSA_PATH, '-n', '1', '-']
            p = Popen(cmd, stdin=PIPE, stdout=PIPE)
            fuzzed = p.communicate(input)[0]
        except Exception as e:
            print("[!] Radamsa Fail")
            print(str(e))
            sys.exit(1)

    return fuzzed


def log_events(log_info, type_event):
    log_msg = "[" + time.ctime() + "]" + log_info

    if type_event == "fuzzing":
        try:
            fd = open('fuzz.log', 'a')
        except IOError as err:
            print("[!] Error opening log file: %s" % str(err))

    elif type_event == "error":
        try:
            fd = open('error.log', 'a')
        except IOError as err:
            print("[!] Error opening error file: %s" % str(err))

    else:
        print("[!] '%s' is an unrecognized log event type." % type_event)

    if fd:
        fd.write(log_msg)


# Replay the pcap while fuzzing the data packets
def pcapFuzz():
    print("[*] Reading pcap")
    # Read packets
    packets_in = rdpcap(PCAP_PATH)
    print("[*] Got %d packets" % len(packets_in))

    # Seed with random randomness
    random.seed(time.time())

    # Filter out responses, only use packets sent from a client to the server
    # --> Build a list of relevant packets and use it later on
    packets_use = []
    packets_use_cnt = 0
    for pkt in packets_in:
        if pkt['IP'].src == CLIENT:
            # [(0, 0xyolo), (1, 0xc0ffee)]
            packets_use.append((packets_use_cnt, str(pkt['Raw'])))
            packets_use_cnt += 1
            sys.stdout.write('.')
            sys.stdout.flush()

    print("")
    print("[*] Using %d/%d packets" % (len(packets_use), len(packets_in)))

    fuzz_loops = 0
    no_answer_loops = 0

    while True:
        print("[->] # %d" % fuzz_loops)

        try:

            for pkt in packets_use:
                time.sleep(SLEEPTIME)

                # [(0, 0xyolo), (1, 0xdc0ffee)]
                payload = pkt[1]
                if random.random() < FUZZ_FACTOR / 100:
                    payload = hax(payload)
                    iter_str = "<->"
                else:
                    iter_str = ""

                SRV.send(payload)
                answer = SRV.recv(timeout=0.5)

                if len(answer) == 0:
                    no_answer_loops += 1
                else:
                    no_answer_loops = 0
                if no_answer_loops > 15:
                    print("[*] Restarting")
                    no_answer_loops = 0
                    break

                iter_str += "\nPayload #%d:\n%s\n" % (
                    (len(packets_use) + pkt[0]), binascii.hexlify(payload))
                iter_str += "\nAnswer:\n%s\n\n" % answer

                print(iter_str)
                log_events(iter_str, "fuzzing")
                print("")

        except Exception as e:
            error_str = "[!] Error in iteration %d: %s (packet %d)" % (
                fuzz_loops, str(e), pkt[0])
            print(error_str)
            log_events(error_str, "error")

        fuzz_loops += 1


# callback for `mitmFuzz` -> modifies the payload
def _mitmFuzzProcess(raw_pkt):
    global MITMFUZZ_PASS
    # get the scapy payload
    packet = IP(raw_pkt.get_payload())
    # modify if it's UDP
    if packet.haslayer(UDP):
        if MITMFUZZ_PASS <= 0:
            # modify or pass
            if random.random() < FUZZ_FACTOR / 100:
                print(".")
                # Modify the payload with a fuzzed one
                payload_original = packet[Raw].load
                payload_fuzzed = hax(str(payload_original))
                packet[Raw].load = payload_fuzzed
                # Force scapy to re-calculate the checksums
                del packet[IP].chksum
                del packet[UDP].chksum
                raw_pkt.set_payload(str(packet))

                log_str = "\nMITM Payload:\no:\t%s\nf:\t%s\n\n" % (
                    (binascii.hexlify(str(payload_original)),
                     binascii.hexlify(str(payload_fuzzed))))
                log_events(log_str, "fuzzing")
        else:
            MITMFUZZ_PASS = MITMFUZZ_PASS - 1 if MITMFUZZ_PASS > 0 else 0
            print("%d packets remaining" % (MITMFUZZ_PASS))
            if MITMFUZZ_PASS == 0:
                print("** Fuzzing started **")

    # forward packet
    raw_pkt.accept()


# required to fuzz packets in mitm mode
def mitmFuzz():
    nfqueue = netfilterqueue.NetfilterQueue()
    # Bind to queue `1`
    nfqueue.bind(1, _mitmFuzzProcess, mode=netfilterqueue.COPY_PACKET)

    try:
        print("Binding...")
        nfqueue.run()
    except:
        nfqueue.unbind()
        sys.exit(1)


if __name__ == '__main__':
    #pcapFuzz()
    mitmFuzz()
