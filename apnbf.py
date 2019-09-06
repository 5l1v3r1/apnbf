#!/usr/bin/env python

#       apnbf.py
#       
#       Copyright 2011 Daniel Mende <mail@c0decafe.de>
#

#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are
#       met:
#       
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following disclaimer
#         in the documentation and/or other materials provided with the
#         distribution.
#       * Neither the name of the  nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#       
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys
import signal
import socket
import struct
import threading
import time
from optparse import OptionParser

VERSION="0.1"

parser = OptionParser(usage="usage: %s [options] address" % os.path.basename(sys.argv[0]), version=VERSION)
parser.add_option("-w", type="string", help="Wordlist to use", dest="wordlist", default="")
parser.add_option("-d", type="int", help="BruteForce delay", metavar="SEC", dest="delay", default=1)
parser.add_option("-v", help="Be verbose", action="store_true", dest="debug", default=False)
(options, args) = parser.parse_args()
if len(args) != 1:
    parser.error("incorrect number of arguments")

GTP_C_PORT = 2123

causelist = {   192 :   "Non-existent",
                193 :   "Invalid message format",
                194 :   "IMSI not known",
                195 :   "MS is GPRS Detached",
                196 :   "MS is not GPRS Responding",
                197 :   "MS Refuses",
                198 :   "Version not supported",
                199 :   "No resources available",
                200 :   "Service not supported",
                201 :   "Mandatory IE incorrect",
                202 :   "Mandatory IE missing",
                203 :   "Optional IE incorrect",
                204 :   "System failure",
                205 :   "Roaming restriction",
                206 :   "P-TMSI Signature mismatch",
                207 :   "GPRS connection suspended",
                208 :   "Authentication failure",
                209 :   "User authentication failed",
                210 :   "Context not found",
                211 :   "All dynamic PDP addresses are occupied",
                212 :   "No memory is available",
                213 :   "Relocation failure",
                214 :   "Unknown mandatory extension header",
                215 :   "Semantic error in the TFT operation",
                216 :   "Syntactic error in the TFT operation",
                217 :   "Semantic errors in packet filter(s)",
                218 :   "Syntactic errors in packet filter(s)",
                219 :   "Missing or unknown APN",
                220 :   "Unknown PDP address or PDP type",
                221 :   "PDP context without TFT already activated",
                222 :   "APN access denied - no subscription",
                223 :   "APN Restriction type incompatibility with currently active PDP Contexts",
                224 :   "MS MBMS Capabilities Insufficient",
                225 :   "Invalid Correlation-ID",
                226 :   "MBMS Bearer Context Superseded",
                227 :   "Bearer Control Mode violation",
                228 :   "Collision with network initiated request",
                }

try:
    wordlist = open(options.wordlist)
except Exception, e:
    parser.error("cant open wordlist: %s" % e)

class listener(threading.Thread):
    def __init__(self, sock):
        threading.Thread.__init__(self)
        self.sock = sock
        self.running = True
    def run(self):
        while self.running:
            try:
                (data, (ip, port)) = self.sock.recvfrom(4096)
            except Exception, e:
                pass
            else:
                out = ""
                if options.debug:
                    out += "%s:%i sent response\n" % (ip, port)
                try:
                    (v, t, l, s, c) = struct.unpack("!BBHxxxxHxxxB", data[:14])
                    if options.debug:
                        out += "\tversion = %i type = %x len = %i seq = %i cause = %d\n" % (v >> 5, t, l, s, c)
                    if t == 0x11:
                        if c == 128:
                            #req accepted
                            out += "*** APN FOUND: %s\n" % db[s]
                        else:
                            if c in causelist:
                                out += "\t%s\n" % causelist[c]
                except:
                    pass
                print out
                
    def quit(self):
        self.running = False

seq = 0
db = {}

def build_pdp_request(apn, gsn):
    global seq
    global db
    s = seq
    seq += 1
    l = len(apn)
    a = struct.pack("!B", l - 1) + apn.rstrip('\r\n')
    g = socket.inet_aton(gsn)
    db[s] = apn

    dpd_req = "\x00\x00\x00\x00" + struct.pack("!H", s) + "\x00\x00\x02\x22\x16\x11\x00\x21\x00\x00\xf1\x0e\x2a\x0f\xfc\x10\x00\x0c\x35\x01\x11\x00\x0c\x26\xee\x14\x05\x80\x00\x02\xf1\x21\x83" + struct.pack("!H", l) + a + "\x85\x00\x04\x0a\x0a\x01\x05\x85\x00\x04\x0a\x0a\x01\x05\x86\x00\x07\x91\x04\x07\x21\x00\x00\xf1\x87\x00\x0f\x02\x02\x62\x1f\x91\x97\xfe\xfe\x76\xf9\x40\x40\x00\x00\x00\x97\x00\x01\x01\x98\x00\x08\x00\x22\x66\x01\xff\xfe\x11\x11\x99\x00\x02\x01\x01\x9a\x00\x08\x99\x99\x00\x10\x02\x00\x10\x11"
    dpd_req = "\x32\x10" + struct.pack("!H", len(dpd_req) - 4) + dpd_req
    return dpd_req

def quit(sig, data):
    global l
    l.quit()
    wordlist.close()

print "apnbf v%s\t\tCopyright 2011 Daniel Mende <mail@c0decafe.de>" % VERSION
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)
s.bind(('', GTP_C_PORT))
l = listener(s)
signal.signal(signal.SIGINT, quit)
l.start()
print "starting scan of " + args[0]
for line in wordlist:
    try:
        print "trying %s" % line.rstrip('\r\n')
        s.sendto(build_pdp_request(line, args[0]), (args[0], GTP_C_PORT))
        time.sleep(options.delay)
    except:
        pass
time.sleep(5)
l.quit()
print "done"
