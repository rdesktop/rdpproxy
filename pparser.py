#!/usr/bin/env python2

import string
import getopt
import sys
import time
import re
import POW
import struct
import os

from keymap import keymap

keys = keymap("keymaps", 'sv')
currentchannel = 0

rdp_channel_flags = [(0x80000000, "OPTION_INITIALIZED"),
                     (1073741824, "OPTION_ENCRYPT_RDP"),
                     (536870912, "OPTION_ENCRYPT_SC"),
                     (268435456, "OPTION_ENCRYPT_CS"),
                     (134217728, "OPTION_PRI_HIGH"),
                     (67108864, "OPTION_PRI_MED"),
                     (33554432, "OPTION_PRI_LOW"),
                     (8388608, "OPTION_COMPRESS_RDP"),
                     (4194304, "OPTION_COMPRESS"),
                     (2097152, "OPTION_SHOW_PROTOCOL")]

rdp_channels = {}

def LaTeX_escape(s):
    s = s.replace("#", "\\#")
    s = s.replace("_", "\\_")
    return s

class PacketPart:
    BER_TAGS = {'BOOLEAN':1,
                'INTEGER':2,
                'OCTET_STRING':4,
                'TAG_RESULT':10,
                'DOMAIN_PARAMS':0x30,
                'CONN_INITIAL':0x7f65,
                'CONN_RESPONSE':0x7f66}

    classname = "PacketPart"

    def __init__(self, description, knvalue=None, indent=0, **kw):
        self.description = description
        self.owntbl = 1
        self.knvalue = knvalue
        self.indent = indent
        self.datatype = "[unknown type]"
        self.value = []
        self.raw = 0
        self.maxlength = 0

        if kw.has_key('maxlength'):
            self.maxlength = kw['maxlength']
        else:
            self.maxlength = None

    def __len__(self):
        ret = 0
        for p in self.value:
            ret+=len(p)
        return ret

    def strvalue(self):
        if 0 == len(self.value):
            return "[no value]"
        else:
            ret = "\n"+" "*self.indent
            ret+=string.join(map(lambda x: str(x),
                                 self.value),
                             "\n"+" "*self.indent)
        return ret

    def tblvalue(self, **kw):
        s =  "%s\t%s\t" % (self.datatype,
                           self.description)
        if None != self.knvalue:
            s+=str(self.knvalue)
        s+="\t%s\t" % self.strvalue()
        return s

    def latexvalue(self, **kw):
        s = "%s & %s &" % (self.datatype, self.description)
        if None != self.knvalue:
            s+=str(self.knvalue)
        s+="& %s \\\\ \n" % self.strvalue()
        return s

    def __str__(self):
        ret = " "*self.indent+self.datatype+" "+self.description+" "
        if None != self.knvalue:
            ret+="(expected: "+str(self.knvalue)+") "
        if self.raw:
            ret+=" RAW DATA (length 0x%.2x (%d))" % (self.rawlength,
                                                   self.rawlength)
        return ret+self.strvalue()

    def hextostr(self, data, fill=1):
        ret = ""
        if fill and len(data) < 16:
            ret+=(16-len(data))*"   "
        for c in data:
            if c >= 0x20 and c < 0x7f:
                ret+=chr(c)
            else:
                ret+="."
        return ret

    def packtobytestring(self, data):
        ret = ""
        for byte in data:
            ret+=struct.pack('B', byte)
        return ret

    def parse(self, data):
        """Parse the packet value into a human readable form.
        In PacketPart (top-level class), we just eat the bytes and
        present it as a hexdump, as a last resort"""

        returndata = []
        if None != self.maxlength:
            returndata = data[self.maxlength:]
            data = data[:self.maxlength]

        self.raw = 1
        self.rawlength = len(data)

        while 0 < len(data):
            hl = HexLine("")
            data = hl.parse(data)
            self.value.append(hl)

        return returndata

    def postparse(self, data):
        return data

    def preparse(self, data):
        return data

    def ppparse(self, data):
        return self.postparse(self.parse(self.preparse(data)))

class CryptoSignature(PacketPart):
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.owntbl = 0

    def latexvalue(self, **kw):
        return "RAW & Crypto signature & & 8 bytes of data\\\\"

class HexLine(PacketPart):

    classname = "HexLine"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype="RAW"
        self.owntbl = 0

    def parse(self, data):
        self.value = data[:16]
        return data[16:]

    def strvalue(self):
        datap = map(lambda x: "%.2x" % x, self.value)
        return string.join(datap, ' ')+" "+self.hextostr(self.value)

    def tblvalue(self, **kw):
        return "RAW\t%s\t\t%s\t%s" % (self.description, string.join(
            map(lambda x: "%.2x" % x, self.value), " "),
                                         self.hextostr(self.value, fill=0))

    def tblvalue(self, **kw):
        return "RAW & %s& & %s & %s \\\n" % (self.description, string.join(
            map(lambda x: "%.2x" % x, self.value), " "),
                                         self.hextostr(self.value, fill=0))
    

    

    def __len__(self):
        return len(self.value)
        
        
class Integer8Part(PacketPart):

    classname = "Integer8Part"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype="Int8 (be)"
        self.value = -1
        self.owntbl = 0

    def __len__(self):
        return 1

    def strvalue(self):
        return "0x%.2x (%d)" % (self.value, self.value)

    def parse(self, data):
        self.value = data[0]
        return data[1:]

class Integer16Part(Integer8Part):

    classname = "Integer16Part"    

    def __init__(self, description, **kw):
        Integer8Part.__init__(self, description, **kw)
        self.datatype="Int16 (be)"

    def __len__(self):
        return 2        

    def strvalue(self):
        return "0x%.4x (%d)" % (self.value, self.value)

    def parse(self, data):
        try:
            self.value = string.atoi(string.join(map(lambda x: "%.2x" % x,
                                                     data[0:2]), ''), 16)
        except ValueError:
            print "Exception while parsing %s:" % self.description
            raise
        return data[2:]

class Integer16or8000Part(Integer16Part):

    classname = "Integer16or8000Part"

    def parse(self, data):
        data = Integer16Part.parse(self, data)
        self.value = self.value & ~0x8000
        self.datatype = "Int16 (be) | 0x8000"
        return data
    
class Integer16lePart(Integer16Part):

    classname = "Integer16lePart"

    def __init__(self, description, **kw):
        Integer8Part.__init__(self, description, **kw)
        self.datatype="Int16 (le)"

    def parse(self, data):
        mydata = data[0:2]
        mydata.reverse()
        Integer16Part.parse(self, mydata)
        return data[2:]

class Integer32Part(Integer8Part):

    classname = "Integer32Part"

    def __init__(self, description, **kw):
        Integer8Part.__init__(self, description, **kw)
        self.datatype="Int32 (be)"

    def __len__(self):
        return 4        

    def strvalue(self):
        return "0x%.8x (%d)" % (self.value, self.value)

    def parse(self, data):
        valstr = string.join(map(lambda x: "%.2x" % x, data[:4]), '')
        try:
            self.value = string.atoi(valstr, 16)
        except ValueError:
            self.value = string.atol(valstr, 16)
        return data[4:]

class Integer32lePart(Integer32Part):

    classname = "Integer32lePart"

    def __init__(self, description, **kw):
        Integer32Part.__init__(self, description, **kw)
        self.datatype="Int32 (le)"

    def parse(self, data):
        mydata = data[0:4]
        mydata.reverse()
        Integer32Part.parse(self, mydata)
        return data[4:]

class Time32le(Integer32lePart):

    classname = "Time32le"

    def __init__(self, description, **kw):
        Integer32lePart.__init__(self, description, **kw)
        self.datatype="Time"

    def strvalue(self):
        return Integer32Part.strvalue(self)+\
               " (%s)" % time.asctime(time.gmtime(self.value))
        

class VariableInt(PacketPart):

    classname = "VariableInt"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.owntbl = 0        

    def parse(self, data):
        self.value = data[0]
        data = data[1:]
        self.datatype = "VariableInt(1)"
        self.lengthbytes = 0
        if self.value & 0x80:
            self.lengthbytes = self.value & ~0x80
            self.datatype = "VariableInt(%d)" % self.lengthbytes
            self.value = string.atoi(string.join(map(lambda x: "%.2x" % x,
                                                     data[0:self.lengthbytes]),
                                                 ''), 16)
            data = data[self.lengthbytes:]
            
        return data

    def __len__(self):
        return self.lengthbytes+1

    def strvalue(self):
        return "0x%.4x (%d)" % (self.value, self.value)

class MSVariableInt(VariableInt):

    classname = "MSVariableInt"

    def parse(self, data):
        self.value = data[0]
        data = data[1:]
        self.datatype = "MSVariableInt(1)"
        self.lengthbytes = 1

        if self.value & 0x80:
            self.lengthbytes = 2
            lb = data[0]
            data = data[1:]
            self.value = ((self.value & ~0x80) << 8) | lb
            self.datatype = "MSVariableInt(2)"
            

        return data

class KnownLengthInt(PacketPart):

    classname = "KnownLengthInt"

    def __init__(self, description, length, **kw):
        PacketPart.__init__(self, description, **kw)
        self.length = length
        self.datatype = "KLIInt(%d)" % (8*length)
        self.owntbl = 0

    def strvalue(self):
        return "0x%.2x (%d)" % (self.value, self.value)

    def parse(self, data):
        self.value = string.atoi(string.join(map(lambda x: "%.2x" % x,
                                                 data[0:self.length]),
                                             ''), 16)
        return data[self.length:]

    def __len__(self):
        return self.length
    

class MultiTableValue(PacketPart):

    classname = "MultiTableValue"

    def tblvalue(self, offset=0):
        s = "%s\n" % self.value[0].tblvalue(offset=offset)
        offset+=len(self.value[0])
        for part in self.value[1:-1]:
            s+="%d\t%s\n" % (offset, part.tblvalue(offset=offset))
            offset+=len(part)
        s+="%d\t%s" % (offset, self.value[-1:][0].tblvalue(offset=offset))
        return s

    def latexvalue(self, offset=0):
        s = "%s\n" % self.value[0].latexvalue(offset=offset)
        offset+=len(self.value[0])
        for part in self.value[1:-1]:
            s+="%d & %s\n" % (offset, part.latexvalue(offset=offset))
            offset+=len(part)
        s+="%d & %s\\\\" % (offset,
                            self.value[-1:][0].latexvalue(offset=offset))
        return s


class BERHeader(PacketPart):

    classname = "BERHeader"

    def __init__(self, description, tag, **kw):
        PacketPart.__init__(self, description, **kw)
        self.tag = tag
        self.owntbl = 0
        self.taglen = 1

    def parse(self, data):
        if self.tag > 0xff:
            self.taglen = 2
            self.realtag = string.atoi(string.join(map(lambda x: "%.2x" % x,
                                                  data[0:2]), ''), 16)

            self.datatype = "BER tag %d" % (self.realtag)

            if self.realtag != self.tag:
                raise "Unexpected BER tag, "\
                      "got %s expected %s" % (str(self.value),
                      str(self.tag))

            data = data[2:]

        else:
            self.realtag = data[0]

            self.datatype = "BER tag %d" % (self.realtag)

            if self.realtag != self.tag:
                raise "Unexpected BER tag, "\
                      "got %s expected %s" % (str(self.value), str(self.tag))

            data = data[1:]

        length = VariableInt("BER length", indent=self.indent+1)
        self.value.append(length)
        return length.parse(data)

    def __len__(self):
        return self.taglen + len(self.value[0])

    def tblvalue(self, offset=0):
        s = "%s\t%s\t%s\t%s\n" % (self.datatype, self.description,
                                  self.tag, self.realtag)
        return s+"%d\t%s" % (offset+self.taglen,
                             self.value[0].tblvalue(offset=offset+self.taglen))

    def latexvalue(self, offset=0):
        s = "%s & %s & %s & %s \\\\" % (self.datatype, self.description,
                                  self.tag, self.realtag)
        return s+"%d & %s" % (offset+self.taglen,
                              self.value[0].latexvalue(offset=offset+self.taglen))
        
        


class BERValue(MultiTableValue):

    classname = "BERValue"

    def __init__(self, description, bertype, **kw):
        PacketPart.__init__(self, description, **kw)
        self.bertype = bertype
        self.owntbl = 0 

    def parse(self, data):
        hdr = BERHeader(self.bertype, self.BER_TAGS[self.bertype],
                        indent=self.indent+1)
        self.value.append(hdr)
        data = hdr.parse(data)

        self.datatype = "BER %s(%d)" % (self.bertype,
                                               8*hdr.value[0].value)
        

        kliint = KnownLengthInt(self.description + " Value",
                                hdr.value[0].value,
                                indent=self.indent+1)
        self.value.append(kliint)
        return kliint.parse(data)


class DomainParametersPacket(PacketPart):

    classname = "DomainParametersPacket"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "Domain Parameters"    

    def parse(self, data):
        domparam_initial_header = BERHeader(self.description,
                                            self.BER_TAGS['DOMAIN_PARAMS'],
                                            indent=self.indent)
        self.value.append(domparam_initial_header)

        self.value.append(BERValue("Channels", 'INTEGER',
                                   indent=self.indent+1))
        self.value.append(BERValue("Users", 'INTEGER',
                                   indent=self.indent+1))
        self.value.append(BERValue("Tokens", 'INTEGER',
                                   indent=self.indent+1))
        self.value.append(BERValue("Priorities", 'INTEGER',
                                   indent=self.indent+1))
        self.value.append(BERValue("Throughput", 'INTEGER',
                                   indent=self.indent+1))
        self.value.append(BERValue("Height", 'INTEGER', indent=self.indent+1))
        self.value.append(BERValue("PDUsize", 'INTEGER', indent=self.indent+1))
        self.value.append(BERValue("Protocol", 'INTEGER',
                                   indent=self.indent+1))

        for dp in self.value:
            data = dp.parse(data)

        return data

class Latin1String(PacketPart):
    classname = "Latin1String"

    def __init__(self, description, length, **kw):
        PacketPart.__init__(self, description, **kw)
        self.havenullchar=1
        if kw.has_key("nonullchar"):
            self.havenullchar=0
        self.datatype = "Latin1 String(%d" % length
        if self.havenullchar:
            self.datatype+=" + nullchar)"
        else:
            self.datatype+=")"
        self.length = length
        self.owntbl = 0        



    def __len__(self):
        return self.length + self.havenullchar

    def strvalue(self):
        return self.value

    def parse(self, data):
        self.value = ""
        mydata = data[0:self.length]
        for char in mydata:
            if char != 0:
                self.value+=(chr(char))

        return data[self.length+self.havenullchar:]

class UnicodeString(PacketPart):

    classname = "UnicodeString"

    def __init__(self, description, length, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "Unicode string(%d)" % length
        self.length = length
        self.owntbl = 0

    def __len__(self):
        return self.length

    def strvalue(self):
        return self.value

    def parse(self, data):
        self.value = ""
        mydata = data[0:2*self.length]
        while 0 < len(mydata):
            thischr = mydata[0:2]
            thischr.reverse()
            val = string.atoi(string.join(map(lambda x: "%.2x" % x,
                                              thischr), ''), 16)
            if val in range(1, 256):
                self.value+=unichr(val).encode('latin-1')
            elif 0 == val:
                self.value+="."
            else:
                self.value+="§"
            mydata = mydata[2:]

        return data[2*self.length:]

class ColorDepthInfo(Integer16lePart):

    classname = "ColorDepthInfo"

    depths = {0xca01:'8',
              0xca02:'15',
              0xca03:'16',
              0xca04:'24'}
    
    def __init__(self, description, **kw):
        Integer16lePart.__init__(self, description, **kw)
        self.datatype = "ColorDepth (Int16 (le))"

    def strvalue(self):
        return Integer16lePart.strvalue(self) + "(%s bits depth)" % self.depths.get(self.value, "Unknown")
        

class UserdataClientinfoPacket(PacketPart):

    classname = "UserdataClientinfoPacket"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "MCS userdata/clientinfo"

    def parse(self, data):
        clinfotag = Integer16lePart("Client info tag", knvalue=0xc001,
                                    indent=self.indent)
        self.value.append(clinfotag)
        data = clinfotag.parse(data)

        if clinfotag.value != 0xc001:
            raise "Expected Client info (tagged by 0xc001), got %d" % clinfotag.value

        clinfolen = Integer16lePart("Client info length",
                                    knvalue="136 in rdesktop, "\
                                    "%d bytes remaining" % (len(data)-2),
                                    indent=self.indent)
        self.value.append(clinfolen)
        data = clinfolen.parse(data)

        clinfodata = data[:clinfolen.value-4]
        
        self.value.append(Integer16lePart("RDP version",
                                          knvalue="0x0001 for RDP4, "\
                                          "0x0004 for RDP5",
                                          indent=self.indent))
        self.value.append(Integer16lePart("", knvalue=0x0008,
                                          indent=self.indent))
        self.value.append(Integer16lePart("Width",
                                          indent=self.indent))
        self.value.append(Integer16lePart("Height",
                                          indent=self.indent))
        self.value.append(Integer16lePart("", knvalue=0xca01,
                                          indent=self.indent))
        self.value.append(Integer16lePart("", knvalue=0xaa03,
                                          indent=self.indent))
        self.value.append(Integer32lePart("Keylayout", 
                                          indent=self.indent))
        self.value.append(Integer32lePart("Client build", 
                                          indent=self.indent))
        self.value.append(UnicodeString("Hostname", 16,
                                        indent=self.indent))
        self.value.append(Integer32lePart("", knvalue=0x00000004,
                                          indent=self.indent))
        self.value.append(Integer32lePart("", knvalue=0x00000000,
                                          indent=self.indent))
        self.value.append(Integer32lePart("", knvalue=0x0000000c,
                                          indent=self.indent))

        valuelen = len(self.value)
        
        for dp in self.value[2:]:
            clinfodata = dp.parse(clinfodata)

        reserved_data = PacketPart("Reserved data", indent=self.indent)
        self.value.append(reserved_data)
        reserved_data.parse(clinfodata[:64])
        valuelen+=1

        clinfodata = clinfodata[64:]

        self.value.append(ColorDepthInfo("(client)", indent=self.indent))

        self.value.append(Integer16lePart("", knvalue=0x0000,
                                          indent=self.indent))        

        self.value.append(PacketPart("Remaining client data",
                                     indent=self.indent))

        for dp in self.value[valuelen:]:
            clinfodata = dp.parse(clinfodata)

        return data[clinfolen.value-4:]

class CertificatePart(PacketPart):

    classname = "CertificatePart"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "Certificate"

    def parse(self, data):
        returndata = []
        if None != self.maxlength:
            returndata = data[self.maxlength:]
            data = data[:self.maxlength]

        strcert = self.packtobytestring(data)
        x = POW.derRead(POW.X509_CERTIFICATE, strcert)
        self.value = [x.pprint().replace("\\x00", "")]

        return returndata

    def latexvalue(self, **kw):
        return "\\begin{verbatim}\n%s\n\\end{verbatim}" % self.value

class MCSResponseCryptinfoPacket(PacketPart):

    classname = "MCSResponseCryptinfoPacket"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "MCS response userdata cryptinfo"

    def parse(self, data):
        self.value.append(Integer32lePart("RC4 key size", indent=self.indent,
                                          knvalue="1/40 bit, 2/128 bit"))
        self.value.append(Integer32lePart("Encryption level",
                                          indent=self.indent,
                                          knvalue="0/None, 1/Low, 2/Med, 3/High"))
        randsaltlen = Integer32lePart("Random salt len",
                                      indent=self.indent,
                                      knvalue=0x20)
        self.value.append(randsaltlen)

        for dp in self.value:
            data = dp.parse(data)

        valuelen = len(self.value)        

        self.value.append(Integer32lePart("RSA info len",
                                          indent=self.indent,
                                          knvalue=len(data)-32-4))

        for dp in self.value[valuelen:]:
            data = dp.parse(data)

        valuelen = len(self.value)

        self.value.append(PacketPart("Server salt", indent=self.indent, maxlength=randsaltlen.value))

        self.value.append(PacketPart("Cert header", indent=self.indent, maxlength=8))
        cacertlen = Integer32lePart("CA Certificate length", indent=self.indent)
        self.value.append(cacertlen)

        for dp in self.value[valuelen:]:
            data = dp.parse(data)

        valuelen = len(self.value)

        self.value.append(CertificatePart("(CA)", indent=self.indent,
                                          maxlength=cacertlen.value))
        certlen = Integer32lePart("Certificate length", indent=self.indent)
        self.value.append(certlen)
                          
        for dp in self.value[valuelen:]:
            data = dp.parse(data)

        valuelen = len(self.value)

        self.value.append(CertificatePart("", indent=self.indent, maxlength=certlen.value))            
        self.value.append(PacketPart("Remaining info", indent=self.indent))

        for dp in self.value[valuelen:]:
            data = dp.parse(data)
        
        return data
        
class SrvInfoPart(PacketPart):

    classname = "Srvinfopart"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "TAG_SRV_INFO"

    def parse(self, data):
        self.value.append(Integer16lePart("RDP version",
                                          indent=self.indent+1))
        self.value.append(Integer16lePart("Unknown",
                                          indent=self.indent+1,
                                          knvalue=8))

        for dp in self.value:
            data = dp.parse(data)

        return data
        
class TaggedData(PacketPart):

    classname = "TaggedData"

    class HexLines(PacketPart):
        classname = "HexLines"
        def tblvalue(self, offset=0):
            s = self.value[0].tblvalue()+"\n"
            offset+=len(self.value[0])
            for hexline in self.value[1:]:
                s+="%d\t%s\n" % (offset, hexline.tblvalue())
                offset+=len(hexline)
            return s

        def latexvalue(self, offset=0):
            s = self.value[0].latexvalue()+"\n"
            offset+=len(self.value[0])
            for hexline in self.value[1:]:
                s+="%d & %s\\\\\n" % (offset, hexline.latexvalue())
                offset+=len(hexline)
            return s

    class CliChannelsPart(PacketPart):
        classname = "CliChannelsPart"
        class ChannelFlags(Integer32lePart):

            classname = "ChannelFlags"

            def __init__(self, description, **kw):
                PacketPart.__init__(self, description, **kw)
                self.datatype = "RDP Channel Flags"
                self.owntbl = 0

            def strvalue(self):
                ret = Integer32lePart.strvalue(self)+" "
                for flag, desc in rdp_channel_flags:
                    if self.value & flag:
                        ret+="%s, " % desc

                return ret

        def __init__(self, description, **kw):
            PacketPart.__init__(self, description, **kw)
            self.datatype = "RDP Channel data"
            self.owntbl = 1

        def parse(self, data):
            numchannels = Integer32lePart("Number of channels", indent=self.indent+1)
            self.value.append(numchannels)
            data = numchannels.parse(data)

            for i in range(numchannels.value):
                channelname = Latin1String("Channel #%d name" % i, 7, indent=self.indent+2)
                channelflags = self.ChannelFlags("Channel #%d flags" % i, indent=self.indent+2)
                self.value.append(channelname)
                self.value.append(channelflags)
                data = channelname.parse(data)
                data = channelflags.parse(data)

                rdp_channels[i] = (channelname.value, channelflags.value)

            return data
            
            
            
    
    tags = {0xc001:('TAG_CLI_INFO', HexLines),
            0xc002:('TAG_CLI_CRYPT', HexLines),
            0xc003:('TAG_CLI_CHANNELS', CliChannelsPart),
            0x0c01:('TAG_SRV_INFO', SrvInfoPart),
            0x0c02:('TAG_SRV_CRYPT', MCSResponseCryptinfoPacket),
            0x0c03:('TAG_SRV_SRV3', HexLines)}

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "Tagged data"
        self.owntbl = 1

    def parse(self, data):

        while 0 < len(data):

            tag = Integer16lePart("Tag", indent=self.indent+2)
            data = tag.parse(data)

            length = Integer16lePart("Length", indent=self.indent+2)
            data = length.parse(data)

            (tagtype, packetclass) = self.tags.get(tag.value,
                                                   ("Unknown", self.HexLines))

            datapart = packetclass("Data", indent=self.indent+2)
            packetdata = data[:length.value-4]
            datapart.parse(packetdata)

            container = PacketPart("%s" % tagtype,
                                   indent=self.indent+1)
            container.datatype = "Tagged datapart"
            container.value.append(tag)
            container.value.append(length)
            container.value.append(datapart)

            self.value.append(container)

            data = data[length.value-4:]

        return data # Should return empty list.

    def tblvalue(self, offset=0):
        tag = self.value[0].value[0]
        length = self.value[0].value[1]
        dp = self.value[0].value[2]
        (tagtype, packetclass) = self.tags.get(tag.value,
                                               ("Unknown", PacketPart))
        
        s = "%s\tTag\t\t%s (%s)\n" % (tag.datatype,
                                      tag.value, tagtype)
        offset+=len(tag)
        s+= "%d\t%s\n" % (offset, length.tblvalue(offset=offset))
        offset+=len(length)
        s+= "%d\t%s\n" % (offset, dp.tblvalue(offset=offset))
        offset+=len(dp)
        for cont in self.value[1:]:
            tag = cont.value[0]
            length = cont.value[1]
            dp = cont.value[2]
            (tagtype, packetclass) = self.tags.get(tag.value,
                                                   ("Unknown", PacketPart))
        
            s+= "%d\t%s\tTag\t\t%s (%s)\n" % (offset, tag.datatype,
                                              tag.value, tagtype)
            offset+=len(tag)
            s+= "%d\t%s\n" % (offset, length.tblvalue(offset=offset))
            offset+=len(length)
            s+= "%d\t%s\n" % (offset, dp.tblvalue(offset=offset))
            offset+=len(dp)
                               
        return s

    def latexvalue(self, offset=0):
        tag = self.value[0].value[0]
        length = self.value[0].value[1]
        dp = self.value[0].value[2]
        (tagtype, packetclass) = self.tags.get(tag.value,
                                               ("Unknown", PacketPart))
        
        s = "%s & Tag & & %s (%s)\\\\\n" % (tag.datatype,
                                      tag.value, tagtype)
        offset+=len(tag)
        s+= "%d & %s \\\\\n" % (offset, length.latexvalue(offset=offset))
        offset+=len(length)
        s+= "%d & %s \\\\\n" % (offset, dp.latexvalue(offset=offset))
        offset+=len(dp)
        for cont in self.value[1:]:
            tag = cont.value[0]
            length = cont.value[1]
            dp = cont.value[2]
            (tagtype, packetclass) = self.tags.get(tag.value,
                                                   ("Unknown", PacketPart))
        
            s+= "%d & %s & Tag & & %s (%s)\\\\\n" % (offset, tag.datatype,
                                              tag.value, tagtype)
            offset+=len(tag)
            s+= "%d & %s \\\\ " % (offset, length.latexvalue(offset=offset))
            offset+=len(length)
            s+= "%d & %s \\\\\n" % (offset, dp.latexvalue(offset=offset))
            offset+=len(dp)
                               
        return s            

            

class MCSResponseUserdataPacket(PacketPart):

    classname = "MCSResponseUserdataPacket"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "MCS response userdata"

    def parse(self, data):
        userdata_length = BERHeader("Userdata length",
                                    self.BER_TAGS['OCTET_STRING'],
                                    indent=self.indent)
        self.value.append(userdata_length)
        data = userdata_length.parse(data)

        userdata = data[:userdata_length.value[0].value]

        t124 = PacketPart("T.124 data", indent=self.indent)
        t124.parse(userdata[:21])
        self.value.append(t124)

        userdata = userdata[21:]

        remlength = MSVariableInt("Remaining length "\
                                  "(remaining bytes: %d)" % len(userdata),
                                  indent=self.indent)
        self.value.append(remlength)

        userdata = remlength.parse(userdata)

        tagged_data = TaggedData("Tagged data", indent=self.indent)
        self.value.append(tagged_data)
        userdata = tagged_data.parse(userdata)

        if 0 < len(userdata):
            remaining_data = PacketPart("Remaining MCS response user data",
                                        indent=self.indent)
            self.value.append(remaining_data)
            remaining_data.parse(userdata)

        return data[userdata_length.value[0].value:]

class McsInitialUserdataPacket(PacketPart):

    classname = "McsInitialUserdataPacket"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "MCS initial userdata"

    def parse(self, data):
        userdata_length = BERHeader("Userdata length",
                                    self.BER_TAGS['OCTET_STRING'],
                                    indent=self.indent)
        self.value.append(userdata_length)
        self.value.append(Integer16Part("", knvalue=0x05, indent=self.indent))
        self.value.append(Integer16Part("", knvalue=0x14, indent=self.indent))
        self.value.append(Integer8Part("", knvalue=0x7c, indent=self.indent))
        self.value.append(Integer16Part("", knvalue=0x01, indent=self.indent))

        for dp in self.value:
            data = dp.parse(data)

        vallen = len(self.value)
        
        remlen = Integer16or8000Part("Remaining length "\
                                     "(should be %d)" % (len(data)-2),
                                     indent=self.indent)
        self.value.append(remlen)
        
        self.value.append(Integer16Part("", knvalue=0x08, indent=self.indent))
        self.value.append(Integer16Part("", knvalue=0x0f, indent=self.indent))
        self.value.append(Integer8Part("", knvalue=0x00, indent=self.indent))
        self.value.append(Integer16Part("", knvalue=0xc001,
                                        indent=self.indent))
        self.value.append(Integer8Part("", knvalue=0x00, indent=self.indent))
        self.value.append(Integer32lePart("", knvalue="0x61637544 \"Duca\"",
                                          indent=self.indent))

        for dp in self.value[vallen:]:
            data = dp.parse(data)

        remlen = Integer16or8000Part("Remaining length "\
                                     "(should be %d)" % (len(data)-2),
                                     indent=self.indent)
        self.value.append(remlen)
        data = remlen.parse(data)


        clientinfo = UserdataClientinfoPacket("", indent=self.indent+1)
        self.value.append(clientinfo)
        data = clientinfo.parse(data)

        td = TaggedData("", indent=self.indent+1)
        self.value.append(td)
        data = td.parse(data)

        if len(data):
            remaining_userdata = PacketPart("Remaining user data",
                                            indent=self.indent)
            self.value.append(remaining_userdata)
            data = remaining_userdata.parse(data)

        return data[remlen.value:]



class MCSConnInitialPacket(PacketPart):

    classname = "MCSConnInitialPacket"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "MCS Connect Initial"

    def parse(self, data):
        conn_initial_header = BERHeader("MCS Conn initial",
                                        self.BER_TAGS['CONN_INITIAL'],
                                        indent=self.indent)
        self.value.append(conn_initial_header)
        self.value.append(BERValue("Calling Domain", 'OCTET_STRING',
                                   indent=self.indent))

        self.value.append(BERValue("Called Domain", 'OCTET_STRING',
                                   indent=self.indent))
        self.value.append(BERValue("Upward flag", 'BOOLEAN',
                                   indent=self.indent))

        self.value.append(DomainParametersPacket("Target", indent=self.indent))
        self.value.append(DomainParametersPacket("Min", indent=self.indent))
        self.value.append(DomainParametersPacket("Max", indent=self.indent))
        self.value.append(McsInitialUserdataPacket("", indent=self.indent))

        for dp in self.value:
            data = dp.parse(data)
        
        # Code below should basically print nothing, when done deencoding
        # the whole packet.

        rempkt = PacketPart("Remaining MCS conn initial data",
                            indent=self.indent)
        self.value.append(rempkt)
        remdata = rempkt.parse(data[:conn_initial_header.value[0].value])
        return remdata + data[conn_initial_header.value[0].value:]


class MCSConnResponsePacket(PacketPart):

    classname = "MCSConnResponsePacket"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "MCS Connect Response"

    def parse(self, data):
        self.value.append(BERHeader("MCS Conn response",
                                    self.BER_TAGS['CONN_RESPONSE'],
                                    indent=self.indent))
        self.value.append(BERValue("Result", 'TAG_RESULT',
                                   indent=self.indent))
        self.value.append(BERValue("Connection id", 'INTEGER',
                                   indent=self.indent))
        self.value.append(DomainParametersPacket("Target", indent=self.indent))
        self.value.append(MCSResponseUserdataPacket("User data",
                                                    indent=self.indent))

        for dp in self.value:
            data = dp.parse(data)

        return data


class EDRQPart(PacketPart):

    classname = "EDRQPart"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "EDRQ data"

    def parse(self, data):
        self.value.append(Integer16lePart("SubHeight", indent=self.indent))
        self.value.append(Integer16lePart("SubInterval", indent=self.indent))

        for dp in self.value:
            data = dp.parse(data)

        return data

class Enumerated(PacketPart):

    classname = "Enumerated"

    def __init__(self, description, dataparser=Integer8Part, **kw):
        PacketPart.__init__(self, description, **kw)
        self.dataparser = dataparser("")
        

    def parse(self, data):
        data = self.dataparser.parse(data)
        self.value = self.dataparser.value
        res = self.results.get(self.value, "Unknown")
        self.parser = PacketPart
        self.datatype = res
        if type(res) == type(()):
            self.datatype = res[0]
            self.parser = res[1]

        return data
    
    def strvalue(self):
        return self.dataparser.strvalue()+" %s" % self.datatype
                                                                
class MCSResultPart(Enumerated):

    classname = "MCSResultPart"

    results = {0:"RT-SUCCESSFUL",
               1:"RT-DOMAIN-MERGING",
               2:"RT-DOMAIN-NOT-HIEARCHICAL",
               3:"RT-NO-SUCH-CHANNEL",
               4:"RT-NO-SUCH-DOMAIN",
               5:"RT-NO-SUCH-USER",
               6:"RT-NOT-ADMITTED",
               7:"RT-OTHER-USER-ID",
               8:"RT-PARAMETERS-UNACCEPTABLE",
               9:"RT-TOKEN-NOT-AVAILABLE",
               10:"RT-TOKEN-NOT-POSSESSED",
               11:"RT-TOO-MANY-CHANNELS",
               12:"RT-TOO-MANY-TOKENS",
               13:"RT-TOO-MANY-USERS",
               14:"RT-UNSPECIFIED-FAILURE",
               15:"RT-USER-REJECTED"}
               
               
    def __init__(self, description, **kw):
        Enumerated.__init__(self, description, **kw)
        self.datatype = "AUCF data"

class DataPriorityPart(Enumerated):

    classname = "DataPriorityPart"

    results = {0:"top",
               1:"high",
               2:"medium",
               3:"low"}
    
    def __init__(self, description, **kw):
        Enumerated.__init__(self, description, **kw)
        self.datatype = "Data Priority"

class AUCFPart(PacketPart):

    classname = "AUCFPart"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "AUCF data"
    
    def parse(self, data):
        self.value.append(MCSResultPart("", indent=self.indent+1))
        self.value.append(Integer16Part("User id", indent=self.indent+1))

        for dp in self.value:
            data = dp.parse(data)

        return data

class CJRQPart(PacketPart):

    classname = "CJRQPart"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "CJRQ data"
    
    def parse(self, data):
        self.value.append(Integer16Part("User id", indent=self.indent+1))
        self.channelid = Integer16Part("Channel id", indent=self.indent+1)
        self.value.append(self.channelid)

        for dp in self.value:
            data = dp.parse(data)

        global currentchannel
        currentchannel = self.channelid.value

        return data

class CJCFPart(PacketPart):

    classname = "CJCFPart"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "CJCF data"    

    def parse(self, data):
        self.value.append(MCSResultPart("", indent=self.indent+1))
        self.value.append(Integer16Part("Initiator (user id)",
                                        indent=self.indent+1))
        self.value.append(Integer16Part("Requested", indent=self.indent+1))
        self.channelid = Integer16Part("Channel id", indent=self.indent+1)        
        self.value.append(self.channelid)

        for dp in self.value:
            data = dp.parse(data)

        global currentchannel
        currentchannel = self.channelid.value            

        return data

class LicensePart(PacketPart):

    classname = "LicensePart"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "License data"

    def parse(self, data):
        self.value.append(Integer16lePart("Tag", indent=self.indent))
        length = Integer8Part("Length", indent=self.indent)
        self.value.append(length)

        for dp in self.value:
            data = dp.parse(data)

        remaining_data = PacketPart("Remaining license data",
                                    indent=self.indent+1)
        self.value.append(remaining_data)
        remaining_data.parse(data[:length.value-3])

        return data[length.value-3:]

class GeneralCapability(PacketPart):

    classname = "GeneralCapability"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "General Capability set"

    def parse(self, data):
        self.value.append(Integer16lePart("OS major type",
                                          indent=self.indent+1))
        self.value.append(Integer16lePart("OS minor type",
                                          indent=self.indent+1))
        self.value.append(Integer16Part("Protocol version",
                                          indent=self.indent+1))
        self.value.append(Integer16Part("Pad",
                                          indent=self.indent+1))
        self.value.append(Integer16Part("Compression types",
                                          indent=self.indent+1))
        self.value.append(Integer16Part("Pad",
                                          indent=self.indent+1))
        self.value.append(Integer16Part("Update capability",
                                          indent=self.indent+1))
        self.value.append(Integer16Part("Remote unshare capability",
                                          indent=self.indent+1))
        self.value.append(Integer16Part("Compression level",
                                          indent=self.indent+1))
        self.value.append(Integer16Part("Pad",
                                          indent=self.indent+1))

        for dp in self.value:
            data = dp.parse(data)

        return data

class OrderCapability(PacketPart):

    classname = "OrderCapability"
    
    class OrderCaps(PacketPart):

        classname = "OrderCaps"
        
        def __init__(self, description, **kw):
            PacketPart.__init__(self, description, **kw)
            self.datatype = "Orders supported"

        def parse(self, data):
            self.value.append(Integer8Part("Dest blt",
                                           indent=self.indent+1,
                                           knvalue=1))
            self.value.append(Integer8Part("Pat blt",
                                           indent=self.indent+1,
                                           knvalue=1))
            self.value.append(Integer8Part("Screen blt",
                                           indent=self.indent+1,
                                           knvalue=1))            
            self.value.append(Integer8Part("Req for memblt?",
                                           indent=self.indent+1,
                                           knvalue=1))
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))                        
            self.value.append(Integer8Part("Line",
                                           indent=self.indent+1,
                                           knvalue=1))
            self.value.append(Integer8Part("Line",
                                           indent=self.indent+1,
                                           knvalue=1))            
            self.value.append(Integer8Part("Rect",
                                           indent=self.indent+1,
                                           knvalue=1))
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))
            self.value.append(Integer8Part("Memblt",
                                           indent=self.indent+1,
                                           knvalue=1))
            self.value.append(Integer8Part("Triblt",
                                           indent=self.indent+1,
                                           knvalue=1))
            self.value.append(Integer8Part("Triblt",
                                           indent=self.indent+1,
                                           knvalue=1))                        
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))
            self.value.append(Integer8Part("Unknown",
                                           indent=self.indent+1,
                                           knvalue=0))
            self.value.append(Integer8Part("Polyline",
                                           indent=self.indent+1,
                                           knvalue=1))
            self.value.append(Integer8Part("Text2",
                                           indent=self.indent+1,
                                           knvalue=1))
            self.value.append(PacketPart("Rem. order support data",
                                         indent=self.indent+1,
                                         maxlength=8))

            for dp in self.value:
                data = dp.parse(data)

            return data

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "Order Capability set"

    def parse(self, data):
        self.value.append(PacketPart("Terminal desc, pad",
                                     indent=self.indent+1,
                                     maxlength=20))
        self.value.append(Integer16lePart("Cache X granularity",
                                          knvalue=1,
                                          indent=self.indent+1))
        self.value.append(Integer16lePart("Cache Y granularity",
                                          knvalue=20,
                                          indent=self.indent+1))
        self.value.append(Integer16lePart("Pad",
                                          knvalue=0,
                                          indent=self.indent+1))
        self.value.append(Integer16lePart("Max order level",
                                          knvalue=1,
                                          indent=self.indent+1))
        self.value.append(Integer16lePart("Number of fonts",
                                          knvalue=0x147,
                                          indent=self.indent+1))
        self.value.append(Integer16lePart("Capability flags",
                                          knvalue=0x2a,
                                          indent=self.indent+1))
        self.value.append(self.OrderCaps("Orders supported",
                                         indent=self.indent+1,
                                         maxlength=32))
        self.value.append(Integer16lePart("Text capability flags",
                                          knvalue=0x6a1,
                                          indent=self.indent+1))
        self.value.append(PacketPart("Pad",
                                     indent=self.indent+1,
                                     maxlength=6))
        self.value.append(Integer32lePart("Desktop cache size",
                                          knvalue=0x38400,
                                          indent=self.indent+1))
        self.value.append(Integer32lePart("Unknown",
                                          knvalue=0,
                                          indent=self.indent+1))
        self.value.append(Integer32lePart("Unknown",
                                          knvalue=0x4e4,
                                          indent=self.indent+1))

        for dp in self.value:
            data = dp.parse(data)

        return data
        
        

class CapsetPart(PacketPart):

    classname = "CapsetPart"

    class CapabilityType(Integer16lePart):

        classname = "CapabilityType"
        
        types = {1:('GENERAL', GeneralCapability),
                 2:('BITMAP', PacketPart),
                 3:('ORDER', OrderCapability),
                 4:('BMPCACHE', PacketPart),
                 5:('CONTROL', PacketPart),             
                 7:('ACTIVATE', PacketPart),
                 8:('POINTER', PacketPart),
                 9:('SHARE', PacketPart),
                 10:('COLCACHE', PacketPart),
                 13:('UNKNOWN', PacketPart)}

        def strvalue(self):
            return Integer16lePart.strvalue(self)+" "+self.pkttype

        def parse(self, data):
            data = Integer16lePart.parse(self, data)
            (self.pkttype, self.parser) = self.types.get(self.value,
                                                         ("Unknown",
                                                          PacketPart))
            return data
             
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "Capability set"

    def parse(self, data):
        pkttype = self.CapabilityType("Capability type", indent=self.indent+1)
        data = pkttype.parse(data)
        self.value.append(pkttype)

        pktlen = Integer16lePart("Capability length", indent=self.indent+1)
        data = pktlen.parse(data)
        self.value.append(pktlen)

        datapart = pkttype.parser("", indent=self.indent+1,
                                  maxlength=pktlen.value-4)
        data = datapart.parse(data)
        self.value.append(datapart)

        return data


class DemandActivePart(PacketPart):

    classname = "DemandActivePart"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "Demand Active data"

    def parse(self, data):
        self.value.append(Integer32lePart("Share ID", indent=self.indent+1))
        sourcelen = Integer16lePart("Length of source",
                                    indent=self.indent+1)
        self.value.append(sourcelen)
        self.value.append(Integer16lePart("Capabilities length",
                                          indent=self.indent+1))

        for dp in self.value:
            data = dp.parse(data)

        valuelen = len(self.value)

        self.value.append(PacketPart("Source", indent=self.indent+1,
                                     maxlength=sourcelen.value))

        numcapabilities = Integer16lePart("Number of capabilities",
                                          indent=self.indent+1)
        self.value.append(numcapabilities)
        self.value.append(Integer16lePart("Pad",
                                          indent=self.indent+1))
        self.value.append(Integer16lePart("Pad",
                                          indent=self.indent+1))
        self.value.append(Integer16lePart("Pad",
                                          indent=self.indent+1))

        self.value.append(Integer16lePart("User ID", indent=self.indent+1))

        self.value.append(Integer16lePart("Pad",
                                          indent=self.indent+1))

        for dp in self.value[valuelen:]:
            data = dp.parse(data)

        for i in range(numcapabilities.value):
            capability = CapsetPart("", indent=self.indent+1)
            data = capability.parse(data)
            self.value.append(capability)

        remaining_data = PacketPart("Remaining capability data",
                                    indent=self.indent+1)
        self.value.append(remaining_data)
        
        data = remaining_data.parse(data)

        return data

class ConfirmActivePart(PacketPart):

    classname = "ConfirmActivePart"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "Confirm Active data"

    def parse(self, data):
        self.value.append(Integer32lePart("Share ID", indent=self.indent+1))
        self.value.append(Integer16lePart("User ID", indent=self.indent+1))
        sourcelen = Integer16lePart("Length of source",
                                    indent=self.indent+1)
        self.value.append(sourcelen)
        self.value.append(Integer16lePart("Capabilities length",
                                          indent=self.indent+1))

        for dp in self.value:
            data = dp.parse(data)

        valuelen = len(self.value)

        self.value.append(PacketPart("Source", indent=self.indent+1,
                                     maxlength=sourcelen.value))

        numcapabilities = Integer16lePart("Number of capabilities",
                                          indent=self.indent+1)
        self.value.append(numcapabilities)
        self.value.append(Integer16lePart("Pad",
                                          indent=self.indent+1))

        for dp in self.value[valuelen:]:
            data = dp.parse(data)

        for i in range(numcapabilities.value):
            capability = CapsetPart("", indent=self.indent+1)
            data = capability.parse(data)
            self.value.append(capability)

        remaining_data = PacketPart("Remaining capability data",
                                    indent=self.indent+1)
        self.value.append(remaining_data)
        
        data = remaining_data.parse(data)

        return data    

class DataPDUSynchronize(PacketPart):

    classname = "DataPDUSynchronize"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "RDP Data PDU Synchronize"

    def parse(self, data):
        self.value.append(Integer16lePart("Type", indent=self.indent+1))
        self.value.append(Integer16lePart("Userid(?)", indent=self.indent+1))

        for dp in self.value:
            data = dp.parse(data)

        return data

class DataPDUControl(PacketPart):

    classname = "DataPDUControl"

    class DataPDUControlType(Enumerated):

        classname = "DataPDUControlType"
        
        results = {1:'Request control',
                   2:'Grant control',
                   3:'Control detach',
                   4:'Cooperate'}

        def __init__(self, description, **kw):
            Enumerated.__init__(self, description,
                                dataparser=Integer16lePart, **kw)
            self.datatype = "RDP Control"
        
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "RDP Data PDU Control"

    def parse(self, data):
        self.value.append(self.DataPDUControlType("Action",
                                                  indent=self.indent+1))
        self.value.append(Integer16Part("Userid(?)", indent=self.indent+1))
        # FIXME - Integer32 (not le) in rdesktop
        self.value.append(Integer32lePart("Control id", 
                                        indent=self.indent+1))        

        for dp in self.value:
            data = dp.parse(data)

        return data

class DataPDUFont(PacketPart):

    classname = "DataPDUFont"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "RDP Data PDU Font"

    def parse(self, data):
        self.value.append(Integer16Part("Number of fonts",
                                        indent=self.indent+1))
        self.value.append(Integer16lePart("Unknown",
                                          indent=self.indent+1,
                                          knvalue=0x3e))
        self.value.append(Integer16lePart("Unknown (Sequence?)",
                                          indent=self.indent+1))
        self.value.append(Integer16lePart("Entry size", indent=self.indent+1,
                                          knvalue=0x32))

        for dp in self.value:
            data = dp.parse(data)

        return data

class DataPDUInput(PacketPart):

    classname = "DataPDUInput"

    class InputEvent(PacketPart):

        classname = "InputEvent"

        class MessageType(Enumerated):

            classname = "MessageType"
            
            results = {0:'Synchronize',
                       1:'Codepoint',
                       2:'Virtual key',
                       4:'Scancode',
                       0x8001:'Mouse'}
            
            def __init__(self, description, **kw):
                Enumerated.__init__(self, description,
                                    dataparser=Integer16lePart, **kw)

        class ScanCodePart(Integer16lePart):
            classname = "ScanCodePart"
            
            def strvalue(self):
                return Integer16lePart.strvalue(self) + " (%s)" % keys[self.value]

        def __init__(self, description, **kw):
            PacketPart.__init__(self, description, **kw)
            self.datatype = "Input event"

        def parse(self, data):
            self.value.append(Time32le("Event timestamp",
                                       indent=self.indent+1))
            mt = self.MessageType("Event type",
                                  indent=self.indent+1)
            
            self.value.append(mt)

            # Stoppa in parsning av keycode här på nått sätt. *bonk*

            # Fixme: We should have an enumerated here.
            self.value.append(Integer16lePart("Device flags",
                                              indent=self.indent+1))
            for dp in self.value:
                data = dp.parse(data)
            valuelen = len(self.value)
            
            if 4 == mt.value:
                self.value.append(self.ScanCodePart("Key number",
                                                    indent=self.indent+1))
            else:
                self.value.append(Integer16lePart("Param #1",
                                                  indent=self.indent+1))
            self.value.append(Integer16lePart("Param #2",
                                              indent=self.indent+1))

            for dp in self.value[valuelen:]:
                data = dp.parse(data)

            return data
    

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "RDP Data PDU Input"

    def parse(self, data):
        numevents = Integer16lePart("Number of inputs", indent=self.indent+1)
        self.value.append(numevents)
        data = numevents.parse(data)
        
        self.value.append(Integer16Part("Pad", indent=self.indent+1,
                                        knvalue=0))
        for ordernum in range(numevents.value):
            self.value.append(self.InputEvent("%d" % (ordernum+1),
                                              indent=self.indent+1))

        for dp in self.value[1:]:
            data = dp.parse(data)

        return data
            


class RDP_DATA_PDUType(Enumerated):

    classname = "RDP_DATA_PDUType"
    
    results = {2:'Update',
               20:('Control', DataPDUControl),
               27:'Pointer',
               28:('Input', DataPDUInput),
               31:('Synchronize', DataPDUSynchronize),
               34:'Bell',
               38:'Logon',
               39:('Font2', DataPDUFont)}
               
    
    def __init__(self, description, **kw):
        Enumerated.__init__(self, description, **kw)
        self.datatype = "Data PDUType"
    

class RDP_PDU_DataPart(PacketPart):

    classname = "RDP_PDU_DataPart"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "RDP data PDU"

    def parse(self, data):
        self.value.append(Integer32lePart("Share id", indent=self.indent+1))
        self.value.append(Integer8Part("Pad", indent=self.indent+1,
                                       knvalue=0))
        self.value.append(Integer8Part("Stream id", indent=self.indent+1,
                                       knvalue=1))
        self.value.append(Integer16lePart("Remaining length",
                                          indent=self.indent+1,
                                          knvalue=len(data)-8))
        rdpt = RDP_DATA_PDUType("", indent=self.indent+1)
        self.value.append(rdpt)
        self.value.append(Integer8Part("Compress type", indent=self.indent+1))
        self.value.append(Integer16Part("Compressed length",
                                        indent=self.indent+1))
        for dp in self.value:
            data = dp.parse(data)

        remaining_data = rdpt.parser("", indent=self.indent+1)
        self.value.append(remaining_data)

        data = remaining_data.parse(data)

        return data
        
class RDP_PDUtype(Integer16lePart):

    classname = "RDP_PDUtype"
    
    types = {1:('DEMAND_ACTIVE', DemandActivePart),
             3:('CONFIRM_ACTIVE', ConfirmActivePart),
             6:('DEACTIVATE', PacketPart),
             7:('DATA', RDP_PDU_DataPart)}

    def __init__(self, description, **kw):
        Integer16lePart.__init__(self, description, **kw)
        self.datatype = "RDP pdu type"

    def parse(self, data):
        data = Integer16lePart.parse(self, data)
        (self.typestr, self.parser) = self.types.get((self.value & 0xf),
                                                     ("Unknown", PacketPart))
        return data

    def strvalue(self):
        return Integer16lePart.strvalue(self)+\
               " & 0xf = %d (%s)" % (self.value & 0xf, self.typestr)

class SDIN_RDPData(PacketPart):

    classname = "SDIN_RDPData"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "RDP payload"

    def parse(self, data):
        length = Integer16lePart("Length", indent=self.indent+1)
        self.value.append(length)
        pdutype = RDP_PDUtype("Packet type",
                              indent=self.indent+1)
        self.value.append(pdutype)
        self.value.append(Integer16lePart("User id",
                                        indent=self.indent+1))

        for dp in self.value:
            data = dp.parse(data)

        remaining_data = pdutype.parser("", indent=self.indent+1)
        self.value.append(remaining_data)
        data = remaining_data.parse(data)

        return data


class RDPLogonPart(PacketPart):

    classname = "RDPLogonPart"
    
    class LogonFlags(Integer32lePart):

        classname = "LogonFlags"
        
        flags = [(0x33, "LOGON_NORMAL"),
                 (0x8, "LOGON_AUTO"),
                 (0x100, "BLOB_EXISTS"),
                 (0x280, "COMPRESS")]
        
        def __init__(self, description, **kw):
            PacketPart.__init__(self, description, **kw)
            self.datatype = "RDP Logon Flags"

        def strvalue(self):
            ret = Integer32lePart.strvalue(self)+" "
            for flag, desc in self.flags:
                if self.value & flag:
                    ret+="%s, " % desc

            return ret



    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "RDP Logon packet"

    def parse(self, data):
        self.value.append(Integer32Part("Unknown", indent=self.indent+1,
                                        knvalue=0))
        logonflags = self.LogonFlags("", indent=self.indent+1)
        self.value.append(logonflags)
        len_domain = Integer16lePart("Domain length", indent=self.indent+1)
        len_user = Integer16lePart("User length", indent=self.indent+1)
        self.value+=[len_domain, len_user]

        for dp in self.value:
            data = dp.parse(data)
        valuelen = len(self.value)

        if logonflags.value & 0x8:
            len_password = Integer16lePart("Password length",
                                           indent=self.indent+1)
            self.value.append(len_password)
            
        len_blob = Integer16lePart("BLOB length",
                                        indent=self.indent+1)
        len_blob.value = 0
        if logonflags.value & 0x100:
            self.value.append(len_blob)
        len_program = Integer16lePart("Program length",
                                   indent=self.indent+1)
        self.value.append(len_program)

        for dp in self.value[valuelen:]:
            data = dp.parse(data)

        valuelen = len(self.value)            

        len_directory = Integer16lePart("Directory length", indent=self.indent+1)
        len_directory.value = 0

#        if 0 < len_program.value:
        self.value.append(len_directory)
#        else:
#            self.value.append(Integer16lePart("Instead of directory length", indent=self.indent+1))

        if 0 < len_domain.value:
            self.value.append(UnicodeString("Domain", len_domain.value/2+1,
                                            indent=self.indent+1))
        else:
            self.value.append(Integer16lePart("Instead of domain", indent=self.indent+1))

        if 0 < len_user.value:
            self.value.append(UnicodeString("User", len_user.value/2+1,
                                            indent=self.indent+1))
        if logonflags.value & 0x8:
            self.value.append(UnicodeString("Password", len_password.value/2+1,
                                            indent=self.indent+1))
#        self.value.append(Integer16lePart("Unknown1", indent=self.indent+1,
#                                          knvalue=0xd806))


        if logonflags.value & 0x100:
            self.value.append(PacketPart("BLOB",
                                         indent=self.indent+1,
                                         maxlength=len_blob.value))
            self.value.append(Integer16lePart("Unknown2", indent=self.indent+1,
                                              knvalue=0))        


        for dp in self.value[valuelen:]:
            data = dp.parse(data)

        valuelen = len(self.value)


        if 0 < len_program.value:
            self.value.append(UnicodeString("Program", len_program.value/2+1,
                                            indent=self.indent+1))
        else:
            self.value.append(Integer16lePart("Instead of Program, #0", indent=self.indent+1))
            if 0 == len_directory.value:
                self.value.append(Integer16lePart("Instead of Directory", indent=self.indent+1))

        if 0 < len_directory.value:
            self.value.append(UnicodeString("Directory",
                                            len_directory.value/2+1,
                                            indent=self.indent+1))

        elif 0 < len_program.value:
            self.value.append(Integer16lePart("Instead of directory",
                                              indent=self.indent+1))


        self.value.append(Integer16lePart("Unknown", knvalue=2,
                                          indent=self.indent+1))
        
        iplen = Integer16lePart("Client ip length", indent=self.indent+1)
        self.value.append(iplen)

        for dp in self.value[valuelen:]:
            data = dp.parse(data)
        valuelen = len(self.value)

        

        self.value.append(UnicodeString("Client ip", iplen.value/2, indent=self.indent+1))

        for dp in self.value[valuelen:]:
            data = dp.parse(data)
        valuelen = len(self.value)
            

        if 0 < len(data): # This data seems to be here only when running RDP 5.2 (maybe in .1)

            dllstrlen = Integer16lePart("DLL String length",
                                        indent=self.indent+1)
            self.value.append(dllstrlen)
            data = dllstrlen.parse(data)
            valuelen+=1

            self.value.append(UnicodeString("DLL/executable used", dllstrlen.value/2, indent=self.indent+1))

            self.value.append(Integer16lePart("Unknown3", knvalue=0xffc4, indent=self.indent+1))
            self.value.append(Integer16lePart("Unknown3½", knvalue=0xffff,
                                              indent=self.indent+1))            

            self.value.append(UnicodeString("Time zone #0", 32,
                                            indent=self.indent+1))

            self.value.append(PacketPart("Unknown", indent=self.indent+1,
                                         maxlength=20))

            self.value.append(UnicodeString("Time zone #1", 32, indent=self.indent+1))

            self.value.append(PacketPart("Remaining RDP Logon data",
                                         indent=self.indent+1))

            for dp in self.value[valuelen:]:
                data = dp.parse(data)

        return data

class ClipboardData(PacketPart):

    classname = "ClipboardData"

    class FormatDescription(PacketPart):
        classname = "FormatDescription"

        def __init__(self, description, **kw):
            PacketPart.__init__(self, description, **kw)
            self.datatype = "Clipboard format description"

        def parse(self, data):
            self.value.append(Integer32lePart("Numeric code",
                                              indent=self.indent+1))
            self.value.append(UnicodeString("Text representation", 16,
                                            indent=self.indent+1))

            for dp in self.value:
                data = dp.parse(data)

            return data

    class ChannelDataFlags(Integer32lePart):

        classname = "ChannelDataFlags"

        flags =  [(1, "FLAG_FIRST"),
                  (2, "FLAG_LAST"),
                  (0, "FLAG_MIDDLE"),]

        def __init__(self, description, **kw):
            PacketPart.__init__(self, description, **kw)
            self.datatype = "Channel data flags"
            self.owntbl = 0

        def strvalue(self):
            ret = Integer32lePart.strvalue(self)+" "
            for flag, desc in self.flags:
                if self.value & flag:
                    ret+="%s, " % desc

            return ret        

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "Clipboard data"

    def parse(self, data):
        CHANNEL_FLAG_FIRST = 1
        CHANNEL_FLAG_LAST = 2
        cdlength = Integer32lePart("Clpbrd data length",
                                   indent=self.indent+1)
        flags = self.ChannelDataFlags("Flags", 
                                 indent=self.indent+1)

        self.value = [cdlength, flags]

        for dp in self.value:
            data = dp.parse(data)

        valuelen = len(self.value)

        if flags.value == 2: # Last packet:
            self.value.append(PacketPart("Clipboard data, last packet of several", indent=self.indent+1))            
        elif flags.value & 0x0f ==  0x3: # Single write op.
            ptype0 = Integer16lePart("Ptype0", indent=self.indent+1)
            ptype1 = Integer16lePart("Ptype1", indent=self.indent+1)
            self.value.append(ptype0)
            self.value.append(ptype1)

            for dp in self.value[valuelen:]:
                data = dp.parse(data)

            valuelen = len(self.value)

            if 2 == ptype0.value: # Format announce
                remlen = Integer32lePart("Remaining length", indent=self.indent+1)
                self.value.append(remlen)
                valuelen+=1
                data = remlen.parse(data)

                for i in range(remlen.value/36):
                    self.value.append(self.FormatDescription("#%d" % i,
                                                             indent=self.indent+1))
                self.value.append(Integer32lePart("Unknown (Pad?)", indent=self.indent+1))

            elif 1 == ptype0.value or 3 == ptype0.value: # First pkt from server / answer to format announce
                remlen = Integer32lePart("Remaining length", indent=self.indent+1)
                self.value.append(remlen)
                valuelen+=1
                data = remlen.parse(data)

                self.value.append(Integer32lePart("Unknown (Pad?)", indent=self.indent+1))

            elif 4 == ptype0.value: # Request data
                remlen = Integer32lePart("Remaining length", indent=self.indent+1)
                self.value.append(remlen)
                valuelen+=1
                data = remlen.parse(data)

                self.value.append(Integer32lePart("Requested format code", indent=self.indent+1))
                self.value.append(Integer32lePart("Unknown (Pad?)", indent=self.indent+1))

            elif 5 == ptype0.value: # Send data
                remlen = Integer32lePart("Remaining length", indent=self.indent+1)
                self.value.append(remlen)
                valuelen+=1
                data = remlen.parse(data)

                if remlen.value > 1600:
                    datalen = 1592
                else:
                    datalen = remlen.value

                self.value.append(PacketPart("Clipboard data", indent=self.indent+1,
                                             maxlength=datalen))
                if remlen.value < 1600:
                    self.value.append(Integer32lePart("Unknown (Pad?)", indent=self.indent+1))
                
                
        elif (not (flags.value & CHANNEL_FLAG_FIRST) and not (flags.value & CHANNEL_FLAG_LAST)) or (flags.value & CHANNEL_FLAG_LAST):
            self.value.append(PacketPart("Clipboard data", indent=self.indent+1))

        for dp in self.value[valuelen:]:
            data = dp.parse(data)

        return data
        
        
class SDINPart(PacketPart):

    classname = "SDINPart"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "SDIN data"

    def parse(self, data):
        self.value.append(Integer16Part("Initiator (user id)",
                                        indent=self.indent+1))
        self.channelid = Integer16Part("Channel id", indent=self.indent+1)
        self.value.append(self.channelid)
        self.value.append(Integer8Part("Flags", indent=self.indent+1))
        remaining_length = MSVariableInt("Data length", indent=self.indent+1)
        self.value.append(remaining_length)
        flags = Integer32lePart("Flags(?)", indent=self.indent+1)
        self.value.append(flags)

        for dp in self.value:
            data = dp.parse(data)

        global currentchannel
        currentchannel = self.channelid.value            

        valuelen = len(self.value)

        if flags.value & 0x0008: # Encrypted == have signature
            self.value.append(CryptoSignature("Crypto signature",
                                         indent=self.indent+1, maxlength=8))

        if flags.value & 0x0080: # License packet.
            self.value.append(LicensePart("", indent=self.indent+1))
        elif 1003 < self.channelid.value:
            self.value.append(ClipboardData("", indent=self.indent+1))
        else:
            self.value.append(SDIN_RDPData("", indent=self.indent+1))

        try:
            for dp in self.value[valuelen:]:
                data = dp.parse(data)
        except ValueError:
            if flags.value & 0x260000:
                mysterious = PacketPart("Mysterious data",
                                        indent=self.indent+1)
                self.value.append(mysterious)
                data = mysterious.parse(data)

        if 0 < len(data):
            rem_data = PacketPart("Remaining SDIN data",
                                  indent=self.indent+1)
            data = rem_data.parse(data)
            self.value.append(rem_data)


        return data

class SDRQPart(PacketPart):

    classname = "SDRQPart"

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "SDRQ data"

    def parse(self, data):
        self.value.append(Integer16Part("Initiator (user id)",
                                        indent=self.indent+1))
        self.channelid = Integer16Part("Channel id", indent=self.indent+1)
        self.value.append(self.channelid)
        self.value.append(Integer8Part("Flags", indent=self.indent+1))
        remaining_length = MSVariableInt("Data length", indent=self.indent+1)
        self.value.append(remaining_length)
        flags = Integer32lePart("Flags(?)", indent=self.indent+1)
        self.value.append(flags)

        for dp in self.value:
            data = dp.parse(data)

        global currentchannel
        currentchannel = self.channelid.value            

        valuelen = len(self.value)

        if flags.value & 0x0008:
            cryptsig = CryptoSignature("Crypto signature", indent=self.indent+1)
            cryptsig.parse(data[:8])
            data = data[8:]
            self.value.append(cryptsig)

            valuelen = len(self.value)

            if flags.value & 0x0040: # RDP Logon info
                self.value.append(RDPLogonPart("", indent=self.indent+1))

            elif flags.value & 0x0080: # License neg.
                self.value.append(LicensePart("", indent=self.indent+1))
            elif 1003 < self.channelid.value:
                self.value.append(ClipboardData("", indent=self.indent+1))
            else:
                self.value.append(SDIN_RDPData("", indent=self.indent+1))

        elif flags.value & 0x0001: # Client random
            saltlen = Integer32lePart("Client salt len",
                                      indent=self.indent+1)
            self.value.append(saltlen)
            for dp in self.value[valuelen:]:
                data = dp.parse(data)
            valuelen = len(self.value)

            self.value.append(PacketPart("Client salt", indent=self.indent+1,
                                         maxlength=saltlen.value))

        else:
        
            self.value.append(PacketPart("Remaining SDRQ data",
                                         indent=self.indent+1))

        for dp in self.value[valuelen:]:
            data = dp.parse(data)

        return data


class MCSPacket(PacketPart):

    classname = "MCSPacket"

    class MCStype8(Integer8Part):

        classname = "MCStype8"
        
        types = {1:('EDRQ', EDRQPart), 
                 8:('DPUM', PacketPart), 
                 10:('AURQ', PacketPart), 
                 11:('AUCF', AUCFPart), 
                 14:('CJRQ', CJRQPart), 
                 15:('CJCF', CJCFPart), 
                 25:('SDRQ', SDRQPart), 
                 26:('SDIN', SDINPart)}
        def strvalue(self):
            return "0x%.2x (%d) %s" % (self.value, self.value,
                                       self.typestr)

        def parse(self, data):
            data = Integer8Part.parse(self, data)
            self.value = self.value >> 2
            (self.typestr, self.parser) = self.types.get(self.value,
                                                         ("Unknown",
                                                          PacketPart))
            return data

    class MCStype16(Integer16Part):

        classname = "MCStype16"
        
        types = {0x7f65:'Connect Initial',
                 0x7f66:'Connect Response'}
        def strvalue(self):
            return "0x%.4x (%d) %s" % (self.value, self.value,
                                       self.types.get(self.value, "Unknown"))
    
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "MCS packet"

    def parse(self, data):
        origdata = data
        mcstype = self.MCStype8("MCS type", indent=self.indent+1)
        ndata = mcstype.parse(data)
        if 0x1f == mcstype.value:
            mcstype = self.MCStype16("MCS type", indent=self.indent+1) 
            data = mcstype.parse(data)
        else:
            data = ndata

        if 0x7f65 == mcstype.value:
            rempkt = MCSConnInitialPacket("",
                                          indent=self.indent+1)
        elif 0x7f66 == mcstype.value:
            rempkt = MCSConnResponsePacket("",
                                           indent=self.indent+1)
        else:
            self.value.append(mcstype)
            rempkt = mcstype.parser("", indent=self.indent+1)
            self.value.append(rempkt)
            return rempkt.parse(data)
            

        self.value.append(rempkt)

        # Special case - we print the type twice. Probably not good..
        data = rempkt.parse(origdata)

        return data
            

class ISOPacket(PacketPart):

    classname = "TPDU"

    class ISOPacketType(Integer8Part):

        classname = "TPDU"
        
        types = {0xe0:'Connection request',
                 0xd0:'Connection confirm',
                 0x80:'Disconnect request',
                 0xf0:'Data',
                 0x70:'Error'}    

        def strvalue(self):
            return "0x%.2x (%d) %s" % (self.value, self.value,
                                       self.types.get(self.value, "Unknown"))
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "TPDU"

    def parse(self, data):
        headerlen = Integer8Part("TPDU hdr length", indent=self.indent+1)
        self.value.append(headerlen)

        isotype = self.ISOPacketType("TPDU packet type", indent=self.indent+1)
        self.value.append(isotype)

        data = headerlen.parse(data)
        data = isotype.parse(data)

        if 2 == headerlen.value:
            eot = Integer8Part("TPDU eot", knvalue = 0x80, indent=self.indent+1)
            self.value.append(eot)
            data = eot.parse(data)
            mcs = MCSPacket("", indent=self.indent+1)
            self.value.append(mcs)
            data = mcs.parse(data)

        else:
            dst_ref = Integer16Part("Dst ref", indent=self.indent+1)
            self.value.append(dst_ref)
            
            src_ref = Integer16Part("Src ref", indent=self.indent+1)
            self.value.append(src_ref)

            cls = Integer8Part("Class", indent=self.indent+1)
            self.value.append(cls)

            data = dst_ref.parse(data)
            data = src_ref.parse(data)
            data = cls.parse(data)

        return data
        

class TPKT(PacketPart):

    classname = "TPKT"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "TPKT"

    def parse(self, data):
        
        self.value.append(Integer8Part("TPKT version", indent=self.indent+1,
                                       knvalue = 3))
        self.value.append(Integer8Part("TPKT reserved", indent=self.indent+1,
                                      knvalue = 0))
        self.value.append(Integer16Part("TPKT length", indent=self.indent+1))
        self.value.append(ISOPacket("", indent=self.indent+1))

        for dp in self.value:
            data = dp.parse(data)

        if (0 < len(data)):
            mstshash = Latin1String("mstshash", len(data)-2, nonullchar=1,
                                indent=self.indent+1)
            self.value.append(mstshash)
            data = mstshash.parse(data)

            if (0 < len(data)):
                remaining = Integer16lePart("Unknown", indent=self.indent+1)
                data = remaining.parse(data)
                self.value.append(remaining)

            
                


        return data
        

class OrdersPart(PacketPart):

    classname = "OrdersPart"
    
    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "Orders"

    def parse(self, data):
        if None != self.maxlength:
            returndata = data[self.maxlength:]
            data = data[:self.maxlength]

        self.value.append(Integer16lePart("Order count",
                                          indent=self.indent+1))
        self.value.append(PacketPart("Order data",
                                     indent=self.indent+1))

        for dp in self.value:
            data = dp.parse(data)

        return returndata



class BitmapUpdatePart(PacketPart):

    classname = "BitmapUpdatePart"
    
    class UpdateSubPart(PacketPart):

        classname = "UpdateSubPart"
        
        def __init__(self, description, **kw):
            PacketPart.__init__(self, description, **kw)
            self.datatype = "Bitmap update subpart"

        def parse(self, data):
            pad = Integer16lePart("Pad?", indent=self.indent+1)
            left = Integer16lePart("Left", indent=self.indent+1)
            top = Integer16lePart("Top", indent=self.indent+1)
            right = Integer16lePart("Right", indent=self.indent+1)
            bottom = Integer16lePart("Bottom", indent=self.indent+1)
            width = Integer16lePart("Width", indent=self.indent+1)
            height = Integer16lePart("Height", indent=self.indent+1)
            bpp = Integer16lePart("bpp", indent=self.indent+1)
            compress = Integer16lePart("Compress", indent=self.indent+1)
            bufsize = Integer16lePart("Bufsize", indent=self.indent+1)

            self.value = [pad, left, top, right, bottom, width,
                          height, bpp, compress, bufsize]

            for dp in self.value:
                data = dp.parse(data)

            bmpdata = None
            Bpp = (bpp.value+7) / 8

            if not compress.value:
                bmpdata = PacketPart("BMP data (not compressed)", indent=self.indent+1,
                                     maxlength=width.value*height.value*Bpp)
                data = bmpdata.parse(data)
                self.value.append(bmpdata)
                return data
                
            valuelen = len(self.value)
            
            if compress.value & 0x400:
                size = bufsize
            else:
                self.value.append(Integer16Part("Pad", indent=self.indent+1))
                size = Integer16lePart("Size", indent=self.indent+1)
                self.value.append(size)
                self.value.append(Integer16lePart("Line size", indent=self.indent+1))
                self.value.append(Integer16lePart("Final size", indent=self.indent+1))
                for dp in self.value[valuelen:]:
                    data = dp.parse(data)

            bmpdata = PacketPart("BMP data (compressed)", indent=self.indent+1,
                                 maxlength=size.value)
            data = bmpdata.parse(data)
            self.value.append(bmpdata)
            return data

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "Bitmap update"

    def parse(self, data):
        if None != self.maxlength:
            returndata = data[self.maxlength:]
            data = data[:self.maxlength]

        num_updates = Integer16lePart("# of updates", indent=self.indent+1)
        data = num_updates.parse(data)
        self.value.append(num_updates)

        for i in range(num_updates.value):
            self.value.append(self.UpdateSubPart("%d" % i, indent=self.indent+1))

        for dp in self.value[1:]:
            data = dp.parse(data)

        if 0 < len(data):
            remaining_data = PacketPart("Remaining Bitmap update data", indent=self.indent+1)
            remaining_data.parse(data)
            self.value.append(remaining_data)

        return returndata

class RDP5Packet(PacketPart):

    classname = "RDP5Packet"

    class RDP5StartByte(Integer8Part):

        classname = "RDP5StartByte"
        
        def strvalue(self):
            ret = Integer8Part.strvalue(self)
            if self.value & 0x80:
                ret+=", encrypted"
            ret+=", %d inputs" % ((self.value & 124) >> 2)
            return ret

    class RDP5PacketType(Enumerated):

        classname = "RDP5PacketType"
        
        def __init__(self, description, **kw):
            Enumerated.__init__(self, description, **kw)
            self.datatype = "RDP5 packetpart"
            
        results = {0x00:('Orders', OrdersPart),
                   0x01:('Bitmap update', BitmapUpdatePart),
                   0x02:'Palette',
                   0x03:'Palette with offset 3(?)',
                   0x05:'NullSystemPointer(?)',
                   0x06:'DefaultSystemPointer(?)',
                   0x07:'MonoPointer(?)',
                   0x08:'Position(?)',
                   0x09:'ColourPointer(?)',
                   0x0a:'CachedPointer(?)',
                   0x0b:'Mouse pointer (b/w)'}

    def __init__(self, description, **kw):
        PacketPart.__init__(self, description, **kw)
        self.datatype = "RDP5 packet"

    def encrypted(self):
        return self.startbyte.value & 0x80

    def parse(self, data):
        self.startbyte = self.RDP5StartByte("RDP5 start byte",
                                            indent=self.indent+1)
        self.value.append(self.startbyte)

        remaining_length = MSVariableInt("Packet length",
                                         indent=self.indent+1,
                                         knvalue=len(data))
        self.value.append(remaining_length)

        valuelen = len(self.value)

        for dp in self.value:
            data = dp.parse(data)

        if self.encrypted():
            cryptsig = PacketPart("Cryptsig", indent=self.indent+1)
            self.value.append(cryptsig)
            cryptsig.parse(data[:8])
            data = data[8:]
            valuelen+=1

        while 0 < len(data):
            pt = self.RDP5PacketType("",
                                     indent=self.indent+2)
            self.value.append(pt)
            data = pt.parse(data)
            partlen = Integer16lePart("Partlen(?)",
                                      indent=self.indent+2)
            self.value.append(partlen)
            data = partlen.parse(data)

            partdata = pt.parser("Part data", indent=self.indent+3,
                                 maxlength=partlen.value)
            data = partdata.parse(data)
            self.value.append(partdata)

        remaining_data = PacketPart("Remaining data",
                                     indent=self.indent+1)
        self.value.append(remaining_data)
        return remaining_data.parse(data)

class LaTeXindex:
    def __init__(self):
        self.figs = []
    
    def append(self, filename, description):
        self.figs.append((filename, description))

    def __str__(self):
        ret = """
\\documentclass{report}
\\usepackage[english]{babel}
\\usepackage[latin1]{inputenc}
\\usepackage{graphicx}
\\begin{document}

"""
        for (filename, description) in self.figs:
            ret+= """
\\begin{figure}[h]
\\includegraphics{%s.eps}
\\caption{%s}
\\label{fig:%s}
\\end{figure}

""" % (filename, description, filename)

        ret+= """
\\end{document}


"""
        return ret
        
            

        

clsrefs = {}


def create_tbl(ofile, p, origin, totpacketno, packetno,
               location, classnames, infilename):
    if "Server" == origin:
        origin = "S"
    else:
        origin = "C"

    class PlaceHolder(PacketPart):
        def strvalue(self):
            return self.value

    def rec(part, res, packetno):
        if type([]) == type(part.value):
            newvalue = []
            partno = 0
            for subpart in part.value:
                if isinstance(subpart, PacketPart) and subpart.owntbl:
                    subpart.packetno = "%s%d" % (packetno, partno)
                    res.append(subpart)
                    rec(subpart, res, "%s%d-" % (packetno, partno))

                    placeholder = PlaceHolder(subpart.description)
                    placeholder.datatype = subpart.datatype
                    placeholder.value = "See %s%s%d" % (origin, packetno, partno)
                    newvalue.append(placeholder)

                    partno+=1
                else:
                    newvalue.append(subpart)
            part.value = newvalue

    
    if 0 == totpacketno:
        return

    res = [p]
    p.packetno = packetno
    rec(p, res, "%d-" % packetno)

    outfile = None

    for ppart in res:
        if location:
            if outfile:
                outfile.close()
            if classnames:
                num = 0
                if clsrefs.has_key(ppart.classname):
                    num = clsrefs[ppart.classname]
                    clsrefs[ppart.classname]+=1
                else:
                    clsrefs[ppart.classname]=1
                path = os.path.join(location, "%s-%d-%s%d-%s-%d.tbl" % (infilename.replace(".", "-"), totpacketno, origin, packetno, ppart.classname, num))
            else:
                path = os.path.join(location, "%s%s.tbl" % (origin, ppart.packetno))
            outfile = open(path, 'w')
        else:
            outfile = ofile
        print >> outfile, """
.TS
box;
lB| cB s s s s
r l l l l l
r l l l l l.
%s%s (%s)\t%s %s\t
_
Offset\tDatatype\tDescription\tExpected value\tValue\t
_""" % (origin, ppart.packetno, ppart.classname, ppart.datatype, ppart.description)

        s = ""
        offset = 0
        if type([]) == type(ppart.value):
            for subpart in ppart.value:
                if type("") == type(subpart):
                    print >> outfile, "(str)\t\t\t%s\t" % (subpart)
                else:
                    print >> outfile, "%d\t%s" % (offset,
                                                  subpart.tblvalue(offset=offset))
                    offset+=len(subpart)
                    
        else:
            s =  "off\t%s\t%s\t" % (ppart.datatype,
                                    ppart.description)
            if None != ppart.knvalue:
                s+=str(ppart.knvalue)
            s+="\t%s\t" % ppart.value
            print >> outfile, s
        print >> outfile, ".TE\n"


def create_latex(ofile, p, origin, totpacketno, packetno,
                 location, classnames, infilename):
    if "Server" == origin:
        origin = "S"
    else:
        origin = "C"

    class PlaceHolder(PacketPart):
        def strvalue(self):
            return self.value

    def rec(part, res, packetno):
        if type([]) == type(part.value):
            newvalue = []
            partno = 0
            for subpart in part.value:
                if isinstance(subpart, PacketPart) and subpart.owntbl:
                    subpart.packetno = "%s%d" % (packetno, partno)
                    res.append(subpart)
                    rec(subpart, res, "%s%d-" % (packetno, partno))

                    placeholder = PlaceHolder(subpart.description)
                    placeholder.datatype = subpart.datatype
                    placeholder.value = "\pktref{%s%s%d}" % (origin,
                                                             packetno,
                                                             partno)
                    newvalue.append(placeholder)

                    partno+=1
                else:
                    newvalue.append(subpart)
            part.value = newvalue

    
    if 0 == totpacketno:
        return

    res = [p]
    p.packetno = packetno
    rec(p, res, "%d-" % packetno)

    outfile = None

    summaryfile = open(os.path.join(location, "%s-%d-summary.tex" % (infilename.replace(".", "-"), totpacketno)), 'w')

    print >> summaryfile, """
\\begin{tabular}{l}"""

    fname = ""

    i = 0
    for ppart in res:
        if location:
            if outfile:
                outfile.close()
            if classnames:
                num = 0
                if clsrefs.has_key(ppart.classname):
                    num = clsrefs[ppart.classname]
                    clsrefs[ppart.classname]+=1
                else:
                    clsrefs[ppart.classname]=1
                fname = "%s-%d-%s%d-%s-%d.tex" % (infilename.replace(".", "-"), totpacketno, origin, packetno, ppart.classname, num)
            else:
                fname = "%s%s.tex" % (origin, ppart.packetno)
            outfile = open(os.path.join(location, fname), 'w')
        else:
            outfile = ofile
        print >> outfile, LaTeX_escape("\pkttab{%s%s}{%s %s}{\n" % (origin, ppart.packetno, ppart.datatype, ppart.description))


        s = ""
        offset = 0
        if type([]) == type(ppart.value):
            for subpart in ppart.value:
                if type("") == type(subpart):
                    print >> outfile, LaTeX_escape("(str)&&&&%s\\\\" % (subpart))
                else:
                    print >> outfile, LaTeX_escape("%d & %s" % (offset,
                                                  subpart.latexvalue(offset=offset)))
                    offset+=len(subpart)
                    
        else:
            s =  "off & %s & %s & " % (ppart.datatype,
                                    ppart.description)
            if None != ppart.knvalue:
                s+=str(ppart.knvalue)
            s+="& %s \\\\" % ppart.value
            print >> outfile, LaTeX_escape(s)
        print >> outfile, "}\n"
        if id(ppart) != id(res[-1:][0]):
            print >> summaryfile, "\input{%s}\\\\[\\betweenpktheight]" % os.path.join("figures", "pktfigs", fname)
        else:
            print >> summaryfile, "\input{%s}\\\\" % os.path.join("figures", "pktfigs", fname)

    print >> summaryfile, """\n\\end{tabular}"""

        
    
    
    

def parse_rdpproxy(infile, outfile, outputformat, location,
                   classnames, infilename, wantedchannels, quiet):
    pktre = re.compile("#([0-9]*?), #([0-9]*?) from (Server|Client), type (TPKT|RDP5), l: ([0-9]*), ")
    databeginre = re.compile("^0000 [0-9]{2} ")
    line = infile.readline()
    while line:
        mo = pktre.search(line)
        if None != mo:
            headerline = line
            totpacketno = int(mo.group(1))
            partpacketno = int(mo.group(2))
            part = mo.group(3)
            pkttype = mo.group(4)
            pktlength = int(mo.group(5))
            line = infile.readline()
            while None ==  databeginre.search(line): # Unknown data, print.
                line = infile.readline()
            # We are now expecting pktlength bytes of data
            data = line[5:53]
            lines = pktlength / 16
            if pktlength % 16:
                lines+=1
            lines-=1
            for i in range(lines):
                thisdata = infile.readline()[5:53]
                data+= thisdata
            data = map(lambda x: string.atoi(x, 16), data.strip().split(' '))
            remaining = []
            if "TPKT" == pkttype:
                p = TPKT("from %s" % part)
                remaining = p.parse(data)
            elif "RDP5" == pkttype:
                p = RDP5Packet("from %s" % part)
                remaining = p.parse(data)
            global currentchannel
            if 0 < len(wantedchannels) and currentchannel not in wantedchannels:
                line = infile.readline()
                continue
            currentchannel = 0
            if "TBL" == outputformat:
                create_tbl(outfile, p, part, totpacketno, partpacketno, location, classnames, infilename)
            elif "LATEX" == outputformat:
                create_latex(outfile, p, part, totpacketno, partpacketno, location, classnames, infilename)
            else:
                if not quiet:
                    outfile.write(headerline)
                print >> outfile, p
            if 0 < len(remaining):
                rempkt = PacketPart("Remaining data")
                rempkt.parse(remaining)
                print >> outfile, rempkt
            
        else: # Unknown data line, just print it out.
            if not quiet and "TXT" == outputformat:
                outfile.write("Unknown data: %s" % line)

        outfile.flush()
        line = infile.readline()


    
def print_usage(progname):
    print "%s <infile> <outfile>" % progname
    print "<infile> and <outfile> may be '-' to use stdin/stdout"
    print
    print "OPTIONS is zero or more of the following:"
    print "-f <outputformat> specifies that another format than text is wanted."
    print "                  Possible formats are TXT (default), TBL and LATEX"
    print "-l                Specifies where the files produced by the TBL and LATEX formats should be written."
    print "                  When this flag is used, outfile can be left out"
    print "-n                Use the names of the classes when printing out TBL and LATEX"
    print "-c <channels>     Print only output from specific channels."
    print "-q                Be quiet."
    print "--help            Print this not very helpful message :-)"
    print
    
if '__main__' == __name__:
    now = time.time()
    optlist, args = getopt.getopt(sys.argv[1:], 'f:l:ni:c:q')

    outputformat = "TXT"
    location = None
    classnames = None
    ltxindex_out = None
    channels = []
    quiet = 0
    for arg, opt in optlist:
        if '-f' == arg:
            outputformat = opt
        if '-l' == arg:
            location = opt
        if '-n' == arg:
            classnames = 1
        if '-c' == arg:
            channels = map(int, opt.split(','))
        if '-q' == arg:
            quiet = 1
        if '--help' == arg:
            print_usage(sys.argv[0])
            sys.exit(0)            

    if len(args) < 2 and not location:
        print_usage(sys.argv[0])
        sys.exit(0)

    infile = sys.stdin
    outfile = sys.stdout

    infilename = "stdin"

    if '-' != args[0]:
        infilename = os.path.basename(args[0])
        infile = open(args[0], 'r')
    if not location and '-' != args[1]:
        outfile = open(args[1], 'w')

    parse_rdpproxy(infile, outfile, outputformat, location,
                   classnames, infilename, channels, quiet)

    print "Total processing time: %.2f seconds" % (time.time() - now)

    if sys.stdin != outfile: 
        infile.close()
    if sys.stdout != outfile:
        outfile.close()


# sys.argv = ["ARGL!", '/home/forsberg/xjobb/sniff/w2ktsk.1.out', '/home/forsberg/xjobb/rdpproxy/p.out']
