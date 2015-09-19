import dpkt # for packet parsing
import sys # for error handeling
import time # for export_time
from collections import OrderedDict

#---------------base class---------------
template_defs = OrderedDict()

"""Building blocks of the IPFIX packet"""
class building_blocks:
    _size_map = {}

    def _get_size_string(self, key):
        if key in self._size_map:
            # hex string represents one byte with
            # 2 chars
            return self._size_map[key] * 2

    def _get_size_bytes(self, key):
        if key in self._size_map:
            return self._size_map[key]

    def _extract_int(self, buff, var_size):
        return int(buff[:var_size], 16), buff[var_size:]

    def _extract_string(self, buff, str_size):
        return str(buff[:str_size].decode('hex')), buff[str_size:]

    """If possible converts data into readable format
       otherwise returns hex representation of the data """
    def print_block(self):
        print"Invalid ipfix_block"

    """Parse input buff and initialize self.
        Retunrs left-over buffer for next block"""
    def parse_block(self, buff):
        return buff

#--------------ipfix header--------------
class IPFIX_HEADER(building_blocks):
    version = 0x0000
    length =  0x0010
    export_time = 0x00
    sequence_no = 0
    domain_id = 0

    """In bytes. For hex string"""
    _size_map = {
            'version':2,
            'length' :2,
            'export_time' : 4,
            'sequence_no' : 4,
            'domain_id' : 4
            }

    def print_block(self):
        print"Version: " + str(self.version)
        print"length: " + str(self.length)
        print"export_time: " + str(self.export_time)
        print"sequence_no: " + str(self.sequence_no)
        print"domain_id : " + str(self.domain_id)
        print'_'*40

    def parse_block(self, buff):
        self.version, buff = self._extract_int(buff, self._get_size_string('version'))
        self.length, buff = self._extract_int(buff, self._get_size_string('length'))
        exp_time, buff = self._extract_int(buff,self._get_size_string('export_time'))
        self.export_time = time.ctime(exp_time)
        self.sequence_no, buff = self._extract_int(buff, self._get_size_string('sequence_no'))
        self.domain_id, buff = self._extract_int(buff, self._get_size_string('domain_id'))
        return buff

#------------ipfix set header------------
class IPFIX_SET_HEADER(building_blocks):
    set_id = 0
    set_length = 0

    _size_map = {
            'set_id': 2,
            'set_length': 2
            }
    def print_block(self):
        print"set_id: " + str(self.set_id)
        print"set_length: " + str(self.set_length)
        print'_'*40

    def parse_block(self, buff):
        self.set_id, buff = self._extract_int(buff, self._get_size_string('set_id'))
        self.set_length, buff = self._extract_int(buff, self._get_size_string('set_length'))
        return buff

# field specifier class
class IPFIX_FIELDS(building_blocks):
    f_id = 0
    f_length = 0
    f_ent = 0

    _size_map = {
            'f_id': 2,
            'f_length': 2,
            'f_ent': 4
            }
    def print_block(self):
        print"field id: " + str(self.f_id & 0x7fff)

        if self.f_length == 0xffff:
            length = "Variable"
        else :
            length = str(self.f_length)

        print"field length: " + length
        if self.f_id & 0x8000:
            print"Ent bit was 1"
            print"Ent no.: " + str(self.f_ent)
        print '.'*40

    def parse_block(self, buff):
        self.f_id, buff = self._extract_int(buff, self._get_size_string('f_id'))
        self.f_length, buff = self._extract_int(buff, self._get_size_string('f_length'))
        if self.f_id & 0x8000:
            self.f_ent, buff = self._extract_int(buff, self._get_size_string('f_ent'))
        return buff

#template class
class IPFIX_TEMPLATE(building_blocks):
    temp_id = 0
    temp_length = 0
    fields = OrderedDict()

    _size_map = {
            'temp_id': 2,
            'temp_length': 2
            }

    def print_block(self):
        print "TEMPLATE: " + str(self.temp_id)
        print"temp_length: " + str(self.temp_length)
        for field in self.fields:
            self.fields[field].print_block()
        print '+'*40

    def parse_block(self, buff):
        self.temp_id, buff = self._extract_int(buff, self._get_size_string('temp_id'))
        self.temp_length, buff = self._extract_int(buff, self._get_size_string("temp_length"))
        for i in range(self.temp_length):
            f = IPFIX_FIELDS()
            buff = f.parse_block(buff)
            self.fields[f.f_id] = f

        return buff

#parser for data records.
class IPFIX_DATA(building_blocks):
    m_tempId = 0

    def __init__(self, temp_id):
        self.m_tempId = temp_id

    def print_block(self):
        print "Not implemented"

    def parse_block(self, buff):
        return buff

class IPFIX_SET(building_blocks):
    set_header = IPFIX_SET_HEADER()
    data = []

    def print_block(self):
        self.set_header.print_block()
        for record in self.data:
            record.print_block()

    def parse_block(self, buff):
        # parse header
        buff = self.set_header.parse_block(buff)

        # if this is template set
        # parse it and add it to template defs
        if self.set_header.set_id == 2:
            obj = IPFIX_TEMPLATE()
            buff = obj.parse_block(buff)
            template_defs[obj.temp_id] = obj
        else:
            obj = IPFIX_DATA(self.set_header.set_id)
            obj.m_tempId = self.set_header.set_id
            buff = obj.parse_block(buff)

        self.data.append(obj)

        return buff


# header has fixed structure and hence easiest to parse
def parse_ipfix_header(buff):
    # make header
    hdr = IPFIX_HEADER()
    buff = hdr.parse_block(buff)

    # make set
    st = IPFIX_SET()
    buff = st.parse_block(buff)

    for temp in template_defs:
        template_defs[temp].print_block()



    #
    print'='*40
# parse decides if the packet is template of data
# and routes data to appropriate function
def parse(hex_payload):
    parse_ipfix_header(hex_payload)


def extract_ipfix(pcap):
    # loop through packets and extract udp payload
    i = 1
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            vzFlow = ip.data
            print "PACKET " + str(i)
            i+=1
            parse(vzFlow.data.encode('hex'))
        except:
            print"Unexpected error: ", sys.exc_info()[0]
            raise


if __name__ == "__main__":
    # TODO: use getopt for this::
    f = open('test.pcap')
    pcap = dpkt.pcap.Reader(f)
    extract_ipfix(pcap)
