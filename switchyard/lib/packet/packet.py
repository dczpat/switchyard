from abc import ABCMeta, abstractmethod
from copy import deepcopy

class Packet(object):
    '''
    Base class for packet headers.
    '''
    __slots__ = ['__headers','__raw']

    def __init__(self, raw=None, first_header=None):
        self.__headers = []
        self.__raw = None
        if raw:
            self.__raw = raw
            self.__parse(raw, first_header)            

    def __len__(self):
        '''Return the packed length of this packet, and all
        subsequent headers and payloads.'''
        return self.size()

    def size(self):
        '''Return the packed length of this header'''
        return sum([len(ph) for ph in self.__headers])

    def to_bytes(self):
        '''
        Returns serialized bytes object representing all headers/
        payloads in this packet'''
        rawlist = []
        i = len(self.__headers)-1
        while i >= 0:
            self.__headers[i].tail_serialized(b''.join(rawlist))
            rawlist.insert(0, self.__headers[i].to_bytes())
            i -= 1
        self.__raw = b''.join(rawlist)
        return self.__raw

    def __parse(self, raw, next_cls):
        '''
        Parse a raw bytes object and construct the list of packet header
        objects (and possible remaining bytes) that are part of this packet.
        '''
        if next_cls is None:
            from switchyard.lib.packet import Ethernet
            next_cls = Ethernet

        self.__headers = []
        while issubclass(next_cls, PacketHeaderBase):
            packet_header_obj = next_cls()
            raw = packet_header_obj.from_bytes(raw)
            self.add_header(packet_header_obj)
            next_cls = packet_header_obj.next_header_class()
            if next_cls is None:
                break
        if raw:
            self.add_header(RawPacketContents(raw))

    @staticmethod
    def from_bytes(raw, first_header):
        '''Create a new packet by parsing the contents of a bytestring'''
        p = Packet(raw, first_header)        
        return p

    def __iadd__(self, ph):
        '''Add the packet header to the end of this packet; return
           this packet header.  Only += (iadd) is defined, since 
           this method is inherently mutating.'''
        if not isinstance(ph, (PacketHeaderBase, bytes)):
            raise Exception("Invalid operand type for +: can't add {} to a Packet".format(type(ph)))
        self.add_header(ph)
        return self

    def __add__(self, pobj):
        if isinstance(pobj, Packet):
            p = deepcopy(self)
            for header in pobj:
                p.add_header(header)
            return p
        elif isinstance(pobj, (PacketHeaderBase, bytes)):
            p = deepcopy(self)
            p.add_header(pobj)
            return p
        else:
            raise Exception("Invalid operand type for +: can't add {} and {} together".format(type(self), type(pobj)))

    def headers(self):
        '''
        Return a list of packet header names in this packet.
        '''
        return [ ph.__class__.__name__ for ph in self.__headers ]
        
    def add_header(self, ph):
        '''
        Add a PacketHeaderBase derived class object, or a raw bytes object
        as the next "header" item in this packet.  Note that 'header'
        may be a slight misnomer since the last portion of a packet is
        considered application payload and not a header per se.
        '''
        if isinstance(ph, PacketHeaderBase) or isinstance(ph, bytes):
            self.__headers.append(ph)            
            return self
        raise Exception("Payload for a packet header must be an object that is a subclass of PacketHeaderBase, or a bytes object.")

    def add_payload(self, ph):
        '''Alias for add_header'''
        self.add_header(ph)

    def has_header(self, hdrclass):
        for hdr in self.__headers:
            if isinstance(hdr, hdrclass):
                return True
        return False

    def get_header(self, hdrclass):
        for hdr in self.__headers:
            if isinstance(hdr, hdrclass):
                return hdr
        return None

    def __iter__(self):
        return iter(self.__headers)

    def __checkidx(self, index):
        if not isinstance(index, int):
            raise TypeError("Indexes must be integers")
        if index < 0:
            index = len(self.__headers) - index
        if not (0 <= index < len(self.__headers)):
            raise IndexError("Index out of range")
        return index
        
    def __getitem__(self, index):
        index = self.__checkidx(index)
        return self.__headers[index]

    def __setitem__(self, index, value):
        index = self.__checkidx(index)
        if not isinstance(value, (PacketHeaderBase, bytes)):
            raise TypeError("Can't assign a non-packet header in a packet")
        self.__headers[index] = value

    def __contains__(self, obj):
        for ph in self.__headers:
            if ph == obj:
                return True
        return False

    def __delitem__(self, index):
        index = self.__checkidx(index)
        self.__headers = self.__headers[:index] + self.__headers[(index+1):] 

    def __eq__(self, other):
        if not isinstance(other, Packet):
            raise TypeError("Can't compare Packet with non-Packet for equality")
        if len(self.headers()) != len(other.headers()):
            return False
        for i in range(len(other.headers())):
            if self[i] != other[i]:
                return False
        return True

    def __str__(self):
        return ' | '.join([str(ph) for ph in self.__headers if isinstance(ph,PacketHeaderBase)])


class PacketHeaderBase(object, metaclass=ABCMeta):
    '''
    Base class for packet headers.
    '''
    __slots__ = []

    def __init__(self):
        pass

    def __len__(self):
        '''Return the packed length of this packet; calls
        abstract method size(), which must be overridden in
        derived classes.'''
        return self.size()

    @abstractmethod
    def size(self):
        '''Return the packed length of this header'''
        return 0

    @abstractmethod
    def next_header_class(self):
        '''Return class of next header, if known.'''
        pass

    @abstractmethod
    def tail_serialized(self, raw):
        '''
        Callback into the header class when any subsequent packet headers
        are serialized.
        '''
        pass

    @abstractmethod
    def to_bytes(self):
        '''return a 'packed' byte-level representation of *this*
        packet header.'''
        return b''

    @abstractmethod
    def from_bytes(self, raw):
        pass        

    def __add__(self, ph):
        '''Add two packet headers together to get a new packet object.'''
        if not isinstance(ph, (bytes,PacketHeaderBase)):
            raise Exception("Only objects derived from PacketHeaderBase and bytes objects can be added to create a new packet.")
        p = Packet()
        p.add_header(self)
        p.add_header(ph)
        return p

    @abstractmethod
    def __eq__(self, other):
        pass

    def __str__(self):
        return self.__class__.__name__


class RawPacketContents(PacketHeaderBase):
    __slots__ = ['__raw'] 

    def __init__(self, raw=None):
        self.__raw = raw

    def to_bytes(self):
        return self.__raw    

    def from_bytes(self, raw):
        self.__raw = bytes(raw)

    def next_header_class(self):
        return None

    def tail_serialized(self, raw):
        return

    def size(self):
        return len(self.__raw)

    def __eq__(self, other):
        return self.to_bytes() == other.to_bytes()

    def __str__(self):
        ellipse = '...'
        if len(self.__raw) < 10:
            ellipse = ''
        return '{} ({} bytes) {}{}'.format(self.__class__.__name__,
            len(self.__raw), self.__raw[:10], ellipse)
