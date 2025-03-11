import os
import enum
import ctypes
import struct
import typing
import dns.message
import dns.name
import dns.rdataclass
from dns.rdataclass import RdataClass
from dataclasses import dataclass
from ipaddress import ip_address, IPv4Address 

# Get the absolute path of the shared library
LIBRARY_NAME = "measuredns.so"  # Change to "measuredns.dll" for Windows if needed
LIBRARY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), LIBRARY_NAME)

# Load shared C library safely
dns_lib = ctypes.CDLL(LIBRARY_PATH)

# Define DNSResponse struct
class DNSResponse(ctypes.Structure):
    _fields_ = [
        ("response_size", ctypes.c_int),
        ("latency_ms", ctypes.c_double),
        ("response", ctypes.c_ubyte * 512)
    ]

# Define return and argument types
dns_lib.query_dns.argtypes = [
    ctypes.c_char_p, 
    ctypes.POINTER(ctypes.c_ubyte), 
    ctypes.c_int, 
    ctypes.POINTER(DNSResponse),
    ctypes.c_int,  # use_ipv6 flag
    ctypes.c_int   # additional flags (e.g., IPv6 traffic class)
]
dns_lib.query_dns.restype = ctypes.c_int

class DNSFlags(enum.IntEnum):
    NoFlag = 0x0000
    PdmMetric = 0x0001
    PreResolve4 = 0x0010 # Resolves the DNS Server domain IPv4
    PreResolve6 = 0x0100 # Resolves the DNS Server domain IPv6
    # DummyFlagB = 0x1000


@dataclass
class DNSQuery:
    qname: dns.name.Name | str
    rdtype: dns.rdatatype.RdataType | str
    rdclass: dns.rdataclass.RdataClass | str = RdataClass.IN
    use_edns: int | bool | None = None
    want_dnssec: bool = False
    ednsflags: int | None = None
    payload: int | None = None
    request_payload: int | None = None
    options: typing.List[dns.edns.Option] | None = None
    idna_codec: dns.name.IDNACodec | None = None
    id: int | None = None
    flags: int = 256
    pad: int = 0

@dataclass
class DNSResult:
    response: dns.message.QueryMessage
    latency_ms: float

def build_dns_query(
        qname: dns.name.Name | str, 
        rdtype: dns.rdatatype.RdataType | str, 
        rdclass: dns.rdataclass.RdataClass | str = RdataClass.IN, 
        use_edns: int | bool | None = None, 
        want_dnssec: bool = False, 
        ednsflags: int | None = None, 
        payload: int | None = None, 
        request_payload: int | None = None, 
        options: typing.List[dns.edns.Option] | None = None, 
        idna_codec: dns.name.IDNACodec | None = None, 
        id: int | None = None, 
        flags: int = 256, 
        pad: int = 0
    ) -> bytes:
    """Builds a raw DNS query packet."""
    query = dns.message.make_query(
        qname = qname,
        rdtype = rdtype,
        rdclass = rdclass,
        use_edns = use_edns,
        want_dnssec = want_dnssec,
        ednsflags = ednsflags,
        payload = payload,
        request_payload = request_payload,
        options = options,
        idna_codec = idna_codec,
        id = id,
        flags = flags,
        pad = pad,
    )

    return query.to_wire()
    
def send_dns_query(query: DNSQuery, dns_server: str, extra_flags : DNSFlags = 0) -> DNSResult:
    """Sends a DNS query and returns the response along with latency."""
    request = build_dns_query(
        qname = query.qname,
        rdtype = query.rdtype,
        rdclass = query.rdclass,
        use_edns = query.use_edns,
        want_dnssec = query.want_dnssec,
        ednsflags = query.ednsflags,
        payload = query.payload,
        request_payload = query.request_payload,
        options = query.options,
        idna_codec = query.idna_codec,
        id = query.id,
        flags = query.flags,
        pad = query.pad,
    )
    request_size = len(request)

    request_ctypes = (ctypes.c_ubyte * request_size)(*request)
    dns_server_ctypes = ctypes.c_char_p(dns_server.encode())

    use_ipv6_ctypes = ctypes.c_int(0 if type(ip_address(dns_server)) is IPv4Address else 1)
    extra_flags_ctypes = ctypes.c_int(extra_flags)

    response_struct = DNSResponse()
    response_size = dns_lib.query_dns(
        dns_server_ctypes,
        request_ctypes,
        request_size,
        ctypes.byref(response_struct),
        use_ipv6_ctypes,
        extra_flags_ctypes
    )
    if response_size > 0:
        return DNSResult(response=decode_dns_response(bytes(response_struct.response[:response_size])), latency_ms=response_struct.latency_ms)
    else:
        return None

def decode_dns_response(response_bytes) -> dns.message.QueryMessage:
    """Decodes a raw DNS response using dnspython."""
    try:
        message = dns.message.from_wire(response_bytes)
        return message

    except Exception as e:
        return {"error": f"Failed to decode response: {e}"}