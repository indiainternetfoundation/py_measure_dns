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

# Define additional parameter structure
class AdditionalParam(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),  # Type identifier for the parameter
        ("data", ctypes.c_ubyte * 32)  # Storage for the parameter data
    ]


# Define PDM Option Structure
class PDMOption(ctypes.Structure):
    _fields_ = [
        ("option_type", ctypes.c_uint8),   # 0x0F (00001111)
        ("opt_len", ctypes.c_uint8),       # 10 (length excluding type and length fields)
        ("scale_dtlr", ctypes.c_uint8),    # Scale for Delta Time Last Received
        ("scale_dtls", ctypes.c_uint8),    # Scale for Delta Time Last Sent
        ("psntp", ctypes.c_uint16),        # Packet Sequence Number This Packet
        ("psnlr", ctypes.c_uint16),        # Packet Sequence Number Last Received
        ("deltatlr", ctypes.c_uint16),     # Delta Time Last Received
        ("deltatls", ctypes.c_uint16)      # Delta Time Last Sent
    ]

# Define Destination Option Header Structure
class DestOptHdr(ctypes.Structure):
    _fields_ = [
        ("next_header", ctypes.c_uint8),  # Next header after this extension
        ("hdr_ext_len", ctypes.c_uint8),  # Header extension length (in 8-octet units)
        ("options", ctypes.c_uint8 * 14)  # PDM option + padding (14 bytes)
    ]

# Define DNSResponse struct
class DNSResponse(ctypes.Structure):
    _fields_ = [
        ("response_size", ctypes.c_int),
        ("latency_ns", ctypes.c_double),
        ("response", ctypes.c_ubyte * 512),
        ("num_additional_params", ctypes.c_int),
        ("additional_params", ctypes.POINTER(AdditionalParam))
    ]

# Define return and argument types
dns_lib.query_dns.argtypes = [
    ctypes.c_char_p, 
    ctypes.POINTER(ctypes.c_ubyte), 
    ctypes.c_int, 
    ctypes.POINTER(DNSResponse),
    ctypes.c_int,  # use_ipv6 flag
    ctypes.c_int,  # additional flags (e.g., IPv6 traffic class)
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
    latency_ns: float
    additional_params: list

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
    response_struct.num_additional_params = 0
    response_size = dns_lib.query_dns(
        dns_server_ctypes,
        request_ctypes,
        request_size,
        ctypes.byref(response_struct),
        use_ipv6_ctypes,
        extra_flags_ctypes,
    )
    additional_params_list = []
    for i in range(response_struct.num_additional_params):
        params = response_struct.additional_params[i]
        if params.type == 59:
            # Destination Option
            dstopt = ctypes.cast(params.data, ctypes.POINTER(DestOptHdr)).contents


            # Extract PDM Option (first 10 bytes of options)
            pdm_raw = bytes(dstopt.options[:12])
            
            # Cast the extracted bytes into a PDMOption structure
            pdm_option = PDMOption.from_buffer_copy(pdm_raw)
            additional_params_list.append(pdm_option)

    if response_size > 0:
        return DNSResult(response=decode_dns_response(bytes(response_struct.response[:response_size])), latency_ns=response_struct.latency_ns, additional_params=additional_params_list)
    else:
        return None

def decode_dns_response(response_bytes) -> dns.message.QueryMessage:
    """Decodes a raw DNS response using dnspython."""
    try:
        message = dns.message.from_wire(response_bytes)
        return message

    except Exception as e:
        return {"error": f"Failed to decode response: {e}"}