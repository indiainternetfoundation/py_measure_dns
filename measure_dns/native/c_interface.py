import ctypes
import os

# Get the absolute path of the shared library
LIBRARY_NAME = "measuredns.so"  # Change to "measuredns.dll" for Windows if needed
LIBRARY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'compiler', LIBRARY_NAME)

if not os.path.exists(LIBRARY_PATH):
    from measure_dns.compiler.ensure_measuredns import ensure_measuredns

    print("building `measuredns`", end=" :\t")
    print(ensure_measuredns())

# Load shared C library safely
dns_lib = ctypes.CDLL(LIBRARY_PATH)


class AdditionalParam(ctypes.Structure):
    """
    Represents an additional parameter returned by the measuredns C library.

    Attributes:
        type (int): Identifier indicating the type of the additional parameter.
        data (bytes): Raw binary data associated with the parameter (max 32 bytes).
    """

    _fields_ = [
        ("type", ctypes.c_int),  # Type identifier for the parameter
        ("data", ctypes.c_ubyte * 32),  # Storage for the parameter data
    ]


class PDMOption(ctypes.Structure):
    """
    Represents the Performance and Diagnostic Metrics (PDM) option structure.

    Attributes:
        option_type (int): Type identifier for the option (usually 0x0F).
        opt_len (int): Length of the option data.
        scale_dtlr (int): Scaling factor for delta time last received.
        scale_dtls (int): Scaling factor for delta time last sent.
        psntp (int): Packet sequence number of this packet.
        psnlr (int): Packet sequence number last received.
        deltatlr (int): Delta time last received.
        deltatls (int): Delta time last sent.
    """

    _fields_ = [
        ("option_type", ctypes.c_uint8),  # 0x0F (00001111)
        ("opt_len", ctypes.c_uint8),  # 10 (length excluding type and length fields)
        ("scale_dtlr", ctypes.c_uint8),  # Scale for Delta Time Last Received
        ("scale_dtls", ctypes.c_uint8),  # Scale for Delta Time Last Sent
        ("psntp", ctypes.c_uint16),  # Packet Sequence Number This Packet
        ("psnlr", ctypes.c_uint16),  # Packet Sequence Number Last Received
        ("deltatlr", ctypes.c_uint16),  # Delta Time Last Received
        ("deltatls", ctypes.c_uint16),  # Delta Time Last Sent
    ]


class DestOptHdr(ctypes.Structure):
    """
    Represents an IPv6 Destination Option Header.

    Attributes:
        next_header (int): Indicates the next header type.
        hdr_ext_len (int): Header extension length in 8-octet units.
        options (bytes): Raw option data (typically includes PDM option).
    """

    _fields_ = [
        ("next_header", ctypes.c_uint8),  # Next header after this extension
        ("hdr_ext_len", ctypes.c_uint8),  # Header extension length (in 8-octet units)
        ("options", ctypes.c_uint8 * 14),  # PDM option + padding (14 bytes)
    ]


class DNSResponse(ctypes.Structure):
    """
    Represents the raw DNS response returned from the C library.

    Attributes:
        response_size (int): Size of the DNS response in bytes.
        latency_ns (float): Latency of the DNS request in nanoseconds.
        response (bytes): Raw DNS response (max 512 bytes).
        num_additional_params (int): Number of additional diagnostic parameters returned.
        additional_params (pointer): Pointer to the array of AdditionalParam.
    """

    _fields_ = [
        ("response_size", ctypes.c_int),
        ("latency_ns", ctypes.c_double),
        ("response", ctypes.c_ubyte * 512),
        ("num_additional_params", ctypes.c_int),
        ("additional_params", ctypes.POINTER(AdditionalParam)),
    ]


# Configure argument and return type of the native query_dns function
# Ensures safe interoperation between Python and C
# Signature:
#   int query_dns(char*, uint8_t*, int, DNSResponse*, int, int);
dns_lib.query_dns.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_int,
    ctypes.POINTER(DNSResponse),
    ctypes.c_int,  # use_ipv6 flag
    ctypes.c_int,  # additional flags (e.g., IPv6 traffic class)
]
dns_lib.query_dns.restype = ctypes.c_int