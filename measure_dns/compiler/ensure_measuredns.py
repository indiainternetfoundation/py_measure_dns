import os
import platform

from .gcc_executor import check_gcc,exec_gcc


IS_WINDOWS = platform.system() == "Windows"
SRC_NAME = "measuredns.c"

SRC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "native",
    SRC_NAME
)
LIBRARY_NAME = "measuredns.so"
LIBRARY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), LIBRARY_NAME)


def ensure_measuredns() -> bool:
    if not check_gcc("gcc"):
        print("GCC compiler not found.")
        exit(-1)

    FLAGS = [
        "-shared",
        "-fPIC",
        "-fno-strict-overflow",
        "-Wsign-compare",
        "-DNDEBUG",
        "-g",
        "-O2",
        "-Wall",
    ]

    return exec_gcc("gcc", FLAGS, LIBRARY_PATH, SRC_PATH)
