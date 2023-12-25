import ctypes

_lib = ctypes.CDLL('./libcm.so')

enc = _lib.enc
enc.argtypes = [ctypes.c_uint64]
enc.restype = ctypes.c_uint64

