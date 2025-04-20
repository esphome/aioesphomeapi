# file: _packets.pxd
from .noise_encryption cimport EncryptCipher

cpdef bytes make_plain_text_packets(list packets)

cpdef bytes make_noise_packets(list packets, EncryptCipher encrypt_cipher)
