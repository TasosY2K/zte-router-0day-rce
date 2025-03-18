import argparse
import struct
import zlib
from io import BytesIO
from os import stat
from Crypto.Cipher import AES


def _read_exactly(fd, size, desc='data'):
    """Reads exactly `size` bytes from file-like `fd`. Returns the bytes or None on failure."""
    chunk = fd.read(size)
    if len(chunk) != size:
        print(f'ERROR: failed to read {desc}')
        return None
    return chunk


def _read_struct(fd, fmt, desc='struct'):
    """Reads a struct (defined by `fmt`) from `fd`, returns tuple or None on failure."""
    size = struct.calcsize(fmt)
    data = _read_exactly(fd, size, desc)
    if data is None:
        return None
    return struct.unpack(fmt, data)


def read_aes_data(fd_in, key):
    """Reads AES-encrypted data in chunked form. Decrypts all at once using AES ECB."""
    encrypted_data = b''
    while True:
        # Each AES chunk has a 12-byte header: (unknown, chunk_length, marker)
        aes_hdr = _read_struct(fd_in, '>3I', desc='AES chunk header')
        if aes_hdr is None:
            return None
        _, chunk_len, marker = aes_hdr
        print('AES chunk length:             ', hex(chunk_len))

        chunk = _read_exactly(fd_in, chunk_len, desc='AES chunk data')
        if chunk is None:
            return None

        encrypted_data += chunk
        if marker == 0:
            break

    cipher = AES.new(key.ljust(16, b'\0')[:16], AES.MODE_ECB)
    fd_out = BytesIO()
    fd_out.write(cipher.decrypt(encrypted_data))
    fd_out.seek(0)
    return fd_out


def read_compressed_data(fd_in, enc_header):
    """Reads zlib-compressed data in chunked form, validates CRC."""
    print('encryption header CRC32:       0x{:08X}'.format(enc_header[6]))
    hdr_crc = zlib.crc32(struct.pack('>6I', *enc_header[:6]))
    if enc_header[6] != hdr_crc:
        print("ERROR: encryption header CRC32 doesn't match")
        return None

    total_crc = 0
    fd_out = BytesIO()

    while True:
        # Each compression chunk has a 12-byte header: (uncompressed_len, compressed_len, marker)
        comp_hdr = _read_struct(fd_in, '>3I', desc='compression chunk header')
        if comp_hdr is None:
            return None
        uncompr_len, compr_len, marker = comp_hdr
        print('compressed length:            ', hex(compr_len))
        print('uncompressed length:          ', hex(uncompr_len))

        chunk = _read_exactly(fd_in, compr_len, desc='compression chunk data')
        if chunk is None:
            return None

        total_crc = zlib.crc32(chunk, total_crc)
        uncompressed = zlib.decompress(chunk)
        if len(uncompressed) != uncompr_len:
            print('ERROR: wrong length of uncompressed data')
            return None

        fd_out.write(uncompressed)
        if marker == 0:
            break

    print('compressed data CRC32:         0x{:08X}'.format(enc_header[5]))
    if enc_header[5] != total_crc:
        print("ERROR: compressed data CRC32 doesn't match")
        return None

    fd_out.seek(0)
    return fd_out


def read_config(fd_in, fd_out, key):
    """Reads and decodes the configuration file from ZTE routers."""
    # -- First version header (20 bytes) ----------------------------------
    ver_header_1 = _read_struct(fd_in, '>5I', desc='1st version header')
    if ver_header_1 is None:
        return
    print('first version header magic:   ', ', '.join(f'0x{x:08X}' for x in ver_header_1[:4]))
    if ver_header_1[:4] != (0x99999999, 0x44444444, 0x55555555, 0xAAAAAAAA):
        print('ERROR: expected magic is 0x99999999, 0x44444444, 0x55555555, 0xAAAAAAAA')

    # fifth element is added to 0x14 to get second version header offset
    ver_header_2_offset = 0x14 + ver_header_1[4]
    print('second version header offset: ', hex(ver_header_2_offset))

    fd_in.seek(ver_header_2_offset)
    ver_header_2 = _read_struct(fd_in, '>11I', desc='2nd version header')
    if ver_header_2 is None:
        return
    ver_header_3_offset = ver_header_2[10]
    print('third version header offset:  ', hex(ver_header_3_offset))

    fd_in.seek(ver_header_3_offset)
    ver_header_3 = _read_struct(fd_in, '>2H5I', desc='3rd version header')
    if ver_header_3 is None:
        return
    signed_cfg_size = ver_header_3[3]
    print('signed config size:           ', hex(signed_cfg_size))

    # Validate config size vs. file size
    file_size = stat(fd_in.name).st_size
    if signed_cfg_size != file_size - 0x80:
        print(f"ERROR: config size (0x{signed_cfg_size:x} + 0x80) doesn't match real file size (0x{file_size:x})")

    # -- Signature header & signature -------------------------------------
    fd_in.seek(0x80)
    sign_header = _read_struct(fd_in, '>3I', desc='signature header')
    if sign_header is None:
        return
    print('signature header magic:        0x{:08X}'.format(sign_header[0]))
    if sign_header[0] != 0x04030201:
        print('ERROR: expected magic is 0x04030201')
        return

    sign_length = sign_header[2]
    print('signature length:             ', sign_length)

    signature = _read_exactly(fd_in, sign_length, desc='signature')
    if signature is None:
        return
    print('signature:                    ', signature.decode(errors='replace'))

    # -- Encryption header #1 ---------------------------------------------
    enc_header_raw = _read_exactly(fd_in, 0x3C, desc='encryption header')
    if enc_header_raw is None:
        return
    encryption_header = struct.unpack('>15I', enc_header_raw)
    print('encryption header magic:       0x{:08X}'.format(encryption_header[0]))
    if encryption_header[0] != 0x01020304:
        print('ERROR: expected magic is 0x01020304')
        return

    enc_type = encryption_header[1]
    print('encryption type:              ', enc_type)

    # -- AES decryption if enc_type in [1, 2] -----------------------------
    if enc_type in (1, 2):
        if not key:
            print("ERROR: no AES key specified. Use --key '...'")
            return
        fd_in = read_aes_data(fd_in, key)
        if fd_in is None:
            return

    # If enc_type == 2, read another encryption header (commonly leads to compression)
    if enc_type == 2:
        enc_header_raw = _read_exactly(fd_in, 0x3C, desc='second encryption header')
        if enc_header_raw is None:
            return
        encryption_header = struct.unpack('>15I', enc_header_raw)
        print('encryption header magic:       0x{:08X}'.format(encryption_header[0]))
        if encryption_header[0] != 0x01020304:
            print('ERROR: expected magic is 0x01020304 - likely wrong AES key')
            return
        enc_type = 0  # Next step: compression

    # -- Decompress if enc_type == 0 --------------------------------------
    if enc_type == 0:
        fd_in = read_compressed_data(fd_in, encryption_header)
        if fd_in is None:
            return

    # -- Finally, write out decoded data ----------------------------------
    fd_out.write(fd_in.read())


def main():
    parser = argparse.ArgumentParser(
        description='Decode configuration file (config.bin) from ZTE routers'
    )
    parser.add_argument('infile', type=argparse.FileType('rb'), help='Encoded configuration file')
    parser.add_argument('outfile', type=argparse.FileType('wb'), help='Output file')
    parser.add_argument('--key', type=lambda x: x.encode(), default=b'',
                        help="Key for AES encryption")
    args = parser.parse_args()

    read_config(args.infile, args.outfile, args.key)


if __name__ == '__main__':
    main()