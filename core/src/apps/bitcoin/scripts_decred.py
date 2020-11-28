from trezor import utils, wire
from trezor.crypto import base58
from trezor.crypto.base58 import blake256d_32

from apps.common.writers import empty_bytearray


# A submission for a script hash.
def output_script_sstxsubmissionsh(addr: str) -> bytearray:
    try:
        raw_address = base58.decode_check(addr, blake256d_32)
    except ValueError:
        raise wire.DataError("Invalid address")
    w = empty_bytearray(24)
    w.append(0xBA)  # OP_SSTX
    w.append(0xA9)  # OP_HASH160
    w.append(0x14)  # OP_DATA_20
    w.extend(raw_address[2:])
    w.append(0x87)  # OP_EQUAL
    return w


# A submission for an address hash.
def output_script_sstxsubmissionpkh(addr: str) -> bytearray:
    try:
        raw_address = base58.decode_check(addr, blake256d_32)
    except ValueError:
        raise wire.DataError("Invalid address")
    w = empty_bytearray(26)
    w.append(0xBA)  # OP_SSTX
    w.append(0x76)  # OP_DUP
    w.append(0xA9)  # OP_HASH160
    w.append(0x14)  # OP_DATA_20
    w.extend(raw_address[2:])
    w.append(0x88)  # OP_EQUALVERIFY
    w.append(0xAC)  # OP_CHECKSIG
    return w


# A currently unused stake change script. Output amount has been checked to be
# zero. The addr is also checked as to whether it pays to a zeroed hash.
def output_script_sstxchange(addr: str) -> bytearray:
    try:
        raw_address = base58.decode_check(addr, blake256d_32)
    except ValueError:
        raise wire.DataError("Invalid address")
    # Using change addresses is no longer common practice. Inputs are split
    # beforehand.
    for b in raw_address[2:]:
        if b != 0:
            raise wire.DataError("Only zeroed addresses accepted for sstx change")
    w = empty_bytearray(26)
    w.append(0xBD)  # OP_SSTXCHANGE
    w.append(0x76)  # OP_DUP
    w.append(0xA9)  # OP_HASH160
    w.append(0x14)  # OP_DATA_20
    w.extend(raw_address[2:])
    w.append(0x88)  # OP_EQUALVERIFY
    w.append(0xAC)  # OP_CHECKSIG
    return w


# Spend from a stake revocation.
def input_script_ssrtx(pkh: bytes) -> bytearray:
    utils.ensure(len(pkh) == 20)
    s = bytearray(26)
    s[0] = 0xBC  # OP_SSRTX
    s[1] = 0x76  # OP_DUP
    s[2] = 0xA9  # OP_HASH160
    s[3] = 0x14  # OP_DATA_20
    s[4:24] = pkh
    s[24] = 0x88  # OP_EQUALVERIFY
    s[25] = 0xAC  # OP_CHECKSIG
    return s


# Spend from a stake generation.
def input_script_ssgen(pkh: bytes) -> bytearray:
    utils.ensure(len(pkh) == 20)
    s = bytearray(26)
    s[0] = 0xBB  # OP_SSGEN
    s[1] = 0x76  # OP_DUP
    s[2] = 0xA9  # OP_HASH160
    s[3] = 0x14  # OP_DATA_20
    s[4:24] = pkh
    s[24] = 0x88  # OP_EQUALVERIFY
    s[25] = 0xAC  # OP_CHECKSIG
    return s


# Retrieve pkh bytes from a stake commitment OPRETURN.
def pkh_from_sstxcommitment(s: bytes) -> bytes:
    utils.ensure(len(s) == 30)
    pkh = s[:20]
    return pkh
