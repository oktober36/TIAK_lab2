import random
from datetime import datetime

from crypt import Cypher
from crypt_lib import enc


def crypt_def(M: bytes):
    return M


if __name__ == "__main__":
    pairs = {}
    M = random.randbytes(6)
    C = crypt_def(M)


def find_key():
    pairs: dict[int, tuple[int, int]] = {}
    start_time = datetime.now()
    cypher = Cypher()

    while True:
        if len(pairs) % 1_000_000 == 0:
            print(f"Done {format(len(pairs), ',')} in {(datetime.now() - start_time).total_seconds()} secs")

        pt = int.from_bytes(random.randbytes(6), "big")
        ct = enc(pt)
        if pt ^ ct in pairs:
            idx = pt ^ ct
            pt_: int = pairs[idx][0]
            ct_: int = pairs[idx][1]
            if pt_ == pt:
                continue
            key1 = pt ^ int.from_bytes(cypher.inv_s(cypher.rcshift(int.to_bytes(pt_, 6, "big"), 11)), "big")
            key2 = ct ^ int.from_bytes(cypher.inv_s(cypher.rcshift(int.to_bytes(ct_, 6, "big"), 11)), "big")

            print(f"Found keys candidates {key2}, {key1}")

            if key1 == key2:
                if (pt == int.from_bytes(
                        cypher.decrypt(int.to_bytes(ct, 6, "big"), key1.to_bytes(6, "big")),
                        "big") and
                        pt_ == int.from_bytes(cypher.decrypt(int.to_bytes(ct_, 6, "big"), key1.to_bytes(6, "big")),
                                              "big")):
                    print(f"Found key {key1} in {(datetime.now() - start_time).total_seconds()} secs")
                    return key1
        pairs[int.from_bytes(cypher.inv_s(cypher.rcshift(int.to_bytes(pt, 6, "big"), 11)), "big") ^ int.from_bytes(
            cypher.inv_s(cypher.rcshift(int.to_bytes(ct, 6, "big"), 11)), "big")] = (pt, ct)


if __name__ == '__main__':
    key = find_key()

    c = Cypher()
    pt = c.decrypt((0x097f07940fec1159ed6cffa9).to_bytes(12, "big"), (key).to_bytes(6, "big"))
    print(f"Decrypted text: {pt.decode()}")
