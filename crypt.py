class Cypher:
    _s_change = [14, 7, 8, 4, 1, 9, 2, 15, 5, 10, 11, 0, 6, 12, 13, 3]

    def __init__(self, default_rounds=32, block_size=6):
        self._default_rounds = default_rounds
        self._block_size = block_size

    # L ops
    def lcshift(self, block: bytes, d: int) -> bytes:
        bits_array = list(
            bin(int.from_bytes(block, "big"))[2:].zfill(self._block_size * 8)
        )
        return int("".join(bits_array[d:] + (bits_array[:d])), 2).to_bytes(
            self._block_size, "big"
        )

    def rcshift(self, block: bytes, d: int) -> bytes:
        bits_array = list(
            bin(int.from_bytes(block, "big"))[2:].zfill(self._block_size * 8)
        )
        return int("".join(bits_array[-d:] + bits_array[:-d]), 2).to_bytes(
            self._block_size, "big"
        )

    # S ops
    def s(self, block: bytes):
        return bytes(
            [
                self._s_change[x & 0b1111] | (self._s_change[x >> 4] << 4)
                for x in list(block)
            ]
        )

    def inv_s(self, block: bytes):
        return bytes(
            [
                self._s_change.index(x & 0b1111)
                | (self._s_change.index(x >> 4) << 4)
                for x in list(block)
            ]
        )

    # X ops
    def x(self, block: bytes, key: int):
        return (int.from_bytes(block, "big") ^ key).to_bytes(self._block_size, "big")

    def encrypt(self, pt: bytes, key: bytes, rounds: int = None, ):

        key_i = int.from_bytes(key[:self._block_size], "big")

        if rounds is None:
            rounds = self._default_rounds

        pt_ba = bytearray(pt)

        for i in range(
                len(pt) // self._block_size
                + 1 * bool(int(len(pt) % self._block_size))
        ):
            for _ in range(rounds):
                block = pt_ba[i : i + self._block_size]
                block = self.lcshift(self.s(self.x(block, key_i)), 11)
                pt_ba[i : i + 6] = block
        return bytes(pt_ba)

    def decrypt(self, ct: bytes, key: bytes, rounds: int = None):
        key_i = int.from_bytes(key[:self._block_size], "big")
        if rounds is None:
            rounds = self._default_rounds

        ct_ba = bytearray(ct)

        for i in range(
                len(ct) // self._block_size
                + 1 * bool(int(len(ct) % self._block_size))
        ):
            for _ in range(rounds):
                block = ct_ba[i * self._block_size : (i + 1) * self._block_size]
                block = self.x(self.inv_s(self.rcshift(block, 11)), key_i)
                ct_ba[i * self._block_size : (i + 1) * self._block_size] = block

        return bytes(ct_ba)

    def __call__(self, pt: bytes, key: bytes):
        return self.encrypt(pt, key)

    def __getitem__(self, ct: bytes, key: bytes):
        return self.decrypt(ct, key)


