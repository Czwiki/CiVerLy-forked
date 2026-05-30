from civerly.component import Component
from civerly.component import ConstXOR_CVL
from civerly.cipher import Cipher
from civerly.util import int_to_vec, vec_to_int


class KATAN_Component(Component):
    def __init__(self, variant=32, R=254, key=0, name=None):
        if variant == 32:
            L1, L2 = 13, 19
            xs = (12, 7, 8, 5, 3)
            ys = (18, 7, 12, 10, 8, 3)
            times = 1
        elif variant == 48:
            L1, L2 = 19, 29
            xs = (18, 12, 15, 7, 6)
            ys = (28, 19, 21, 13, 15, 6)
            times = 2
        elif variant == 64:
            L1, L2 = 25, 39
            xs = (24, 15, 20, 11, 9)
            ys = (38, 25, 33, 21, 14, 9)
            times = 3
        else:
            raise ValueError("Unsupported KATAN variant")

        self.variant = variant
        self.L1 = L1
        self.L2 = L2
        self.block_size = L1 + L2
        self.R = R
        self.key = int(key)
        self.xs = xs
        self.ys = ys
        self.times = times
        if name is None:
            name = f"KATAN{variant}"
        super().__init__(self.block_size, self.block_size, name=name)

    def eval(self, x):
        # x is a bit vector (tuple/list). Convert to integer, L2 occupies
        # the least significant bits, L1 the higher bits (as in spec)
        assert len(x) == self.block_size
        P = vec_to_int(x)
        maskL2 = (1 << self.L2) - 1
        L2 = P & maskL2
        L1 = (P >> self.L2) & ((1 << self.L1) - 1)

        # generate key bit sequence k_i using recurrence
        needed = 2 * self.R * self.times
        # ensure enough bits: need at least 2*R*times bits
        k = [(self.key >> i) & 1 for i in range(80)]
        for i in range(80, needed + 80 + 10):
            # k_i = k_{i-80} xor k_{i-61} xor k_{i-50} xor k_{i-13}
            v = k[i-80] ^ k[i-61] ^ k[i-50] ^ k[i-13]
            k.append(v)

        # counter LFSR for irregular update: 8-bit LFSR
        ctr = [1] * 8
        # clock once before encryption
        def clock_ctr(s):
            # polynomial x^8 + x^7 + x^5 + x^3 + 1 -> taps at 7,6,4,2
            new = s[7] ^ s[6] ^ s[4] ^ s[2]
            # shift left: drop MSB, insert new at position 0
            return [new] + s[:7]

        ctr = clock_ctr(ctr)

        # perform R rounds
        ki_idx = 0
        for round_no in range(self.R):
            # each round may apply fa/fb multiple times (times)
            for t in range(self.times):
                ka = k[ki_idx]
                kb = k[ki_idx + 1]
                ki_idx += 2

                IR = ctr[-1]  # use MSB of the 8-bit LFSR as IR

                # compute fa from L1
                x1, x2, x3, x4, x5 = self.xs
                a = ((L1 >> x1) & 1) ^ ((L1 >> x2) & 1)
                a = a ^ (((L1 >> x3) & 1) & ((L1 >> x4) & 1))
                a = a ^ ((((L1 >> x5) & 1) & IR))
                a = a ^ ka

                # compute fb from L2
                y1, y2, y3, y4, y5, y6 = self.ys
                b = ((L2 >> y1) & 1) ^ ((L2 >> y2) & 1)
                b = b ^ (((L2 >> y3) & 1) & ((L2 >> y4) & 1))
                b = b ^ ((((L2 >> y5) & 1) & ((L2 >> y6) & 1)))
                b = b ^ kb

                # shift registers left and load new LSBs
                L1 = (((L1 << 1) & ((1 << self.L1) - 1)) | b)
                L2 = (((L2 << 1) & ((1 << self.L2) - 1)) | a)

                # update counter
                ctr = clock_ctr(ctr)

        C = (L1 << self.L2) | L2
        return int_to_vec(C, self.block_size)

    def _model_milp(self, model_options):
        raise NotImplementedError("MILP modeling for KATAN not implemented")

    def _model_sat(self, model_options):
        raise NotImplementedError("SAT modeling for KATAN not implemented")


class KATAN_CVL:
    def __init__(self, variant=32, R=254, key=0, name=None):
        if name is None:
            name = f"KATAN{variant}"
        comp = KATAN_Component(variant=variant, R=R, key=key, name=name)
        cipher = Cipher(comp.input_length, comp.output_length, name=name)
        node = cipher.add_subcipher(comp, [(cipher.IN, (i, i)) for i in range(comp.input_length)])
        cipher.add_output([(node, (i, i)) for i in range(comp.output_length)])
        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(KATAN_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
