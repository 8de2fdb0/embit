import hmac
import hashlib
from embit.misc import secure_randint
from .wordlist import SLIP39_WORDS

# functions for SLIP39 checksum
def rs1024_polymod(values):
    GEN = [
        0xE0E040,
        0x1C1C080,
        0x3838100,
        0x7070200,
        0xE0E0009,
        0x1C0C2412,
        0x38086C24,
        0x3090FC48,
        0x21B1F890,
        0x3F3F120,
    ]
    chk = 1
    for v in values:
        b = chk >> 20
        chk = (chk & 0xFFFFF) << 10 ^ v
        for i in range(10):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def cs_bstring(extendable: bool):
    if extendable:
        return b"shamir_extendable"
    else:
        return b"shamir"


def rs1024_verify_checksum(extendable: bool, data):
    cs = cs_bstring(extendable)
    return rs1024_polymod([x for x in cs] + data) == 1


def rs1024_create_checksum(extendable: bool, data):
    cs = cs_bstring(extendable)
    values = [x for x in cs] + data
    polymod = rs1024_polymod(values + [0, 0, 0]) ^ 1
    return [(polymod >> 10 * (2 - i)) & 1023 for i in range(3)]


def _get_salt(id, extendable):
    if extendable:
        return bytes()
    else:
        return b"shamir" + id.to_bytes(2, "big")


# function for encryption/decryption
def _crypt(payload, id, extendable, exponent, passphrase, indices):
    if len(payload) % 2:
        raise ValueError("payload should be an even number of bytes")
    else:
        half = len(payload) // 2
    left = payload[:half]
    right = payload[half:]
    salt = _get_salt(id, extendable)
    for i in indices:
        f = hashlib.pbkdf2_hmac(
            "sha256",
            i + passphrase,
            salt + right,
            # BUG: should be 10000
            # see: https://github.com/satoshilabs/slips/blob/master/slip-0039.md#format-of-the-share-mnemonic
            2500 << exponent,
            half,
        )
        left, right = right, bytes(x ^ y for x, y in zip(left, f))
    return right + left


class Share:
    def __init__(
        self,
        share_bit_length,
        id,
        extendable,
        exponent,
        group_index,
        group_threshold,
        group_count,
        member_index,
        member_threshold,
        value,
    ):
        self.share_bit_length = share_bit_length
        self.id = id
        self.extendable = extendable
        self.exponent = exponent
        self.group_index = group_index
        if group_index < 0 or group_index > 15:
            raise ValueError("Group index should be between 0 and 15 inclusive")
        self.group_threshold = group_threshold
        if group_threshold < 1 or group_threshold > group_count:
            raise ValueError(
                "Group threshold should be between 1 and %d inclusive" % group_count
            )
        self.group_count = group_count
        if group_count < 1 or group_count > 16:
            raise ValueError("Group count should be between 1 and 16 inclusive")
        self.member_index = member_index
        if member_index < 0 or member_index > 15:
            raise ValueError("Member index should be between 0 and 15 inclusive")
        self.member_threshold = member_threshold
        if member_threshold < 1 or member_threshold > 16:
            raise ValueError("Member threshold should be between 1 and 16 inclusive")
        self.value = value
        self.bytes = value.to_bytes(share_bit_length // 8, "big")

    @classmethod
    def parse(cls, mnemonic):
        # convert mnemonic into bits
        words = mnemonic.split()
        indices = [SLIP39_WORDS.index(word) for word in words]
        id = (indices[0] << 5) | (indices[1] >> 5)
        extendable =  bool((indices[1] >> 4) & 1)
        if not rs1024_verify_checksum(extendable, indices):
            raise ValueError("Invalid Checksum")
        exponent = indices[1] & 0x0F
        group_index = indices[2] >> 6
        group_threshold = ((indices[2] >> 2) & 15) + 1
        group_count = (((indices[2] & 3) << 2) | (indices[3] >> 8)) + 1
        member_index = (indices[3] >> 4) & 15
        member_threshold = (indices[3] & 15) + 1
        value = 0
        for index in indices[4:-3]:
            value = (value << 10) | index
        share_bit_length = (len(indices) - 7) * 10 // 16 * 16
        if value >> share_bit_length != 0:
            raise SyntaxError("Share not 0-padded properly")
        if share_bit_length < 128:
            raise ValueError("not enough bits")
        return cls(
            share_bit_length,
            id,
            extendable,
            exponent,
            group_index,
            group_threshold,
            group_count,
            member_index,
            member_threshold,
            value,
        )

    def mnemonic(self):
        all_bits = (self.id << 5) | self.extendable << 4 | self.exponent
        all_bits <<= 4
        all_bits |= self.group_index
        all_bits <<= 4
        all_bits |= self.group_threshold - 1
        all_bits <<= 4
        all_bits |= self.group_count - 1
        all_bits <<= 4
        all_bits |= self.member_index
        all_bits <<= 4
        all_bits |= self.member_threshold - 1
        padding = 10 - self.share_bit_length % 10
        all_bits <<= padding + self.share_bit_length
        all_bits |= self.value
        num_words = 4 + (padding + self.share_bit_length) // 10
        indices = [
            (all_bits >> 10 * (num_words - i - 1)) & 1023 for i in range(num_words)
        ]
        checksum = rs1024_create_checksum(self.extendable, indices)
        return " ".join([SLIP39_WORDS[index] for index in indices + checksum])


class ShareSet:
    exp = bytearray(255)
    log2 = bytearray(256)

    @classmethod
    def _load(cls):
        """Pre-computes the exponent/log for LaGrange calculation"""
        cur = 1
        for i in range(255):
            cls.exp[i] = cur
            cls.log2[cur] = i
            cur = (cur << 1) ^ cur
            if cur > 255:
                cur ^= 0x11B

    def __init__(self, shares):
        self.shares = shares
        if len(shares) > 1:
            # check that the identifiers are the same
            ids = {s.id for s in shares}
            if len(ids) != 1:
                raise TypeError("Shares are from different secrets")
            # check that the extendable flags are the same
            extendable = {s.extendable for s in shares}
            if len(extendable) != 1:
                raise TypeError("Shares should have the same extendable flag")
            # check that the exponents are the same
            exponents = {s.exponent for s in shares}
            if len(exponents) != 1:
                raise TypeError("Shares should have the same exponent")
            # check that the k-of-n is the same
            k = {s.group_threshold for s in shares}
            if len(k) != 1:
                raise ValueError("K of K-of-N should be the same")
            n = {s.group_count for s in shares}
            if len(n) != 1:
                raise ValueError("N of K-of-N should be the same")
            if k.pop() > n.pop():
                raise ValueError("K > N in K-of-N")
            # check that the share lengths are the same
            lengths = {s.share_bit_length for s in shares}
            if len(lengths) != 1:
                raise ValueError("all shares should have the same length")
            # check that the x coordinates are unique
            xs = {(s.group_index, s.member_index) for s in shares}
            if len(xs) != len(shares):
                raise ValueError("Share indices should be unique")
        self.id = shares[0].id
        self.extendable = shares[0].extendable
        self.salt = _get_salt(self.id, self.extendable)
        self.exponent = shares[0].exponent
        self.group_threshold = shares[0].group_threshold
        self.group_count = shares[0].group_count
        self.share_bit_length = shares[0].share_bit_length

    def decrypt(self, secret, passphrase=b""):
        # decryption does the reverse of encryption
        indices = (b"\x03", b"\x02", b"\x01", b"\x00")
        return _crypt(secret, self.id, self.extendable, self.exponent, passphrase, indices)

    @classmethod
    def encrypt(cls, payload, id, extendable, exponent, passphrase=b""):
        # encryption goes from 0 to 3 in bytes
        indices = (b"\x00", b"\x01", b"\x02", b"\x03")
        return _crypt(payload, id, extendable, exponent, passphrase, indices)

    @classmethod
    def interpolate(cls, x, share_data):
        """Gets the y value at a particular x"""
        # we're using the LaGrange formula
        # https://github.com/satoshilabs/slips/blob/master/slip-0039/lagrange.png
        # the numerator of the multiplication part is what we're pre-computing
        # (x - x_i) 0<=i<=m where x_i is each x in the share
        # we don't store this, but the log of this
        # and exponentiate later
        log_product = sum(cls.log2[share_x ^ x] for share_x, _ in share_data)
        # the y value that we want is stored in result
        result = bytes(len(share_data[0][1]))
        for share_x, share_bytes in share_data:
            # we have to subtract the current x - x_i since
            # the formula is for j where j != i
            log_numerator = log_product - cls.log2[share_x ^ x]
            # the denominator we can just sum because we cheated and made
            # log(0) = 0 which will happen when i = j
            log_denominator = sum(
                cls.log2[share_x ^ other_x] for other_x, _ in share_data
            )
            log = (log_numerator - log_denominator) % 255
            result = bytes(
                c ^ (cls.exp[(cls.log2[y] + log) % 255] if y > 0 else 0)
                for y, c in zip(share_bytes, result)
            )
        return result

    @classmethod
    def digest(cls, r, shared_secret):
        return hmac.new(r, shared_secret, "sha256").digest()[:4]

    @classmethod
    def recover_secret_from_share_data(cls, share_data):
        """return a shared secret from a list of shares"""
        shared_secret = cls.interpolate(255, share_data)
        digest_share = cls.interpolate(254, share_data)
        digest = digest_share[:4]
        random = digest_share[4:]
        if digest != cls.digest(random, shared_secret):
            raise ValueError("Digest does not match secret")
        return shared_secret

    def recover(self, passphrase=b""):
        """recover a shared secret from the current group of shares"""
        # group by group index
        groups = [[] for _ in range(self.group_count)]
        for share in self.shares:
            groups[share.group_index].append(share)
        # gather share data of each group
        share_data = []
        for i, group in enumerate(groups):
            if len(group) == 0:
                continue
            member_thresholds = {share.member_threshold for share in group}
            if len(member_thresholds) != 1:
                raise ValueError("Member thresholds should be the same within a group")
            member_threshold = member_thresholds.pop()
            if member_threshold == 1:
                share_data.append((i, group[0].bytes))
            elif member_threshold > len(group):
                raise ValueError("Not enough shares")
            else:
                member_data = [(share.member_index, share.bytes) for share in group]
                share_data.append((i, self.recover_secret_from_share_data(member_data)))
        if self.group_threshold == 1:
            return self.decrypt(share_data[0][1], passphrase)
        elif self.group_threshold > len(share_data):
            raise ValueError("Not enough shares")
        shared_secret = self.recover_secret_from_share_data(share_data)
        return self.decrypt(shared_secret, passphrase)

    @classmethod
    def split_secret(cls, secret, k, n, randint=secure_randint):
        """Split secret into k-of-n shares"""
        if n < 1:
            raise ValueError("N is too small, must be at least 1")
        if n > 16:
            raise ValueError("N is too big, must be 16 or less")
        if k < 1:
            raise ValueError("K is too small, must be at least 1")
        if k > n:
            raise ValueError("K is too big, K <= N")
        num_bytes = len(secret)
        if num_bytes not in (16, 32):
            raise ValueError("secret should be 128 bits or 256 bits")
        if k == 1:
            return [(0, secret)]
        else:
            r = bytes(randint(0, 255) for _ in range(num_bytes - 4))
            digest = cls.digest(r, secret)
            digest_share = digest + r
            share_data = [
                (i, bytes(randint(0, 255) for _ in range(num_bytes)))
                for i in range(k - 2)
            ]
            more_data = share_data.copy()
            share_data.append((254, digest_share))
            share_data.append((255, secret))
            for i in range(k - 2, n):
                more_data.append((i, cls.interpolate(i, share_data)))
        return more_data

ShareSet._load()

def slip39_generate_shares(
    seed, k, n, passphrase=b"", extendable=True, exponent=0, identifier=-1, randint=secure_randint,
):
    """
    Generates a list of SLIP39 mnemonics.
    Parameters
    ----------
    seed: bytes 
        Random 128 or 256 bit seed.
    k: int
        Group threshold.
    n: int
        Group size.
    passphrase: bytes, optional
        Passphrase used to encrypyt the seed. Default to "".
    extendable: bool, optionl
        Enables extendable SLIP39 shamir shares, Default to False.
    exponent: int, optional
        Defines iteration exponent for pbkdf2_hmac when seed is encrypted with a passphrase. Default to 0.
    identifier: int, optional
        Group identifier, must be between 0 and 32767, if set to -1 a radom value is generated. Default to -1.
    randint: Callable[[int], [int]], optional
        A function that takes a lower and upper bound and returns a random value within the bound. Default to embit.misc.secure_randint.
    
    Returns
    -------
    List[str]
        A list of SLIP39 share mnemonics.
    """
    
    num_bits = len(seed) * 8
    if num_bits not in (128, 256):
        raise ValueError("mnemonic must be 12 or 24 words")
    # generate id if set to -1
    id = identifier if identifier > -1 & identifier < 32768 else randint(0, 32767)
    # encrypt secret with passphrase
    encrypted = ShareSet.encrypt(seed, id, extendable, exponent, passphrase)
    # split encrypted payload and create shares
    shares = []
    data = ShareSet.split_secret(encrypted, k, n, randint=randint)
    for group_index, share_bytes in data:
        share = Share(
            share_bit_length=num_bits,
            id=id,
            extendable=extendable,
            exponent=exponent,
            group_index=group_index,
            group_threshold=k,
            group_count=n,
            member_index=0,
            member_threshold=1,
            value=int.from_bytes(share_bytes, "big"),
        )
        shares.append(share.mnemonic())
    return shares

def slip39_load_share_set(share_mnemonics):
    """
    Load ShareSet.
    Parameter
    ---------
    share_mnemonics: List[str]
        A list of SLIP39 share mnemonics, number of shares must be equal or bigger then group threshold.
    passphrase: bytes, optional
        Passphrase used to encrypyt the seed. Default to "".
 
    Returns
    -------
    ShareSet
        The loaded ShareSet.
    """
    shares = [Share.parse(m) for m in share_mnemonics]
    return ShareSet(shares)

def slip39_update_shares(
    share_mnemonics, new_k, new_n, passphrase=b"", randint=secure_randint,
):
    """
    Updates a extendable SLIP39 shamir secret.
    Parameter
    --------
    share_mnemonics: List[str]
        A list of SLIP39 share mnemonics, number of shares must be equal or bigger then group threshold.
    new_k: int
        New group threshold.
    new_n: int
        New group size.
    passphrase: bytes, optional
        Passphrase used to encrypyt the seed. Default to "".
    randint: Callable[[int], [int]], optional
        A function that takes a lower and upper bound and returns a random value within the bound. Default to embit.misc.secure_randint.
 
    Returns
    -------
    List[str]
        A list of SLIP39 share mnemonics with the updated group parameters.
    """
    share_set = slip39_load_share_set(share_mnemonics)
    if not share_set.extendable:
        raise ValueError("Cannot update extendable share sets")
    secret = share_set.recover(passphrase)
    
    # generate a new identifier different from the old one
    new_identifier = share_set.id
    while new_identifier == share_set.id:
        new_identifier = randint(0, 32767)
    return slip39_generate_shares(
        secret, new_k, new_n, passphrase, True, share_set.exponent, new_identifier, randint
    )

def slip39_recover_seed(share_mnemonics, passphrase=b""):
    """
    Recovers the seed.
    
            Parameter
    --------
    share_mnemonics: List[str]
        A list of SLIP39 share mnemonics, number of shares must be equal or bigger then group threshold.
    passphrase: bytes, optional
        Passphrase used to encrypyt the seed. Default to "".
    Returns
    -------
    bytes
        The seed, 128 or 256 bit value.
    """
    share_set = slip39_load_share_set(share_mnemonics)
    return share_set.recover(passphrase)