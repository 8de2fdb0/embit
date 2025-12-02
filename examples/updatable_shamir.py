from embit import bip32
from embit.networks import NETWORKS
from embit_slip39 import slip39_load_share_set, slip39_generate_shares, slip39_update_shares

import random

def dump_hd_privkey(share_mnemonics, msg):
    share_set = slip39_load_share_set(share_mnemonics)

    print(f"{msg} {share_set.group_threshold}/{share_set.group_count} SLIP39 shamir set:")
    for index, mnmemonic in enumerate(share_mnemonics):
        print(f"Shamir Share {index + 1}: {mnmemonic}")

    # convert to seed, empty password
    seed = share_set.recover(passphrase=b"embit_example")
    
    # convert to the root key
    # you can define the version - x/y/zprv for desired network
    root = bip32.HDKey.from_seed(seed, version=NETWORKS["test"]["xprv"])
    print(f"Bip32 PrivKey: {root.to_base58()}\n")


def main():

    entropy = bytes([random.getrandbits(8) for i in range(16)])

    share_mnemonics = slip39_generate_shares(entropy, 1, 1, passphrase=b"embit_example", extendable=1)
    dump_hd_privkey(share_mnemonics, "Generated a new")
    updated_share = slip39_update_shares(share_mnemonics, 3, 5, passphrase=b"embit_example")
    dump_hd_privkey(updated_share, "Updated last shamir shares to a")
    updated_share = slip39_update_shares(updated_share[:3], 2, 10, passphrase=b"embit_example")
    dump_hd_privkey(updated_share, "Updated last shamir shares to a")
    updated_share = slip39_update_shares(updated_share[:2], 5, 15, passphrase=b"embit_example")
    dump_hd_privkey(updated_share, "Updated last shamir shares to a")



if __name__ == "__main__":
    main()
