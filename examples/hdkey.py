from embit import script
from embit import bip32
from embit.networks import NETWORKS
from embit_slip39 import slip39_generate_shares, slip39_recover_seed

import random

def main():

    entropy = bytes([random.getrandbits(8) for i in range(16)])

    share_mnemonics = slip39_generate_shares(entropy, 2, 3, passphrase=b"embit_example")

    print("generated 2/3 SLIP39 shamir set:")
    for index, mnmemonic in enumerate(share_mnemonics):
        print(f"Shamir Share {index + 1}: {mnmemonic}")

    print("\nKeys and Addresses:")

    # convert to seed, empty password
    seed = slip39_recover_seed(share_mnemonics, passphrase=b"embit_example")

    # convert to the root key
    # you can define the version - x/y/zprv for desired network
    root = bip32.HDKey.from_seed(seed, version=NETWORKS["test"]["xprv"])
    print(f"BIP-32 SEED: {root.to_base58()}")

    # derive account according to bip44
    bip44_xprv = root.derive("m/44h/1h/0h")
    print(f"BIP-44 - legacy: {bip44_xprv.to_base58()}")
    
    # corresponding master public key:
    bip44_xpub = bip44_xprv.to_public()
    print(f"BIP-44 Master Pub: {bip44_xpub.to_base58()}")
    # first 5 receiving addresses
    for i in range(5):
        # .key member is a public key for HD public keys
        #            and a private key for HD private keys
        pub = bip44_xpub.derive("m/0/%d" % i).key
        sc = script.p2pkh(pub)
        print(f" BIP-44 Account {i} Pub: {sc.address(NETWORKS["test"])}")

if __name__ == "__main__":
    main()
