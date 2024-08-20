from mnemonic import Mnemonic
import bip32utils
import bitcoin

# Initialize the Mnemonic class for the English language
mnemo = Mnemonic("english")

def generate_seed_phrase():
    # Generate a 12-word mnemonic (BIP-39 seed phrase)
    return mnemo.generate(128)  # 128 bits of entropy for a 12-word seed phrase

def seed_phrase_to_private_key(seed_phrase):
    # Convert seed phrase to seed
    seed = mnemo.to_seed(seed_phrase, "")
    # Create BIP32 root key from the seed
    bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
    # Derive the first child private key (m/0'/0'/0'/0) for simplicity
    child_key = bip32_root_key.ChildKey(0).ChildKey(0).ChildKey(0).ChildKey(0)
    return child_key.WalletImportFormat()  # Returns the private key in WIF format

def private_key_to_public_key(private_key):
    # Convert private key to public key using bitcoin library
    return bitcoin.privkey_to_pubkey(private_key)

def public_key_to_address(public_key):
    # Convert public key to Bitcoin address using bitcoin library
    return bitcoin.pubkey_to_address(public_key)

def validate_address(address):
    # Validate if a Bitcoin address is correctly formatted
    try:
        # A valid address should be decodable back to a public key
        return bitcoin.address_to_pubkey(address) is not None
    except Exception:
        return False

def generate_and_validate_wallet():
    while True:
        # Generate a new seed phrase
        seed_phrase = generate_seed_phrase()
        print(f"Generated seed phrase: {seed_phrase}")
        
        # Convert the seed phrase to a private key
        private_key = seed_phrase_to_private_key(seed_phrase)
        
        # Derive the public key from the private key
        public_key = private_key_to_public_key(private_key)
        
        # Generate a Bitcoin address from the public key
        address = public_key_to_address(public_key)
        
        print(f"Generated Bitcoin address: {address}")
        
        # Validate the address
        if validate_address(address):
            print("Address is valid.")
            return seed_phrase, address
        else:
            print("Address is invalid. Generating a new seed phrase...")

# Example usage
valid_seed_phrase, valid_address = generate_and_validate_wallet()
print(f"Found a valid seed phrase: {valid_seed_phrase}")
print(f"Found a valid Bitcoin address: {valid_address}")
