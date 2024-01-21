from ast import Return
from inspect import signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# This generates the RSA private-public key pairs for multiple users, more users can be added)
users = {
    "user1": rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "user2": rsa.generate_private_key(public_exponent=65537, key_size=2048)
}

# This reads the contents of the file, plaintext.txt)
with open("plaintext.txt", "rb") as file:
    plaintext = file.read()

# This generates the SHA256 hash of the plaintext.txt file)
hash_object = hashes.Hash(hashes.SHA256())
hash_object.update(plaintext)
digest = hash_object.finalize()

# This section will encrypt the file contents with the public keys of all users
ciphertexts = {}
for user, private_key in users.items():
    public_key = private_key.public_key()
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    ciphertexts[user] = ciphertext

    # This section will Write the encrypted contents to a new file for each user
    with open(f"encrypted_{user}.txt", "wb") as file:
        file.write(ciphertext)

    # This will save the private key to a file for each user
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"private_key_{user}.pem", "wb") as file:
        file.write(pem)

    # This will save the public key to a file for each user
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"public_key_{user}.pem", "wb") as file:
        file.write(pem)

# This will decrypt the file contents with the private keys of all users
for user in users.keys():
    private_key = load_pem_private_key(
        open(f"private_key_{user}.pem", "rb").read(), password=None)
    decrypted_plaintext = private_key.decrypt(
        ciphertexts[user],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # This will verify the signature using the public key of the user
    public_key = load_pem_public_key(
        open(f"public_key_{user}.pem", "rb").read())
    hash_object = hashes.Hash(hashes.SHA256())
    hash_object.update(decrypted_plaintext)
    digest = hash_object.finalize()
    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"Signature is valid for user {user}.")
    except:
        print(f"Signature is invalid for user {user}.")
        
    # Write the decrypted plaintext to a new file for each user
    with open(f"decrypted_{user}.txt", "wb") as file:
        file.write(decrypted_plaintext)
    
    # The following files will be created from plaintext.txt file and 
    # stored in the same location as the the python code:
    # - encrypted_user1.txt file
    # - encrypted_user2.txt
    # - decrypted_user1.txt (containing original information)
    # - decrypted_user2.txt (containing original information)
    # - private_key_user1.pem (private key for user 1)
    # - private_key_user2.pem (private key for user 2)
    # - public_key_user1.pem (public key for user 1)
    # - public_key_user2.pem (public key for user 1)
