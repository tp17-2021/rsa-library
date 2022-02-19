import json
import base64
import asyncio
import traceback

from typing import List
from pydantic import BaseModel

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme


async def _from_bytes_to_string(encrypted_bytes):
    return base64.b64encode(encrypted_bytes).decode("utf-8")


async def _from_string_to_bytes(string):
    return base64.b64decode(string.encode("utf-8"))


class VoteEncrypted(BaseModel):
    """
    Attributes
    ----------
    encrypted_message: str
        AES encrypted message.
    encrypted_object: str
        RSA encrypted AES key and other data.
    """
    
    encrypted_message: str
    encrypted_object: str


async def get_rsa_key_pair(key_length: int=2048) -> tuple[str, str]:
    """
    Generate RSA key pair using OAEP padding algorithm.

    Keyword Arguments
    -----------------
    key_length : int (default: 2048)
        Length of the generated RSA key.

    Returns
    -------
    tuple[str, str]
        RSA private key and public key in PEM format.
    """

    private_key = RSA.generate(key_length)
    public_key = private_key.publickey()

    private_key_pem = private_key.exportKey()
    public_key_pem = public_key.exportKey()

    private_key_pem = private_key_pem.decode("utf-8")
    public_key_pem = public_key_pem.decode("utf-8")
    
    return private_key_pem, public_key_pem


async def encrypt_vote(
        vote: dict,
        g_rsa_private_key_pem: str,
        rsa_public_key_pem: str,
        aes_key_length: int=32
    ) -> VoteEncrypted:
    """Sign and encrypt vote using local private key and remote public key and
    ad-hoc AES key.

    Parameters
    ----------
    vote : dict
        json.dumps serializable object to be signed and encrypted.
    g_rsa_private_key_pem : str
        RSA Private key of the sender used to encrypt generated AES key.
    rsa_public_key_pem : str
        RSA Public key of the receiver used to create signature.

    Keyword Arguments
    -----------------
    aes_key_length : int (default: 32)
        Length of the AES key.

    Returns
    -------
    VoteEncrypted
        Encrypted object with signature and aes_key.
    """
    
    # convert dict to bytes
    message = json.dumps(vote).encode("utf-8")

    # import g_rsa_private_key
    g_rsa_private_key_pem = g_rsa_private_key_pem.encode("utf-8")
    g_rsa_private_key = RSA.import_key(g_rsa_private_key_pem)

    # create signature from message
    hash = SHA256.new(message)
    signer = PKCS115_SigScheme(g_rsa_private_key)
    signature = signer.sign(hash)
    
    # convert bytes to string
    signature = await _from_bytes_to_string(signature)

    # create dict from vote and signature
    message = {
        "vote": vote,
        "signature": signature,
    }

    # convert dict to bytes
    message = json.dumps(message).encode("utf-8")

    # encrypt message with aes key
    aes_key = get_random_bytes(aes_key_length)
    aes_encryptor = AES.new(aes_key, AES.MODE_EAX)
    encrypted_message, tag = aes_encryptor.encrypt_and_digest(message)
    nonce = aes_encryptor.nonce

    # convert bytes to to string
    encrypted_message = await _from_bytes_to_string(encrypted_message)
    aes_key = await _from_bytes_to_string(aes_key)
    tag = await _from_bytes_to_string(tag)
    nonce = await _from_bytes_to_string(nonce)

    # create dict from aes_key, tag and nonce
    other_data = {
        "aes_key": aes_key,
        "tag": tag,
        "nonce": nonce
    }

    # convert dict to bytes
    other_data = json.dumps(other_data).encode("utf-8")

    # import rsa_public_key
    rsa_public_key_pem = rsa_public_key_pem.encode("utf-8")
    rsa_public_key = RSA.import_key(rsa_public_key_pem)

    # encrypt object with rsa_public_key
    rsa_encryptor = PKCS1_OAEP.new(rsa_public_key)
    encrypted_object = rsa_encryptor.encrypt(other_data)

    # convert bytes to string
    encrypted_object = await _from_bytes_to_string(encrypted_object)

    return VoteEncrypted(
        encrypted_message=encrypted_message,
        encrypted_object=encrypted_object
    )


async def decrypt_vote(
        encrypted_vote: VoteEncrypted,
        rsa_private_key_pem: str,
        g_rsa_public_key_pem: str
    ) -> dict:
    """Decrypt vote using local private key and ad-hoc AES and check signature
    by remote public key.
    
    Parameters
    ----------
    encrypted_vote : VoteEncrypted
        RSA Encrypted object with signature and aes_key.
    rsa_private_key_pem : str
        RSA Private key of the recevier to decrypt generated AES key.
    g_rsa_public_key_pem : str
        RSA Public key of the sender to chack signature.

    Returns
    -------
    dict
        Decrypted and verified vote.
    """

    # extract encrypted_object, encrypted_message from encrypted_vote
    encrypted_object = encrypted_vote.encrypted_object
    encrypted_message = encrypted_vote.encrypted_message

    # convert string to bytes
    encrypted_object = await _from_string_to_bytes(encrypted_object)

    # import rsa_private_key
    rsa_private_key_pem = rsa_private_key_pem.encode("utf-8")
    rsa_private_key = RSA.import_key(rsa_private_key_pem)

    # decrypt object with rsa_private_key
    rsa_decryptor = PKCS1_OAEP.new(rsa_private_key)
    decrypted_object = rsa_decryptor.decrypt(encrypted_object)

    # convert bytes to dict
    decrypted_object = json.loads(decrypted_object.decode("utf-8"))

    # extract tag, nonce, aes_key and convert them to bytes
    tag = await _from_string_to_bytes(decrypted_object["tag"])
    nonce = await _from_string_to_bytes(decrypted_object["nonce"])
    aes_key = await _from_string_to_bytes(decrypted_object["aes_key"])

    # convert string to bytes
    encrypted_message = await _from_string_to_bytes(encrypted_message)

    # decrypt message with eas_key
    aes_decryptor = AES.new(aes_key, AES.MODE_EAX, nonce)
    decrypted_message = aes_decryptor.decrypt_and_verify(encrypted_message, tag)

    # convert bytes to dict
    decrypted_message = json.loads(decrypted_message.decode("utf-8"))

    # extract vote, signature from dict
    vote = decrypted_message["vote"]
    signature = decrypted_message["signature"]

    # convert dict to bytes
    message = json.dumps(vote).encode("utf-8")
    
    # convert string to bytes
    signature = await _from_string_to_bytes(signature)

    # import g_rsa_public_key
    g_rsa_public_key_pem = g_rsa_public_key_pem.encode("utf-8")
    g_rsa_public_key = RSA.import_key(g_rsa_public_key_pem)

    hash = SHA256.new(message)
    verifier = PKCS115_SigScheme(g_rsa_public_key)
    verifier.verify(hash, signature)

    return vote


async def example():
    # CLIENT
    rsa_private_key_pem, rsa_public_key_pem = await get_rsa_key_pair()
    g_rsa_private_key_pem, g_rsa_public_key_pem = await get_rsa_key_pair()

    vote = {
        "token": "A"*64,
        "election_id": "election_id",
        "party_id": 10000,
        "candidates_ids": [
            10000,
            10000,
            10000,
            10000,
            10000
        ]
    }

    encrypted_vote = await encrypt_vote(vote, g_rsa_private_key_pem, rsa_public_key_pem)

    # SERVER
    vote = await decrypt_vote(encrypted_vote, rsa_private_key_pem, g_rsa_public_key_pem)
    print(vote)

# asyncio.run(example())


# USEFUL LINKS
# https://wizardforcel.gitbooks.io/practical-cryptography-for-developers-book/content/asymmetric-key-ciphers/ecc-encryption-decryption.html
# https://www.youtube.com/watch?v=p3jraFbfnHw&ab_channel=MisterArk
# https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples