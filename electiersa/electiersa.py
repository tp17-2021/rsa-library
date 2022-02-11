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


KEY_LENGTH = 2048
AES_KEY_LENGTH = 32

# for this phase election_id = "election_id"
class Vote(BaseModel):
    token: str = None
    party_id: int
    election_id: str
    candidates_ids: List[int] = []


async def validate_vote(vote: Vote):
    if len(list(vote.keys())) != 4:
        raise Exception("Incorrect number of keys")

    if "token" not in vote or type(vote["token"]) != str:
        raise Exception("Incorrect format for key 'token'")

    if "party_id" not in vote or type(vote["party_id"]) != int:
        raise Exception("Incorrect format for key 'party_id'")


    if "election_id" not in vote or type(vote["election_id"]) != str:
        raise Exception("Incorrect format for key 'election_id'")

    if "candidates_ids" not in vote or type(vote["candidates_ids"]) != list or \
            not all([type(candidate_id) == int for candidate_id in vote["candidates_ids"]]):
        raise Exception("Incorrect format for key 'candidates_ids'")


async def from_bytes_to_string(encrypted_bytes):
    return base64.b64encode(encrypted_bytes).decode("utf-8")


async def from_string_to_bytes(string):
    return base64.b64decode(string.encode("utf-8"))
     

async def get_rsa_key_pair():
    """
    OAEP padding algorithm
    """
    private_key = RSA.generate(KEY_LENGTH)
    public_key = private_key.publickey()

    private_key_pem = private_key.exportKey()
    public_key_pem = public_key.exportKey()

    private_key_pem = private_key_pem.decode("utf-8")
    public_key_pem = public_key_pem.decode("utf-8")
    
    return private_key_pem, public_key_pem


async def get_aes_key():
    global AES_KEY_LENGTH
    aes_key = get_random_bytes(AES_KEY_LENGTH)
    aes_key = await from_bytes_to_string(aes_key)
    return aes_key


async def encrypt_vote(vote: Vote, g_rsa_private_key_pem: str, rsa_public_key_pem: str):
    try:
        await validate_vote(vote)
        
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
        signature = await from_bytes_to_string(signature)

        # create dict from vote and signature
        message = {
            "vote": vote,
            "signature": signature,
        }

        # convert dict to bytes
        message = json.dumps(message).encode("utf-8")

        # encrypt message with aes key
        aes_key = get_random_bytes(AES_KEY_LENGTH)
        aes_encryptor = AES.new(aes_key, AES.MODE_EAX)
        encrypted_message, tag = aes_encryptor.encrypt_and_digest(message)
        nonce = aes_encryptor.nonce

        # convert bytes to to string
        encrypted_message = await from_bytes_to_string(encrypted_message)
        aes_key = await from_bytes_to_string(aes_key)
        tag = await from_bytes_to_string(tag)
        nonce = await from_bytes_to_string(nonce)

        # create dict from aes_key, tag and nonce
        object = {
            "aes_key": aes_key,
            "tag": tag,
            "nonce": nonce
        }

        # convert dict to bytes
        object = json.dumps(object).encode("utf-8")

        # import rsa_public_key
        rsa_public_key_pem = rsa_public_key_pem.encode("utf-8")
        rsa_public_key = RSA.import_key(rsa_public_key_pem)

        # encrypt object with rsa_public_key
        rsa_encryptor = PKCS1_OAEP.new(rsa_public_key)
        encrypted_object = rsa_encryptor.encrypt(object)

        # convert bytes to string
        encrypted_object = await from_bytes_to_string(encrypted_object)

        return encrypted_message, encrypted_object
    except:
        traceback.print_exc()



async def decrypt_vote(encrypted_object: str, rsa_private_key_pem: str, encrypted_message: str, g_rsa_public_key_pem: str):
    try:
        # convert string to bytes
        encrypted_object = await from_string_to_bytes(encrypted_object)

        # import rsa_private_key
        rsa_private_key_pem = rsa_private_key_pem.encode("utf-8")
        rsa_private_key = RSA.import_key(rsa_private_key_pem)

        # decrypt object with rsa_private_key
        rsa_decryptor = PKCS1_OAEP.new(rsa_private_key)
        decrypted_object = rsa_decryptor.decrypt(encrypted_object)

        # convert bytes to dict
        decrypted_object = json.loads(decrypted_object.decode("utf-8"))

        # extract tag, nonce, aes_key and convert them to bytes
        tag = await from_string_to_bytes(decrypted_object["tag"])
        nonce = await from_string_to_bytes(decrypted_object["nonce"])
        aes_key = await from_string_to_bytes(decrypted_object["aes_key"])

        # convert string to bytes
        encrypted_message = await from_string_to_bytes(encrypted_message)

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
        signature = await from_string_to_bytes(signature)

        # import g_rsa_public_key
        g_rsa_public_key_pem = g_rsa_public_key_pem.encode("utf-8")
        g_rsa_public_key = RSA.import_key(g_rsa_public_key_pem)

        hash = SHA256.new(message)
        verifier = PKCS115_SigScheme(g_rsa_public_key)
        verifier.verify(hash, signature)

        return vote
    except:
        traceback.print_exc()


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

    encrypted_vote, encrypted_object = await encrypt_vote(vote, g_rsa_private_key_pem, rsa_public_key_pem)

    # SERVER
    vote = await decrypt_vote(encrypted_object, rsa_private_key_pem, encrypted_vote, g_rsa_public_key_pem)
    print(vote)

# asyncio.run(example())


# USEFUL LINKS
# https://wizardforcel.gitbooks.io/practical-cryptography-for-developers-book/content/asymmetric-key-ciphers/ecc-encryption-decryption.html
# https://www.youtube.com/watch?v=p3jraFbfnHw&ab_channel=MisterArk
# https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples