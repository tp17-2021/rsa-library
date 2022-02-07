import json
import base64
import traceback

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import asyncio

from typing import List
from pydantic import BaseModel

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


async def validate_encrypted_vote(vote: str):
    if type(vote) != str:
        raise Exception("Incorrect type for parameter 'data'")


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


async def encrypt_message_with_aes_key(message: str, aes_key: str):
    message = message.encode("utf-8")

    aes_key = await from_string_to_bytes(aes_key)
    aes_encryptor = AES.new(aes_key, AES.MODE_EAX)

    encrypted_message, tag = aes_encryptor.encrypt_and_digest(message)
    encrypted_message = await from_bytes_to_string(encrypted_message)
    tag = await from_bytes_to_string(tag)
    nonce = await from_bytes_to_string(aes_encryptor.nonce)

    return encrypted_message, tag, nonce


async def encrypt_aes_key_with_rsa_pub_key(aes_key: str, rsa_public_key_pem: str):
    aes_key = await from_string_to_bytes(aes_key)

    rsa_public_key_pem = rsa_public_key_pem.encode("utf-8")
    rsa_public_key = RSA.import_key(rsa_public_key_pem)
    rsa_encryptor = PKCS1_OAEP.new(rsa_public_key)

    encrypted_aes_key = rsa_encryptor.encrypt(aes_key)
    encrypted_aes_key = await from_bytes_to_string(encrypted_aes_key)
    
    return encrypted_aes_key


async def decrypt_aes_key_with_rsa_priv_key(encrypted_aes_key: str, rsa_private_key_pem: str):
    encrypted_aes_key = await from_string_to_bytes(encrypted_aes_key)

    rsa_private_key_pem = rsa_private_key_pem.encode("utf-8")
    rsa_private_key = RSA.import_key(rsa_private_key_pem)
    rsa_decryptor = PKCS1_OAEP.new(rsa_private_key)

    decrypted_aes_key = rsa_decryptor.decrypt(encrypted_aes_key)
    decrypted_aes_key = await from_bytes_to_string(decrypted_aes_key)

    return decrypted_aes_key


async def decrypt_message_with_aes_key(encrypted_message: str, tag: str, nonce: str, aes_key: str):
    encrypted_message = await from_string_to_bytes(encrypted_message)
    tag = await from_string_to_bytes(tag)
    nonce = await from_string_to_bytes(nonce)
    aes_key = await from_string_to_bytes(aes_key)

    aes_decryptor = AES.new(aes_key, AES.MODE_EAX, nonce)
    decrypted_message = aes_decryptor.decrypt_and_verify(encrypted_message, tag)
    decrypted_message = decrypted_message.decode("utf-8")

    return decrypted_message


async def encrypt_vote(vote: Vote, aes_key: str, rsa_public_key_pem: str):
    try: 
        await validate_vote(vote)
        message = json.dumps(vote)

        encrypted_message, tag, nonce = await encrypt_message_with_aes_key(message, aes_key)
        encrypted_aes_key = await encrypt_aes_key_with_rsa_pub_key(aes_key, rsa_public_key_pem)
        return encrypted_message, tag, nonce, encrypted_aes_key
    except:
        traceback.print_exc()


async def decrypt_vote(encrypted_vote: str, tag: str, nonce: str, encrypted_aes_key: str, rsa_private_key_pem: str):
    try:
        await validate_encrypted_vote(encrypted_vote)

        decrypted_aes_key = await decrypt_aes_key_with_rsa_priv_key(encrypted_aes_key, rsa_private_key_pem)
        decrypted_message = await decrypt_message_with_aes_key(encrypted_vote, tag, nonce, decrypted_aes_key)
        
        vote = json.loads(decrypted_message)
        return vote
    except:
        traceback.print_exc()


async def example():
    # CLIENT
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

    aes_key = await get_aes_key()
    rsa_private_key_pem, rsa_public_key_pem = await get_rsa_key_pair()
    encrypted_vote, tag, nonce, encrypted_aes_key = await encrypt_vote(vote, aes_key, rsa_public_key_pem)

    # SERVER
    decrypted_vote = await decrypt_vote(encrypted_vote, tag, nonce, encrypted_aes_key, rsa_private_key_pem)
    print(decrypted_vote)

asyncio.run(example())


# CLIENT
# vote
# aes key
# rsa public key

# SERVER
# rsa private key

# https://wizardforcel.gitbooks.io/practical-cryptography-for-developers-book/content/asymmetric-key-ciphers/ecc-encryption-decryption.html
# https://www.youtube.com/watch?v=p3jraFbfnHw&ab_channel=MisterArk

# RSA
# data = around 150 bytes
# 2048 bits = 256 bytes -> 214 bytes is ok (42 padding) cca 70% utilized
# 4096 bits = 512 bytes -> 470 bytes is ok (42 padding) cca 32% utilized