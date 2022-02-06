import json
import base64
import traceback

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# RSA
# data = around 150 bytes

# 2048 bits = 256 bytes -> 214 bytes is ok (42 padding) cca 70% utilized
# 4096 bits = 512 bytes -> 470 bytes is ok (42 padding) cca 32% utilized

from typing import List
from pydantic import BaseModel

KEY_LENGTH = 4096

# for this phase election_id = "election_id"
class Data(BaseModel):
    token: str = None
    party_id: int
    election_id: str
    candidates_ids: List[int] = []


async def validate_to_be_encrypted_data(data: Data):
    if len(list(data.keys())) != 4:
        raise Exception("Incorrect number of keys")

    if "token" not in data or type(data["token"]) != str:
        raise Exception("Incorrect format for key 'token'")

    if "party_id" not in data or type(data["party_id"]) != int:
        raise Exception("Incorrect format for key 'party_id'")


    if "election_id" not in data or type(data["election_id"]) != str:
        raise Exception("Incorrect format for key 'election_id'")

    if "candidates_ids" not in data or type(data["candidates_ids"]) != list or \
            not all([type(candidate_id) == int for candidate_id in data["candidates_ids"]]):
        raise Exception("Incorrect format for key 'candidates_ids'")


async def validate_to_be_decrypted_data(data: str):
    if type(data) != str:
        raise Exception("Incorrect type for parameter 'data'")


async def get_rsa_key_pair():
    """
    OAEP padding algorithm
    """
    private_key = RSA.generate(KEY_LENGTH)
    public_key = private_key.publickey()

    private_key_pem = private_key.exportKey()
    public_key_pem = public_key.exportKey()
    
    return private_key_pem, public_key_pem


async def encrypt_message(message, public_key):
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(bytes(message, encoding="utf-8"))
    return base64.b64encode(encrypted)


async def decrypt_message(base64_encoded_message, private_key):
    decrypted = base64.b64decode(base64_encoded_message)
    decryptor = PKCS1_OAEP.new(private_key)
    return decryptor.decrypt(decrypted)


async def encrypt_vote(public_key_pem: str, data: Data):
    try:
        await validate_to_be_encrypted_data(data)
        data = json.dumps(data)
        try: 
            public_key_pem = public_key_pem.encode("utf-8")
            public_key = RSA.import_key(public_key_pem)

            encrypted_data = await encrypt_message(data, public_key)
            encrypted_data = encrypted_data.decode("utf-8")
            return encrypted_data
        except:
            traceback.print_exc()
    except:
        traceback.print_exc()


async def decrypt_vote(private_key_pem: str, data: str):
    try:
        await validate_to_be_decrypted_data(data)
        try: 
            private_key_pem = private_key_pem.encode("utf-8")
            private_key = RSA.import_key(private_key_pem)

            decrypted_data = await decrypt_message(data, private_key)
            decrypted_data = decrypted_data.decode("utf-8")
            decrypted_data = json.loads(decrypted_data)
            return decrypted_data
        except:
            traceback.print_exc()
    except:
        traceback.print_exc()


# async def tmp():
#     private_key_pem, public_key_pem = await get_rsa_key_pair()
#     print(private_key_pem)
#     print(public_key_pem)

#     private_key_pem = private_key_pem.decode("utf-8")
#     public_key_pem = public_key_pem.decode("utf-8")


#     data = {
#         "token": "A"*64,
#         "election_id": "election_id",
#         "party_id": 10000,
#         "candidates_ids": [
#             10000,
#             10000,
#             10000,
#             10000,
#             10000
#         ]
#     }

#     print(data)

#     data_e = encrypt_vote(public_key_pem, data)
#     print(data_e)

#     print("---")
#     data_d = decrypt_vote(private_key_pem, data_e)
#     print(data_d)


# import asyncio
# asyncio.run(tmp())
