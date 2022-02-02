import json
import base64
import traceback

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from typing import List
from pydantic import BaseModel


class Data(BaseModel):
    token: str = None
    party_id: str
    election_id: str
    candidates_ids: List[str] = []


async def validate_to_be_encrypted_data(data: Data):
    if len(list(data.keys())) != 4:
        raise Exception("Incorrect number of keys")

    if "token" not in data or type(data["token"]) != str:
        raise Exception("Incorrect format for key 'token'")

    if "party_id" not in data or type(data["party_id"]) != str:
        raise Exception("Incorrect format for key 'party_id'")


    if "election_id" not in data or type(data["election_id"]) != str:
        raise Exception("Incorrect format for key 'election_id'")

    if "candidates_ids" not in data or type(data["candidates_ids"]) != list or not all([type(candidate_id) == str for candidate_id in data["candidates_ids"]]):
        raise Exception("Incorrect format for key 'candidates_ids'")


async def validate_to_be_decrypted_data(data: str):
    if type(data) != str:
        raise Exception("Incorrect type for parameter 'data'")


def get_rsa_key_pair():
    """
    OAEP padding algorithm
    """
    private_key = RSA.generate(8192)
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

# private_key_pem, public_key_pem = get_rsa_key_pair(8192)
# print(private_key_pem.decode("utf-8"))
# print(public_key_pem.decode("utf-8"))