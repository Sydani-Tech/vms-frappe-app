import hashlib

def generate_hash(secret_data):
    # create the hash object
    hash_object = hashlib.sha256()
    # update the hash object with the secret data
    hash_object.update(secret_data.encode())
    # get the hexadecimal representation of the hash
    secret_hash = hash_object.hexdigest()
    return secret_hash


def verify_hash(secret_data, stored_hash):
    # create the hash object and update with the secret data
    hash_object = hashlib.sha256()
    hash_object.update(secret_data.encode())
    # get the hexadecimal representation of the hash
    computed_hash = hash_object.hexdigest()
    # compare the stored hash with the computed hash
    if stored_hash == computed_hash:
        return 1
    else:
        return 0