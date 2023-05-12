import time

import rsa
import model
import sql


def generate_keys():
    publicKey, privateKey = rsa.newkeys(512)
    return publicKey.save_pkcs1().decode(), privateKey.save_pkcs1().decode()

def create_signature(message, private_key_str):
    private_key = rsa.PrivateKey.load_pkcs1(private_key_str.encode())
    message_hash = rsa.compute_hash(message.encode('utf-8'), 'SHA-256')
    signature = rsa.sign_hash(message_hash, private_key, 'SHA-256')
    return signature.hex()

def verify_signature(message, signature, public_key_pem):
    public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
    message_hash = rsa.compute_hash(message.encode('utf-8'), 'SHA-256')
    try:
        rsa.verify(message.encode('utf-8'), bytes.fromhex(signature), public_key)
        return True
    except rsa.VerificationError:
        return False



def encrypt_message(message, public_key_pem):
    public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
    ciphertext = rsa.encrypt(message.encode(), public_key)
    return ciphertext


def decrypt_message(ciphertext, private_key_pem):
    private_key = rsa.PrivateKey.load_pkcs1(private_key_pem.encode())
    plaintext = rsa.decrypt(ciphertext, private_key)
    return plaintext.decode()

def send_secure_message(message, sender_private_key_pem, receiver_public_key_pem):
    signature = create_signature(message, sender_private_key_pem)
    encrypted_message = encrypt_message(message, receiver_public_key_pem)
    return encrypted_message, signature

def receive_secure_message(encrypted_message, signature, sender_public_key_pem, receiver_private_key_pem):
    decrypted_message = decrypt_message(encrypted_message, receiver_private_key_pem)
    print(decrypted_message)
    if verify_signature(decrypted_message, signature, sender_public_key_pem):
        print("Signature verification passed")
        return decrypted_message
    else:
        return "Signature verification failed"

def init():
    database_args = "UserDatabase.db"  # Currently runs in RAM, might want to change this to a file if you use it
    sql_db = sql.SQLDatabase(database_args)
    sql_db.user_database_setup()
    sql_db.conn.close()

    model.register_user("newUser", "123")
    model.register_user("YAHAHA", "123")
    model.add_friend("newUser","admin")
    timestamp = int(time.time())
    model.send_message("admin","newUser","A new message for you", timestamp)
    model.send_message("newUser","admin","I received", timestamp)

def showAllMessage():
    print("The database info are shown below:")
    database_args = "UserDatabase.db"
    sql_db = sql.SQLDatabase(database_args)

    query = """
         SELECT *
         FROM Users
     """
    sql_db.execute(query)
    print(sql_db.cur.fetchall())

    query = """
         SELECT *
         FROM Friends
     """
    sql_db.execute(query)
    print()
    print(sql_db.cur.fetchall())

    query = """
         SELECT *
         FROM Messages
    """
    sql_db.execute(query)
    print()
    print(sql_db.cur.fetchall())
    sql_db.conn.close()

def test():

    database_args = "UserDatabase.db"
    sql_db = sql.SQLDatabase(database_args)
    timestamp = int(time.time())





#init()
#test()