
import rsa

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



# Generate key pairs for sender and receiver

sender_public_key_pem, sender_private_key_pem = generate_keys()

receiver_public_key_pem, receiver_private_key_pem = generate_keys()

# Test the send_secure_message and receive_secure_message functions
original_message = "Hello, this is a secure message!"
print("Original message:", original_message)

encrypted_message, signature = send_secure_message(original_message, sender_private_key_pem, receiver_public_key_pem)

received_message = receive_secure_message(encrypted_message, signature, sender_public_key_pem, receiver_private_key_pem)


print("Received message:", received_message)





