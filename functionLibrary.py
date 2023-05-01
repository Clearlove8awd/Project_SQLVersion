import rsa

def generate_keys():
    publicKey, privateKey = rsa.newkeys(512)
    return publicKey.save_pkcs1().decode(), privateKey.save_pkcs1().decode()
