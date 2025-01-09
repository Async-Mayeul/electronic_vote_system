from ecelgamal import *

print("starting...")
(priv,pub) = ECEG_generate_keys(ORDER, (BaseU, BaseV), p)

messages = [1, 0, 1, 1, 0]
encrypted_messages = []
for m in messages:
    encoded_message = EGencode(m)
    print("encoded message : " + str(encoded_message[0]) + "," + str(encoded_message[1]) + "\n")
    encrypted_cipher = ECEG_encrypt(pub, encoded_message, (BaseU, BaseV), p, ORDER)
    print("encrypted message : " + str(encrypted_cipher[0]) + "," + str(encrypted_cipher[1]) + "\n")
    encrypted_messages.append(encrypted_cipher)

r = encrypted_messages[0][0] + encrypted_messages[1][0] + encrypted_messages[2][0] + encrypted_messages[3][0] + encrypted_messages[4][0]
c = encrypted_messages[0][1] + encrypted_messages[1][1] + encrypted_messages[2][1] + encrypted_messages[3][1] + encrypted_messages[4][1]


decrypted_cipher = ECEG_decrypt(priv, (r, c), p)
print("decrypted message : " + str(decrypted_cipher[0]) + "," + str(decrypted_cipher[1]) + "\n")
print("bruteforcing...")
print(str(bruteECLog(decrypted_cipher[0], decrypted_cipher[1], p)))
