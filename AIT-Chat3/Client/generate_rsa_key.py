from Crypto.PublicKey import RSA
key = RSA.generate(2048)
# export the entire key pair in PEM format
ofile = open('elon_private.pem', 'w')
ofile.write(key.exportKey('PEM'))
ofile.close()
# export only the public key in PEM format
ofile = open('elon_public.pem', 'w')
ofile.write(key.publickey().exportKey('PEM'))
ofile.close()