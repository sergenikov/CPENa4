import sys
import hashlib
import binascii

"""
Replaces the password located in the binary file with the
newly calculated hash.
Usage:
python q4crack.py hello
Where hello is the new password.
Any other usage is undefined and unpredictable.
"""

print 'Number of arguments:', len(sys.argv), 'arguments.'
print 'Argument List:', str(sys.argv)

new_pwd = sys.argv[1]
print "new_password is", new_pwd

new_pwd_sha1 = hashlib.sha1(new_pwd) # hashed password as byte array
print "New hash", binascii.hexlify(new_pwd_sha1.digest())

list_sha1 = list(new_pwd_sha1.hexdigest())
print "LIST SHA1"
print list_sha1
sha1_bytes = binascii.a2b_hex(''.join(list_sha1))
print "SHA1_BYTES"
print sha1_bytes



# open the file
binary = open('35643097.program2.exe', 'rb')
binary.seek(75804)
print "Current hash before overwriting it"
with binary:
    byte = binary.read(20)
    hexadecimal = binascii.hexlify(byte)
    decimal = int(hexadecimal, 16)
    binary = bin(decimal)[2:].zfill(8)
    print("hex: %s" % (hexadecimal))

# Open file again to write the new password in place of the old one.
binary = open('35643097.program2.exe', 'r+b')
binary.seek(75804)
binary.write(sha1_bytes)
print "Current hash after overwriting it"
binary.seek(75804)
with binary:
    byte = binary.read(20)
    hexadecimal = binascii.hexlify(byte)
    decimal = int(hexadecimal, 16)
    binary = bin(decimal)[2:].zfill(8)
    print("hex: %s" % (hexadecimal))