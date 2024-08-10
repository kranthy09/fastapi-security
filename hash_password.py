from argon2 import PasswordHasher

ph = PasswordHasher()
hash = ph.hash("secret")
print(hash)

# Verify the password
print(ph.verify(hash, "secret"))
