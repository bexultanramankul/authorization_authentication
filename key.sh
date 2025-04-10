# Приватный ключ (только для Auth)
openssl genpkey -algorithm RSA -out config/jwt_key/jwt_private.pem -pkeyopt rsa_keygen_bits:2048

# Публичный ключ (для User и Post)
openssl rsa -pubout -in config/jwt_key/jwt_private.pem -out config/jwt_key/jwt_public.pem