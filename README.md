# SharperFish

---

A proxy for certain game's score prober written by C#

## Functions

- Bypass CORS restriction for setting ``Set-Cookies`` of ``jwt_token``

- Encryption for password and jwt_token while connecting between client and proxy

## API Reference

- ``POST /api/login`` - Login into the prober and get jwt_token with encrypted
  
  Parameters in ``application/json``
  
  ```json
  {
      "username": "username",
      "password": "Password_with_aes_encryption_of_predefined_key_and_its_first_16byte_of_sha256_as_iv"
  }
  ```


