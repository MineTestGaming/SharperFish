# SharperFish

A proxy for certain game's score prober written by C#

## Functions

- Bypass CORS restriction for setting ``Set-Cookies`` of ``jwt_token``

- Encryption for password and jwt_token while connecting between client and proxy

- Get diving-fish user profile without setting diving-fish's cookie

- [Out of the box serverless function compute implement](https://github.com/MineTestGaming/SharperFishFC)

## API Reference

- ``POST /api/advanced_login/getKey`` - Generate a new key pair and get the public key for authenication
  
  Parameters in ``text/plain``
  
  will returns a public key without BEGIN PUBLIC KEY and END PUBLIC KEY

- ``POST /api/advanced_login/login`` - Get the jwt_token of the prober and get jwt_token with encrypted (Recommended)
  
  Parameters in `application/json`
  
  ```json
  {
      "username": "username",
      "password": "password_need_to_be_encrypted_with_public_key_from_getKey"
  }
  ```
  
  will returns a cookies encrypted with decrypted password's SHA256 as key and time with format "yyyyMMDDHH"'s first 16-bit SHA256 as IV

- ``POST /api/login`` - Get the jwt_token of the prober and get jwt_token without encrypted (insecure and not recommended)
  
  Parameters in ``application/json``
  
  ```json
  {
      "username": "username",
      "password": "password"
  }
  ```
  
  returns
  
  ```
  jwt_token
  ```

- ``POST /api/profile`` - Get the profile of the user, which is associated with jwt_token
  Parameters in ``application/json`` with RSA public key encryption from ``api/advanced_login/getKey``
  
  Parameter: 
  
  ```json
  {
      "username": "username",
      "encryptedData": "jwt_token_with_encrypted"
  }
  ```
  
  Result: 
  
  ```json
  {
      "accept_agreement":true, // whether the user accepted diving-fish's user agreement
      "additional_rating":0, // Rating
      "bind_qq":"QQ_ID",
      "import_token":"IMPORT_TOKEN_FOR_BOT",
      "mask":true, // score mask
      "nickname":"username_in_maimai_cn",
      "plate":"name_plate",
      "privacy":true, // if the bot could get the userdata
      "qq_channel_uid":"QQ_channel_uid",
      "user_general_data":null,
      "username":"Diving-Fish Username"
  }
  ```

```

```
