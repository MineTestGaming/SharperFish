using System.Security.Cryptography;
using System.Text;

namespace SharperFishProxy;

public class EncryptHelper
{
        public static class AESHelper
    {
        public static string Encrypt(string input, byte[] key, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            ICryptoTransform transform = aes.CreateEncryptor(); // 创建Transform Encryptor
            string result = String.Empty; // 存储Result

            using MemoryStream ms = new MemoryStream(); // 创建MemoryStream以使用内存空间并提供给CryptoStream
            using CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Write); // 创建CryptoStream
            using (StreamWriter writer = new(cs)) // 将CryptoStream中的内容使用StreamWriter写入
            {
                writer.Write(input);
            }

            return Convert.ToBase64String(ms.ToArray()); // 使用Base64编码
        }

        public static string Decrypt(string input, byte[] key, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            ICryptoTransform transform = aes.CreateDecryptor();

            using MemoryStream ms = new MemoryStream(Convert.FromBase64String(input));
            using CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Read);
            using StreamReader reader = new(cs);
            return reader.ReadToEnd();
        }
    }

    public static class RSAHelper
    {
        public static (string publicKey, string privateKey) GenerateKey()
        {
            using RSA rsa = RSA.Create();
            string publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
            string privateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
            return (publicKey, privateKey);
        }

        public static string Encrypt(string input, string publicKey)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
            return Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(input), RSAEncryptionPadding.OaepSHA256));
        }

        public static string Decrypt(string input, string privateKey)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
            return Encoding.UTF8.GetString(
                rsa.Decrypt(Convert.FromBase64String(input), RSAEncryptionPadding.OaepSHA256));
        }
    }
}