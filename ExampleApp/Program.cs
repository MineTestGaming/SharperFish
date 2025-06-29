using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Spectre.Console;

namespace ExampleApp;

class Program
{
    static void Main(string[] args)
    {
        String serverAddress = AnsiConsole.Prompt(new TextPrompt<string>("Server Address: "));
        if (serverAddress.EndsWith('/')) serverAddress = serverAddress.Substring(0, serverAddress.Length - 1);
        Console.WriteLine($"Current Server: {serverAddress}");
        LoginInfo loginInfo = new LoginInfo();
        loginInfo.username = AnsiConsole.Prompt(new TextPrompt<string>("Username: "));
        loginInfo.password = AnsiConsole.Prompt(new TextPrompt<string>("Password: ").Secret());
        HttpClientHandler handler = new HttpClientHandler()
        {
            UseCookies = false
        };

        // Get the public key
        using HttpClient client = new();
        Uri requestKeyUri = new Uri($"{serverAddress}/api/advanced_login/getKey");
        StringContent requestContent = new(loginInfo.username, Encoding.UTF8, "text/plain");
        StreamReader reader = new StreamReader(client.PostAsync(requestKeyUri, requestContent).Result.Content.ReadAsStream());
        String key = reader.ReadToEnd();
        // Encrypt the password
        String ogPassword = loginInfo.password;
        loginInfo.password = RSAHelper.Encrypt(loginInfo.password, key);
        
        // Sending encrypted password with username to the server to get encrypted cookie
        Uri postUri = new Uri($"{serverAddress}/api/advanced_login/login");
        StringContent content = new StringContent(JsonSerializer.Serialize(loginInfo), Encoding.UTF8, "application/json");
        StreamReader passwordReader =
            new StreamReader(client.PostAsync(postUri, content).Result.Content.ReadAsStream());
        String response = passwordReader.ReadToEnd();
        // Decrypting the cookie with password and time
        byte[] decKey = SHA256.HashData(Encoding.UTF8.GetBytes(ogPassword));
        String currentTime = DateTime.Now.ToString("yyyyMMddHH");
        byte[] decIv = SHA256.HashData(Encoding.UTF8.GetBytes(currentTime))[..16];
        
        Console.WriteLine(AESHelper.Decrypt(response, decKey, decIv));
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
            return Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(input), RSAEncryptionPadding.Pkcs1));
        }
        
        public static string Decrypt(string input, string privateKey)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
            return Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(input), RSAEncryptionPadding.Pkcs1));
        }
    }
    
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

    public class LoginInfo
    {
        public string username { get; set; } = string.Empty;
        public string password { get; set; } = string.Empty;
    }
}