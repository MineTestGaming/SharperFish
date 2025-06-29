using System.Runtime.InteropServices.JavaScript;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace SharperFishProxy;

public class Program
{
    public static void Main(string[] args)
    {
        Dictionary<String, String> privateKeyDict = new();
        
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddCors(options =>
        {
            options.AddPolicy(name: "CORSPolicy",
                policyBuilder => { policyBuilder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod(); });
        });
        var app = builder.Build();


        app.UseCors("CORSPolicy");
        app.MapGet("/", () => "Hello World!");

        app.MapPost("/api/login", async (LoginInfo loginInfo) => // Login with no encryption
        {
            string decryptedPassword = loginInfo.password;
            HttpClientHandler handler = new HttpClientHandler
            {
                UseCookies = false
            };
            string postData = "{\"username\":\"" + loginInfo.username + "\",\"password\":\"" + decryptedPassword +
                              "\"}";
            using (HttpClient http = new HttpClient(handler))
            {
                string url = "https://www.diving-fish.com/api/maimaidxprober/login";
                var content = new StringContent(postData, Encoding.UTF8, "application/json");
                var response = await http.PostAsync(url, content);
                response.Headers.TryGetValues("Set-Cookie", out var cookies);
                if (!(cookies != null && cookies.First().Contains("jwt_token"))) return "Failed";
                string cookiesContent = cookies.First().Split(';').First(x => x.Contains("jwt_token")).Split('=')[1];
                return cookiesContent;
            }
        });

        app.MapPost("/api/test", async (HttpRequest request) =>
        {
            using (var reader = new StreamReader(request.Body))
            {
                string body = await reader.ReadToEndAsync();
                return body;
            }
        });
        
        app.MapPost("/api/advanced_login/getKey",async (HttpRequest request) => // Generate keys
        {
            using var reader = new StreamReader(request.Body);
            String username = await reader.ReadToEndAsync();
            privateKeyDict.Remove(username);
            (String publicKey, String privateKey) = RSAHelper.GenerateKey(); // Generate keys
            privateKeyDict.Add(username, privateKey); // Save the private key
            return publicKey; // return the public key
        });
        
        app.MapPost("/api/advanced_login/login", async (LoginInfo loginInfo) => // Username is not encrypted as the credential
        {
            if (!privateKeyDict.ContainsKey(loginInfo.username)) return "{\"message\": \"No private key available\"}"; // Error processing
            // Decrypt the password with private key that saved before
            String decryptedPassword = RSAHelper.Decrypt(loginInfo.password, privateKeyDict[loginInfo.username]); 
            HttpClientHandler handler = new HttpClientHandler
            {
                UseCookies = false
            };
            string postData = "{\"username\":\"" + loginInfo.username + "\",\"password\":\"" + decryptedPassword +
                              "\"}"; // Process the JSON that needs to be sent
            using (HttpClient http = new HttpClient(handler))
            {
                string url = "https://www.diving-fish.com/api/maimaidxprober/login";
                var content = new StringContent(postData, Encoding.UTF8, "application/json");
                var response = await http.PostAsync(url, content);
                response.Headers.TryGetValues("Set-Cookie", out var cookies);
                if (!(cookies != null && cookies.First().Contains("jwt_token"))) return "Failed";
                string cookiesContent = cookies.First().Split(';').First(x => x.Contains("jwt_token")).Split('=')[1];
                
                // Encrypt the cookie with the password and current time's SHA256
                byte[] newKey = SHA256.HashData(Encoding.UTF8.GetBytes(decryptedPassword));
                String currentTime = DateTime.Now.ToString("yyyyMMddHH");
                byte[] newIv = SHA256.HashData(Encoding.UTF8.GetBytes(currentTime))[..16];
                return AESHelper.Encrypt(cookiesContent, newKey, newIv);
            }
        });

        app.Run();
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

    public class LoginInfo
    {
        public string username { get; set; } = string.Empty;
        public string password { get; set; } = string.Empty;
    }

    public class Msg
    {
        public required string Message;

        public Msg(string message)
        {
            Message = message;
        }
    } 
}