using System.Net;
using System.Runtime.InteropServices.JavaScript;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

// ReSharper disable PossibleMultipleEnumeration

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
        string divingFishAddress = "https://www.diving-fish.com";

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
                string url = $"{divingFishAddress}/api/maimaidxprober/login";
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

        app.MapPost("/api/advanced_login/getKey", async (HttpRequest request) => // Generate keys
        {
            using var reader = new StreamReader(request.Body);
            String username = await reader.ReadToEndAsync();
            privateKeyDict.Remove(username);
            (String publicKey, String privateKey) = RSAHelper.GenerateKey(); // Generate keys
            privateKeyDict.Add(username, privateKey); // Save the private key
            return publicKey; // return the public key
        });

        app.MapPost("/api/advanced_login/login",
            async (LoginInfo loginInfo) => // Username is not encrypted as the credential
            {
                if (!privateKeyDict.ContainsKey(loginInfo.username))
                    return "{\"message\": \"No private key available\"}"; // Error processing
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
                    string cookiesContent =
                        cookies.First().Split(';').First(x => x.Contains("jwt_token")).Split('=')[1];

                    // Encrypt the cookie with the password and current time's SHA256
                    byte[] newKey = SHA256.HashData(Encoding.UTF8.GetBytes(decryptedPassword));
                    String currentTime = DateTime.UtcNow.ToString("yyyyMMddHH");
                    byte[] newIv = SHA256.HashData(Encoding.UTF8.GetBytes(currentTime))[..16];
                    privateKeyDict.Remove(loginInfo.username);
                    return AESHelper.Encrypt(cookiesContent, newKey, newIv);
                }
            });

        app.MapPost("/api/profile", async (EncryptBundle bundle) =>
        {
            Console.WriteLine(bundle.username);
            // Decrypt the jwt_token
            string decryptedData = RSAHelper.Decrypt(bundle.encryptedContent, privateKeyDict[bundle.username]);

            // Set the cookie
            CookieContainer cookieContainer = new CookieContainer();
            cookieContainer.Add(new Uri(divingFishAddress), new Cookie("jwt_token", decryptedData));
            HttpClientHandler handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer
            };

            // Get the data from diving fish
            using HttpClient client = new HttpClient(handler);
            string uri = $"{divingFishAddress}/api/maimaidxprober/player/profile";
            var response = await client.GetAsync(uri);
            using StreamReader reader = new StreamReader(await response.Content.ReadAsStreamAsync());
            privateKeyDict.Remove(bundle.username);
            return await reader.ReadToEndAsync();
        });

        app.MapPost("/api/profile/set", async (ProfileBundle profile) =>
        {
            try
            {
                string decryptedJwtToken = RSAHelper.Decrypt(profile.Authenication.encryptedContent,
                    privateKeyDict[profile.Authenication.username]); // Decrypt the jwt_token

                // Set the cookie and associate it into handler
                CookieContainer cookieContainer = new CookieContainer();
                cookieContainer.Add(new Uri(divingFishAddress), new Cookie("jwt_token", decryptedJwtToken));
                HttpClientHandler handler = new HttpClientHandler
                {
                    CookieContainer = cookieContainer
                };

                // Select the key value pair which includes in the acceptable profile key
                Dictionary<string, object> verifiedData = profile.Data
                    .Where(x => ProfileKey.GetAcceptableProfileKeys().Contains(x.Key)).ToDictionary();

                // Send the request to the server
                using HttpClient client = new HttpClient(handler);
                StringContent content = new(JsonSerializer.Serialize(verifiedData), Encoding.UTF8, "application/json");
                var response = await client.PostAsync($"{divingFishAddress}/api/maimaidxprober/player/profile", content);
                privateKeyDict.Remove(profile.Authenication.username);
                return await new StreamReader(await response.Content.ReadAsStreamAsync()).ReadToEndAsync();
            }
            catch (Exception exception)
            {
                return "{Message: " + exception + " }";
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

    public class LoginInfo
    {
        public string username { get; set; } = string.Empty;
        public string password { get; set; } = string.Empty;
    }

    public class EncryptBundle
    {
        public string username { get; set; }
        public string encryptedContent { get; set; }
    }

    public class ProfileBundle
    {
        public EncryptBundle Authenication { get; set; }
        public Dictionary<string, object> Data { get; set; } = new();
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