using System.Text;
using System.Security.Cryptography;

namespace SharperFishProxy;

public class Program
{
    public static void Main(string[] args)
    {
        byte[] initKey = Encoding.UTF8.GetBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // 在这里更改你的初始定义值，必须为32位字符
        byte[] initIv = SHA256.HashData(initKey)[..16];
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddCors(options =>
        {
            options.AddPolicy(name: "CORSPolicy",
                policyBuilder => { policyBuilder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod(); });
        });
        var app = builder.Build();


        app.UseCors("CORSPolicy");
        app.MapGet("/", () => "Hello World!");

        app.MapPost("/api/login", async (LoginInfo loginInfo) =>
        {
            string decryptedPassword = AESHelper.Decrypt(loginInfo.password, initKey, initIv);
            HttpClientHandler handler = new HttpClientHandler
            {
                UseCookies = false
            };
            string postData = "{\"username\":\"" + loginInfo.username + "\",\"password\":\"" + decryptedPassword + "\"}";
            using (HttpClient http = new HttpClient(handler))
            {
                string url = "https://www.diving-fish.com/api/maimaidxprober/login";
                var content = new StringContent(postData, Encoding.UTF8, "application/json");
                var response = await http.PostAsync(url, content);
                response.Headers.TryGetValues("Set-Cookie", out var cookies);
                if (!(cookies != null && cookies.First().Contains("jwt_token"))) return "Failed";
                string cookiesContent = cookies.First().Split(';').First(x => x.Contains("jwt_token")).Split('=')[1];
                byte[] newKey = SHA256.HashData(Encoding.UTF8.GetBytes(decryptedPassword));
                byte[] newIv = SHA256.HashData(newKey)[..16];
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
    
    public class LoginInfo
    {
        public string username { get; set; } = string.Empty;
        public string password { get; set; } = string.Empty;
    }
}