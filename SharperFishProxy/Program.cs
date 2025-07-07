using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
        string aliasProxy = "ALIAS_PROXY_URL";

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
            (String publicKey, String privateKey) = EncryptHelper.RSAHelper.GenerateKey(); // Generate keys
            privateKeyDict.Add(username, privateKey); // Save the private key
            return publicKey; // return the public key
        });

        app.MapPost("/api/advanced_login/login",
            async (LoginInfo loginInfo) => // Username is not encrypted as the credential
            {
                if (!privateKeyDict.ContainsKey(loginInfo.username))
                    return "{\"message\": \"No private key available\"}"; // Error processing
                // Decrypt the password with private key that saved before
                String decryptedPassword =
                    EncryptHelper.RSAHelper.Decrypt(loginInfo.password, privateKeyDict[loginInfo.username]);
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
                    return EncryptHelper.AESHelper.Encrypt(cookiesContent, newKey, newIv);
                }
            });

        app.MapPost("/api/profile", async (EncryptBundle bundle) =>
        {
            Console.WriteLine(bundle.username);
            // Decrypt the jwt_token
            string decryptedData =
                EncryptHelper.RSAHelper.Decrypt(bundle.encryptedContent, privateKeyDict[bundle.username]);

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
                string decryptedJwtToken = EncryptHelper.RSAHelper.Decrypt(profile.Authentication.encryptedContent,
                    privateKeyDict[profile.Authentication.username]); // Decrypt the jwt_token

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
                HttpResponseMessage response;

                // Special process for agreement agree
                if (profile.Data.ContainsKey("agreement_agree") && profile.Data.Count == 1)
                    response = await client.PutAsync($"{divingFishAddress}/api/maimaidxprober/player/agreement",
                        content);
                else
                    // Normal process for others data post
                    response = await client.PostAsync($"{divingFishAddress}/api/maimaidxprober/player/profile",
                        content);
                privateKeyDict.Remove(profile.Authentication.username);
                return await new StreamReader(await response.Content.ReadAsStreamAsync()).ReadToEndAsync();
            }
            catch (Exception exception)
            {
                return "{Message: " + exception + " }";
            }
        });

        app.MapPost("/api/getRecords", async (EncryptBundle bundle) =>
        {
            string decryptedJwtToken = EncryptHelper.RSAHelper.Decrypt(bundle.encryptedContent,
                privateKeyDict[bundle.username]);
            CookieContainer container = new CookieContainer();
            container.Add(new Uri(divingFishAddress), new Cookie("jwt_token", decryptedJwtToken));
            HttpClientHandler handler = new HttpClientHandler
            {
                CookieContainer = container
            };

            using HttpClient client = new HttpClient(handler);
            return await new StreamReader(
                await client.GetStreamAsync($"{divingFishAddress}/api/maimaidxprober/player/records"))
                .ReadToEndAsync();
        });

        app.MapPost("/api/refreshImportToken", async (EncryptBundle bundle) =>
        {
            string decryptedJwtToken = EncryptHelper.RSAHelper.Decrypt(bundle.encryptedContent,
                privateKeyDict[bundle.username]);
            CookieContainer container = new CookieContainer();
            container.Add(new Uri(divingFishAddress), new Cookie("jwt_token", decryptedJwtToken));
            HttpClientHandler handler = new HttpClientHandler
            {
                CookieContainer = container
            };

            using HttpClient client = new HttpClient(handler);
            return await new StreamReader(
                    await client.GetStreamAsync($"{divingFishAddress}/api/maimaidxprober/player/import_token"))
                .ReadToEndAsync();
        });

        app.MapPost("/api/alias", async () =>
        {
            HttpClient client = new HttpClient();

            return new StreamReader(await client.GetAsync($"{aliasProxy}").Result.Content.ReadAsStreamAsync())
                .ReadToEndAsync();
        });
        app.Run();
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
        public EncryptBundle Authentication { get; set; }
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