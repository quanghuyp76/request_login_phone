﻿using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using System.Web;
using static Auther.OTP.LoginAuther;

namespace Auther.OTP
{
    public class LoginAuther : IDisposable
    {
        private HttpClient _client;

        private CookieContainer cookieContainer;

        public required WebProxy webProxy { get; set; }

        public string useragain { get; set; }
        public required string UrlGetOTP { get; set; }

        public class Loadpage
        {
            public int i13 { get; set; }
            public string login { get; set; }
            public string loginfmt { get; set; }
            public int type { get; set; }
            public int LoginOptions { get; set; }
            public string SentProofID { get; set; }

            public string purpose { get; set; }

            public string piotc { get; set; }

            public int ps { get; set; }
 
            public string psRNGCDefaultType { get; set; }
            public string psRNGCEntropy { get; set; }
            public string psRNGCSLK { get; set; }
            public string canary { get; set; }
            public string ctx { get; set; }
            public string hpgrequestid { get; set; }
            public string flowToken { get; set; }
            public string PPSX { get; set; }
            public int NewUser { get; set; }
            public string FoundMSAs { get; set; }
            public int fspost { get; set; }
            public string i21 { get; set; }
            public int CookieDisclosure { get; set; }
            public int IsFidoSupported { get; set; }
            public int isSignupPost { get; set; }
            public string DfpArtifact { get; set; }
            public string i19 { get; set; }

        }
        public class LoginRequest
        {
            public bool CheckPhones { get; set; }
            public string Country { get; set; }
            public int FederationFlags { get; set; }
            public string FlowToken { get; set; }
            public bool ForceOtcLogin { get; set; }
            public bool IsCookieBannerShown { get; set; }
            public bool IsExternalFederationDisallowed { get; set; }
            public bool IsFederationDisabled { get; set; }
            public bool IsFidoSupported { get; set; }
            public bool IsOtherIdpSupported { get; set; }
            public bool IsRemoteConnectSupported { get; set; }
            public bool IsRemoteNgcSupported { get; set; }
            public bool IsSignup { get; set; }
            public string OriginalRequest { get; set; }
            public bool OtcLoginDisallowed { get; set; }
            public string Uaid { get; set; }
            public string Username { get; set; }
        }

        public class PostOtp
        {
            public string FlowToken { get; set; }
            public string Ctx { get; set; }
            public string AdditionalAuthData { get; set; }
            
            
        }

        public class School
        {
            public string Channel { get; set; }
            public string FlowToken { get; set; }
            public string OriginalRequest { get; set;}
        }




        public LoginAuther(string useragain)
        {
            _client = new HttpClient(new HttpClientHandler()
            {
                UseCookies = true,
                UseProxy = false,
                AllowAutoRedirect = true,
                Proxy = webProxy,
                CookieContainer = cookieContainer = new CookieContainer(),
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            });
            _client.Timeout = TimeSpan.FromSeconds(15);
            _client.DefaultRequestHeaders.Add("accept", "application/json, text/plain, */*");
            _client.DefaultRequestHeaders.Add("accept-encoding", "gzip, deflate, br, zstd");
            _client.DefaultRequestHeaders.Add("accept-language", "en-US,en;q=0.9");
            _client.DefaultRequestHeaders.UserAgent.ParseAdd(useragain);
        }

        public async Task<byte> LoginAsysc(string phone, string useragain)
        {
            try
            {
                _client = new HttpClient(new HttpClientHandler()
                {
                    UseCookies = true,
                    UseProxy = true,
                    AllowAutoRedirect = true,
                    Proxy = webProxy,
                    CookieContainer = cookieContainer = new CookieContainer(),
                    SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                    AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
                });
                _client.Timeout = TimeSpan.FromSeconds(15);
                // Script
                ////////////////////////////////////////////////////////////////////////////////////
                // Check ip

                string Urlcheckip = "https://ifconfig.co/ip";
                try
                {
                    var messageCheckip = new HttpRequestMessage(HttpMethod.Get, Urlcheckip);
                    var responseCheckip = await _client.SendAsync(messageCheckip);
                    if (!responseCheckip.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"Warning[{phone}] : {responseCheckip.StatusCode}");
                        return 0;
                    }
                    var contentCheckip = await responseCheckip.Content.ReadAsStringAsync();
                    contentCheckip = contentCheckip.Replace("\n", "").Replace("\r", "").Trim();
                    Console.WriteLine( $"Suscces[{phone}] : { contentCheckip}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}]: {ex.Message}");
                    return 0;
                }
                //Console.WriteLine($"Suscces[{phone}] : {useragain}");
                ///////////////////////////////////////////////////////////////////////////////////////////////
                //Truy cập vào urlRedirect
                Console.WriteLine($"Suscces[{phone}] : Go To Microsoft Entra");
                string UrlEntra = "https://entra.microsoft.com/signin/index";
                string? urlRedirect = string.Empty;
                string? contentGotoUrlEntra = string.Empty;
                try
                {
                    var messageGotoUrlEntra = new HttpRequestMessage(HttpMethod.Get, UrlEntra);
                    var responseGotoUrlEntra = await _client.SendAsync(messageGotoUrlEntra);
                    contentGotoUrlEntra = await responseGotoUrlEntra.Content.ReadAsStringAsync();
                    if (!responseGotoUrlEntra.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"Warning[{phone}] : {responseGotoUrlEntra.StatusCode}");
                        return 0;
                    }
                    urlRedirect = Regex.Match(contentGotoUrlEntra, @"https:\/\/login\.microsoftonline\.com[^\s""]+").Groups[0].Value;
                    if (string.IsNullOrEmpty(urlRedirect))
                    {
                        Console.WriteLine($"Warning[{phone}] : Không tìm thấy Url ReDirect");
                        return 0;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : Go to Microsoft Entra Fail ({ex.Message})");
                    return 0;
                }
                Console.WriteLine($"Suscces[{phone}] : Go to Url Redirect");
                // Truy cập Microsoft Entra
                string? ApiCanary = string.Empty;
                string? flowToken = string.Empty;
                string? urllogin = string.Empty;
                string? clientrequestid = string.Empty;
                string? uaid = string.Empty;
                string? urlGetCredentialType = string.Empty;
                string? contentUrlReDirect = string.Empty;
                string? canaryentra = string.Empty;
                string? hpgrequestidloadpage = string.Empty;
                try
                {
                    var messageUrlReDirect = new HttpRequestMessage(HttpMethod.Get, urlRedirect);
                    var responseUrlReDirect = await _client.SendAsync(messageUrlReDirect);
                    contentUrlReDirect = await responseUrlReDirect.Content.ReadAsStringAsync();
                    if (responseUrlReDirect.Headers.TryGetValues("x-ms-request-id", out var values))
                    {
                        hpgrequestidloadpage = values.FirstOrDefault();
                    }
                    ApiCanary = Regex.Match(contentUrlReDirect, @"""apiCanary"":""([^""]+)""").Groups[1].Value;
                    canaryentra = Regex.Match(contentUrlReDirect, @"""canary"":""([^""]+)""").Groups[1].Value;
                    flowToken = Regex.Match(contentUrlReDirect, @"""sFT"":""([^""]+)""").Groups[1].Value;
                    urllogin = Regex.Match(contentUrlReDirect, @"\?ctx=([a-zA-Z0-9_-]+)").Groups[1].Value;
                    clientrequestid = Regex.Match(contentUrlReDirect, @"client-request-id=([^\\]+)").Groups[1].Value;
                    uaid = Regex.Match(contentUrlReDirect, @"uaid=([^\\]+)").Groups[1].Value;
                    urlGetCredentialType = "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US";
                    if (string.IsNullOrEmpty(flowToken) || string.IsNullOrEmpty(ApiCanary) || string.IsNullOrEmpty(urllogin) || string.IsNullOrEmpty(clientrequestid) || string.IsNullOrEmpty(uaid))
                    {
                        Console.WriteLine($"Warning[{phone}] : No Found Data Login Phone");
                        return 0;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : GO to Url Redirect Fail ({ex.Message})");
                    return 0;
                }

                // get otp cũ
                string? otpold = string.Empty;
                try
                {
                    otpold = await VFarmOTP.GetOTPFarm(UrlGetOTP, phone);
                    if (!string.IsNullOrEmpty(otpold))
                    {
                        Console.WriteLine($"Suscces[{phone}] : otpold {otpold}");
                    }
                    else
                    {
                        Console.WriteLine($"Suscces[{phone}] : NO OTPOLD");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : {ex.Message}");
                    return 0;
                }
                // Giửi yêu cầu đăng nhập phone
                var loginRequest = new LoginRequest
                    {
                        CheckPhones = true,
                        Country = "VN",
                        FederationFlags = 0,
                        FlowToken = flowToken,
                        ForceOtcLogin = false,
                        IsCookieBannerShown = false,
                        IsExternalFederationDisallowed = false,
                        IsFidoSupported = true,
                        IsOtherIdpSupported = true,
                        IsRemoteConnectSupported = false,
                        IsRemoteNgcSupported = true,
                        IsSignup = false,
                        OriginalRequest = urllogin,
                        Username = phone
                    };
                var jsonBody = JsonConvert.SerializeObject(loginRequest);
                // post data Login Phone
                var messageLoginPhone = new HttpRequestMessage(HttpMethod.Post, urlGetCredentialType);
                messageLoginPhone.Content = new StringContent(jsonBody, MediaTypeHeaderValue.Parse("application/json"));
                messageLoginPhone.Headers.Add("Canary", ApiCanary);
                messageLoginPhone.Headers.Add("Hpgid", "1104");
                messageLoginPhone.Headers.Add("Hpgact", "1800");
                messageLoginPhone.Headers.Add("origin", "https://login.microsoftonline.com");
                messageLoginPhone.Headers.Add("priority", "u=1, i");
                messageLoginPhone.Headers.Add("referer", urlRedirect);
                messageLoginPhone.Headers.Add("client-request-id", clientrequestid);
                string? contentLoginPhone = string.Empty;
                try
                {
                    var responseLoginPhone = await _client.SendAsync(messageLoginPhone);
                    contentLoginPhone = await responseLoginPhone.Content.ReadAsStringAsync();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] :Sent Phone Fail {ex.Message}");
                    return 0;
                }
                JObject jsonObject = JObject.Parse(contentLoginPhone);
                string? flowTokenSentOTP = string.Empty;
                string flowToken1 = Regex.Match(contentLoginPhone, @"""FlowToken"":""([^""]+)""").Groups[1].Value;
                string apiCanary1 = Regex.Match(contentLoginPhone, @"""apiCanary"":""([^""]+)""").Groups[1].Value;
                if (string.IsNullOrEmpty(flowToken1))
                {
                    Console.WriteLine($"Warning[{phone}] : Sent OTP Fail");
                    lock (lockObjectOTP)
                    {
                        File.AppendAllText($"input\\SentOTPFail.txt", $"{phone}" + Environment.NewLine);
                    }
                    return 0;
                }
                else
                {
                    Console.WriteLine($"Suscces[{phone}] : Sent OTP Suscces");
                    var ifExistsResult = (int)jsonObject["IfExistsResult"];
                    if (ifExistsResult == 6)
                    {
                        try
                        {
                            Console.WriteLine($"Suscces[{phone}] : Work Or School Account");
                            string UrlGetOneTimeCode = "https://login.microsoftonline.com/common/GetOneTimeCode";
                            var school = new School
                            {
                                Channel = "SMS",
                                FlowToken = flowToken1,
                                OriginalRequest = urllogin,
                            };
                            var jsonBodySchool = JsonConvert.SerializeObject(school);
                            var messageSchool = new HttpRequestMessage(HttpMethod.Post, UrlGetOneTimeCode);
                            messageSchool.Content = new StringContent(jsonBodySchool, MediaTypeHeaderValue.Parse("application/json"));
                            messageSchool.Headers.Add("Canary", apiCanary1);
                            messageSchool.Headers.Add("origin", "https://login.microsoftonline.com");
                            messageSchool.Headers.Add("Hpgid", "1104");
                            messageSchool.Headers.Add("Hpgact", "1800");
                            messageSchool.Headers.Add("priority", "u=1, i");
                            var responseSchool = await _client.SendAsync(messageSchool);
                            var contentSchool = await responseSchool.Content.ReadAsStringAsync();
                            // lấy flowtoken mới
                            JObject jsonSchool = JObject.Parse(contentSchool);
                            flowTokenSentOTP = (string)jsonSchool["FlowToken"];
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning[{phone}] : {ex.Message}");
                            return 0;
                        }

                    }
                    else
                    {
                        flowTokenSentOTP=flowToken1;
                    }    

                }             
                string? otp = string.Empty;
                int count = 10;
                Console.WriteLine($"Suscces[{phone}] : GetOTP");
                while (count > 0)
                {
                    try
                    {
                        otp = await VFarmOTP.GetOTPFarm(UrlGetOTP, phone);
                        if (!string.IsNullOrEmpty(otp) && otp != otpold )
                        {
                            //Console.WriteLine($"Suscces[{phone}] : {otp}");
                            string dirPath = $"output\\{DateTime.Now:dd_MM_yyyy}";
                            Directory.CreateDirectory(dirPath); // Tạo nếu chưa có
                            lock (lockObjectOTP)
                            {
                                File.AppendAllText($"output\\{DateTime.Now.ToString("dd_MM_yyyy")}\\phoneUsed.txt", $"{phone}" + Environment.NewLine);
                                File.AppendAllText($"output\\{DateTime.Now.ToString("dd_MM_yyyy")}\\otp.txt", $"{phone}|{otp}" + Environment.NewLine);
                            }
                            break;
                        }

                        count--;
                        await Task.Delay(3000);

                    }
                    catch(Exception ex)
                    {
                        Console.WriteLine($"Warning[{phone}] : {ex.Message}");
                        return 0;
                    }
                    
                }
                string? contentSentOTP = string.Empty;
                string? flowTokenLoadpage = string.Empty;
                string? ctxloadpage = string.Empty;
                if (count >= 0 && !string.IsNullOrEmpty(otp) && otp != otpold)
                {
                    ///post otp
                    Console.WriteLine($"Suscces[{phone}] : {otp}");
                    var UrlPostOTP = "https://login.microsoftonline.com/common/PIA/EndAuth";
                    var postOtp = new PostOtp
                    {
                        AdditionalAuthData = otp,
                        FlowToken = flowTokenSentOTP,
                        Ctx = urllogin,
                    };
                   
                    var jsonBody1 = JsonConvert.SerializeObject(postOtp);
                    var messageSentOTP = new HttpRequestMessage(HttpMethod.Post, UrlPostOTP);
                    messageSentOTP.Content = new StringContent(jsonBody1, MediaTypeHeaderValue.Parse("application/json"));
                    messageSentOTP.Headers.Add("Canary", apiCanary1);
                    messageSentOTP.Headers.Add("origin", "https://login.microsoftonline.com");
                    messageSentOTP.Headers.Add("Hpgid", "1104");
                    messageSentOTP.Headers.Add("Hpgact", "1800");
                    messageSentOTP.Headers.Add("priority", "u=1, i");
                    var responseSentOTP = await _client.SendAsync(messageSentOTP);
                    contentSentOTP = await responseSentOTP.Content.ReadAsStringAsync();
                    JObject jsonSentOTP = JObject.Parse(contentSentOTP);
                    bool success = jsonSentOTP["SasParams"]?["Success"]?.Value<bool>() ?? false;
                    if (success)
                    {
                        Console.WriteLine($"Suscces[{phone}] : ______________________________Confirm OTP Suscces {otp}");
                        flowTokenLoadpage = jsonSentOTP["FlowToken"]?.ToString();
                        ctxloadpage = jsonSentOTP["Ctx"]?.ToString();
                        goto loadpage;
                    }
                    else
                    {
                        Console.WriteLine($"Warning[{phone}] : ______________________________Confirm OTP False");
                    }
                    return 1;
                }
                else
                {
                    Console.WriteLine($"Suscces[{phone}] : Không có OTP");
                    File.AppendAllText($"output\\{DateTime.Now.ToString("dd_MM_yyyy")}\\Nootp.txt", $"{phone}|{otp}" + Environment.NewLine);
                    return 0;
                }

            loadpage:
                

                Console.WriteLine($"Suscces[{phone}] : Bắt đầu load page {otp}");
                string UrlLoadPage = "https://login.microsoftonline.com/common/login";
                var messageloadpage = new HttpRequestMessage(HttpMethod.Post, UrlLoadPage);
                messageloadpage.Content = new StringContent($"i13=0&login={phone}&loginfmt=%2B{phone.Substring(0, 2)}+{phone.Substring(2, 3)}+{phone.Substring(5, 3)}+{phone.Substring(8, 3)}&SentProofID={phone}&purpose=PublicIdentifierAuth&piotc={otp}&ps=3&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary={canaryentra}&ctx={ctxloadpage}&hpgrequestid={hpgrequestidloadpage}&flowToken={flowTokenLoadpage}&PPSX=&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&DfpArtifact=&i19=", MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded"));
                var responseloadpage = await _client.SendAsync(messageloadpage);
                var contentloadpage = await responseloadpage.Content.ReadAsStringAsync();                
                return 1;

            }
            catch(Exception ex)
            {
                File.AppendAllText($"output\\{DateTime.Now.ToString("dd_MM_yyyy")}\\nootp.txt", $"{phone}" + Environment.NewLine);
                Console.WriteLine($"Warning[{ phone}] : {ex.Message}");
                return 0;
            }

        }









        private static object lockObjectOTP = new object();

        public void Dispose()
        {
            _client?.Dispose();
        }
    }
    
    
}