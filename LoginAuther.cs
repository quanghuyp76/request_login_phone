using Newtonsoft.Json;
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

        public required string UrlRenewOTP { get; set; }
        public class SentPhone
        {
            public string AuthMethodId { get; set; }
            public string Method { get; set; }
            public string ctx { get; set; }
            public string flowToken { get; set; }
        }

        public class SentOTP
        {
            public string Method { get; set; }
            public string SessionId { get; set; }
            public string FlowToken { get; set; }
            public string Ctx { get; set; }
            public string AuthMethodId { get; set; }
            public string AdditionalAuthData { get; set; }
            public int PollCount { get; set; }
        }
        public class SentPass
        {
            public int i13 { get; set; }
            public string login { get; set; }
            public string loginfmt { get; set; }
            public int type { get; set; }
            public int LoginOptions { get; set; }
            public string lrt { get; set; }

            public string lrtPartition { get; set; }

            public string hisRegion { get; set; }

            public string hisScaleUnit { get; set; }
            public string passwd { get; set; }
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

        public static string UnescapeUnicode(string input)
        {
            return Regex.Replace(input, @"\\u([0-9A-Fa-f]{4})", match =>
            {
                var unicode = Convert.ToInt32(match.Groups[1].Value, 16);
                return ((char)unicode).ToString();
            });
        }

        public static Dictionary<string, string> ToFormDictionary(object obj)
        {
            var dict = new Dictionary<string, string>();
            var jObj = JObject.FromObject(obj);

            foreach (var prop in jObj)
            {
                if (prop.Value != null)
                {
                    dict[prop.Key] = prop.Value.ToString();
                }
            }

            return dict;
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

        public async Task<byte> LoginAsysc(string email, string password ,string phone,string group, string useragain)
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
                //Import
                string? ApiCanaryEntraRedirect = string.Empty;
                string? flowTokenEntraRedirect = string.Empty;
                string? urlloginEntraRedirect = string.Empty;
                string? clientrequestidEntraRedirect = string.Empty;
                string? uaidEntraRedirect = string.Empty;
                string? urlGetCredentialTypeEntraRedirect = string.Empty;
                string? contentEntraRedirect = string.Empty;
                string? canaryEntraRedirect = string.Empty;
                string? hpgrequestidloadpageEntraRedirect = string.Empty;
                string? hpgrequestidloadpage = string.Empty;
                string? contentsentpasss0 = string.Empty;
                string? UrlSentPhone = string.Empty;
                string? sCtxSentPhone = string.Empty;
                string? flowTokenSentPhone = string.Empty;
                // Script
                ////////////////////////////////////////////////////////////////////////////////////
                // Check ip
                #region checkip()
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
                    Console.WriteLine($"Warning[{phone}]: CheckIP Fail ({ex.Message})");
                    return 0;
                }
                #endregion
                ///////////////////////////////////////////////////////////////////////////////////////////////
                //Truy cập vào Microsoft Entra
                #region GotoMSEntra()
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
                        Console.WriteLine($"Warning[{phone}] : Request Go to MS Entra Fail ({responseGotoUrlEntra.StatusCode})");
                        return 0;
                    }
                    urlRedirect = Regex.Match(contentGotoUrlEntra, @"https:\/\/login\.microsoftonline\.com[^\s""]+").Groups[0].Value;
                    if (string.IsNullOrEmpty(urlRedirect))
                    {
                        Console.WriteLine($"Warning[{phone}] : Không tìm thấy Url MSEnTra ReDirect");
                        return 0;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : Go to Microsoft Entra Fail ({ex.Message})");
                    return 0;
                }
                #endregion
                ///////////////////////////////////////////////////////////////////////////////////////////////
                // Truy cập Microsoft Entra Redirect
                #region GotoUrlEntraRedirect()
                Console.WriteLine($"Suscces[{phone}] : Go to Url Microsoft Entra Redirect");
                try
                {
                    var messageUrlReDirect = new HttpRequestMessage(HttpMethod.Get, urlRedirect);
                    var responseUrlReDirect = await _client.SendAsync(messageUrlReDirect);
                    contentEntraRedirect = await responseUrlReDirect.Content.ReadAsStringAsync();
                    if (responseUrlReDirect.Headers.TryGetValues("x-ms-request-id", out var values))
                    {
                        hpgrequestidloadpageEntraRedirect = values.FirstOrDefault();
                    }
                    ApiCanaryEntraRedirect = Regex.Match(contentEntraRedirect, @"""apiCanary"":""([^""]+)""").Groups[1].Value;
                    canaryEntraRedirect = Regex.Match(contentEntraRedirect, @"""canary"":""([^""]+)""").Groups[1].Value;
                    flowTokenEntraRedirect = Regex.Match(contentEntraRedirect, @"""sFT"":""([^""]+)""").Groups[1].Value;
                    urlloginEntraRedirect = Regex.Match(contentEntraRedirect, @"\?ctx=([a-zA-Z0-9_-]+)").Groups[1].Value;
                    clientrequestidEntraRedirect = Regex.Match(contentEntraRedirect, @"client-request-id=([^\\]+)").Groups[1].Value;
                    uaidEntraRedirect = Regex.Match(contentEntraRedirect, @"uaid=([^\\]+)").Groups[1].Value;
                    urlGetCredentialTypeEntraRedirect = "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US";
                    if (string.IsNullOrEmpty(flowTokenEntraRedirect) || string.IsNullOrEmpty(ApiCanaryEntraRedirect) || string.IsNullOrEmpty(urlloginEntraRedirect) || string.IsNullOrEmpty(clientrequestidEntraRedirect) || string.IsNullOrEmpty(uaidEntraRedirect))
                    {
                        Console.WriteLine($"Warning[{phone}] : No Found Data Login Phone");
                        return 0;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : GO to Url Microsoft Entra Redirect Fail ({ex.Message})");
                    return 0;
                }
                #endregion
                ///////////////////////////////////////////////////////////////////////////////////////////////
                // get otp cũ
                int? k_getotpfarmx = 0;
                string? otpold1 = string.Empty;
                #region GETOTPOLD1_VFARMOTP()
                if (k_getotpfarmx == 1)
                {
                    try
                    {
                        VFarmOTP.GetOTPVFarmRenew(UrlRenewOTP, phone);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning[{phone}] : Giửi Renew Fail ({ex.Message})");
                        return 0;
                    }
                    try
                    {
                        otpold1 = await VFarmOTP.GetOTPVFarmm(UrlGetOTP, phone);
                        if (!string.IsNullOrEmpty(otpold1))
                        {
                            Console.WriteLine($"Suscces[{phone}] : otpold1 ({otpold1})");
                        }
                        else
                        {
                            Console.WriteLine($"Suscces[{phone}] : NO OTPOLD 1");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning[{phone}] : GET OTP OLD1 Fail ({ex.Message})");
                        return 0;
                    }
                }
                #endregion
                // getotpold report
                int? k_getotpreport = 1;
                #region GetOtpReport()
                if (k_getotpreport == 1)
                {
                    try
                    {
                        otpold1 = await VFarmOTP.GetOTPFarm(UrlGetOTP, phone);
                        if (!string.IsNullOrEmpty(otpold1))
                        {
                            Console.WriteLine($"Suscces[{phone}] : otpold1 ({otpold1})");
                        }
                        else
                        {
                            Console.WriteLine($"Suscces[{phone}] : NO OTPOLD 1");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning[{phone}] : GET OTP OLD1 Fail ({ex.Message})");
                        return 0;
                    }
                }
                #endregion
                ///////////////////////////////////////////////////////////////////////////////////////////////
                // post data sent phone login
                #region LoginPhone()
                var loginRequest = new LoginRequest
                    {
                        CheckPhones = true,
                        Country = "VN",
                        FederationFlags = 0,
                        FlowToken = flowTokenEntraRedirect,
                        ForceOtcLogin = false,
                        IsCookieBannerShown = false,
                        IsExternalFederationDisallowed = false,
                        IsFidoSupported = true,
                        IsOtherIdpSupported = true,
                        IsRemoteConnectSupported = false,
                        IsRemoteNgcSupported = true,
                        IsSignup = false,
                        OriginalRequest = urlloginEntraRedirect,
                        Username = phone
                    };
                var jsonBody = JsonConvert.SerializeObject(loginRequest);
                var messageLoginPhone = new HttpRequestMessage(HttpMethod.Post, urlGetCredentialTypeEntraRedirect);
                messageLoginPhone.Content = new StringContent(jsonBody, MediaTypeHeaderValue.Parse("application/json"));
                messageLoginPhone.Headers.Add("Canary", ApiCanaryEntraRedirect);
                messageLoginPhone.Headers.Add("Hpgid", "1104");
                messageLoginPhone.Headers.Add("Hpgact", "1800");
                messageLoginPhone.Headers.Add("origin", "https://login.microsoftonline.com");
                messageLoginPhone.Headers.Add("priority", "u=1, i");
                messageLoginPhone.Headers.Add("referer", urlRedirect);
                messageLoginPhone.Headers.Add("client-request-id", clientrequestidEntraRedirect);
                string? contentLoginPhone = string.Empty;
                try
                {
                    var responseLoginPhone = await _client.SendAsync(messageLoginPhone);
                    contentLoginPhone = await responseLoginPhone.Content.ReadAsStringAsync();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] :Sent Phone 1 Fail {ex.Message}");
                    return 0;
                }
                JObject jsonObject = JObject.Parse(contentLoginPhone);
                string? flowTokenSentOTP = string.Empty;
                string flowToken1 = Regex.Match(contentLoginPhone, @"""FlowToken"":""([^""]+)""").Groups[1].Value;
                string apiCanary1 = Regex.Match(contentLoginPhone, @"""apiCanary"":""([^""]+)""").Groups[1].Value;
                if (string.IsNullOrEmpty(flowToken1))
                {
                    Console.WriteLine($"Warning[{phone}] : Sent OTP 1 Fail");
                    lock (lockObjectOTP)
                    {
                        File.AppendAllText($"input\\SentOTPFail.txt", $"{phone}" + Environment.NewLine);
                    }
                    return 0;
                }
                else
                {
                    Console.WriteLine($"Suscces[{phone}] : Sent OTP 1 Suscces");
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
                                OriginalRequest = urlloginEntraRedirect,
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
                #endregion
                ///////////////////////////////////////////////////////////////////////////////////////////////
                // get otp 1
                #region GETOTP1()
                string? otp1 = string.Empty;
                int count1 = 10;
                Console.WriteLine($"Suscces[{phone}] : GetOTP");
                int k_vfarmotprenew = 0;
                #region getotpvfamotprenew()
                if (k_vfarmotprenew == 1 )
                {
                    try
                    {
                        VFarmOTP.GetOTPVFarmRenew(UrlRenewOTP, phone);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning[{phone}] : Giửi Renew Fail ({ex.Message})");
                        return 0;
                    }
                }
                #endregion
                #region getotpvframeotp1()
                if (k_getotpfarmx == 1)
                {
                    while (count1 > 0)
                    {
                        try
                        {
                            otp1 = await VFarmOTP.GetOTPVFarmm(UrlGetOTP, phone);
                            if (!string.IsNullOrEmpty(otp1) && otp1 != otpold1)
                            {
                                //Console.WriteLine($"Suscces[{phone}] : {otp}");
                                string dirPath = $"output\\{DateTime.Now:dd_MM_yyyy}";
                                Directory.CreateDirectory(dirPath); // Tạo nếu chưa có
                                lock (lockObjectOTP)
                                {
                                    File.AppendAllText($"output\\{DateTime.Now.ToString("dd_MM_yyyy")}\\phoneUsed.txt", $"{email}|{password}|{phone}" + Environment.NewLine);
                                    File.AppendAllText($"output\\{DateTime.Now.ToString("dd_MM_yyyy")}\\otp.txt", $"{phone}|{otp1}" + Environment.NewLine);
                                }
                                break;
                            }

                            count1--;
                            await Task.Delay(3000);

                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning[{phone}] : GET OTP1 Fail ({ex.Message})");
                            return 0;
                        }

                    }
                }
                #endregion
                #region getotpreport()
                if (k_getotpreport==1)
                {
                    while (count1 > 0)
                    {
                        try
                        {
                            otp1 = await VFarmOTP.GetOTPFarm(UrlGetOTP, phone);
                            if (!string.IsNullOrEmpty(otp1) && otp1 != otpold1)
                            {
                                //Console.WriteLine($"Suscces[{phone}] : {otp}");
                                string dirPath = $"output\\{DateTime.Now:dd_MM_yyyy}";
                                Directory.CreateDirectory(dirPath); // Tạo nếu chưa có
                                lock (lockObjectOTP)
                                {
                                    File.AppendAllText($"output\\{DateTime.Now.ToString("dd_MM_yyyy")}\\phoneUsed.txt", $"{email}|{password}|{phone}|{group}" + Environment.NewLine);
                                    File.AppendAllText($"output\\{DateTime.Now.ToString("dd_MM_yyyy")}\\otp.txt", $"{email}|{password}|{phone}|gr{group}|{otp1}" + Environment.NewLine);
                                }
                                break;
                            }

                            count1--;
                            await Task.Delay(3000);

                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning[{phone}] : GET OTP1 Fail ({ex.Message})");
                            return 0;
                        }

                    }
                }
                #endregion
                #endregion
                ///////////////////////////////////////////////////////////////////////////////////////////////
                // Post OTP 1
                #region PostOTP1()
                string? contentSentOTP = string.Empty;
                string? flowTokenLoadpage = string.Empty;
                string? ctxloadpage = string.Empty;
                
                if (count1 >= 0 && !string.IsNullOrEmpty(otp1) && otp1 != otpold1)
                {
                    ///post otp
                    Console.WriteLine($"Suscces[{phone}] : {otp1}");
                    var UrlPostOTP = "https://login.microsoftonline.com/common/PIA/EndAuth";
                    var postOtp = new PostOtp
                    {
                        AdditionalAuthData = otp1,
                        FlowToken = flowTokenSentOTP,
                        Ctx = urlloginEntraRedirect,
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
                        Console.WriteLine($"Suscces[{phone}] : ______________________________Confirm OTP1 Suscces {otp1}");
                        flowTokenLoadpage = jsonSentOTP["FlowToken"]?.ToString();
                        ctxloadpage = jsonSentOTP["Ctx"]?.ToString();
                        goto loadpage;
                    }
                    else
                    {
                        Console.WriteLine($"Warning[{phone}] : ______________________________Confirm OTP1 False");
                        return 0;
                    }
                    
                }
                else
                {
                    Console.WriteLine($"Suscces[{phone}] : Không có OTP 1");
                    File.AppendAllText($"output\\{DateTime.Now.ToString("dd_MM_yyyy")}\\Nootp.txt", $"{phone}|{otp1}" + Environment.NewLine);
                    return 0;
                }
            #endregion


            loadpage:
                ///////////////////////////////////////////////////////////////////////////////////////////////
                // Loadpage
                #region LoadPage()
                Console.WriteLine($"Suscces[{phone}] : Bắt đầu load page {otp1}");
                string UrlLoadPage = "https://login.microsoftonline.com/common/login";
                string? contentloadpages0 = string.Empty;
                try
                {
                    var messageloadpage = new HttpRequestMessage(HttpMethod.Post, UrlLoadPage);
                    string firtphone = phone.Substring(0, 2);
                    string firtphone1 = string.Empty;
                    if (firtphone == "84")
                    {
                        firtphone1 = $"i13=0&login={phone}&loginfmt=%2B{phone.Substring(0, 2)}+{phone.Substring(2, 3)}+{phone.Substring(5, 3)}+{phone.Substring(8, 3)}&SentProofID={phone}&purpose=PublicIdentifierAuth&piotc={otp1}&ps=3&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary={canaryEntraRedirect}&ctx={ctxloadpage}&hpgrequestid={hpgrequestidloadpage}&flowToken={flowTokenLoadpage}&PPSX=&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&DfpArtifact=&i19=";
                    }
                    else
                    {
                        firtphone1 = $"i13=0&login={phone}&loginfmt=%2B{phone.Substring(0, 3)}+{phone.Substring(3, 2)}+{phone.Substring(5, 3)}+{phone.Substring(8, 4)}&type=24&LoginOptions=3&SentProofID={phone}&purpose=PublicIdentifierAuth&piotc={otp1}&ps=3&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary={canaryEntraRedirect}&ctx={ctxloadpage}&hpgrequestid={hpgrequestidloadpage}&flowToken={flowTokenLoadpage}&PPSX=&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&DfpArtifact=&i19=";
                    }
                    messageloadpage.Content = new StringContent(firtphone1, MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded"));
                    var responseloadpage = await _client.SendAsync(messageloadpage);
                    if (responseloadpage.Headers.TryGetValues("x-ms-request-id", out var values1))
                    {
                        hpgrequestidloadpage = values1.FirstOrDefault();
                    }
                    contentloadpages0 = await responseloadpage.Content.ReadAsStringAsync();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] :Load Page Fail ({ex.Message})");
                    return 0;
                }
                string PageCases0 = Regex.Match(contentloadpages0, @"<meta\s+name=""PageID""\s+content=""([^""]+)""").Groups[1].Value;
                if(PageCases0== "KmsiInterrupt")
                {
                    Console.WriteLine($"Warning[{phone}] :Load Page Suscces Go to Kmsi");
                    //goto Kmsi;
                    return 1;
                }
                if(PageCases0== "ConvergedChangePassword")
                {
                    Console.WriteLine($"Warning[{phone}] :Load Page Suscces Go to Change Password");
                    //goto ChangePass;
                    return 1;
                }
                else
                {
                    Console.WriteLine($"Warning[{phone}] :Không tìm thấy kịch bản");
                    lock (lockObjectOTP)
                    {
                        File.AppendAllText($"input\\Nofind.txt", $"{email}|{password}|{phone}" + Environment.NewLine);
                    }

                }
            #endregion
            ConvergedSignIn:

            Kmsi:
                ///////////////////////////////////////////////////////////////////////////////////////////////
                // KMSI
                #region KMSI1()
                string sCtxLoadPages0 = Regex.Match(contentloadpages0, @"""sCtx"":""([^""]+)""").Groups[1].Value;
                string flowTokenLoadPages0 = Regex.Match(contentloadpages0, @"""sFT"":""([^""]+)""").Groups[1].Value;
                string canaryLoadPages0 = Regex.Match(contentloadpages0, @"""canary"":""([^""]+)""").Groups[1].Value;
                string apicanaryLoadPages0 = Regex.Match(contentloadpages0, @"""apiCanary"":""([^""]+)""").Groups[1].Value;
                string UrlKmsi = "https://login.microsoftonline.com/kmsi";
                string? contentKmsi = string.Empty;
                var messageKmsi = new HttpRequestMessage(HttpMethod.Post, UrlKmsi);
                messageKmsi.Headers.Add("priority", "u=0, i");
                messageKmsi.Headers.Add("referer", "https://login.microsoftonline.com/common/login");
                messageKmsi.Headers.Add("Origin", "https://login.microsoftonline.com");
                messageKmsi.Content = new StringContent($"LoginOptions=1&type=28&ctx={sCtxLoadPages0}&hpgrequestid={hpgrequestidloadpage}&flowToken={flowTokenLoadPages0}&canary={apicanaryLoadPages0} ", MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded"));
                try
                {
                    Console.WriteLine($"Suscces[{phone}] : Go To Kmsi Suscces");
                    var responseKmsi = await _client.SendAsync(messageKmsi);
                    contentKmsi = await responseKmsi.Content.ReadAsStringAsync();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : Go to Kmsi Fail ({ex.Message})");
                    return 0;
                }
                #endregion
                #region KMSIINDEX()
                string? codeKmsi = Regex.Match(contentKmsi, @"<input[^>]*name\s*=\s*""code""[^>]*value\s*=\s*""([^""]+)""").Groups[1].Value;
                string? id_tokenKmsi = Regex.Match(contentKmsi, @"<input[^>]*name\s*=\s*""id_token""[^>]*value\s*=\s*""([^""]+)""").Groups[1].Value;
                string? stateKmsi = Regex.Match(contentKmsi, @"<input[^>]*name\s*=\s*""state""[^>]*value\s*=\s*""([^""]+)""").Groups[1].Value;
                string? session_stateKmsi = Regex.Match(contentKmsi, @"<input[^>]*name\s*=\s*""session_state""[^>]*value\s*=\s*""([^""]+)""").Groups[1].Value;
                string? correlation_idKmsi = Regex.Match(contentKmsi, @"<input[^>]*name\s*=\s*""correlation_id""[^>]*value\s*=\s*""([^""]+)""").Groups[1].Value;
                Console.WriteLine($"Suscces[{phone}] : Go To ReDirect KmsiInterrupt 1");
                if (string.IsNullOrEmpty(codeKmsi) || string.IsNullOrEmpty(id_tokenKmsi) || string.IsNullOrEmpty(stateKmsi) || string.IsNullOrEmpty(session_stateKmsi) || string.IsNullOrEmpty(correlation_idKmsi))
                {
                    Console.WriteLine($"Warning[{phone}] : No Found Data Kmsi");
                    return 0;
                }
                string? UrlKmsiIndexs0 = "https://entra.microsoft.com/signin/index";
                string? contentKmsiIndexs0 = string.Empty;
                var messageKmsiIndexs0 = new HttpRequestMessage(HttpMethod.Post, UrlKmsiIndexs0);
                messageKmsiIndexs0.Headers.Add("origin", "https://login.microsoftonline.com");
                messageKmsiIndexs0.Content = new StringContent($"code={codeKmsi}&id_token={id_tokenKmsi}&state={stateKmsi}&session_state={session_stateKmsi}&correlation_id={correlation_idKmsi}", MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded"));
                try
                {
                    var responseKmsiIndexs0 = await _client.SendAsync(messageKmsiIndexs0);
                    contentKmsiIndexs0 = await responseKmsiIndexs0.Content.ReadAsStringAsync();
                    if (!responseKmsiIndexs0.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"Warning[{phone}] : Go to Kmsi Index Fail ({responseKmsiIndexs0.StatusCode})");
                        return 0;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : Go to Kmsi Index Fail ({ex.Message})");
                    return 0;
                }
                var UrlReDirectKmsis0 = Regex.Match(contentKmsiIndexs0, @"MsPortalImpl\.redirectToUri\(""([^""]+)""\)").Groups[1].Value;
                UrlReDirectKmsis0 = UnescapeUnicode(UrlReDirectKmsis0);
                string? contentGotoReDirectKmsis0 = string.Empty;
                if (string.IsNullOrEmpty(UrlReDirectKmsis0))
                {
                    Console.WriteLine($"Warning[{phone}] : Go to ReDirectKmsi Fail");
                    return 0;
                }
                try
                {
                    var messageGotoReDirectKmsis0 = new HttpRequestMessage(HttpMethod.Get, UrlReDirectKmsis0);
                    var responseGotoReDirectKmsis0 = await _client.SendAsync(messageGotoReDirectKmsis0);
                    contentGotoReDirectKmsis0 = await responseGotoReDirectKmsis0.Content.ReadAsStringAsync();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : Go to ReDirectKmsi Fail 1 ({ex.Message})");
                    return 0;
                }

                string? UrlReDirectKmsis10 = Regex.Match(contentGotoReDirectKmsis0, @"https:\/\/login\.microsoftonline\.com[^\s""]+").Groups[0].Value;
                string? contentGotoReDirectKmsis10 = string.Empty;
                string? hpgrequestidSentPhone = string.Empty;
                if (string.IsNullOrEmpty(UrlReDirectKmsis10))
                {
                    Console.WriteLine($"Warning[{phone}] : No Found Url ReDirectKmsi1");
                    return 0;
                }
                try
                {
                    Console.WriteLine($"Suscces[{phone}] : Go To ReDirect KmsiInterrupt 2");
                    var messageGotoReDirectKmsis10 = new HttpRequestMessage(HttpMethod.Get, UrlReDirectKmsis10);
                    var responseGotoReDirectKmsis10 = await _client.SendAsync(messageGotoReDirectKmsis10);
                    contentGotoReDirectKmsis10 = await responseGotoReDirectKmsis10.Content.ReadAsStringAsync();
                    if (responseGotoReDirectKmsis10.Headers.TryGetValues("x-ms-request-id", out var values0))
                    {
                        hpgrequestidSentPhone = values0.FirstOrDefault();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : Go to ReDirectKmsi 2 Fail ({ex.Message})");
                    return 0;
                }
                string usernameGotoRedirectKmsi = Regex.Match(contentGotoReDirectKmsis10, @"""Username"":""([^""]+)""").Groups[1].Value;
                string canaryGotoRedirectKmsi = Regex.Match(contentGotoReDirectKmsis10, @"""canary"":""([^""]+)""").Groups[1].Value;
                string flowTokenGotoRedirectKmsi = Regex.Match(contentGotoReDirectKmsis10, @"""sFT"":""([^""]+)""").Groups[1].Value;
                string sCtxGotoRedirectKmsi = Regex.Match(contentGotoReDirectKmsis10, @"""sCtx"":""([^""]+)""").Groups[1].Value;
                string Urlpost0GotoRedirectKmsi = Regex.Match(contentGotoReDirectKmsis10, @"""urlPost"":""([^""]+)""").Groups[1].Value;
                string UrlpostGotoRedirectKmsi = "https://login.microsoftonline.com" + Urlpost0GotoRedirectKmsi;
                string apicanaryGotoRedirectKmsi = Regex.Match(contentGotoReDirectKmsis10, @"""apiCanary"":""([^""]+)""").Groups[1].Value;

                var messagesentpasss0 = new HttpRequestMessage(HttpMethod.Post, UrlpostGotoRedirectKmsi);
                messagesentpasss0.Headers.Add("origin", "https://login.microsoftonline.com");
                var BodySentPass = new SentPass
                {
                    i13 = 0,
                    login = usernameGotoRedirectKmsi,
                    loginfmt = usernameGotoRedirectKmsi,
                    type = 11,
                    LoginOptions = 3,
                    lrt = null,
                    lrtPartition = null,
                    hisRegion = null,
                    hisScaleUnit = null,
                    passwd = password,
                    ps = 2,
                    psRNGCDefaultType = null,
                    psRNGCEntropy = null,
                    psRNGCSLK = null,
                    canary = canaryGotoRedirectKmsi,
                    ctx = sCtxGotoRedirectKmsi,
                    hpgrequestid = hpgrequestidSentPhone,
                    flowToken = flowTokenGotoRedirectKmsi,
                    PPSX = null,
                    NewUser = 1,
                    FoundMSAs = null,
                    fspost = 0,
                    i21 = null,
                    CookieDisclosure = 0,
                    IsFidoSupported = 1,
                    isSignupPost = 0,
                    DfpArtifact = null,
                    i19 = null,
                };
              
                var formDataSentPass = ToFormDictionary(BodySentPass);
                messagesentpasss0.Content = new FormUrlEncodedContent(formDataSentPass);
                var responsesentpasss0 = await _client.SendAsync(messagesentpasss0);
                contentsentpasss0 = await responsesentpasss0.Content.ReadAsStringAsync();
                string PageCase1 = Regex.Match(contentsentpasss0, @"<meta\s+name=""PageID""\s+content=""([^""]+)""").Groups[1].Value;
                if (PageCase1 == "ConvergedTFA")
                {
                    UrlSentPhone = Regex.Match(contentsentpasss0, @"""urlBeginAuth""\s*:\s*""([^""]+)""").Groups[1].Value;
                    if (UrlSentPhone == "https://login.microsoftonline.com/common/SAS/BeginAuth")
                    {
                        sCtxSentPhone = Regex.Match(contentsentpasss0, @"""sCtx"":""([^""]+)""").Groups[1].Value;
                        flowTokenSentPhone = Regex.Match(contentsentpasss0, @"""sFT"":""([^""]+)""").Groups[1].Value;
                        //goto OneWaySMS;
                    }
                    else
                    {
                        Console.WriteLine($"Warning[{phone}] : No Found Url Sent Phone");
                        return 0;
                    }
                }
                else
                {
                    Console.WriteLine($"Warning[{phone}] : Không tìm thấy kịch bản 2");
                    lock (lockObjectOTP)
                    {
                        File.AppendAllText($"input\\Nofind.txt", $"{email}|{password}|{phone}" + Environment.NewLine);
                    }
                }
            #endregion


            ///////////////////////////////////////////////////////////////////////////////////////////////
            goto OneWaySMS;

            OneWaySMS:
                #region OneWaySMS2()
                UrlSentPhone = "https://login.microsoftonline.com/common/SAS/BeginAuth";

                SentPhone sentPhone = new SentPhone
                {
                    AuthMethodId = "OneWaySMS",
                    Method = "BeginAuth",
                    ctx = sCtxSentPhone,
                    flowToken = flowTokenSentPhone,
                };
                var jsonBodyPhone = JsonConvert.SerializeObject(sentPhone);
                var messageSentPhone = new HttpRequestMessage(HttpMethod.Post, UrlSentPhone);
                messageSentPhone.Headers.Add("Canary", apicanaryGotoRedirectKmsi);
                messageSentPhone.Headers.Add("Hpgid", "1114");
                messageSentPhone.Headers.Add("Hpgact", "2000");
                messageSentPhone.Headers.Add("origin", "https://login.microsoftonline.com");
                messageSentPhone.Headers.Add("priority", "u=1, i");
                messageSentPhone.Headers.Add("Hpgrequestid", hpgrequestidSentPhone);
                messageSentPhone.Headers.Add("client-request-id", clientrequestidEntraRedirect);
                messageSentPhone.Content = new StringContent(jsonBodyPhone, MediaTypeHeaderValue.Parse("application/json"));
                string? sessionIdSentPhone = string.Empty;
                string? ctxSentPhone = string.Empty;
                try
                {
                    var responseSentPhone = await _client.SendAsync(messageSentPhone);
                    var contentSentPhone = await responseSentPhone.Content.ReadAsStringAsync();
                    JObject jsonSentPhone = JObject.Parse(contentSentPhone);
                    bool isSuccess = jsonSentPhone["Success"]?.ToObject<bool>() == true;
                    if (isSuccess)
                    {
                        Console.WriteLine($"Suscces[{phone}] : Sent OTP2 Suscces");
                    }
                    else
                    {
                        lock (lockObjectOTP)
                        {
                            File.AppendAllText($"input\\SentOTPFail.txt", $"{email}|{password}|{phone}" + Environment.NewLine);
                        }
                        Console.WriteLine($"Suscces[{phone}] : Sent OTP2 Fail 0");
                        return 0;
                    }
                    flowTokenSentPhone = jsonSentPhone["FlowToken"]?.ToString();
                    sessionIdSentPhone = jsonSentPhone["SessionId"]?.ToString();
                    ctxSentPhone = jsonSentPhone["Ctx"]?.ToString();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : sent phone({ex.Message})");
                    return 0;
                }

                try
                {
                    VFarmOTP.GetOTPVFarmRenew(UrlRenewOTP,phone);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : Giửi Renew Fail ({ex.Message})");
                    return 0;
                }
                string? otpold2 = string.Empty;
                try
                {
                    otpold2 = await VFarmOTP.GetOTPVFarmm(UrlGetOTP, phone);
                    if (!string.IsNullOrEmpty(otpold2))
                    {
                        Console.WriteLine($"Suscces[{phone}] : otpold2 {otpold2}");
                    }
                    else
                    {
                        Console.WriteLine($"Suscces[{phone}] : NO OTPOLD2");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : GET OTP2 Fail ({ex.Message})");
                    return 0;
                }
                string? otp2 = string.Empty;
                int count2 = 10;
                Console.WriteLine($"Suscces[{phone}] : GetOTP");
                try
                {
                    VFarmOTP.GetOTPVFarmRenew(UrlRenewOTP,phone);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning[{phone}] : Giửi Renew Fail ({ex.Message})");
                    return 0;
                }
                while (count2 > 0)
                {
                    try
                    {
                        otp2 = await VFarmOTP.GetOTPVFarmm(UrlGetOTP, phone);
                        if (!string.IsNullOrEmpty(otp2) && otp2 != otpold2)
                        {
                            //Console.WriteLine($"Suscces[{phone}] : {otp}");
                            string dirPath = $"output\\{DateTime.Now:dd_MM_yyyy}";
                            Directory.CreateDirectory(dirPath); // Tạo nếu chưa có
                            lock (lockObjectOTP)
                            {
                                File.AppendAllText($"output\\{DateTime.Now.ToString("dd_MM_yyyy")}\\phoneUsed.txt", $"{phone}" + Environment.NewLine);
                                File.AppendAllText($"output\\{DateTime.Now.ToString("dd_MM_yyyy")}\\otp.txt", $"{phone}|{otp2}" + Environment.NewLine);
                            }
                            break;
                        }

                        count2--;
                        await Task.Delay(3000);

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning[{phone}] : get otp({ex.Message})");
                        return 0;
                    }

                }

                if (count2 >= 0 && !string.IsNullOrEmpty(otp2) && otp2 != otpold2)
                {
                    // post otp
                    Console.WriteLine($"Suscces[{phone}] : {otp2}");
                    var UrlSentOTP = "https://login.microsoftonline.com/common/SAS/EndAuth";
                    var sentOTP = new SentOTP
                    {
                        Method = "EndAuth",
                        SessionId = sessionIdSentPhone,
                        FlowToken = flowTokenSentPhone,
                        Ctx = ctxSentPhone,
                        AuthMethodId = "OneWaySMS",
                        AdditionalAuthData = otp2,
                        PollCount = 1,
                    };
                    var jsonBodySentOTP = JsonConvert.SerializeObject(sentOTP);
                    try
                    {
                        var messageSentOTP = new HttpRequestMessage(HttpMethod.Post, UrlSentOTP);
                        messageSentOTP.Content = new StringContent(jsonBodySentOTP, MediaTypeHeaderValue.Parse("application/json"));
                        messageSentOTP.Headers.Add("client-request-id", clientrequestidEntraRedirect);
                        //messageSentOTP.Headers.Add("canary", apiCanaryLoginPass);
                        messageSentOTP.Headers.Add("Hpgact", "2001");
                        messageSentOTP.Headers.Add("Hpgid", "1114");
                        var responseSentOTP = await _client.SendAsync(messageSentOTP);
                        var contentSentOTP1 = await responseSentOTP.Content.ReadAsStringAsync();
                        JObject jsonSentOTP = JObject.Parse(contentSentOTP1);
                        bool isSuccess1 = jsonSentOTP["Success"]?.ToObject<bool>() == true;
                        if (isSuccess1)
                        {
                            Console.WriteLine($"Suscces[{phone}] : ______________________________Confirm OTP2 Suscces {otp2}");
                        }
                        else
                        {
                            Console.WriteLine($"Suscces[{phone}] : ______________________________Confirm OTP2 Fail {otp2}");
                            return 0;
                        }
                        return 1;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning[{phone}] : comfirm OTP2 fail({ex.Message})");
                        return 0;
                    }

                }
                else
                {
                    Console.WriteLine($"Suscces[{phone}] : Không có OTP");
                    return 0;
                }



                #endregion

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