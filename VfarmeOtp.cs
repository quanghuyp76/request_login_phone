using Auther.OTP;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace Auther.OTP
{
    internal class VFarmOTP
    {

        public static async Task<string> GetOTPFarm(string url, string phone)
        {
            var responseMessage = await Program.httpClient.GetAsync($"{url}{phone}");
            var content = await responseMessage.Content.ReadAsStringAsync();
            //Console.WriteLine(content);
            string? otp = Regex.Match(content, "\"otp\":\"(.*?)\"").Groups[1].Value;
            string? message = Regex.Match(content, "\"message\":\"(.*?)\"").Groups[1].Value;
            if (string.IsNullOrEmpty(otp) && !string.IsNullOrEmpty(message))
            {
                return "";
            }
            return otp;
        }
    }
}
