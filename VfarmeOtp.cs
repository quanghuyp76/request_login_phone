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
    class PhoneFilter
    {
        public static void FilterPhones(string file1Path, string file2Path, int maxAllowed)
        {
            // Đọc danh sách số trong file1
            List<string> phonesFile1 = File.ReadAllLines(file1Path)
                                           .Select(p => p.Trim())
                                           .Where(p => !string.IsNullOrEmpty(p))
                                           .ToList();

            // Đọc danh sách số trong file2
            List<string> phonesFile2 = File.ReadAllLines(file2Path)
                                           .Select(p => p.Trim())
                                           .Where(p => !string.IsNullOrEmpty(p))
                                           .ToList();

            // Đếm số lần xuất hiện trong file2
            var phoneCounts = phonesFile2.GroupBy(p => p)
                                         .ToDictionary(g => g.Key, g => g.Count());

            // Lọc lại danh sách file1: chỉ giữ số xuất hiện < maxAllowed lần
            var filteredPhones = phonesFile1
                                 .Where(p => !phoneCounts.ContainsKey(p) || phoneCounts[p] < maxAllowed)
                                 .ToList();

            // Ghi lại file1.txt sau khi lọc
            File.WriteAllLines(file1Path, filteredPhones);
            Console.WriteLine();
            Console.WriteLine($"Đã lọc xong OTP. Còn lại {filteredPhones.Count} phone.");
        }
    }
}
