using System.Collections.Concurrent;
using System.Net;
using System.Text;

namespace Auther.OTP
{
    internal class Program
    {
        private static ConcurrentBag<string> listData;

        private static string[] listuseragain = [];

        private static string[] listProxy = [];

        private static string UrlGetOTp { get; set; }

        private static string TypeProxy { get; set; }

        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            Console.Write("Nhập số vòng lặp: ");

            int totalLoops;

            while (!int.TryParse(Console.ReadLine(), out totalLoops) || totalLoops <= 0)
            {
                Console.Write("Số vòng lặp không hợp lệ: ");
            }

            Console.Write("Thời gian giữa các vòng lặp: ");

            int sleep;

            while (!int.TryParse(Console.ReadLine(), out sleep) || sleep <= 0)
            {
                Console.Write("Thời gian giữa các vòng lặp không hợp lệ ");
            }
            int FilterOTP;
            Console.Write("Nhập số lượng OTP cần lọc: ");
            while (!int.TryParse(Console.ReadLine(), out FilterOTP) || FilterOTP <= 0)
            {
                Console.Write("Số lượng OTP cần lọc không hợp lệ: ");
            }
            // chờ time
            bool enableStartupDelay = false;
            string sleepFlagPath = "input\\EnableSleep.txt";
            if (File.Exists(sleepFlagPath))
            {
                string flagContent = File.ReadAllText(sleepFlagPath).Trim().ToLower();
                enableStartupDelay = flagContent == "true";
            }
            if (enableStartupDelay)
            {
                Console.Write("⏱ Nhập số giờ cần đợi: ");
                int waitHours;
                while (!int.TryParse(Console.ReadLine(), out waitHours) || waitHours < 0)
                {
                    Console.Write("Không hợp lệ. Nhập lại số giờ: ");
                }

                Console.Write("⏱ Nhập số phút cần đợi: ");
                int waitMinutes;
                while (!int.TryParse(Console.ReadLine(), out waitMinutes) || waitMinutes < 0)
                {
                    Console.Write("Không hợp lệ. Nhập lại số phút: ");
                }

                // Gọi hàm chờ
                await WaitByDuration(waitHours, waitMinutes);
            }
            else
            {
                Console.Write("Bỏ qua sleep");
            }





            File.WriteAllText("input\\SentOTPFail.txt", string.Empty);

            while (totalLoops > 0)
            {
                if (FilterOTP > 0)
                {
                    string file1 = "input\\data.txt";
                    string file2 = "input\\SentOTPFail.txt";
                    PhoneFilter.FilterPhones(file1, file2, FilterOTP);
                }
                string content = File.ReadAllText("input\\data.txt");

                // Kiểm tra nếu file không có dữ liệu
                if (string.IsNullOrEmpty(content))
                {
                    Console.WriteLine("File không có dữ liệu.");
                }


                listuseragain = await File.ReadAllLinesAsync("input\\UserAgain.txt");

                UrlGetOTp = await File.ReadAllTextAsync("input\\UrlGetOtp.txt");

                listData = new ConcurrentBag<string>(await File.ReadAllLinesAsync("input\\data.txt"));

                int Thread = int.Parse(await File.ReadAllTextAsync("input\\Thread.txt"));

                listProxy = await File.ReadAllLinesAsync("input\\listProxy.txt");

                if (listProxy.Length == 0)
                {
                    Console.WriteLine("⚠ Lỗi: File listProxy.txt không có dữ liệu!");
                    return;
                }
                try
                {
                    await RunMain(Thread);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
                finally
                {
                    Console.WriteLine($"Hoàn thành vòng lặp {totalLoops}");
                    totalLoops = totalLoops - 1;
                    await WaitSeconds(sleep);
                }
                if (totalLoops == 0)
                {
                    Console.WriteLine();
                    Console.WriteLine($"Đã hoàn thành chương trình"); 
                }
            }
            Console.ReadKey();

        }


        static async Task RunMain(int thread)
        {
            var task = new List<Task>();
            for (int i = 0; i < thread; i++)
            {
                int k = i;
                task.Add(Task.Run(async () =>
                {
                    await Start(k);
                }));
            }
            await Task.WhenAll(task);
        }

        private static Random random = new Random();

        static async Task Start(int thread)
        {
            while (listData.TryTake(out string? data))
            {
                string phone = data.Trim();
                string proxy = listProxy[random.Next(0, listProxy.Length)];
                string useragain = listuseragain[random.Next(0, listuseragain.Length)];
                WebProxy? webProxy = null;
                if (proxy.Split(':').Length == 2)
                {
                    webProxy = new WebProxy($"http://{proxy}");
                }
                else if (proxy.Split(':').Length == 4)
                {
                    webProxy = new WebProxy($"http://{proxy.Split(':')[0]}:{proxy.Split(':')[1]}");
                    webProxy.Credentials = new NetworkCredential(proxy.Split(':')[2], proxy.Split(':')[3]);
                }
                else
                {
                    Console.WriteLine("Proxy không hợp lệ");
                }

                LoginAuther loginAuther = new LoginAuther(useragain) { UrlGetOTP = UrlGetOTp, webProxy = webProxy };

                var Logins1 = await loginAuther.LoginAsysc(phone, useragain);
            }
        }
        private static object lockObjectLoginFail = new object();
        public static HttpClient httpClient = new HttpClient();
        public static HttpClient httpClientScrape = new HttpClient();


        static async Task WaitByDuration(int hours, int minutes)
        {
            int totalSeconds = (hours * 3600) + (minutes * 60); // Tổng số giây

            if (totalSeconds <= 0)
            {
                Console.WriteLine("⛔ Thời gian chờ phải lớn hơn 0 giây.");
                return;
            }

            // In thông báo bắt đầu đếm ngược
            Console.WriteLine($"⏳ Bắt đầu đếm ngược {totalSeconds} giây để chạy tool...");

            for (int i = totalSeconds; i > 0; i--)
            {
                int remainingMinutes = i / 60;
                int remainingSeconds = i % 60;

                // Di chuyển con trỏ về đầu dòng (dòng hiện tại)
                Console.SetCursorPosition(0, Console.CursorTop);

                // Xóa dòng trước đó và in lại thông báo mới
                Console.Write(new string(' ', Console.WindowWidth)); // Xóa dòng cũ
                Console.SetCursorPosition(0, Console.CursorTop); // Di chuyển lại về đầu dòng
                Console.Write($"====> Còn {remainingMinutes} phút {remainingSeconds} giây nữa sẽ chạy<====");

                // Delay 1 giây
                await Task.Delay(1000);
            }
        }

        private static async Task WaitSeconds(int seconds)
        {
            if (seconds <= 0) return;
            for (int i = seconds; i > 0; i--)
            {
                Console.SetCursorPosition(0, Console.CursorTop);
                Console.Write(new string(' ', Console.WindowWidth));
                Console.SetCursorPosition(0, Console.CursorTop);
                Console.Write($"===>>>> Chờ {i} giây để bắt đầu vòng lặp mới");
                await Task.Delay(1000);
            }
        }

    }
}