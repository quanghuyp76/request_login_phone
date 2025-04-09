using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Threading;

namespace Auther.OTP
{
    internal class Program
    {
        private static ConcurrentBag<string> listData;

        private static string[] listuseragain = [];

        private static string[] listProxy= [];

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
                Console.Write("Số vòng lặp không hợp lệ: ");
            }

            while (totalLoops > 0)
            {
                listuseragain =  await File.ReadAllLinesAsync("input\\UserAgain.txt");

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
                    Console.WriteLine("Done");
                    totalLoops = totalLoops - 1;
                    Console.WriteLine($"Sleep {sleep}");
                    await Task.Delay(sleep);
                }
                if (totalLoops == 0)
                { Console.WriteLine($"Đã hoàn thành"); }
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
                    Console.ReadKey();
                }

                LoginAuther loginAuther = new LoginAuther(useragain) { UrlGetOTP = UrlGetOTp, webProxy = webProxy };

                var Logins1 = await loginAuther.LoginAsysc(phone, useragain);
            }
        }
        private static object lockObjectLoginFail = new object();
        public static HttpClient httpClient = new HttpClient();
        public static HttpClient httpClientScrape = new HttpClient();
    }
}