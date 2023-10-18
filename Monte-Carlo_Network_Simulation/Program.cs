using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using OxyPlot;
using OxyPlot.Series;
using OxyPlot.WindowsForms;
using OxyPlot.Wpf;

class NetworkSecuritySimulation
{
    static int numSimulations = 10000; // Количество симуляций
    static int numDevices = 10; // Количество устройств
    static int passwordComplexity = 2; // Сложность паролей
    static double successProbability = 0.1; // Вероятность успешной атаки

    static int totalSimulations = 0; // Общее количество симуляций
    static int successSimulations = 0; // Количество успешных симуляций
    static int failureSimulations = 0; // Количество неуспешных симуляций
    static double minSuccessRate = 1; // Минимальная вероятность успеха
    static double maxSuccessRate = 0; // Максимальная вероятность успеха
    static int totalDevicesHacked = 0; // Общее количество взломанных устройств
    static int totalDevicesNotHacked = numDevices * numSimulations;
    static Dictionary<string, int> passwordOccurrences = new Dictionary<string, int>(); // Словарь для отслеживания встречаемости паролей

    static void Main(string[] args)
    {
        List<double> successRates = new List<double>(); // Список вероятностей успеха

        for (int i = 0; i < numSimulations; i++)
        {
            double successRate = SimulateNetworkSecurity(); // Выполнение симуляции безопасности сети
            successRates.Add(successRate);
            Console.WriteLine($"Симуляция {i + 1}: Вероятность успеха: {successRate:P}");
        }
        Console.WriteLine($"Общее количество симуляций: {totalSimulations/2}");
        Console.WriteLine($"Успешных симуляций: {successSimulations}");
        Console.WriteLine($"Неуспешных симуляций: {failureSimulations}");
        Console.WriteLine($"Минимальная вероятность успеха: {minSuccessRate:P}");
        Console.WriteLine($"Максимальная вероятность успеха: {maxSuccessRate:P}");
        Console.WriteLine($"Общее количество взломанных устройств: {totalDevicesHacked}");
        Console.WriteLine($"Total Devices Not Hacked: {totalDevicesNotHacked}");
        var mostCommonPassword = passwordOccurrences.OrderByDescending(x => x.Value).First().Key; // Наиболее распространенный пароль
        Console.WriteLine($"Самый распространенный пароль: {mostCommonPassword}");

        ShowSuccessRateGraph(successRates); // Отображение графика вероятности успеха

        Console.ReadKey();
    }

    static void ShowSuccessRateGraph(List<double> successRates)
    {
        var plotModel = new PlotModel { Title = "Вероятность успеха в симуляциях" };
        var lineSeries = new LineSeries
        {
            Title = "Вероятность успеха",
            LineStyle = LineStyle.Solid,
            MarkerType = MarkerType.Circle,
            MarkerSize = 4,
            MarkerStroke = OxyColors.Blue,
            MarkerFill = OxyColors.Blue
        };
        for (int i = 0; i < successRates.Count; i++)
        {
            lineSeries.Points.Add(new DataPoint(i + 1, successRates[i]));
        }
        plotModel.Series.Add(lineSeries);

        var plotView = new OxyPlot.WindowsForms.PlotView
        {
            Model = plotModel,
            Dock = System.Windows.Forms.DockStyle.Fill
        };

        var form = new System.Windows.Forms.Form
        {
            Size = new System.Drawing.Size(800, 600)
        };
        form.Controls.Add(plotView);
        form.ShowDialog();
    }

    static double SimulateNetworkSecurity()
    {
        int successfulAttacks = 0;
        Parallel.For(0, numDevices, _ =>
        {
            var network = InitializeNetwork(); // Инициализация сети
            string attackerPassword = GenerateUniquePassword(network.Passwords); // Генерация уникального пароля для атаки

            if (AttemptAttack(network, attackerPassword)) // Попытка атаки
            {
                Interlocked.Increment(ref successfulAttacks);
                // Увеличение количества успешно атакованных устройств
                Interlocked.Increment(ref totalDevicesHacked);
                // Уменьшение количества не взломанных устройств
                Interlocked.Decrement(ref totalDevicesNotHacked);

            }
            // Сбор статистики о паролях
            lock (passwordOccurrences)
            {
                if (passwordOccurrences.ContainsKey(attackerPassword))
                {
                    passwordOccurrences[attackerPassword]++;
                }
                else
                {
                    passwordOccurrences[attackerPassword] = 1;
                }
            }
        });

        // Сбор статистики о симуляциях
        Interlocked.Increment(ref totalSimulations);
        if (successfulAttacks > 0)
        {
            Interlocked.Increment(ref successSimulations);
        }
        else
        {
            Interlocked.Increment(ref failureSimulations);
        }
        double successRate = (double)successfulAttacks / numDevices;
        Interlocked.Increment(ref totalSimulations);

        if (successRate < minSuccessRate)
        {
            minSuccessRate = successRate;
        }
        if (successRate > maxSuccessRate)
        {
            maxSuccessRate = successRate;
        }

        return (double)successfulAttacks / numDevices;
    }

    static Network InitializeNetwork()
    {
        var network = new Network();

        for (int i = 0; i < numDevices; i++)
        {
            string password = GenerateUniquePassword(network.Passwords);
            bool isVulnerable = RandomBoolean();
            network.AddDevice(password, isVulnerable);
        }

        return network;
    }

    static string GenerateUniquePassword(Dictionary<string, bool> existingPasswords)
    {
        string password;

        do
        {
            password = GeneratePassword(passwordComplexity);
        } while (existingPasswords.ContainsKey(password));

        return password;
    }

    static string GeneratePassword(int length)
    {
        const string characters = "01";
        char[] password = new char[length];
        Random random = new Random();

        for (int i = 0; i < length; i++)
        {
            password[i] = characters[random.Next(characters.Length)];
        }

        return new string(password);
    }

    static bool AttemptAttack(Network network, string attackerPassword)
    {
        if (network.ContainsDevice(attackerPassword) && network.IsDeviceVulnerable(attackerPassword))
        {
            return RandomDouble() < successProbability;
        }
        return false;
    }

    static bool RandomBoolean()
    {
        return new Random().Next(2) == 0;
    }

    static double RandomDouble()
    {
        return new Random().NextDouble();
    }
}

class Network
{
    private readonly Dictionary<string, bool> devices = new Dictionary<string, bool>();

    public Dictionary<string, bool> Passwords { get; } = new Dictionary<string, bool>();

    public void AddDevice(string password, bool isVulnerable)
    {
        devices[password] = isVulnerable;
    }

    public bool ContainsDevice(string password)
    {
        return devices.ContainsKey(password);
    }

    public bool IsDeviceVulnerable(string password)
    {
        return devices[password];
    }
}
