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
    static int numSimulations = 10000;
    static int numDevices = 10;
    static int passwordComplexity = 1;
    static double successProbability = 1;

    static int totalSimulations = 0;
    static int successSimulations = 0;
    static int failureSimulations = 0;
    static double minSuccessRate = 1;
    static double maxSuccessRate = 0;
    static int totalDevicesHacked = 0;

    static Dictionary<string, int> passwordOccurrences = new Dictionary<string, int>();


    static void Main(string[] args)
    {
        List<double> successRates = new List<double>();

        for (int i = 0; i < numSimulations; i++)
        {
            double successRate = SimulateNetworkSecurity();
            successRates.Add(successRate);
            Console.WriteLine($"Simulation {i + 1}: Success Rate: {successRate:P}");
        }
        Console.WriteLine($"Total Simulations: {totalSimulations}");
        Console.WriteLine($"Successful Simulations: {successSimulations}");
        Console.WriteLine($"Failed Simulations: {failureSimulations}");
        Console.WriteLine($"Min Success Rate: {minSuccessRate:P}");
        Console.WriteLine($"Max Success Rate: {maxSuccessRate:P}");
        Console.WriteLine($"Total Devices Hacked: {totalDevicesHacked}");

        var mostCommonPassword = passwordOccurrences.OrderByDescending(x => x.Value).First().Key;
        Console.WriteLine($"Most Common Password: {mostCommonPassword}");


        ShowSuccessRateGraph(successRates);

        Console.ReadKey();
    }

    static void ShowSuccessRateGraph(List<double> successRates)
    {
        var plotModel = new PlotModel { Title = "Success Rate over Simulations" };
        var lineSeries = new LineSeries
        {
            Title = "Success Rate",
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
            var network = InitializeNetwork();
            string attackerPassword = GenerateUniquePassword(network.Passwords);

            if (AttemptAttack(network, attackerPassword))
            {
                Interlocked.Increment(ref successfulAttacks);
                // Увеличение количества успешно атакованных устройств
                Interlocked.Increment(ref totalDevicesHacked);
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
        const string characters = "0123456789";
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
