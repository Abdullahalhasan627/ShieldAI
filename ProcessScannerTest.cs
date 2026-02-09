using System;
using System.Threading.Tasks;
using ShieldAI.Core.Scanning;
using ShieldAI.Core.Models;

namespace ShieldAI.TestConsole
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Starting ProcessScanner Test...");
            try
            {
                var scanner = new ProcessScanner();
                var processes = await scanner.ScanAllProcessesAsync();
                
                Console.WriteLine($"Found {processes.Count} processes.");
                
                foreach (var p in processes)
                {
                    Console.WriteLine($"[{p.ProcessId}] {p.ProcessName} - {p.ExecutablePath ?? "No Path"}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fatal Error: {ex}");
            }
            Console.WriteLine("Test Completed.");
        }
    }
}
