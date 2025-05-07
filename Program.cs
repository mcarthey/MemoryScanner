// Enhanced memory search and structure identification
using Spectre.Console;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_READ = 0x0010;

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    static void Main(string[] args)
    {
        var search = AnsiConsole.Ask<string>("Enter part of the process name to search for:");

        var matchingProcesses = Process.GetProcesses()
            .Where(p => !string.IsNullOrEmpty(p.ProcessName) &&
                        p.ProcessName.Contains(search, StringComparison.OrdinalIgnoreCase))
            .OrderBy(p => p.ProcessName)
            .ToList();

        if (!matchingProcesses.Any())
        {
            AnsiConsole.MarkupLine("[red]No matching processes found.[/]");
            return;
        }

        var selectedName = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select a [green]process[/] to attach to:")
                .PageSize(10)
                .AddChoices(matchingProcesses.Select(p => $"{p.ProcessName} (PID: {p.Id})")));

        var pid = int.Parse(selectedName.Split("PID: ")[1].TrimEnd(')'));
        var process = Process.GetProcessById(pid);
        AnsiConsole.MarkupLine($"[blue]Attached to:[/] {process.ProcessName} (PID: {pid})");

        IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (processHandle == IntPtr.Zero)
        {
            AnsiConsole.MarkupLine("[red]Failed to open process.[/]");
            return;
        }

        var candidateRegions = new Dictionary<IntPtr, (byte[] regionData, int score, List<int> offsets)>();

        while (true)
        {
            var input = AnsiConsole.Ask<string>("Enter the next chat string to search for [grey](leave blank to exit)[/]:").Trim();
            if (string.IsNullOrEmpty(input)) break;

            IntPtr address = IntPtr.Zero;
            uint mbiSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

            while (VirtualQueryEx(processHandle, address, out MEMORY_BASIC_INFORMATION mbi, mbiSize) != 0)
            {
                if (mbi.State == 0x1000 && (mbi.Protect & 0x04) != 0)
                {
                    byte[] buffer = new byte[(long)mbi.RegionSize];
                    if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer, buffer.Length, out int bytesRead))
                    {
                        string bufferText = Encoding.ASCII.GetString(buffer);
                        int start = 0;

                        while (true)
                        {
                            int index = bufferText.IndexOf(input, start, StringComparison.OrdinalIgnoreCase);
                            if (index == -1) break;

                            if (!candidateRegions.ContainsKey(mbi.BaseAddress))
                                candidateRegions[mbi.BaseAddress] = (buffer, 0, new List<int>());

                            var entry = candidateRegions[mbi.BaseAddress];
                            entry.score++;
                            entry.offsets.Add(index);
                            candidateRegions[mbi.BaseAddress] = entry;

                            start = index + input.Length;
                        }
                    }
                }

                address = new IntPtr(mbi.BaseAddress.ToInt64() + (long)mbi.RegionSize);
            }

            if (candidateRegions.Any())
            {
                var sorted = candidateRegions.OrderByDescending(kvp => kvp.Value.score).ToList();
                foreach (var (baseAddr, (regionData, score, offsets)) in sorted)
                {
                    foreach (var offset in offsets)
                    {
                        string preview = Encoding.ASCII.GetString(ExtractContext(regionData, offset, 128)).Replace("\0", ".");
                        var patterns = DetectPatterns(preview).ToList();
                        AnsiConsole.MarkupLine($"[green]Match at:[/] [blue]0x{(baseAddr + offset).ToInt64():X}[/] (score: [yellow]{score}[/])");
                        AnsiConsole.WriteLine($"Context: {preview}");
                        if (patterns.Any())
                            AnsiConsole.MarkupLine($"[grey]Patterns: {string.Join(", ", patterns)}[/]");
                        Console.WriteLine();
                    }
                }
            }
            else
            {
                AnsiConsole.MarkupLine("[yellow]No matches found for this round. Scores preserved.[/]");
            }
        }

        CloseHandle(processHandle);
        AnsiConsole.MarkupLine("[blue]Search session complete.[/]");
    }

    static byte[] ExtractContext(byte[] data, int index, int windowSize)
    {
        int start = Math.Max(index - windowSize / 2, 0);
        int length = Math.Min(windowSize, data.Length - start);
        byte[] slice = new byte[length];
        Array.Copy(data, start, slice, 0, length);
        return slice;
    }

    static IEnumerable<string> DetectPatterns(string text)
    {
        var patterns = new List<string>();
        if (text.Contains("{\"")) patterns.Add("JSON block");
        if (text.Count(c => c == '\\') > 5) patterns.Add("Backslash-heavy");
        if (text.Split(new[] { "\":" }, StringSplitOptions.None).Length - 1 > 3) patterns.Add("Key-value like");
        if (text.Contains('[') && text.Contains(']')) patterns.Add("Bracketed content");
        return patterns;
    }
}
