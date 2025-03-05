﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Injector
{
    public static class NativeMethods
    {
        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName,
               string lpCommandLine, IntPtr lpProcessAttributes,
               IntPtr lpThreadAttributes,
               bool bInheritHandles, ProcessCreationFlags dwCreationFlags,
               IntPtr lpEnvironment, string lpCurrentDirectory,
               ref STARTUPINFO lpStartupInfo,
               out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);
    }

    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [Flags]
    public enum ProcessCreationFlags : uint
    {
        ZERO_FLAG = 0x00000000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_NO_WINDOW = 0x08000000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_SEPARATE_WOW_VDM = 0x00001000,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        DEBUG_PROCESS = 0x00000001,
        DETACHED_PROCESS = 0x00000008,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        INHERIT_PARENT_AFFINITY = 0x00010000
    }
    internal class Injector
    {
        private const int PROCESS_CREATE_THREAD = 0x0002;
        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_VM_OPERATION = 0x0008;
        private const int PROCESS_VM_WRITE = 0x0020;
        private const int PROCESS_VM_READ = 0x0010;

        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RESERVE = 0x00002000;
        private const uint MEM_RELEASE = 0x00008000;
        private const uint PAGE_READWRITE = 4;

        private const int OPEN_PROCESS = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                                         PROCESS_VM_WRITE | PROCESS_VM_READ;

        private const uint MEM_CREATE = MEM_COMMIT | MEM_RESERVE;
        private static readonly Logger logger = Logger.Instance();

        private readonly InjectorOptions opts;

        public Injector(InjectorOptions opts)
        {
            this.opts = opts;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize,
            out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess,
            IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);

        public void Inject()
        {
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            Process process = null;
            if (opts.ProcessId != null)
            {
                // find process by pid
                var pid = opts.ProcessId.Value;
                try
                {
                    logger.Info("Attempting to find running process by id...");
                    process = Process.GetProcessById((int) opts.ProcessId.Value);
                }
                catch (ArgumentException)
                {
                    Program.HandleError($"Could not find process id {pid}");
                }
            }
            else if (opts.StartProcess != null)
            {
                logger.Debug("Checking if process has already started");
                process = FindProcessByName(
                    opts.ProcessName == null
                        ? opts.StartProcess
                        : opts.ProcessName
                );
                if (process == null)
                {
                    // starts a process
                    if (!File.Exists(opts.StartProcess))
                    {
                        if (opts.StartProcess.Contains('!'))
                        {
                            logger.Debug("Could not find the process to start, but it could be a Microsoft store app");
                            opts.IsWindowsApp = true;
                        }
                        else
                        {
                            Program.HandleError($"{opts.StartProcess} not found. Ensure the path is correct");
                        }
                    }

                    var app = opts.StartProcess;
                    var app_args = "";
                    if (opts.IsWindowsApp)
                    {
                        logger.Debug("Process to start is a Microsoft store app");
                        app = "explorer.exe";
                        app_args = $"shell:AppsFolder\\{opts.StartProcess}";
                    }

                    logger.Info($"Starting {opts.StartProcess}");
                    //process = Process.Start(app, app_args);
                    STARTUPINFO si = new STARTUPINFO();
                    bool success = NativeMethods.CreateProcess(app, app_args,
                        IntPtr.Zero, IntPtr.Zero, false,
                        ProcessCreationFlags.CREATE_SUSPENDED,
                        IntPtr.Zero, null, ref si, out pi);

                    if (opts.ProcessName != null)
                    {
                        // if the exe to inject to is different than the one started
                        logger.Debug("Waiting for real process to start...");
                        process = WaitForProcess(opts.ProcessName, opts.Timeout);
                    }

                    if (opts.ProcessRestarts)
                    {
                        logger.Debug("Waiting for original process to exit");
                        process = WaitForProcessRestart(process, opts.Timeout);
                        opts.ProcessRestarts = false;
                    }
                    else
                    {
                        // set this to true, so we can attempt to wait for a restart even if the option is not set
                        opts.ProcessRestarts = true;
                    }
                }
                else
                {
                    logger.Info("Process already started.");
                }
            }
            else if (opts.ProcessName != null)
            {
                logger.Info("Attempting to find running process by name...");
                process = WaitForProcess(opts.ProcessName, opts.Timeout);
            }
            process = Process.GetProcessById((int)pi.dwProcessId);
            if (process == null)
            {
                Program.HandleError("No process to inject.");
            }
            
            var dlls = BuildDllInfos(opts.Dlls);
            var wait_dlls = BuildDllInfos(opts.WaitDlls);


            logger.Info($"Injecting {dlls.Count} DLL(s) into {process.ProcessName} ({process.Id})");
            InjectIntoProcess(process, dlls.ToArray(), opts.InjectLoopDelay);
            IntPtr ThreadHandle = pi.hThread;
            NativeMethods.ResumeThread(ThreadHandle);
        }

        private List<FileInfo> BuildDllInfos(IEnumerable<string> option_dlls)
        {
            var dllInfos = new List<FileInfo>();
            foreach (var dll in option_dlls)
            {
                var dllInfo = opts.GetDllInfo(dll);
                dllInfos.Add(dllInfo);
            }

            return dllInfos;
        }

        private void InjectIntoProcess(Process process, FileInfo[] dlls, uint delay = InjectorOptions.DEFAULT_INJECTION_LOOP_DELAY)
        {
            logger.Debug("Opening handle to process");
            var procHandle = OpenProcess(OPEN_PROCESS, false, process.Id);
            if (procHandle == IntPtr.Zero)
            {
                Program.HandleWin32Error($"Unable to open {process.ProcessName}. Make sure to start the tool with Administrator privileges");
            }

            logger.Debug("Retrieving the memory address to LoadLibraryA");
            var loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            if (loadLibraryAddr == IntPtr.Zero)
            {
                Program.HandleWin32Error("Unable not retrieve the address for LoadLibraryA");
            }

            var dllIndex = 1;
            foreach (var dll in dlls)
            {
                logger.Info($"Attempting to inject DLL, {dllIndex} of {dlls.Length}, {dll.Name}...");
                var size = (uint) (dll.FullName.Length + 1);
                logger.Debug("Allocating memory in the process to write the DLL path");
                var allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, size, MEM_CREATE, PAGE_READWRITE);
                if (allocMemAddress == IntPtr.Zero)
                {
                    Program.HandleWin32Error("Unable to allocate memory in the process. Make sure to start the tool with Administrator privileges");
                }

                logger.Debug("Writing the DLL path in the process memory");
                var result = WriteProcessMemory(
                    procHandle,
                    allocMemAddress,
                    Encoding.Default.GetBytes(dll.FullName),
                    size,
                    out var bytesWritten
                );
                if (!result)
                {
                    Program.HandleWin32Error("Failed to write the DLL path into the memory of the process");
                }

                logger.Debug("Creating remote thread. This is where the magic happens!");
                var threadHandle = CreateRemoteThread(
                    procHandle,
                    IntPtr.Zero,
                    0,
                    loadLibraryAddr,
                    allocMemAddress,
                    0,
                    IntPtr.Zero
                );
                if (procHandle == IntPtr.Zero)
                {
                    Program.HandleWin32Error("Unable to create a remote thread in the process. Failed to inject the dll");
                }

                logger.Debug("Waiting for DLL to load...");
                while (!IsDllLoaded(process, dll))
                {
                    Thread.Sleep(100);
                }


                logger.Debug("Closing remote thread");
                CloseHandle(threadHandle);
                logger.Debug("Freeing memory");
                VirtualFreeEx(procHandle, allocMemAddress, UIntPtr.Zero, MEM_RELEASE);

                if (dllIndex < dlls.Length)
                {
                    if (delay == 0)
                    {
                        logger.Debug("No delay between next DLL injection");
                    }
                    else
                    {
                        logger.Debug($"Delaying next DLL injection by {delay} ms");
                        Thread.Sleep((int) delay);
                    }
                }

                dllIndex++;

                logger.Info("Injected!");
            }

            logger.Debug("Closing handle to process");
            CloseHandle(procHandle);
        }

        private Process FindProcessByName(string name)
        {
            name = Path.GetFileNameWithoutExtension(name);
            logger.Debug($"Finding processes matching '{name}'");
            var processes = Process.GetProcessesByName(name);
            if (processes.Length == 1)
            {
                logger.Debug("Found one match!");
                return processes[0];
            }

            if (processes.Length > 1)
            {
                Program.HandleError($"Too many processes matching {name}");
            }

            logger.Debug("No process found matching the supplied name");
            return null;
        }

        private Process WaitForProcess(string name, uint timeout = InjectorOptions.DEFAULT_TIMEOUT)
        {
            Process process = null;
            var timeout_counter = (int) timeout;
            var polling_rate = 500;

            logger.Debug($"Waiting for process '{name}'");
            while (timeout_counter > 0)
            {
                process = FindProcessByName(name);
                if (process != null)
                {
                    logger.Debug("Process found!");
                    break;
                }

                timeout_counter -= polling_rate;
                Thread.Sleep(polling_rate);
            }

            if (process == null)
            {
                Program.HandleError($"Timed out waiting for process '{name}'");
            }

            return process;
        }

        private Process WaitForProcessRestart(Process process, uint timeout = InjectorOptions.DEFAULT_TIMEOUT)
        {
            if (process.WaitForExit((int) timeout))
            {
                logger.Debug("Waiting for process to restart with new pid");
                var processPath = opts.ProcessName == null
                    ? opts.StartProcess
                    : opts.ProcessName;
                process = WaitForProcess(processPath, opts.Timeout);
            }
            else
            {
                logger.Debug("Process may have already exited");
            }

            return process;
        }

        private bool IsDllLoaded(Process process, FileInfo dll)
        {
            process.Refresh();
            foreach (ProcessModule processModule in process.Modules)
            {
                if (processModule.FileName.Equals(dll.FullName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private void WaitForDlls(Process process, List<FileInfo> waitDlls, uint timeout = InjectorOptions.DEFAULT_INJECTION_DELAY)
        {
            var loadedModules = new Dictionary<string, List<string>>();

            var timeout_counter = (int) timeout;
            var polling_rate = 100;

            while (timeout_counter > 0)
            {
                var modulesChanged = false;
                process.Refresh();
                foreach (ProcessModule processModule in process.Modules)
                {
                    var moduleLoaded = false;
                    if (!loadedModules.ContainsKey(processModule.ModuleName))
                    {
                        logger.Debug($"Loaded {processModule.ModuleName} - {processModule.FileName}");
                        loadedModules[processModule.ModuleName] = new List<string>();
                        moduleLoaded = true;
                    }
                    else if (!loadedModules[processModule.ModuleName].Contains(processModule.FileName.ToLower()))
                    {
                        logger.Debug($"Changed {processModule.ModuleName} - {processModule.FileName}");
                        moduleLoaded = true;
                    }

                    if (moduleLoaded)
                    {
                        loadedModules[processModule.ModuleName].Add(processModule.FileName.ToLower());
                        foreach (var waitDll in waitDlls)
                        {
                            if (processModule.FileName.Equals(waitDll.FullName, StringComparison.OrdinalIgnoreCase))
                            {
                                logger.Info($"Wait DLL loaded: {waitDll.FullName}");
                                waitDlls.Remove(waitDll);
                                break;
                            }
                        }

                        modulesChanged = true;
                    }
                }

                if (modulesChanged)
                {
                    logger.Debug("timeout reset since modules changed");
                    timeout_counter = (int) timeout;
                }

                timeout_counter -= polling_rate;
                Thread.Sleep(polling_rate);
            }

            if (waitDlls.Count > 0)
            {
                logger.Warn("Not all wait DLLs found. Continuing with injection. See log for details");
                foreach (var waitDll in waitDlls)
                {
                    logger.Debug($"wait DLL not found: {waitDll.FullName}");
                }
            }
            else
            {
                logger.Info("Process modules possibly fully loaded");
            }
        }
    }
}