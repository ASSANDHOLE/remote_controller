using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using TrayWrapper.Properties;

namespace TrayWrapper
{
    public class TrayApplicationContext : ApplicationContext
    {
        private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private string appArgs = "";

        private string appName = "TrayWrapper"; // Default name of the app if not specified in config.json
        private string appPath;
        private Process appProcess;
        private string appWorkingDir = "";
        private MenuItem autoStartMenuItem;
        private string errorLogPath;
        private string iconPath;

        private IntPtr jobHandle;
        private long maxLogSize;

        private NotifyIcon notifyIcon;

        private string outLogPath;

        public TrayApplicationContext() {
            try {
                CreateJobObject();
                LoadConfig();
                InitializeContext();
                StartApp();
            }
            catch (Exception ex) {
                MessageBox.Show(ex.ToString(), "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Exit(null, null);
            }
        }

        private void CreateJobObject() {
            jobHandle = CreateJobObject(IntPtr.Zero, null);
            var info = new JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            };
            var extendedInfo = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                BasicLimitInformation = info
            };

            var length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            var extendedInfoPtr = Marshal.AllocHGlobal(length);
            Marshal.StructureToPtr(extendedInfo, extendedInfoPtr, false);

            if (!SetInformationJobObject(jobHandle, JobObjectInfoType.ExtendedLimitInformation, extendedInfoPtr,
                    (uint)length)) throw new InvalidOperationException("Unable to set information for Job Object.");

            Marshal.FreeHGlobal(extendedInfoPtr);
        }

        private void LoadConfig() {
            var exeLocation = Assembly.GetExecutingAssembly().Location;
            var exeDirectory = Path.GetDirectoryName(exeLocation);
            var configPath = Path.Combine(exeDirectory, "config.json");

            var config = JObject.Parse(File.ReadAllText(configPath));

            appPath = (string)config["appPath"];
            if (config["appArgs"] != null) appArgs = (string)config["appArgs"];
            if (config["appWorkingDir"] != null) appWorkingDir = (string)config["appWorkingDir"];
            outLogPath = (string)config["outLogPath"];
            errorLogPath = (string)config["errorLogPath"];
            maxLogSize = (long)config["maxLogSize"];
            if (config["appName"] != null) appName = (string)config["appName"];

            if (config["iconPath"] != null) iconPath = (string)config["iconPath"];
        }

        private void InitializeContext() {
            autoStartMenuItem = new MenuItem("Autostart", ToggleAutoStart) {
                Checked = IsAutoStartEnabled()
            };
            var appIcon = iconPath != null ? new Icon(iconPath) : Resources.TrayWrapper;
            notifyIcon = new NotifyIcon {
                Icon = appIcon,
                ContextMenu = new ContextMenu(new[] {
                    new MenuItem("Exit", Exit)
                }),
                Visible = true,
                Text = appName
            };
            var restartAppProcessMenuItem = new MenuItem("Restart", (sender, e) => {
                StopAppProcess();
                StartApp();
            });
            notifyIcon.ContextMenu.MenuItems.Add(restartAppProcessMenuItem);
            notifyIcon.ContextMenu.MenuItems.Add(autoStartMenuItem);
        }

        private void OnAppProcessExit(object sender, EventArgs e) {
            RestartApp();
        }

        private void StartApp() {
            appProcess = new Process();
            appProcess.StartInfo.CreateNoWindow = true;
            appProcess.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            appProcess.StartInfo.FileName = appPath;
            appProcess.StartInfo.Arguments = appArgs;
            appProcess.StartInfo.WorkingDirectory = appWorkingDir;
            appProcess.StartInfo.RedirectStandardOutput = true;
            appProcess.StartInfo.RedirectStandardError = true;
            appProcess.StartInfo.UseShellExecute = false;
            appProcess.EnableRaisingEvents = true;
            appProcess.OutputDataReceived += (sender, e) => LogToFile(e.Data, outLogPath);
            appProcess.ErrorDataReceived += (sender, e) => LogToFile(e.Data, errorLogPath);
            appProcess.Exited += OnAppProcessExit;
            appProcess.Start();
            AssignProcessToJobObject(appProcess);
            appProcess.BeginOutputReadLine();
            appProcess.BeginErrorReadLine();
        }

        private void RestartApp() {
            if (!appProcess.HasExited) return;
            StartApp();
        }

        private void LogToFile(string data, string logPath) {
            if (string.IsNullOrEmpty(data)) return;

            using (var stream = new FileStream(logPath, FileMode.Append))
            using (var writer = new StreamWriter(stream)) {
                writer.WriteLine(data);
            }

            var fileInfo = new FileInfo(logPath);
            if (fileInfo.Length > maxLogSize) {
                var lines = File.ReadAllLines(logPath);
                File.WriteAllLines(logPath, lines.Skip(lines.Length / 2)); // Keep the last half of the lines
            }
        }

        private void StopAppProcess() {
            // Attempt a graceful shutdown
            if (appProcess != null && !appProcess.HasExited) {
                LogToFile("Stopping process", outLogPath);
                appProcess.Exited -= OnAppProcessExit;

                // TODO: Send a signal to the process to shut down gracefully
                // like sending a Ctrl+C signal to a console application
                // using something like `GenerateConsoleCtrlEvent` and `AttachConsole`
                appProcess.Kill();
            }
        }

        private void Exit(object sender, EventArgs e) {
            notifyIcon.Visible = false;

            StopAppProcess();

            Application.Exit();
        }

        private bool IsAutoStartEnabled() {
            using (var key = Registry.CurrentUser.OpenSubKey(RunKey)) {
                if (key == null) return false;
                var value = key.GetValue(appName);
                if (value == null) return false;

                // Check if the path matches the current executable's path
                return value.ToString() == Assembly.GetExecutingAssembly().Location;
            }
        }

        private void EnableAutoStart() {
            using (var key = Registry.CurrentUser.OpenSubKey(RunKey, true)) {
                var existingValue = key.GetValue(appName);
                if (existingValue == null) {
                    // If no value exists with the appName, set the value
                    key.SetValue(appName, Assembly.GetExecutingAssembly().Location);
                }
                else if (existingValue.ToString() != Assembly.GetExecutingAssembly().Location) {
                    // If a value with the same appName exists but the path is different
                    var errorMessage =
                        $"Warning: Another application is already using the name '{appName}' in the autostart registry. Autostart was not enabled for TrayWrapper.";
                    MessageBox.Show(errorMessage, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void DisableAutoStart() {
            using (var key = Registry.CurrentUser.OpenSubKey(RunKey, true)) {
                var existingValue = key.GetValue(appName);
                if (existingValue != null && existingValue.ToString() == Assembly.GetExecutingAssembly().Location) {
                    // If a value with the same appName exists and the path is the same, delete the value
                    key.DeleteValue(appName);
                }
                else if (existingValue != null) {
                    // If a value with the same appName exists but the path is different
                    var errorMessage =
                        $"Warning: Another application is already using the name '{appName}' in the autostart registry. Autostart was not disabled for TrayWrapper.";
                    MessageBox.Show(errorMessage, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void ToggleAutoStart(object sender, EventArgs e) {
            if (IsAutoStartEnabled()) {
                DisableAutoStart();
                autoStartMenuItem.Checked = false;
            }
            else {
                EnableAutoStart();
                autoStartMenuItem.Checked = true;
            }
        }

        private void AssignProcessToJobObject(Process process) {
            if (!AssignProcessToJobObject(jobHandle, process.Handle))
                throw new InvalidOperationException("Failed to assign process to job object.");
        }

        #region P/Invoke Declarations

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll")]
        private static extern bool SetInformationJobObject(IntPtr hJob, JobObjectInfoType infoType,
            IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        private enum JobObjectInfoType
        {
            BasicLimitInformation = 2,
            ExtendedLimitInformation = 9
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public long Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        #endregion
    }
}