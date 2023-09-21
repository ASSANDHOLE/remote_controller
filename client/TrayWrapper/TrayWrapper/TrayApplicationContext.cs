using System;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;
using Newtonsoft.Json.Linq;
using System.Linq;

using Microsoft.Win32;
using System.Reflection;


namespace TrayWrapper
{
    public class TrayApplicationContext : ApplicationContext
    {
        private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

        private string appName = "TrayWrapper";  // Default name of the app if not specified in config.json
        private string iconPath = null;

        private NotifyIcon notifyIcon;
        private string appPath;
        private string appArgs = "";
        private string appWorkingDir = "";

        private string outLogPath;
        private string errorLogPath;
        private long maxLogSize;
        private Process appProcess;
        private MenuItem autoStartMenuItem;

        public TrayApplicationContext()
        {
            try
            {
                LoadConfig();
                InitializeContext();
                StartApp();
            }
            catch (Exception ex)
            {
                DebugLog(ex.ToString());
                MessageBox.Show(ex.ToString(), "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Exit(null, null);
            }
        }

        private void DebugLog(string message)
        {
            File.AppendAllText("TrayWrapper_error.log", DateTime.Now + ": " + message + Environment.NewLine);
        }


        private void LoadConfig()
        {
            string exeLocation = System.Reflection.Assembly.GetExecutingAssembly().Location;
            string exeDirectory = Path.GetDirectoryName(exeLocation);
            string configPath = Path.Combine(exeDirectory, "config.json");

            var config = JObject.Parse(File.ReadAllText(configPath));

            appPath = (string)config["appPath"];
            if (config["appArgs"] != null)
            {
                appArgs = (string)config["appArgs"];
            }
            if (config["appWorkingDir"] != null)
            {
                appWorkingDir = (string)config["appWorkingDir"];
            }
            outLogPath = (string)config["outLogPath"];
            errorLogPath = (string)config["errorLogPath"];
            maxLogSize = (long)config["maxLogSize"];
            if (config["appName"] != null)
            {
                appName = (string)config["appName"];
            }

            if (config["iconPath"] != null)
            {
                iconPath = (string)config["iconPath"];
            }
        }

        private void InitializeContext()
        {
            autoStartMenuItem = new MenuItem("Autostart", ToggleAutoStart)
            {
                Checked = IsAutoStartEnabled()
            };
            var appIcon = iconPath != null ? new System.Drawing.Icon(iconPath) : Properties.Resources.TrayWrapper;
            notifyIcon = new NotifyIcon()
            {
                Icon = appIcon,
                ContextMenu = new ContextMenu(new MenuItem[]
                {
                    new MenuItem("Exit", Exit)
                }),
                Visible = true,
                Text = appName
            };
            var restartAppProcessMenuItem = new MenuItem("Restart", (sender, e) => { stopAppProcess(); StartApp(); });
            notifyIcon.ContextMenu.MenuItems.Add(restartAppProcessMenuItem);
            notifyIcon.ContextMenu.MenuItems.Add(autoStartMenuItem);
        }

        private void OnAppProcessExit(object sender, EventArgs e)
        {
            RestartApp();
        }

        private void StartApp()
        {
            appProcess = new Process();
            appProcess.StartInfo.CreateNoWindow = true;
            appProcess.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            appProcess.StartInfo.FileName = appPath;
            appProcess.StartInfo.Arguments = appArgs;
            appProcess.StartInfo.WorkingDirectory = appWorkingDir;
            appProcess.StartInfo.RedirectStandardOutput = true;
            appProcess.StartInfo.RedirectStandardError = true;
            appProcess.StartInfo.UseShellExecute = false;
            appProcess.OutputDataReceived += (sender, e) => LogToFile(e.Data, outLogPath);
            appProcess.ErrorDataReceived += (sender, e) => LogToFile(e.Data, errorLogPath);
            appProcess.Exited += OnAppProcessExit;
            appProcess.Start();
            appProcess.BeginOutputReadLine();
            appProcess.BeginErrorReadLine();

        }

        private void RestartApp()
        {
            if (!appProcess.HasExited) return;
            StartApp();
        }

        private void LogToFile(string data, string logPath)
        {
            if (string.IsNullOrEmpty(data)) return;

            using (var stream = new FileStream(logPath, FileMode.Append))
            using (var writer = new StreamWriter(stream))
            {
                writer.WriteLine(data);
            }

            var fileInfo = new FileInfo(logPath);
            if (fileInfo.Length > maxLogSize)
            {
                var lines = File.ReadAllLines(logPath);
                File.WriteAllLines(logPath, lines.Skip(lines.Length / 2)); // Keep the last half of the lines
            }

        }

        void stopAppProcess()
        {
            // Attempt a graceful shutdown
            if (appProcess != null && !appProcess.HasExited)
            {
                appProcess.Exited -= OnAppProcessExit;
                
                appProcess.Close();

                if (!appProcess.WaitForExit(1000))  // ms
                {
                    // If the process is still running after the timeout, forcefully terminate it
                    appProcess.Kill();
                }

                appProcess.Dispose();
            }
        }

        void Exit(object sender, EventArgs e)
        {
            notifyIcon.Visible = false;

            stopAppProcess();

            Application.Exit();
        }

        private bool IsAutoStartEnabled()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunKey))
            {
                if (key == null) return false;
                object value = key.GetValue(appName);
                if (value == null) return false;

                // Check if the path matches the current executable's path
                return value.ToString() == Assembly.GetExecutingAssembly().Location;
            }
        }

        private void EnableAutoStart()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunKey, true))
            {
                object existingValue = key.GetValue(appName);
                if (existingValue == null)
                {
                    // If no value exists with the appName, set the value
                    key.SetValue(appName, Assembly.GetExecutingAssembly().Location);
                }
                else if (existingValue.ToString() != Assembly.GetExecutingAssembly().Location)
                {
                    // If a value with the same appName exists but the path is different
                    var errorMessage = $"Warning: Another application is already using the name '{appName}' in the autostart registry. Autostart was not enabled for TrayWrapper.";
                    MessageBox.Show(errorMessage, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    DebugLog(errorMessage);
                }
            }
        }


        private void DisableAutoStart()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunKey, true))
            {
                object existingValue = key.GetValue(appName);
                if (existingValue != null && existingValue.ToString() == Assembly.GetExecutingAssembly().Location)
                {
                    // If a value with the same appName exists and the path is the same, delete the value
                    key.DeleteValue(appName);
                }
                else if (existingValue != null)
                {
                    // If a value with the same appName exists but the path is different
                    var errorMessage = $"Warning: Another application is already using the name '{appName}' in the autostart registry. Autostart was not disabled for TrayWrapper.";
                    MessageBox.Show(errorMessage, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    DebugLog(errorMessage);
                }
            }
        }

        private void ToggleAutoStart(object sender, EventArgs e)
        {
            if (IsAutoStartEnabled())
            {
                DisableAutoStart();
                autoStartMenuItem.Checked = false;
            }
            else
            {
                EnableAutoStart();
                autoStartMenuItem.Checked = true;
            }
        }
    }
}
