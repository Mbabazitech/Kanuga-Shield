using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading;
using System.Windows.Forms;

namespace KanugaShield
{
    static class Launcher
    {
        private static Process serverProcess = null;

        [STAThread]
        static void Main(string[] args)
        {
            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string kanugaData = Path.Combine(appData, "Kanuga Shield", "data");

            try
            {
                if (!Directory.Exists(kanugaData))
                {
                    Directory.CreateDirectory(kanugaData);
                }
            }
            catch { }

            int port = 3000;
            bool alreadyRunning = IsServerRunning(port);

            if (!alreadyRunning)
            {
                string nodeExe = Path.Combine(appDir, "node.exe");
                if (!File.Exists(nodeExe))
                {
                    nodeExe = "node";
                }

                string serverScript = Path.Combine(appDir, "server.js");
                if (!File.Exists(serverScript))
                {
                    MessageBox.Show(
                        "Kanuga Shield core application script not found:\n" + serverScript,
                        "Kanuga Shield Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    return;
                }

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = nodeExe;
                psi.Arguments = "\"" + serverScript + "\"";
                psi.WorkingDirectory = appDir;
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                psi.EnvironmentVariables["PORT"] = port.ToString();
                psi.EnvironmentVariables["DATA_DIR"] = kanugaData;
                psi.EnvironmentVariables["NODE_ENV"] = "production";

                try
                {
                    serverProcess = Process.Start(psi);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        "Failed to launch Kanuga Shield background engine:\n" + ex.Message,
                        "Kanuga Shield Launch Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    return;
                }

                // Poll for server availability
                int elapsed = 0;
                while (elapsed < 12000 && !IsServerRunning(port))
                {
                    Thread.Sleep(250);
                    elapsed += 250;
                }
            }

            // Launch Dedicated Desktop Window
            string url = "http://localhost:" + port;
            LaunchDesktopWindow(url, appDir);
        }

        private static bool IsServerRunning(int port)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://localhost:" + port + "/api/firebase/status");
                req.Timeout = 800;
                req.Method = "GET";
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    return resp.StatusCode == HttpStatusCode.OK;
                }
            }
            catch
            {
                return false;
            }
        }

        private static void LaunchDesktopWindow(string url, string appDir)
        {
            string[] candidateEdgePaths = new string[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Microsoft\Edge\Application\msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Microsoft\Edge\Application\msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\Application\msedge.exe")
            };

            string edgeExe = null;
            foreach (string p in candidateEdgePaths)
            {
                if (File.Exists(p))
                {
                    edgeExe = p;
                    break;
                }
            }

            if (edgeExe != null)
            {
                string profileDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Kanuga Shield", "edge-profile");
                try { if (!Directory.Exists(profileDir)) Directory.CreateDirectory(profileDir); } catch { }

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = edgeExe;
                psi.Arguments = "--app=\"" + url + "\" --window-size=1420,920 --user-data-dir=\"" + profileDir + "\"";

                Process edgeProc = Process.Start(psi);
                if (edgeProc != null && serverProcess != null)
                {
                    edgeProc.WaitForExit();
                    try
                    {
                        if (!serverProcess.HasExited)
                        {
                            serverProcess.Kill();
                        }
                    }
                    catch { }
                }
            }
            else
            {
                // Fallback to default browser
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
        }
    }
}
