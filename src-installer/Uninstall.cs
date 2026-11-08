using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;
using Microsoft.Win32;

namespace KanugaShieldInstaller
{
    static class Uninstaller
    {
        [STAThread]
        static void Main()
        {
            DialogResult confirm = MessageBox.Show(
                "Are you sure you want to uninstall Kanuga Shield from your computer?",
                "Uninstall Kanuga Shield",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question
            );

            if (confirm != DialogResult.Yes) return;

            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string startMenu = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string dataDir = Path.Combine(roaming, "Kanuga Shield");

            // 1. Delete Shortcuts
            try
            {
                string desktopLnk = Path.Combine(desktop, "Kanuga Shield.lnk");
                if (File.Exists(desktopLnk)) File.Delete(desktopLnk);

                string startMenuLnk = Path.Combine(startMenu, "Kanuga Shield.lnk");
                if (File.Exists(startMenuLnk)) File.Delete(startMenuLnk);
            }
            catch { }

            // 2. Remove Registry entry
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\KanugaShield", false);
            }
            catch { }

            // 3. Ask about local compliance data
            DialogResult keepData = MessageBox.Show(
                "Would you like to keep your local compliance databases, evidence vault, and credentials for future use?\n\nLocation: " + dataDir,
                "Retain Local Compliance Vault?",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question
            );

            if (keepData == DialogResult.No)
            {
                try
                {
                    if (Directory.Exists(dataDir)) Directory.Delete(dataDir, true);
                }
                catch { }
            }

            // 4. Delete install folder via delayed self-destruct script
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = string.Format("/c ping 127.0.0.1 -n 3 > nul & rmdir /s /q \"{0}\"", appDir.TrimEnd('\\'));
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(psi);
            }
            catch { }

            MessageBox.Show(
                "Kanuga Shield has been successfully uninstalled from your computer.",
                "Uninstall Complete",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information
            );
        }
    }
}
