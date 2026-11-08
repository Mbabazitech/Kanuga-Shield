using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace KanugaShieldInstaller
{
    public class SetupForm : Form
    {
        private ProgressBar progressBar;
        private Label lblStatus;
        private Label lblDetail;
        private Button btnInstall;
        private Button btnCancel;
        private CheckBox chkDesktop;
        private CheckBox chkStartMenu;
        private CheckBox chkLaunch;
        private TextBox txtInstallPath;
        private bool isFinished = false;

        private string installDir;
        private string appDataDir;

        public SetupForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            installDir = Path.Combine(localAppData, "Programs", "Kanuga Shield");
            appDataDir = Path.Combine(roamingAppData, "Kanuga Shield", "data");

            this.Text = "Kanuga Shield Enterprise Setup";
            this.Size = new Size(580, 460);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = true;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(15, 23, 42); // #0F172A
            this.ForeColor = Color.FromArgb(248, 250, 252);
            this.Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);

            // 1. Header Banner Panel
            Panel headerPanel = new Panel();
            headerPanel.Dock = DockStyle.Top;
            headerPanel.Height = 80;
            headerPanel.BackColor = Color.FromArgb(30, 41, 59); // #1E293B
            headerPanel.Padding = new Padding(20, 15, 20, 15);

            Label lblTitle = new Label();
            lblTitle.Text = "Kanuga Shield Enterprise";
            lblTitle.Font = new Font("Segoe UI", 14F, FontStyle.Bold);
            lblTitle.ForeColor = Color.White;
            lblTitle.Location = new Point(20, 14);
            lblTitle.AutoSize = true;

            Label lblSubtitle = new Label();
            lblSubtitle.Text = "Modern Compliance & Security Automation Platform by Kanuga_tech";
            lblSubtitle.Font = new Font("Segoe UI", 8.5F, FontStyle.Regular);
            lblSubtitle.ForeColor = Color.FromArgb(148, 163, 184); // #94A3B8
            lblSubtitle.Location = new Point(22, 44);
            lblSubtitle.AutoSize = true;

            headerPanel.Controls.Add(lblTitle);
            headerPanel.Controls.Add(lblSubtitle);

            // 2. Main Content Body
            Panel bodyPanel = new Panel();
            bodyPanel.Location = new Point(0, 80);
            bodyPanel.Size = new Size(580, 290);
            bodyPanel.BackColor = Color.FromArgb(15, 23, 42);
            bodyPanel.Padding = new Padding(25, 20, 25, 10);

            Label lblIntro = new Label();
            lblIntro.Text = "This installer sets up Kanuga Shield on your computer. Your compliance\ndatabases, evidence vault, and credentials are kept privately on this machine.";
            lblIntro.Location = new Point(25, 15);
            lblIntro.Size = new Size(530, 36);
            lblIntro.ForeColor = Color.FromArgb(226, 232, 240);

            Label lblPathTag = new Label();
            lblPathTag.Text = "Installation Directory:";
            lblPathTag.Font = new Font("Segoe UI", 8F, FontStyle.Bold);
            lblPathTag.ForeColor = Color.FromArgb(148, 163, 184);
            lblPathTag.Location = new Point(25, 62);
            lblPathTag.AutoSize = true;

            txtInstallPath = new TextBox();
            txtInstallPath.Text = installDir;
            txtInstallPath.ReadOnly = true;
            txtInstallPath.Location = new Point(25, 82);
            txtInstallPath.Size = new Size(515, 25);
            txtInstallPath.BackColor = Color.FromArgb(30, 41, 59);
            txtInstallPath.ForeColor = Color.FromArgb(203, 213, 225);
            txtInstallPath.BorderStyle = BorderStyle.FixedSingle;

            chkDesktop = new CheckBox();
            chkDesktop.Text = "Create desktop shortcut (\"Kanuga Shield\")";
            chkDesktop.Checked = true;
            chkDesktop.ForeColor = Color.FromArgb(226, 232, 240);
            chkDesktop.Location = new Point(25, 120);
            chkDesktop.AutoSize = true;

            chkStartMenu = new CheckBox();
            chkStartMenu.Text = "Create Start Menu program shortcut";
            chkStartMenu.Checked = true;
            chkStartMenu.ForeColor = Color.FromArgb(226, 232, 240);
            chkStartMenu.Location = new Point(25, 146);
            chkStartMenu.AutoSize = true;

            chkLaunch = new CheckBox();
            chkLaunch.Text = "Launch Kanuga Shield immediately after setup completes";
            chkLaunch.Checked = true;
            chkLaunch.ForeColor = Color.FromArgb(226, 232, 240);
            chkLaunch.Location = new Point(25, 172);
            chkLaunch.AutoSize = true;

            lblStatus = new Label();
            lblStatus.Text = "Ready to install.";
            lblStatus.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            lblStatus.ForeColor = Color.FromArgb(59, 130, 246); // #3B82F6
            lblStatus.Location = new Point(25, 215);
            lblStatus.Size = new Size(515, 20);

            progressBar = new ProgressBar();
            progressBar.Location = new Point(25, 238);
            progressBar.Size = new Size(515, 14);
            progressBar.Style = ProgressBarStyle.Continuous;
            progressBar.Value = 0;

            lblDetail = new Label();
            lblDetail.Text = "Local storage configured at: %APPDATA%\\Kanuga Shield\\data";
            lblDetail.Font = new Font("Segoe UI", 7.5F, FontStyle.Regular);
            lblDetail.ForeColor = Color.FromArgb(100, 116, 139);
            lblDetail.Location = new Point(25, 258);
            lblDetail.Size = new Size(515, 18);

            bodyPanel.Controls.Add(lblIntro);
            bodyPanel.Controls.Add(lblPathTag);
            bodyPanel.Controls.Add(txtInstallPath);
            bodyPanel.Controls.Add(chkDesktop);
            bodyPanel.Controls.Add(chkStartMenu);
            bodyPanel.Controls.Add(chkLaunch);
            bodyPanel.Controls.Add(lblStatus);
            bodyPanel.Controls.Add(progressBar);
            bodyPanel.Controls.Add(lblDetail);

            // 3. Bottom Action Bar
            Panel footerPanel = new Panel();
            footerPanel.Dock = DockStyle.Bottom;
            footerPanel.Height = 60;
            footerPanel.BackColor = Color.FromArgb(30, 41, 59);

            btnCancel = new Button();
            btnCancel.Text = "Cancel";
            btnCancel.Size = new Size(90, 34);
            btnCancel.Location = new Point(360, 13);
            btnCancel.FlatStyle = FlatStyle.Flat;
            btnCancel.FlatAppearance.BorderColor = Color.FromArgb(71, 85, 105);
            btnCancel.BackColor = Color.FromArgb(51, 65, 85);
            btnCancel.ForeColor = Color.FromArgb(226, 232, 240);
            btnCancel.Cursor = Cursors.Hand;
            btnCancel.Click += (s, e) => { this.Close(); };

            btnInstall = new Button();
            btnInstall.Text = "Install";
            btnInstall.Size = new Size(100, 34);
            btnInstall.Location = new Point(460, 13);
            btnInstall.FlatStyle = FlatStyle.Flat;
            btnInstall.FlatAppearance.BorderSize = 0;
            btnInstall.BackColor = Color.FromArgb(37, 99, 235); // #2563EB
            btnInstall.ForeColor = Color.White;
            btnInstall.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            btnInstall.Cursor = Cursors.Hand;
            btnInstall.Click += async (s, e) => { await StartInstallation(); };

            footerPanel.Controls.Add(btnCancel);
            footerPanel.Controls.Add(btnInstall);

            this.Controls.Add(bodyPanel);
            this.Controls.Add(headerPanel);
            this.Controls.Add(footerPanel);
        }

        private async Task StartInstallation()
        {
            if (isFinished)
            {
                if (chkLaunch.Checked)
                {
                    string launcher = Path.Combine(installDir, "KanugaShield.exe");
                    if (File.Exists(launcher))
                    {
                        Process.Start(new ProcessStartInfo(launcher) { WorkingDirectory = installDir });
                    }
                }
                this.Close();
                return;
            }

            btnInstall.Enabled = false;
            btnCancel.Enabled = false;
            progressBar.Value = 10;
            lblStatus.Text = "Preparing installation directory...";

            await Task.Run(() =>
            {
                try
                {
                    // 1. Create Directories
                    if (!Directory.Exists(installDir))
                    {
                        Directory.CreateDirectory(installDir);
                    }
                    if (!Directory.Exists(appDataDir))
                    {
                        Directory.CreateDirectory(appDataDir);
                    }

                    UpdateProgress(25, "Extracting Kanuga Shield platform files...");

                    // 2. Extract Embedded Payload Archive
                    Assembly assembly = Assembly.GetExecutingAssembly();
                    using (Stream resStream = assembly.GetManifestResourceStream("app-payload.zip"))
                    {
                        if (resStream == null)
                        {
                            throw new Exception("Embedded application payload was not found inside the installer binary.");
                        }

                        using (ZipArchive archive = new ZipArchive(resStream, ZipArchiveMode.Read))
                        {
                            int total = archive.Entries.Count;
                            int count = 0;
                            foreach (ZipArchiveEntry entry in archive.Entries)
                            {
                                string destPath = Path.Combine(installDir, entry.FullName);
                                if (string.IsNullOrEmpty(entry.Name))
                                {
                                    Directory.CreateDirectory(destPath);
                                }
                                else
                                {
                                    string dir = Path.GetDirectoryName(destPath);
                                    if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                                    entry.ExtractToFile(destPath, true);
                                }
                                count++;
                                if (count % 30 == 0)
                                {
                                    int p = 25 + (int)((count / (float)total) * 45);
                                    UpdateProgress(p, string.Format("Extracting {0} ({1}/{2})...", entry.Name, count, total));
                                }
                            }
                        }
                    }

                    UpdateProgress(75, "Creating Windows shortcuts & registering application...");

                    string exePath = Path.Combine(installDir, "KanugaShield.exe");
                    string icoPath = Path.Combine(installDir, "public", "app.ico");

                    // 3. Create Desktop Shortcut
                    if (chkDesktop.Checked)
                    {
                        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                        CreateShortcut(
                            Path.Combine(desktop, "Kanuga Shield.lnk"),
                            exePath,
                            installDir,
                            icoPath,
                            "Kanuga Shield Enterprise Compliance & Security Automation"
                        );
                    }

                    // 4. Create Start Menu Shortcut
                    if (chkStartMenu.Checked)
                    {
                        string startMenu = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
                        CreateShortcut(
                            Path.Combine(startMenu, "Kanuga Shield.lnk"),
                            exePath,
                            installDir,
                            icoPath,
                            "Kanuga Shield Enterprise Compliance & Security Automation"
                        );
                    }

                    // 5. Register in Windows Add/Remove Programs
                    RegisterUninstall(installDir, icoPath);

                    UpdateProgress(100, "Installation complete!");
                }
                catch (Exception ex)
                {
                    this.Invoke((Action)(() =>
                    {
                        MessageBox.Show(
                            "Installation encountered an error:\n\n" + ex.Message,
                            "Installation Error",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Error
                        );
                        btnCancel.Enabled = true;
                    }));
                    return;
                }
            });

            lblStatus.Text = "Kanuga Shield has been installed successfully!";
            lblStatus.ForeColor = Color.FromArgb(16, 185, 129); // Emerald
            lblDetail.Text = "You can launch Kanuga Shield from your Desktop or Start Menu.";
            btnInstall.Text = "Finish";
            btnInstall.Enabled = true;
            btnCancel.Visible = false;
            isFinished = true;
        }

        private void UpdateProgress(int value, string text)
        {
            if (this.InvokeRequired)
            {
                this.Invoke((Action)(() => UpdateProgress(value, text)));
                return;
            }
            progressBar.Value = Math.Min(100, Math.Max(0, value));
            lblStatus.Text = text;
        }

        private void CreateShortcut(string shortcutPath, string targetPath, string workingDir, string iconPath, string description)
        {
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                object shell = Activator.CreateInstance(shellType);
                object shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { shortcutPath });
                Type scType = shortcut.GetType();
                scType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { targetPath });
                scType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { workingDir });
                if (File.Exists(iconPath))
                {
                    scType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, new object[] { iconPath + ",0" });
                }
                scType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut, new object[] { description });
                scType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
            }
            catch { }
        }

        private void RegisterUninstall(string dir, string iconPath)
        {
            try
            {
                string uninstPath = Path.Combine(dir, "Uninstall.exe");
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\KanugaShield"))
                {
                    if (key != null)
                    {
                        key.SetValue("DisplayName", "Kanuga Shield Enterprise");
                        key.SetValue("Publisher", "Kanuga_tech");
                        key.SetValue("DisplayVersion", "1.0.0");
                        key.SetValue("DisplayIcon", iconPath);
                        key.SetValue("UninstallString", "\"" + uninstPath + "\"");
                        key.SetValue("InstallLocation", dir);
                        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                    }
                }
            }
            catch { }
        }

        [STAThread]
        public static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new SetupForm());
        }
    }
}
