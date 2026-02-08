// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/ViewModels/ProcessesViewModel.cs
// ViewModel لمراقبة العمليات
// =====================================================

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace ShieldAI.UI.ViewModels
{
    /// <summary>
    /// ViewModel لصفحة مراقبة العمليات
    /// </summary>
    public class ProcessesViewModel : INotifyPropertyChanged
    {
        private ProcessItem? _selectedProcess;
        private bool _isLoading;
        private string _searchText = "";

        public event PropertyChangedEventHandler? PropertyChanged;

        #region Properties
        public ObservableCollection<ProcessItem> Processes { get; } = new();

        public ProcessItem? SelectedProcess
        {
            get => _selectedProcess;
            set { _selectedProcess = value; OnPropertyChanged(); }
        }

        public bool IsLoading
        {
            get => _isLoading;
            set { _isLoading = value; OnPropertyChanged(); }
        }

        public string SearchText
        {
            get => _searchText;
            set { _searchText = value; OnPropertyChanged(); FilterProcesses(); }
        }
        #endregion

        #region Commands
        public ICommand RefreshCommand { get; }
        public ICommand TerminateCommand { get; }
        public ICommand ScanCommand { get; }
        #endregion

        public ProcessesViewModel()
        {
            RefreshCommand = new RelayCommand(ExecuteRefresh);
            TerminateCommand = new RelayCommand(ExecuteTerminate, () => SelectedProcess != null);
            ScanCommand = new RelayCommand(ExecuteScan, () => SelectedProcess != null);

            LoadProcesses();
        }

        private void ExecuteRefresh()
        {
            LoadProcesses();
        }

        private void ExecuteTerminate()
        {
            if (SelectedProcess == null) return;

            try
            {
                var process = Process.GetProcessById(SelectedProcess.ProcessId);
                process.Kill();
                Processes.Remove(SelectedProcess);
            }
            catch (Exception)
            {
                // Handle error
            }
        }

        private void ExecuteScan()
        {
            // TODO: Scan selected process
        }

        private void LoadProcesses()
        {
            IsLoading = true;
            Processes.Clear();

            try
            {
                var processes = Process.GetProcesses();
                foreach (var proc in processes.OrderBy(p => p.ProcessName))
                {
                    try
                    {
                        Processes.Add(new ProcessItem
                        {
                            ProcessId = proc.Id,
                            Name = proc.ProcessName,
                            MemoryMB = proc.WorkingSet64 / 1024 / 1024,
                            FilePath = GetProcessPath(proc),
                            StartTime = GetProcessStartTime(proc)
                        });
                    }
                    catch
                    {
                        // Skip processes we can't access
                    }
                }
            }
            finally
            {
                IsLoading = false;
            }
        }

        private void FilterProcesses()
        {
            // TODO: Implement filtering
        }

        private string GetProcessPath(Process proc)
        {
            try { return proc.MainModule?.FileName ?? ""; }
            catch { return ""; }
        }

        private DateTime? GetProcessStartTime(Process proc)
        {
            try { return proc.StartTime; }
            catch { return null; }
        }

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class ProcessItem
    {
        public int ProcessId { get; set; }
        public string Name { get; set; } = "";
        public long MemoryMB { get; set; }
        public string FilePath { get; set; } = "";
        public DateTime? StartTime { get; set; }
        public string RiskLevel { get; set; } = "Low";
        public bool IsSuspicious { get; set; }
    }
}
