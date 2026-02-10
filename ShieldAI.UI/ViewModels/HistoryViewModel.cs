// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/ViewModels/HistoryViewModel.cs
// ViewModel لصفحة تاريخ التهديدات
// =====================================================

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ShieldAI.UI.Models;
using ShieldAI.UI.Services;

namespace ShieldAI.UI.ViewModels
{
    /// <summary>
    /// ViewModel لصفحة التاريخ - عرض التهديدات المكتشفة مع الفلترة
    /// </summary>
    public class HistoryViewModel : INotifyPropertyChanged
    {
        private readonly IpcClient _ipcClient;
        private string _selectedVerdictFilter = "الكل";
        private string _selectedEngineFilter = "الكل";
        private DateTime? _dateFrom;
        private DateTime? _dateTo;
        private bool _isLoading;
        private ThreatRecord? _selectedRecord;

        public event PropertyChangedEventHandler? PropertyChanged;

        #region Properties

        /// <summary>
        /// جميع السجلات (غير مفلترة)
        /// </summary>
        public ObservableCollection<ThreatRecord> AllRecords { get; } = new();

        /// <summary>
        /// السجلات المفلترة للعرض
        /// </summary>
        public ObservableCollection<ThreatRecord> FilteredRecords { get; } = new();

        /// <summary>
        /// جلسات الفحص
        /// </summary>
        public ObservableCollection<ScanSession> ScanSessions { get; } = new();

        public ThreatRecord? SelectedRecord
        {
            get => _selectedRecord;
            set { _selectedRecord = value; OnPropertyChanged(); }
        }

        public bool IsLoading
        {
            get => _isLoading;
            set { _isLoading = value; OnPropertyChanged(); }
        }

        public string SelectedVerdictFilter
        {
            get => _selectedVerdictFilter;
            set
            {
                _selectedVerdictFilter = value;
                OnPropertyChanged();
                ApplyFilters();
            }
        }

        public string SelectedEngineFilter
        {
            get => _selectedEngineFilter;
            set
            {
                _selectedEngineFilter = value;
                OnPropertyChanged();
                ApplyFilters();
            }
        }

        public DateTime? DateFrom
        {
            get => _dateFrom;
            set
            {
                _dateFrom = value;
                OnPropertyChanged();
                ApplyFilters();
            }
        }

        public DateTime? DateTo
        {
            get => _dateTo;
            set
            {
                _dateTo = value;
                OnPropertyChanged();
                ApplyFilters();
            }
        }

        /// <summary>
        /// خيارات فلتر القرار
        /// </summary>
        public List<string> VerdictFilters { get; } = new()
        {
            "الكل", "Block", "Quarantine", "NeedsReview", "Allow"
        };

        /// <summary>
        /// خيارات فلتر المحرك
        /// </summary>
        public List<string> EngineFilters { get; } = new()
        {
            "الكل", "SignatureEngine", "HeuristicEngine", "MlEngine", "ReputationEngine", "AmsiEngine"
        };

        public int TotalRecords => AllRecords.Count;
        public int FilteredCount => FilteredRecords.Count;

        #endregion

        #region Commands

        public ICommand RefreshCommand { get; }
        public ICommand ClearFiltersCommand { get; }
        public ICommand ExportCommand { get; }

        #endregion

        public HistoryViewModel()
        {
            _ipcClient = new IpcClient();

            RefreshCommand = new RelayCommand(ExecuteRefresh);
            ClearFiltersCommand = new RelayCommand(ExecuteClearFilters);
            ExportCommand = new RelayCommand(ExecuteExport);

            _ = LoadDataAsync();
        }

        #region Command Handlers

        private async void ExecuteRefresh()
        {
            await LoadDataAsync();
        }

        private void ExecuteClearFilters()
        {
            _selectedVerdictFilter = "الكل";
            _selectedEngineFilter = "الكل";
            _dateFrom = null;
            _dateTo = null;

            OnPropertyChanged(nameof(SelectedVerdictFilter));
            OnPropertyChanged(nameof(SelectedEngineFilter));
            OnPropertyChanged(nameof(DateFrom));
            OnPropertyChanged(nameof(DateTo));

            ApplyFilters();
        }

        private void ExecuteExport()
        {
            // TODO: تصدير السجلات إلى CSV
        }

        #endregion

        #region Data Loading

        private async Task LoadDataAsync()
        {
            IsLoading = true;

            try
            {
                var command = new IpcCommand
                {
                    CommandType = "GetHistory"
                };

                var response = await _ipcClient.SendCommandAsync(command);
                if (response.Success && !string.IsNullOrEmpty(response.Data))
                {
                    AllRecords.Clear();

                    var records = System.Text.Json.JsonSerializer.Deserialize<List<ThreatRecord>>(
                        response.Data,
                        new System.Text.Json.JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true
                        });

                    if (records != null)
                    {
                        foreach (var record in records)
                        {
                            AllRecords.Add(record);
                        }
                    }
                }

                ApplyFilters();
            }
            catch
            {
                // الخدمة غير متاحة - عرض رسالة مناسبة
            }
            finally
            {
                IsLoading = false;
                OnPropertyChanged(nameof(TotalRecords));
            }
        }

        #endregion

        #region Filtering

        private void ApplyFilters()
        {
            FilteredRecords.Clear();

            var filtered = AllRecords.AsEnumerable();

            // فلتر القرار
            if (_selectedVerdictFilter != "الكل")
            {
                filtered = filtered.Where(r =>
                    r.Verdict.Equals(_selectedVerdictFilter, StringComparison.OrdinalIgnoreCase));
            }

            // فلتر المحرك
            if (_selectedEngineFilter != "الكل")
            {
                filtered = filtered.Where(r =>
                    r.EngineResults.Any(e =>
                        e.EngineName.Equals(_selectedEngineFilter, StringComparison.OrdinalIgnoreCase) &&
                        e.Score > 0));
            }

            // فلتر التاريخ
            if (_dateFrom.HasValue)
            {
                filtered = filtered.Where(r => r.DetectedAt >= _dateFrom.Value);
            }

            if (_dateTo.HasValue)
            {
                filtered = filtered.Where(r => r.DetectedAt <= _dateTo.Value.AddDays(1));
            }

            foreach (var record in filtered.OrderByDescending(r => r.DetectedAt))
            {
                FilteredRecords.Add(record);
            }

            OnPropertyChanged(nameof(FilteredCount));
        }

        #endregion

        /// <summary>
        /// إضافة سجل تهديد جديد (يُستدعى من الخدمة عبر IPC)
        /// </summary>
        public void AddThreatRecord(ThreatRecord record)
        {
            AllRecords.Insert(0, record);
            OnPropertyChanged(nameof(TotalRecords));
            ApplyFilters();
        }

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
