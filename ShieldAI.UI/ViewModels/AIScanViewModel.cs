// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// ViewModels/AIScanViewModel.cs
// ViewModel لصفحة AI Scan
// =====================================================

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Detection;
using ShieldAI.Core.ML;
using ShieldAI.UI.Services;

namespace ShieldAI.UI.ViewModels
{
    public class AIScanViewModel : INotifyPropertyChanged
    {
        private readonly IDialogService _dialogService;
        private DeepAnalyzer? _analyzer;
        private CancellationTokenSource? _cts;

        public AIScanViewModel(IDialogService dialogService)
        {
            _dialogService = dialogService;
            Findings = new ObservableCollection<FindingViewModel>();
            
            // تهيئة Commands
            SelectFileCommand = new RelayCommand(SelectFile);
            ClearFileCommand = new RelayCommand(ClearFile);
            StartAnalysisCommand = new RelayCommand(async () => await StartAnalysisAsync(), () => IsFileSelected && !IsScanning);
            CancelCommand = new RelayCommand(CancelAnalysis);
            QuarantineCommand = new RelayCommand(QuarantineFile);
            ExportReportCommand = new RelayCommand(ExportReport);
        }

        #region Properties
        private string _selectedFilePath = "";
        public string SelectedFilePath
        {
            get => _selectedFilePath;
            set
            {
                _selectedFilePath = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsFileSelected));
                OnPropertyChanged(nameof(SelectedFileName));
            }
        }

        public string SelectedFileName => Path.GetFileName(SelectedFilePath);
        public bool IsFileSelected => !string.IsNullOrEmpty(SelectedFilePath);

        private string _fileSizeFormatted = "";
        public string FileSizeFormatted
        {
            get => _fileSizeFormatted;
            set { _fileSizeFormatted = value; OnPropertyChanged(); }
        }

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            set { _isScanning = value; OnPropertyChanged(); }
        }

        private string _currentStage = "";
        public string CurrentStage
        {
            get => _currentStage;
            set { _currentStage = value; OnPropertyChanged(); }
        }

        private int _progressPercent;
        public int ProgressPercent
        {
            get => _progressPercent;
            set { _progressPercent = value; OnPropertyChanged(); }
        }

        private bool _hasResult;
        public bool HasResult
        {
            get => _hasResult;
            set { _hasResult = value; OnPropertyChanged(); }
        }

        private DeepAnalysisResult? _result;
        public DeepAnalysisResult? Result
        {
            get => _result;
            set
            {
                _result = value;
                OnPropertyChanged();
                UpdateResultProperties();
            }
        }

        // Verdict Properties
        public string VerdictIcon => Result?.Verdict switch
        {
            AnalysisVerdict.Clean => "✅",
            AnalysisVerdict.PotentiallyUnwanted => "⚠️",
            AnalysisVerdict.Suspicious => "🔶",
            AnalysisVerdict.Malicious => "🛑",
            _ => "❓"
        };

        public string VerdictText => Result?.Verdict switch
        {
            AnalysisVerdict.Clean => "آمن",
            AnalysisVerdict.PotentiallyUnwanted => "قد يكون غير مرغوب",
            AnalysisVerdict.Suspicious => "مشبوه",
            AnalysisVerdict.Malicious => "خبيث",
            _ => "غير معروف"
        };

        public Brush VerdictBackground => Result?.Verdict switch
        {
            AnalysisVerdict.Clean => new SolidColorBrush(Color.FromRgb(56, 239, 125)),
            AnalysisVerdict.PotentiallyUnwanted => new SolidColorBrush(Color.FromRgb(255, 210, 0)),
            AnalysisVerdict.Suspicious => new SolidColorBrush(Color.FromRgb(247, 151, 30)),
            AnalysisVerdict.Malicious => new SolidColorBrush(Color.FromRgb(249, 57, 67)),
            _ => new SolidColorBrush(Colors.Gray)
        };

        public string ResultSummary => Result?.Summary ?? "";
        public double RiskScore => Result?.OverallRiskScore ?? 0;

        public Brush RiskScoreColor => RiskScore switch
        {
            >= 70 => new SolidColorBrush(Color.FromRgb(249, 57, 67)),
            >= 40 => new SolidColorBrush(Color.FromRgb(247, 151, 30)),
            >= 20 => new SolidColorBrush(Color.FromRgb(255, 210, 0)),
            _ => new SolidColorBrush(Color.FromRgb(56, 239, 125))
        };

        public bool IsThreat => Result?.IsThreat ?? false;
        public bool HasFindings => Findings.Count > 0;

        // Status Properties
        public string SignatureStatus => Result?.SignatureMatch != null ? "مكتشف" : "نظيف";
        public Brush SignatureStatusColor => Result?.SignatureMatch != null 
            ? new SolidColorBrush(Color.FromRgb(249, 57, 67)) 
            : new SolidColorBrush(Color.FromRgb(56, 239, 125));

        public string HeuristicStatus => (Result?.HeuristicResult?.Indicators.Count ?? 0) > 0 
            ? $"{Result?.HeuristicResult?.Indicators.Count} مؤشرات" 
            : "نظيف";
        public Brush HeuristicStatusColor => (Result?.HeuristicResult?.IsMalicious ?? false)
            ? new SolidColorBrush(Color.FromRgb(249, 57, 67))
            : (Result?.HeuristicResult?.IsSuspicious ?? false)
                ? new SolidColorBrush(Color.FromRgb(247, 151, 30))
                : new SolidColorBrush(Color.FromRgb(56, 239, 125));

        public string MLStatus => Result?.MLPrediction != null 
            ? (Result.MLPrediction.IsMalware ? $"{Result.MLPrediction.Probability:P0}" : "نظيف")
            : "N/A";
        public Brush MLStatusColor => (Result?.MLPrediction?.IsMalware ?? false)
            ? new SolidColorBrush(Color.FromRgb(249, 57, 67))
            : new SolidColorBrush(Color.FromRgb(56, 239, 125));

        public string VTStatus
        {
            get
            {
                if (Result?.VirusTotalResult == null || Result.VirusTotalResult.HasError)
                    return "غير متصل";
                if (Result.VirusTotalResult.IsThreat)
                    return $"{Result.VirusTotalResult.Malicious}/{Result.VirusTotalResult.TotalEngines}";
                return "نظيف";
            }
        }
        public Brush VTStatusColor => (Result?.VirusTotalResult?.IsThreat ?? false)
            ? new SolidColorBrush(Color.FromRgb(249, 57, 67))
            : new SolidColorBrush(Color.FromRgb(56, 239, 125));

        public ObservableCollection<FindingViewModel> Findings { get; }
        #endregion

        #region Commands
        public ICommand SelectFileCommand { get; }
        public ICommand ClearFileCommand { get; }
        public ICommand StartAnalysisCommand { get; }
        public ICommand CancelCommand { get; }
        public ICommand QuarantineCommand { get; }
        public ICommand ExportReportCommand { get; }
        #endregion

        #region Methods
        private void SelectFile()
        {
            var dialog = new OpenFileDialog
            {
                Title = "اختر ملف للفحص",
                Filter = "كافة الملفات (*.*)|*.*|ملفات تنفيذية (*.exe)|*.exe|DLL (*.dll)|*.dll"
            };

            if (dialog.ShowDialog() == true)
            {
                SelectedFilePath = dialog.FileName;
                var fileInfo = new FileInfo(dialog.FileName);
                FileSizeFormatted = FormatFileSize(fileInfo.Length);
                HasResult = false;
                Findings.Clear();
            }
        }

        private void ClearFile()
        {
            SelectedFilePath = "";
            FileSizeFormatted = "";
            HasResult = false;
            Result = null;
            Findings.Clear();
        }

        private async Task StartAnalysisAsync()
        {
            if (!IsFileSelected) return;

            IsScanning = true;
            HasResult = false;
            Findings.Clear();
            _cts = new CancellationTokenSource();

            try
            {
                // الحصول على API Key من الإعدادات
                var settings = ConfigManager.Instance.Settings;
                var apiKey = settings.VirusTotalApiKey;
                
                _analyzer = new DeepAnalyzer(apiKey);

                var progress = new Progress<AnalysisProgress>(p =>
                {
                    CurrentStage = p.Stage;
                    ProgressPercent = p.Percent;
                });

                Result = await _analyzer.AnalyzeAsync(
                    SelectedFilePath,
                    useVirusTotal: settings.UseVirusTotalInAIScan,
                    progress: progress,
                    cancellationToken: _cts.Token);

                HasResult = true;
            }
            catch (OperationCanceledException)
            {
                CurrentStage = "تم الإلغاء";
            }
            catch (Exception ex)
            {
                _dialogService.ShowError("خطأ", $"حدث خطأ أثناء التحليل: {ex.Message}");
            }
            finally
            {
                IsScanning = false;
                _cts?.Dispose();
                _cts = null;
            }
        }

        private void CancelAnalysis()
        {
            _cts?.Cancel();
        }

        private void QuarantineFile()
        {
            if (Result == null) return;
            
            // TODO: تنفيذ العزل
            _dialogService.ShowInfo("عزل الملف", $"تم عزل الملف: {Result.FileName}");
        }

        private void ExportReport()
        {
            if (Result == null) return;

            var dialog = new SaveFileDialog
            {
                Title = "حفظ التقرير",
                Filter = "Text File (*.txt)|*.txt|JSON (*.json)|*.json",
                FileName = $"ShieldAI_Report_{DateTime.Now:yyyyMMdd_HHmmss}"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var report = GenerateReport();
                    File.WriteAllText(dialog.FileName, report);
                    _dialogService.ShowInfo("تم الحفظ", "تم حفظ التقرير بنجاح");
                }
                catch (Exception ex)
                {
                    _dialogService.ShowError("خطأ", $"فشل الحفظ: {ex.Message}");
                }
            }
        }

        private string GenerateReport()
        {
            if (Result == null) return "";

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("═══════════════════════════════════════════════════");
            sb.AppendLine("        ShieldAI - AI Deep Analysis Report         ");
            sb.AppendLine("═══════════════════════════════════════════════════");
            sb.AppendLine();
            sb.AppendLine($"File: {Result.FileName}");
            sb.AppendLine($"Path: {Result.FilePath}");
            sb.AppendLine($"Size: {FormatFileSize(Result.FileSize)}");
            sb.AppendLine($"Analysis Time: {Result.Duration.TotalSeconds:F1}s");
            sb.AppendLine($"Date: {Result.AnalysisStartTime:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();
            sb.AppendLine("───────────────────────────────────────────────────");
            sb.AppendLine($"VERDICT: {VerdictText.ToUpper()}");
            sb.AppendLine($"Risk Score: {Result.OverallRiskScore:F0}%");
            sb.AppendLine($"Confidence: {Result.OverallConfidence:F0}%");
            sb.AppendLine("───────────────────────────────────────────────────");
            sb.AppendLine();

            if (Result.Findings.Count > 0)
            {
                sb.AppendLine("FINDINGS:");
                foreach (var finding in Result.Findings)
                {
                    sb.AppendLine($"  [{finding.Severity}] {finding.Title}");
                    sb.AppendLine($"    Source: {finding.Source}");
                    sb.AppendLine($"    {finding.Description}");
                    sb.AppendLine($"    Confidence: {finding.Confidence}%");
                    sb.AppendLine();
                }
            }

            sb.AppendLine("═══════════════════════════════════════════════════");
            return sb.ToString();
        }

        private void UpdateResultProperties()
        {
            OnPropertyChanged(nameof(VerdictIcon));
            OnPropertyChanged(nameof(VerdictText));
            OnPropertyChanged(nameof(VerdictBackground));
            OnPropertyChanged(nameof(ResultSummary));
            OnPropertyChanged(nameof(RiskScore));
            OnPropertyChanged(nameof(RiskScoreColor));
            OnPropertyChanged(nameof(IsThreat));
            OnPropertyChanged(nameof(SignatureStatus));
            OnPropertyChanged(nameof(SignatureStatusColor));
            OnPropertyChanged(nameof(HeuristicStatus));
            OnPropertyChanged(nameof(HeuristicStatusColor));
            OnPropertyChanged(nameof(MLStatus));
            OnPropertyChanged(nameof(MLStatusColor));
            OnPropertyChanged(nameof(VTStatus));
            OnPropertyChanged(nameof(VTStatusColor));

            // تحديث Findings
            Findings.Clear();
            if (Result?.Findings != null)
            {
                foreach (var f in Result.Findings)
                {
                    Findings.Add(new FindingViewModel(f));
                }
            }
            OnPropertyChanged(nameof(HasFindings));
        }

        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }
        #endregion

        #region INotifyPropertyChanged
        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
        #endregion
    }

    /// <summary>
    /// ViewModel للاكتشاف الفردي
    /// </summary>
    public class FindingViewModel
    {
        private readonly AnalysisFinding _finding;

        public FindingViewModel(AnalysisFinding finding)
        {
            _finding = finding;
        }

        public string Title => _finding.Title;
        public string Description => _finding.Description;
        public int Confidence => _finding.Confidence;
        
        public string SeverityText => _finding.Severity switch
        {
            ThreatLevel.Critical => "حرج",
            ThreatLevel.High => "عالي",
            ThreatLevel.Medium => "متوسط",
            ThreatLevel.Low => "منخفض",
            _ => "معلومة"
        };

        public Brush SeverityColor => _finding.Severity switch
        {
            ThreatLevel.Critical => new SolidColorBrush(Color.FromRgb(249, 57, 67)),
            ThreatLevel.High => new SolidColorBrush(Color.FromRgb(247, 151, 30)),
            ThreatLevel.Medium => new SolidColorBrush(Color.FromRgb(255, 210, 0)),
            ThreatLevel.Low => new SolidColorBrush(Color.FromRgb(102, 126, 234)),
            _ => new SolidColorBrush(Colors.Gray)
        };
    }
}
