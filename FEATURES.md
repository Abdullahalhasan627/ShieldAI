# ShieldAI Antivirus - Features & Capabilities

## 🛡️ نظرة عامة
ShieldAI هو برنامج مكافحة فيروسات ذكي مبني على .NET 8 مع واجهة WPF عصرية ومحركات كشف متعددة.

---

## 🔍 محركات الكشف

### 1. Signature Database
| الملف | `ShieldAI.Core/Detection/SignatureDatabase.cs` |
|-------|------------------------------------------------|
| **الوظيفة** | كشف البرمجيات الخبيثة عبر التوقيعات (Hash-based) |
| **الخوارزميات** | MD5, SHA256 |
| **الميزات** | - دعم EICAR Test File<br>- تحميل/حفظ التوقيعات من CSV<br>- تحديث تلقائي |

### 2. Heuristic Analyzer
| الملف | `ShieldAI.Core/Detection/HeuristicAnalyzer.cs` |
|-------|------------------------------------------------|
| **الوظيفة** | تحليل سلوكي للملفات التنفيذية |
| **يكتشف** | - APIs خطيرة (Process Injection, Keylogging)<br>- Packers/Crypters<br>- High Entropy<br>- Suspicious PE Sections<br>- PowerShell Encoded Commands |

### 3. ML.NET Classifier
| الملف | `ShieldAI.Core/ML/MalwareClassifier.cs` |
|-------|----------------------------------------|
| **الوظيفة** | تصنيف باستخدام Machine Learning |
| **النموذج** | Binary Classification (FastTree) |
| **الميزات** | - تدريب على بيانات مخصصة<br>- Rule-based fallback<br>- Probability scoring |

### 4. VirusTotal Integration
| الملف | `ShieldAI.Core/Detection/VirusTotalClient.cs` |
|-------|----------------------------------------------|
| **الوظيفة** | فحص عبر 70+ محرك antivirus |
| **الميزات** | - API v3<br>- Cache للنتائج<br>- Upload support (up to 32MB)<br>- Rate limiting |

### 5. Deep Analyzer
| الملف | `ShieldAI.Core/ML/DeepAnalyzer.cs` |
|-------|-----------------------------------|
| **الوظيفة** | تحليل شامل يجمع كل المحركات |
| **المراحل** | 1. Signature Check<br>2. Heuristic Analysis<br>3. ML Detection<br>4. VirusTotal Scan |
| **الإخراج** | Risk Score, Confidence, Verdict, Detailed Findings |

---

## 🖥️ واجهة المستخدم (WPF)

### الصفحات
| الصفحة | الملفات | الوصف |
|--------|---------|-------|
| Dashboard | `DashboardView.xaml` | لوحة تحكم رئيسية |
| Scan | `ScanView.xaml` | فحص الملفات والمجلدات |
| **AI Scan** | `AIScanView.xaml` | تحليل عميق بالذكاء الاصطناعي |
| Quarantine | `QuarantineView.xaml` | إدارة الملفات المحجورة |
| Settings | `SettingsView.xaml` | الإعدادات + VirusTotal API Key |
| Logs | `LogsView.xaml` | سجل الأحداث |

### التصميم
- 🎨 **Glass Effect** - تأثير زجاجي شفاف
- 🌙 **Dark Theme** - سمة داكنة عصرية
- 📱 **Responsive** - تصميم متجاوب
- ✨ **Animations** - تحريكات سلسة

### Converters المتاحة
- `BoolToVisibilityConverter`
- `InverseBoolToVisibilityConverter`
- `StringToVisibilityConverter`
- `FileSizeConverter`
- `RiskToColorConverter`

---

## ⚙️ الإعدادات

### AppSettings.cs
```csharp
// Paths
QuarantinePath, LogPath, SignatureDatabasePath, MLModelPath

// VirusTotal
VirusTotalApiKey, UseVirusTotalInAIScan, AllowVirusTotalUpload

// Scanning
MaxFileSizeMB, ExcludedExtensions, ExcludedFolders

// AI Scan
EnableDeepAnalysis, AnalysisTimeoutSeconds

// Protection
RealTimeProtection, AutoQuarantine
```

---

## 🔧 البنية التقنية

### المشاريع
```
ShieldAI.sln
├── ShieldAI.Core/      # المحرك الأساسي
├── ShieldAI.UI/        # واجهة WPF
├── ShieldAI.Service/   # Windows Service
└── ShieldAI.Tests/     # Unit Tests
```

### التقنيات
- **.NET 8.0** - Framework
- **WPF** - واجهة المستخدم
- **ML.NET** - Machine Learning
- **VirusTotal API v3** - Cloud Scanning
- **Named Pipes** - IPC Communication

---

## 📊 AI Scan Feature

### الميزات
- ✅ Drag & Drop للملفات
- ✅ Progress Bar مع مراحل التحليل
- ✅ نتائج تفصيلية مع درجة الخطورة
- ✅ تصدير تقرير (TXT/JSON)
- ✅ عزل الملفات الخبيثة

### نتائج التحليل
| الحقل | الوصف |
|-------|-------|
| Verdict | Clean / Suspicious / Malicious |
| Risk Score | 0-100% |
| Confidence | مستوى الثقة |
| Findings | قائمة المؤشرات المكتشفة |

---

## 🚀 التشغيل

```powershell
# Build
dotnet build ShieldAI.sln

# Run UI
dotnet run --project ShieldAI.UI

# Run Tests
dotnet test ShieldAI.Tests
```

---

## 📝 ملاحظات التطوير

### الحالة الحالية
- ✅ Core Engine - مكتمل
- ✅ UI - مكتمل
- ✅ Detection Engines - مكتمل
- ⚠️ Service - يحتاج تحديث APIs
- ✅ Tests - 30/30 ناجح

### التحسينات المستقبلية
- [ ] Real-time Protection Worker
- [ ] Scheduled Scans
- [ ] Cloud Signature Updates
- [ ] Browser Extension Integration
- [ ] Email Scanning
