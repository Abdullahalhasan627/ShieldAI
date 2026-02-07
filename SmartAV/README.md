# SmartAV - مكافح فيروسات ذكي بالذكاء الاصطناعي

مشروع مكافح فيروسات متقدم يستخدم الذكاء الاصطناعي (ONNX Runtime) لاكتشاف التهديدات.

## المتطلبات

### أدوات البناء (اختر واحدة):

| الخيار | الوصف | الرابط |
|--------|-------|--------|
| **MSVC Build Tools** | أدوات Microsoft الرسمية | [تحميل](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) |
| **MinGW-w64** | مترجم GCC لـ Windows | [تحميل](https://www.mingw-w64.org/downloads/) |

### CMake
- **الإصدار:** 3.20 أو أحدث
- **تحميل:** https://cmake.org/download/

### ONNX Runtime (مطلوب للذكاء الاصطناعي)
- **الإصدار الموصى:** 1.16.3
- **تحميل:** https://github.com/microsoft/onnxruntime/releases/tag/v1.16.3
- **الملف:** `onnxruntime-win-x64-1.16.3.zip`

---

## تثبيت ONNX Runtime

1. حمّل `onnxruntime-win-x64-1.16.3.zip`
2. أنشئ مجلد `external/onnxruntime/`
3. استخرج المحتويات:

```
SmartAV/
└── external/
    └── onnxruntime/
        ├── include/
        │   ├── onnxruntime_c_api.h
        │   ├── onnxruntime_cxx_api.h
        │   └── ...
        └── lib/
            ├── onnxruntime.lib
            └── onnxruntime.dll
```

---

## البناء

### الطريقة 1: استخدام build.bat (الأسهل)

```batch
cd SmartAV
build.bat
```

### الطريقة 2: CMake يدوياً

```batch
cd SmartAV
mkdir build
cd build

# باستخدام Visual Studio
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release

# أو باستخدام MinGW
cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

### الطريقة 3: بدون ONNX Runtime

يمكن البناء بدون دعم الذكاء الاصطناعي:

```batch
cmake -DONNXRUNTIME_ROOT="" ..
cmake --build . --config Release
```

---

## هيكل المشروع

```
SmartAV/
├── AI/                     # محرك الذكاء الاصطناعي
│   ├── AIDetector.h
│   └── AIDetector.cpp
├── Core/                   # المحرك الأساسي
│   ├── FileScanner.h/cpp   # فحص الملفات
│   ├── FeatureExtractor.h/cpp  # استخراج الخصائص
│   ├── RealTimeMonitor.h/cpp   # المراقبة اللحظية
│   └── ProcessAnalyzer.h/cpp   # تحليل العمليات
├── Security/               # وحدات الأمان
│   ├── Quarantine.h/cpp    # الحجر الصحي
│   └── SelfProtection.h/cpp    # الحماية الذاتية
├── Service/                # خدمة Windows
│   ├── ServiceModule.h
│   └── ServiceModule.cpp
├── UI/                     # واجهة المستخدم
│   ├── MainWindow.h
│   └── MainWindow.cpp
├── external/               # المكتبات الخارجية
│   └── onnxruntime/
├── main.cpp
├── CMakeLists.txt
├── build.bat
└── README.md
```

---

## التشغيل

```batch
# تشغيل عادي (GUI)
SmartAV.exe

# تثبيت كخدمة (يتطلب Administrator)
SmartAV.exe --install

# تشغيل كخدمة
net start SmartAVService

# إلغاء التثبيت
SmartAV.exe --uninstall
```

---

## الميزات

- ✅ فحص الملفات بالذكاء الاصطناعي (ONNX)
- ✅ المراقبة اللحظية (Real-Time Protection)
- ✅ تحليل العمليات والسلوكيات
- ✅ الحجر الصحي المشفر (AES-256)
- ✅ الحماية الذاتية
- ✅ خدمة Windows مستقلة
- ✅ واجهة مستخدم Win32

---

## الترخيص

هذا المشروع للأغراض التعليمية.

---

## المساهمة

نرحب بالمساهمات! يرجى فتح Issue أو Pull Request.
