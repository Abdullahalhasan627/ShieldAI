// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Monitoring/Quarantine/QuarantineCrypto.cs
// تشفير آمن باستخدام DPAPI + AES
// =====================================================

using System.Security.Cryptography;

namespace ShieldAI.Core.Monitoring.Quarantine
{
    /// <summary>
    /// تشفير آمن للحجر الصحي
    /// يستخدم DPAPI لحماية مفتاح AES بدلاً من مفتاح ثابت
    /// </summary>
    public class QuarantineCrypto
    {
        private readonly string _keyFilePath;
        private byte[]? _cachedKey;
        private readonly object _keyLock = new();

        public QuarantineCrypto(string quarantinePath)
        {
            _keyFilePath = Path.Combine(quarantinePath, ".keystore");
        }

        /// <summary>
        /// حساب HMAC باستخدام مفتاح الحجر
        /// </summary>
        public byte[] ComputeHmac(byte[] data)
        {
            var key = GetOrCreateKey();
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(data);
        }

        public static string ComputeSha256(byte[] data)
        {
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(data);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        /// <summary>
        /// تشفير البيانات
        /// </summary>
        public byte[] Encrypt(byte[] plainData)
        {
            var key = GetOrCreateKey();

            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var encryptedData = encryptor.TransformFinalBlock(plainData, 0, plainData.Length);

            // حساب HMAC للتحقق من السلامة
            var dataToSign = new byte[aes.IV.Length + encryptedData.Length];
            Buffer.BlockCopy(aes.IV, 0, dataToSign, 0, aes.IV.Length);
            Buffer.BlockCopy(encryptedData, 0, dataToSign, aes.IV.Length, encryptedData.Length);
            var mac = ComputeHmac(dataToSign);

            // الهيكل: [IV:16][EncryptedData][HMAC:32]
            var result = new byte[aes.IV.Length + encryptedData.Length + mac.Length];
            Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
            Buffer.BlockCopy(encryptedData, 0, result, aes.IV.Length, encryptedData.Length);
            Buffer.BlockCopy(mac, 0, result, aes.IV.Length + encryptedData.Length, mac.Length);

            return result;
        }

        /// <summary>
        /// فك تشفير البيانات
        /// </summary>
        public byte[] Decrypt(byte[] encryptedPackage)
        {
            var key = GetOrCreateKey();

            if (encryptedPackage.Length < 16 + 32) // IV + HMAC minimum
                throw new CryptographicException("البيانات المشفرة غير صالحة");

            // استخراج الأجزاء
            var iv = new byte[16];
            Buffer.BlockCopy(encryptedPackage, 0, iv, 0, 16);

            var macOffset = encryptedPackage.Length - 32;
            var storedMac = new byte[32];
            Buffer.BlockCopy(encryptedPackage, macOffset, storedMac, 0, 32);

            var encryptedData = new byte[macOffset - 16];
            Buffer.BlockCopy(encryptedPackage, 16, encryptedData, 0, encryptedData.Length);

            // التحقق من HMAC
            var dataToVerify = new byte[16 + encryptedData.Length];
            Buffer.BlockCopy(iv, 0, dataToVerify, 0, 16);
            Buffer.BlockCopy(encryptedData, 0, dataToVerify, 16, encryptedData.Length);
            var computedMac = ComputeHmac(dataToVerify);

            if (!CryptographicOperations.FixedTimeEquals(storedMac, computedMac))
                throw new CryptographicException("فشل التحقق من سلامة البيانات - الملف قد يكون تالفاً");

            // فك التشفير
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        }

        /// <summary>
        /// الحصول على المفتاح أو إنشاء واحد جديد
        /// </summary>
        private byte[] GetOrCreateKey()
        {
            lock (_keyLock)
            {
                if (_cachedKey != null)
                    return _cachedKey;

                if (File.Exists(_keyFilePath))
                {
                    try
                    {
                        var protectedKey = File.ReadAllBytes(_keyFilePath);
                        _cachedKey = ProtectedData.Unprotect(
                            protectedKey,
                            GetEntropy(),
                            DataProtectionScope.CurrentUser);
                        return _cachedKey;
                    }
                    catch
                    {
                        // إذا فشل فك الحماية، ننشئ مفتاح جديد
                    }
                }

                // إنشاء مفتاح جديد
                _cachedKey = new byte[32];
                RandomNumberGenerator.Fill(_cachedKey);

                // حماية المفتاح بـ DPAPI
                var protectedNewKey = ProtectedData.Protect(
                    _cachedKey,
                    GetEntropy(),
                    DataProtectionScope.CurrentUser);

                // حفظ المفتاح المحمي
                var keyDir = Path.GetDirectoryName(_keyFilePath);
                if (!string.IsNullOrEmpty(keyDir) && !Directory.Exists(keyDir))
                    Directory.CreateDirectory(keyDir);

                File.WriteAllBytes(_keyFilePath, protectedNewKey);

                // إخفاء ملف المفتاح
                try
                {
                    File.SetAttributes(_keyFilePath,
                        FileAttributes.Hidden | FileAttributes.System);
                }
                catch { }

                return _cachedKey;
            }
        }

        /// <summary>
        /// بيانات إضافية لـ DPAPI (entropy)
        /// </summary>
        private static byte[] GetEntropy()
        {
            return "ShieldAI.Quarantine.2024"u8.ToArray();
        }
    }
}
