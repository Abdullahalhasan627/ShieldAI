// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Core/Updates/UpdateManager.cs
// إدارة التحديثات (Signatures/ML Model/Rules)
// =====================================================

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ShieldAI.Core.Updates
{
    public enum UpdateChannel
    {
        Signatures,
        MlModel,
        Rules
    }

    public class UpdatePackageInfo
    {
        public UpdateChannel Channel { get; set; }
        public string Version { get; set; } = "0.0.0";
        public string DownloadUrl { get; set; } = "";
        public string HmacBase64 { get; set; } = "";
    }

    public class UpdateApplyResult
    {
        public bool Success { get; set; }
        public string? Message { get; set; }
    }

    /// <summary>
    /// مدير التحديثات - يدعم التحقق والنسخ الاحتياطي والرجوع
    /// </summary>
    public class UpdateManager
    {
        private readonly string _updateRoot;
        private readonly string _statePath;
        private readonly byte[] _hmacKey;

        public UpdateManager(string? updateRoot = null, byte[]? hmacKey = null)
        {
            _updateRoot = updateRoot ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "ShieldAI", "Updates");
            _statePath = Path.Combine(_updateRoot, "update_state.json");
            _hmacKey = hmacKey ?? Encoding.UTF8.GetBytes("ShieldAI.Update.Key.2026");
            Directory.CreateDirectory(_updateRoot);
        }

        public async Task<UpdatePackageInfo?> CheckForUpdatesAsync(UpdateChannel channel, CancellationToken ct = default)
        {
            // Placeholder: يمكن ربطها بسيرفر حقيقي لاحقاً
            await Task.Delay(50, ct);
            return null;
        }

        public async Task<UpdateApplyResult> ApplyUpdateAsync(UpdatePackageInfo package, byte[] packageBytes, CancellationToken ct = default)
        {
            try
            {
                if (!VerifyPackage(packageBytes, package.HmacBase64))
                {
                    return new UpdateApplyResult { Success = false, Message = "فشل التحقق من سلامة الحزمة" };
                }

                var channelDir = Path.Combine(_updateRoot, package.Channel.ToString());
                Directory.CreateDirectory(channelDir);

                var currentPath = Path.Combine(channelDir, "current.bin");
                var backupPath = Path.Combine(channelDir, $"backup_{DateTime.UtcNow:yyyyMMddHHmmss}.bin");

                if (File.Exists(currentPath))
                {
                    File.Copy(currentPath, backupPath, true);
                }

                await File.WriteAllBytesAsync(currentPath, packageBytes, ct);
                await SaveStateAsync(package.Channel, package.Version, ct);

                return new UpdateApplyResult { Success = true, Message = "تم تحديث الحزمة بنجاح" };
            }
            catch (Exception ex)
            {
                return new UpdateApplyResult { Success = false, Message = ex.Message };
            }
        }

        public async Task<UpdateApplyResult> RollbackAsync(UpdateChannel channel, CancellationToken ct = default)
        {
            var channelDir = Path.Combine(_updateRoot, channel.ToString());
            if (!Directory.Exists(channelDir))
                return new UpdateApplyResult { Success = false, Message = "لا يوجد نسخ احتياطية" };

            var backups = Directory.GetFiles(channelDir, "backup_*.bin")
                .OrderByDescending(f => f)
                .ToList();
            if (backups.Count == 0)
                return new UpdateApplyResult { Success = false, Message = "لا يوجد نسخ احتياطية" };

            var currentPath = Path.Combine(channelDir, "current.bin");
            File.Copy(backups[0], currentPath, true);
            await Task.Delay(10, ct);

            return new UpdateApplyResult { Success = true, Message = "تم الرجوع بنجاح" };
        }

        public bool VerifyPackage(byte[] data, string hmacBase64)
        {
            try
            {
                var expected = Convert.FromBase64String(hmacBase64);
                using var hmac = new HMACSHA256(_hmacKey);
                var actual = hmac.ComputeHash(data);
                return CryptographicOperations.FixedTimeEquals(expected, actual);
            }
            catch
            {
                return false;
            }
        }

        private async Task SaveStateAsync(UpdateChannel channel, string version, CancellationToken ct)
        {
            var state = new Dictionary<string, string>();
            if (File.Exists(_statePath))
            {
                try
                {
                    var json = await File.ReadAllTextAsync(_statePath, ct);
                    var existing = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                    if (existing != null)
                        state = existing;
                }
                catch { }
            }

            state[channel.ToString()] = version;
            var outJson = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_statePath, outJson, ct);
        }
    }
}
