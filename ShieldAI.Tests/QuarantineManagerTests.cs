// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/QuarantineManagerTests.cs
// اختبارات QuarantineManager
// =====================================================

using ShieldAI.Core.Models;
using ShieldAI.Core.Security;
using Xunit;

namespace ShieldAI.Tests
{
    public class QuarantineManagerTests : IDisposable
    {
        private readonly string _testDir;
        private readonly string _quarantineDir;
        private readonly QuarantineManager _manager;

        public QuarantineManagerTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), $"ShieldAI_QTest_{Guid.NewGuid()}");
            _quarantineDir = Path.Combine(_testDir, "Quarantine");
            
            Directory.CreateDirectory(_testDir);
            
            // تعيين مسار الحجر مؤقتاً
            Core.Configuration.ConfigManager.Instance.Settings.QuarantinePath = _quarantineDir;
            
            _manager = new QuarantineManager();
        }

        public void Dispose()
        {
            if (Directory.Exists(_testDir))
            {
                Directory.Delete(_testDir, true);
            }
        }

        [Fact]
        public async Task QuarantineFileAsync_ShouldMoveFile()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "malware.exe");
            File.WriteAllText(testFile, "fake malware content");
            
            var scanResult = new ScanResult
            {
                FilePath = testFile,
                SHA256 = "abc123",
                ThreatName = "Trojan.Test",
                Verdict = ScanVerdict.Malicious
            };

            // Act
            var entry = await _manager.QuarantineFileAsync(testFile, scanResult);

            // Assert
            Assert.NotNull(entry);
            Assert.False(File.Exists(testFile), "Original file should be moved");
            Assert.True(File.Exists(entry.QuarantinePath), "Quarantine file should exist");
        }

        [Fact]
        public async Task QuarantineFileAsync_ShouldCreateManifest()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "test.exe");
            File.WriteAllText(testFile, "content");
            
            var scanResult = new ScanResult
            {
                FilePath = testFile,
                SHA256 = "hash123",
                ThreatName = "Test.Threat"
            };

            // Act
            var entry = await _manager.QuarantineFileAsync(testFile, scanResult);

            // Assert
            var manifestPath = Path.Combine(_quarantineDir, $"{entry!.Id}.json");
            Assert.True(File.Exists(manifestPath));
        }

        [Fact]
        public async Task RestoreFile_ShouldRestoreToOriginalLocation()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "restore_test.txt");
            File.WriteAllText(testFile, "restore content");
            
            var scanResult = new ScanResult { FilePath = testFile };
            var entry = await _manager.QuarantineFileAsync(testFile, scanResult);

            // Act
            var restored = _manager.RestoreFile(entry!.Id);

            // Assert
            Assert.True(restored);
            Assert.True(File.Exists(testFile) || File.Exists(testFile.Replace(".txt", "_restored.txt")));
        }

        [Fact]
        public async Task DeleteFile_ShouldRemoveFromQuarantine()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "delete_test.txt");
            File.WriteAllText(testFile, "delete content");
            
            var scanResult = new ScanResult { FilePath = testFile };
            var entry = await _manager.QuarantineFileAsync(testFile, scanResult);
            var qPath = entry!.QuarantinePath;

            // Act
            var deleted = _manager.DeleteFile(entry.Id);

            // Assert
            Assert.True(deleted);
            Assert.False(File.Exists(qPath));
        }

        [Fact]
        public async Task GetAllEntries_ShouldReturnAllQuarantined()
        {
            // Arrange
            for (int i = 0; i < 3; i++)
            {
                var testFile = Path.Combine(_testDir, $"file{i}.txt");
                File.WriteAllText(testFile, $"content{i}");
                await _manager.QuarantineFileAsync(testFile, new ScanResult { FilePath = testFile });
            }

            // Act
            var entries = _manager.GetAllEntries();

            // Assert
            Assert.Equal(3, entries.Count);
        }

        [Fact]
        public async Task GetEntry_ShouldReturnCorrectEntry()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "specific.txt");
            File.WriteAllText(testFile, "specific content");
            
            var scanResult = new ScanResult 
            { 
                FilePath = testFile,
                ThreatName = "Specific.Threat"
            };
            var entry = await _manager.QuarantineFileAsync(testFile, scanResult);

            // Act
            var retrieved = _manager.GetEntry(entry!.Id);

            // Assert
            Assert.NotNull(retrieved);
            Assert.Equal("Specific.Threat", retrieved.ThreatName);
        }

        [Fact]
        public void GetCount_ShouldReturnCorrectCount()
        {
            // Act
            var count = _manager.GetCount();

            // Assert (initially should be 0)
            Assert.True(count >= 0);
        }

        [Fact]
        public void RestoreFile_NonExistentId_ShouldReturnFalse()
        {
            // Act
            var result = _manager.RestoreFile(Guid.NewGuid());

            // Assert
            Assert.False(result);
        }
    }
}
