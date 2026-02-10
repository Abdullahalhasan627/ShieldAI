// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/QuarantineStoreTests.cs
// اختبارات QuarantineStore - تشفير/فك تشفير + metadata
// =====================================================

using ShieldAI.Core.Detection.ThreatScoring;
using ShieldAI.Core.Monitoring.Quarantine;
using Xunit;

namespace ShieldAI.Tests
{
    public class QuarantineStoreTests : IDisposable
    {
        private readonly string _testDir;
        private readonly string _quarantineDir;
        private readonly QuarantineStore _store;

        public QuarantineStoreTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), $"ShieldAI_QSTest_{Guid.NewGuid()}");
            _quarantineDir = Path.Combine(_testDir, "Quarantine");
            Directory.CreateDirectory(_testDir);

            _store = new QuarantineStore(_quarantineDir);
        }

        public void Dispose()
        {
            _store.Dispose();
            if (Directory.Exists(_testDir))
            {
                try { Directory.Delete(_testDir, true); } catch { }
            }
        }

        #region Encryption Roundtrip Tests

        [Fact]
        public async Task QuarantineAndRestore_ShouldPreserveContent()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "roundtrip.txt");
            var originalContent = "This is the original file content for roundtrip test!";
            File.WriteAllText(testFile, originalContent);

            // Act - quarantine
            var metadata = await _store.QuarantineFileAsync(testFile);

            // Assert - file should be removed
            Assert.NotNull(metadata);
            Assert.False(File.Exists(testFile), "Original file should be deleted after quarantine");

            // Act - restore
            var restored = await _store.RestoreFileAsync(metadata.Id);

            // Assert - content should match
            Assert.True(restored, "Restore should succeed");
            Assert.True(File.Exists(testFile), "Restored file should exist");
            var restoredContent = File.ReadAllText(testFile);
            Assert.Equal(originalContent, restoredContent);
        }

        [Fact]
        public async Task QuarantineAndRestore_BinaryFile_ShouldPreserveContent()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "binary.dat");
            var originalBytes = new byte[4096];
            new Random(42).NextBytes(originalBytes);
            File.WriteAllBytes(testFile, originalBytes);

            // Act
            var metadata = await _store.QuarantineFileAsync(testFile);
            Assert.NotNull(metadata);

            var restored = await _store.RestoreFileAsync(metadata.Id);

            // Assert
            Assert.True(restored);
            var restoredBytes = File.ReadAllBytes(testFile);
            Assert.Equal(originalBytes, restoredBytes);
        }

        [Fact]
        public async Task QuarantineAndRestore_LargeFile_ShouldPreserveContent()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "large.bin");
            var originalBytes = new byte[1024 * 1024]; // 1 MB
            new Random(123).NextBytes(originalBytes);
            File.WriteAllBytes(testFile, originalBytes);

            // Act
            var metadata = await _store.QuarantineFileAsync(testFile);
            Assert.NotNull(metadata);

            var restored = await _store.RestoreFileAsync(metadata.Id);

            // Assert
            Assert.True(restored);
            var restoredBytes = File.ReadAllBytes(testFile);
            Assert.Equal(originalBytes, restoredBytes);
        }

        #endregion

        #region Metadata Tests

        [Fact]
        public async Task QuarantineFile_ShouldStoreMetadata()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "metadata_test.exe");
            File.WriteAllText(testFile, "fake exe content");

            var scanResult = new AggregatedThreatResult
            {
                FilePath = testFile,
                RiskScore = 85,
                Verdict = AggregatedVerdict.Block,
                Reasons = new List<string> { "Signature match", "High entropy" },
                EngineResults = new List<ThreatScanResult>
                {
                    new() { EngineName = "SignatureEngine", Score = 95, Verdict = EngineVerdict.Malicious },
                    new() { EngineName = "HeuristicEngine", Score = 70, Verdict = EngineVerdict.Suspicious }
                }
            };

            // Act
            var metadata = await _store.QuarantineFileAsync(testFile, scanResult);

            // Assert
            Assert.NotNull(metadata);
            Assert.Equal(testFile, metadata.OriginalPath);
            Assert.Equal("metadata_test.exe", metadata.OriginalName);
            Assert.Equal("Block", metadata.Verdict);
            Assert.Equal(85, metadata.RiskScore);
            Assert.Equal(2, metadata.Reasons.Count);
            Assert.Contains("Signature match", metadata.Reasons);
            Assert.Equal(2, metadata.EngineSummaries.Count);
            Assert.NotEmpty(metadata.Sha256Hash);
        }

        [Fact]
        public async Task GetItem_ShouldReturnCorrectMetadata()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "get_item.txt");
            File.WriteAllText(testFile, "content");

            var metadata = await _store.QuarantineFileAsync(testFile);
            Assert.NotNull(metadata);

            // Act
            var retrieved = _store.GetItem(metadata.Id);

            // Assert
            Assert.NotNull(retrieved);
            Assert.Equal(metadata.Id, retrieved.Id);
            Assert.Equal(metadata.OriginalPath, retrieved.OriginalPath);
            Assert.Equal(metadata.Sha256Hash, retrieved.Sha256Hash);
        }

        [Fact]
        public async Task GetAllItems_ShouldReturnAll()
        {
            // Arrange
            for (int i = 0; i < 3; i++)
            {
                var f = Path.Combine(_testDir, $"item_{i}.txt");
                File.WriteAllText(f, $"content_{i}");
                await _store.QuarantineFileAsync(f);
            }

            // Act
            var items = _store.GetAllItems();

            // Assert
            Assert.Equal(3, items.Count);
        }

        [Fact]
        public async Task Count_ShouldTrackCorrectly()
        {
            Assert.Equal(0, _store.Count);

            var f1 = Path.Combine(_testDir, "count1.txt");
            File.WriteAllText(f1, "c1");
            await _store.QuarantineFileAsync(f1);
            Assert.Equal(1, _store.Count);

            var f2 = Path.Combine(_testDir, "count2.txt");
            File.WriteAllText(f2, "c2");
            await _store.QuarantineFileAsync(f2);
            Assert.Equal(2, _store.Count);
        }

        #endregion

        #region Hash Verification Tests

        [Fact]
        public async Task Restore_ShouldVerifyHash()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "hash_verify.txt");
            File.WriteAllText(testFile, "hash verification content");

            var metadata = await _store.QuarantineFileAsync(testFile);
            Assert.NotNull(metadata);
            Assert.NotEmpty(metadata.Sha256Hash);

            // Act - restore should verify hash
            var restored = await _store.RestoreFileAsync(metadata.Id);

            // Assert
            Assert.True(restored);
            Assert.True(File.Exists(testFile));
        }

        #endregion

        #region Delete Tests

        [Fact]
        public async Task DeleteFile_ShouldRemoveFromStore()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "delete_test.txt");
            File.WriteAllText(testFile, "delete me");

            var metadata = await _store.QuarantineFileAsync(testFile);
            Assert.NotNull(metadata);

            // Act
            var deleted = await _store.DeleteFileAsync(metadata.Id);

            // Assert
            Assert.True(deleted);
            Assert.Equal(0, _store.Count);
            Assert.Null(_store.GetItem(metadata.Id));
        }

        [Fact]
        public async Task DeleteFile_NonExistent_ShouldReturnFalse()
        {
            var result = await _store.DeleteFileAsync("nonexistent_id");
            Assert.False(result);
        }

        [Fact]
        public async Task ClearAll_ShouldRemoveEverything()
        {
            // Arrange
            for (int i = 0; i < 3; i++)
            {
                var f = Path.Combine(_testDir, $"clear_{i}.txt");
                File.WriteAllText(f, $"c_{i}");
                await _store.QuarantineFileAsync(f);
            }
            Assert.Equal(3, _store.Count);

            // Act
            await _store.ClearAllAsync();

            // Assert
            Assert.Equal(0, _store.Count);
        }

        #endregion

        #region Edge Cases

        [Fact]
        public async Task QuarantineFile_NonExistent_ShouldReturnNull()
        {
            var result = await _store.QuarantineFileAsync(
                Path.Combine(_testDir, "does_not_exist.txt"));
            Assert.Null(result);
        }

        [Fact]
        public async Task RestoreFile_NonExistent_ShouldReturnFalse()
        {
            var result = await _store.RestoreFileAsync("nonexistent_id");
            Assert.False(result);
        }

        [Fact]
        public async Task RestoreFile_ToCustomPath_ShouldWork()
        {
            // Arrange
            var testFile = Path.Combine(_testDir, "custom_restore.txt");
            var customPath = Path.Combine(_testDir, "restored_here.txt");
            File.WriteAllText(testFile, "custom restore content");

            var metadata = await _store.QuarantineFileAsync(testFile);
            Assert.NotNull(metadata);

            // Act
            var restored = await _store.RestoreFileAsync(metadata.Id, customPath);

            // Assert
            Assert.True(restored);
            Assert.True(File.Exists(customPath));
            Assert.Equal("custom restore content", File.ReadAllText(customPath));
        }

        #endregion
    }
}
