// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/AtomicQuarantineTests.cs
// اختبارات الحجر الذري - ملف مقفول، إنشاء سريع، إعادة محاولة
// =====================================================

using ShieldAI.Core.Detection.ThreatScoring;
using ShieldAI.Core.Monitoring.Quarantine;
using Xunit;

namespace ShieldAI.Tests
{
    public class AtomicQuarantineTests : IDisposable
    {
        private readonly string _testDir;
        private readonly string _quarantineDir;
        private readonly QuarantineStore _store;

        public AtomicQuarantineTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), $"ShieldAI_AQTest_{Guid.NewGuid():N}");
            _quarantineDir = Path.Combine(_testDir, "Quarantine");
            Directory.CreateDirectory(_testDir);
            _store = new QuarantineStore(_quarantineDir);
        }

        public void Dispose()
        {
            _store.Dispose();
            try { if (Directory.Exists(_testDir)) Directory.Delete(_testDir, true); } catch { }
        }

        #region Atomic Move Tests

        [Fact]
        public async Task AtomicMove_UnlockedFile_ShouldSucceedOnFirstAttempt()
        {
            // Arrange
            var filePath = Path.Combine(_testDir, "unlocked.txt");
            File.WriteAllText(filePath, "test content for atomic move");

            // Act
            var (success, movedPath) = await _store.TryAtomicMoveToQuarantineAsync(
                filePath, maxRetries: 3, initialDelayMs: 10, maxDelayMs: 50);

            // Assert
            Assert.True(success);
            Assert.NotNull(movedPath);
            Assert.False(File.Exists(filePath), "Original file should no longer exist");
            Assert.True(File.Exists(movedPath), "Moved file should exist in quarantine");
            Assert.Equal("test content for atomic move", File.ReadAllText(movedPath));
        }

        [Fact]
        public async Task AtomicMove_NonExistentFile_ShouldReturnFalse()
        {
            var filePath = Path.Combine(_testDir, "does_not_exist.txt");

            var (success, movedPath) = await _store.TryAtomicMoveToQuarantineAsync(
                filePath, maxRetries: 2, initialDelayMs: 10, maxDelayMs: 50);

            Assert.False(success);
            Assert.Null(movedPath);
        }

        [Fact]
        public async Task AtomicMove_LockedFile_ShouldRetryAndFail()
        {
            // Arrange
            var filePath = Path.Combine(_testDir, "locked.txt");
            File.WriteAllText(filePath, "locked content");

            // Lock the file with exclusive access
            using var lockStream = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

            // Act - should fail after retries because file is locked
            var (success, movedPath) = await _store.TryAtomicMoveToQuarantineAsync(
                filePath, maxRetries: 3, initialDelayMs: 10, maxDelayMs: 30);

            // Assert
            Assert.False(success);
            Assert.Null(movedPath);
            Assert.True(File.Exists(filePath), "Locked file should still exist");
        }

        [Fact]
        public async Task AtomicMove_FileReleasedDuringRetry_ShouldSucceed()
        {
            // Arrange
            var filePath = Path.Combine(_testDir, "release_during_retry.txt");
            File.WriteAllText(filePath, "will be released");

            var lockStream = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

            // Release the file after a short delay
            _ = Task.Run(async () =>
            {
                await Task.Delay(120);
                lockStream.Dispose();
            });

            // Act - should succeed after the lock is released
            var (success, movedPath) = await _store.TryAtomicMoveToQuarantineAsync(
                filePath, maxRetries: 6, initialDelayMs: 50, maxDelayMs: 200);

            // Assert
            Assert.True(success);
            Assert.NotNull(movedPath);
            Assert.False(File.Exists(filePath));
            Assert.True(File.Exists(movedPath));
        }

        #endregion

        #region QuarantineMovedFile Tests

        [Fact]
        public async Task QuarantineMovedFile_ShouldEncryptAndTrackOriginalPath()
        {
            // Arrange
            var originalPath = Path.Combine(_testDir, "original.exe");
            File.WriteAllText(originalPath, "fake exe payload");

            // Simulate atomic move
            var (success, movedPath) = await _store.TryAtomicMoveToQuarantineAsync(
                originalPath, maxRetries: 2, initialDelayMs: 10, maxDelayMs: 50);
            Assert.True(success);
            Assert.NotNull(movedPath);

            var scanResult = new AggregatedThreatResult
            {
                FilePath = originalPath,
                RiskScore = 75,
                Verdict = AggregatedVerdict.Quarantine,
                Reasons = new List<string> { "Quick Gate: Score 45" }
            };

            // Act
            var metadata = await _store.QuarantineMovedFileAsync(movedPath!, originalPath, scanResult);

            // Assert
            Assert.NotNull(metadata);
            Assert.Equal(originalPath, metadata.OriginalPath);
            Assert.Equal("original.exe", metadata.OriginalName);
            Assert.Equal(75, metadata.RiskScore);
            Assert.Contains("Quick Gate: Score 45", metadata.Reasons);
            Assert.NotEmpty(metadata.Sha256Hash);
            Assert.False(File.Exists(movedPath), "Pending file should be cleaned up");
            Assert.Equal(1, _store.Count);
        }

        [Fact]
        public async Task QuarantineMovedFile_NonExistent_ShouldReturnNull()
        {
            var result = await _store.QuarantineMovedFileAsync(
                Path.Combine(_testDir, "gone.pending"),
                Path.Combine(_testDir, "original.exe"));

            Assert.Null(result);
        }

        [Fact]
        public async Task QuarantineMovedFile_ThenRestore_ShouldPreserveContent()
        {
            // Arrange
            var originalPath = Path.Combine(_testDir, "restore_test.bin");
            var content = new byte[1024];
            new Random(99).NextBytes(content);
            File.WriteAllBytes(originalPath, content);

            var (success, movedPath) = await _store.TryAtomicMoveToQuarantineAsync(
                originalPath, maxRetries: 2, initialDelayMs: 10, maxDelayMs: 50);
            Assert.True(success);

            var metadata = await _store.QuarantineMovedFileAsync(movedPath!, originalPath);
            Assert.NotNull(metadata);

            // Act - restore to a safe path (original is in Temp which IsRestorePathSafe rejects)
            var safePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                $"shieldai_restore_test_{Guid.NewGuid():N}.bin");
            try
            {
                var restored = await _store.RestoreFileAsync(metadata.Id, safePath);

                // Assert
                Assert.True(restored);
                Assert.True(File.Exists(safePath));
                Assert.Equal(content, File.ReadAllBytes(safePath));
            }
            finally
            {
                try { if (File.Exists(safePath)) File.Delete(safePath); } catch { }
            }
        }

        #endregion

        #region Rapid Create-Run Scenario

        [Fact]
        public async Task RapidCreateAndQuarantine_ShouldIsolateBeforeExecution()
        {
            // Simulate a rapid create-run scenario:
            // 1. File appears
            // 2. Quick gate detects it as suspicious
            // 3. Atomic move isolates it before it can run

            var filePath = Path.Combine(_testDir, "rapid_dropper.exe");
            File.WriteAllText(filePath, "MZ" + new string('X', 500)); // Fake PE header

            // Step 1: Atomic move (simulating quick gate response)
            var (success, movedPath) = await _store.TryAtomicMoveToQuarantineAsync(
                filePath, maxRetries: 3, initialDelayMs: 10, maxDelayMs: 50);

            Assert.True(success, "Atomic move should succeed immediately for new file");
            Assert.False(File.Exists(filePath), "Original file should be gone - cannot execute");

            // Step 2: Deep scan in quarantine
            var deepResult = new AggregatedThreatResult
            {
                FilePath = filePath,
                RiskScore = 90,
                Verdict = AggregatedVerdict.Block,
                Reasons = new List<string>
                {
                    "Quick Gate: Score 40",
                    "Deep scan confirmed malicious"
                }
            };

            var metadata = await _store.QuarantineMovedFileAsync(movedPath!, filePath, deepResult);

            Assert.NotNull(metadata);
            Assert.Equal(filePath, metadata.OriginalPath);
            Assert.Equal("Block", metadata.Verdict);
            Assert.Equal(90, metadata.RiskScore);
        }

        #endregion

        #region Concurrent Atomic Move Tests

        [Fact]
        public async Task ConcurrentAtomicMoves_ShouldNotCorruptStore()
        {
            // Create multiple files
            var files = new List<string>();
            for (int i = 0; i < 5; i++)
            {
                var f = Path.Combine(_testDir, $"concurrent_{i}.txt");
                File.WriteAllText(f, $"content_{i}");
                files.Add(f);
            }

            // Move all concurrently
            var moveTasks = files.Select(f =>
                _store.TryAtomicMoveToQuarantineAsync(f, maxRetries: 2, initialDelayMs: 10, maxDelayMs: 50));
            var moveResults = await Task.WhenAll(moveTasks);

            // All should succeed
            Assert.All(moveResults, r => Assert.True(r.Success));

            // Quarantine all moved files concurrently
            var quarantineTasks = moveResults.Select((r, i) =>
                _store.QuarantineMovedFileAsync(r.MovedPath!, files[i]));
            var metadatas = await Task.WhenAll(quarantineTasks);

            Assert.All(metadatas, m => Assert.NotNull(m));
            Assert.Equal(5, _store.Count);
        }

        #endregion
    }
}
