// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/StreamingHasherTests.cs
// اختبارات StreamingHasher
// =====================================================

using ShieldAI.Core.Scanning;
using Xunit;

namespace ShieldAI.Tests
{
    public class StreamingHasherTests : IDisposable
    {
        private readonly string _testFile;

        public StreamingHasherTests()
        {
            // إنشاء ملف اختبار
            _testFile = Path.GetTempFileName();
            File.WriteAllText(_testFile, "This is a test file for hashing.\nLine 2\nLine 3");
        }

        public void Dispose()
        {
            if (File.Exists(_testFile))
                File.Delete(_testFile);
        }

        [Fact]
        public async Task ComputeSHA256Async_ShouldReturnValidHash()
        {
            // Act
            var hash = await StreamingHasher.ComputeSHA256Async(_testFile);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(64, hash.Length); // SHA256 = 64 hex chars
            Assert.True(hash.All(c => "0123456789abcdef".Contains(c)));
        }

        [Fact]
        public async Task ComputeMD5Async_ShouldReturnValidHash()
        {
            // Act
            var hash = await StreamingHasher.ComputeMD5Async(_testFile);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(32, hash.Length); // MD5 = 32 hex chars
            Assert.True(hash.All(c => "0123456789abcdef".Contains(c)));
        }

        [Fact]
        public async Task ComputeBothAsync_ShouldReturnBothHashes()
        {
            // Act
            var (sha256, md5) = await StreamingHasher.ComputeBothAsync(_testFile);

            // Assert
            Assert.Equal(64, sha256.Length);
            Assert.Equal(32, md5.Length);
        }

        [Fact]
        public void ComputeSHA256_Sync_ShouldMatchAsync()
        {
            // Act
            var syncHash = StreamingHasher.ComputeSHA256(_testFile);
            var asyncHash = StreamingHasher.ComputeSHA256Async(_testFile).Result;

            // Assert
            Assert.Equal(asyncHash, syncHash);
        }

        [Fact]
        public async Task ComputeSHA256Async_SameContent_SameHash()
        {
            // Arrange
            var file2 = Path.GetTempFileName();
            File.WriteAllText(file2, "This is a test file for hashing.\nLine 2\nLine 3");

            try
            {
                // Act
                var hash1 = await StreamingHasher.ComputeSHA256Async(_testFile);
                var hash2 = await StreamingHasher.ComputeSHA256Async(file2);

                // Assert
                Assert.Equal(hash1, hash2);
            }
            finally
            {
                File.Delete(file2);
            }
        }

        [Fact]
        public async Task ComputeSHA256Async_DifferentContent_DifferentHash()
        {
            // Arrange
            var file2 = Path.GetTempFileName();
            File.WriteAllText(file2, "Different content here");

            try
            {
                // Act
                var hash1 = await StreamingHasher.ComputeSHA256Async(_testFile);
                var hash2 = await StreamingHasher.ComputeSHA256Async(file2);

                // Assert
                Assert.NotEqual(hash1, hash2);
            }
            finally
            {
                File.Delete(file2);
            }
        }

        [Fact]
        public async Task ComputeSHA256Async_EmptyFile_ShouldWork()
        {
            // Arrange
            var emptyFile = Path.GetTempFileName();
            File.WriteAllText(emptyFile, "");

            try
            {
                // Act
                var hash = await StreamingHasher.ComputeSHA256Async(emptyFile);

                // Assert
                Assert.NotNull(hash);
                // SHA256 of empty content
                Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
            }
            finally
            {
                File.Delete(emptyFile);
            }
        }

        [Fact]
        public async Task ComputeSHA256Async_LargeFile_ShouldWork()
        {
            // Arrange
            var largeFile = Path.GetTempFileName();
            var content = new byte[1024 * 1024]; // 1MB
            new Random().NextBytes(content);
            await File.WriteAllBytesAsync(largeFile, content);

            try
            {
                // Act
                var hash = await StreamingHasher.ComputeSHA256Async(largeFile);

                // Assert
                Assert.NotNull(hash);
                Assert.Equal(64, hash.Length);
            }
            finally
            {
                File.Delete(largeFile);
            }
        }
    }
}
