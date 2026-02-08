// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/FileEnumeratorTests.cs
// اختبارات FileEnumerator
// =====================================================

using ShieldAI.Core.Scanning;
using Xunit;

namespace ShieldAI.Tests
{
    public class FileEnumeratorTests : IDisposable
    {
        private readonly string _testDir;
        private readonly FileEnumerator _enumerator;

        public FileEnumeratorTests()
        {
            // إنشاء مجلد اختبار
            _testDir = Path.Combine(Path.GetTempPath(), $"ShieldAI_Test_{Guid.NewGuid()}");
            Directory.CreateDirectory(_testDir);
            
            // إنشاء ملفات
            File.WriteAllText(Path.Combine(_testDir, "file1.txt"), "content1");
            File.WriteAllText(Path.Combine(_testDir, "file2.exe"), "content2");
            File.WriteAllText(Path.Combine(_testDir, "file3.dll"), "content3");
            
            // مجلد فرعي
            var subDir = Path.Combine(_testDir, "subdir");
            Directory.CreateDirectory(subDir);
            File.WriteAllText(Path.Combine(subDir, "file4.txt"), "content4");
            
            _enumerator = new FileEnumerator();
        }

        public void Dispose()
        {
            if (Directory.Exists(_testDir))
            {
                Directory.Delete(_testDir, true);
            }
        }

        [Fact]
        public void EnumerateFiles_ShouldFindAllFiles()
        {
            // Act
            var files = _enumerator.EnumerateFiles(_testDir).ToList();

            // Assert
            Assert.True(files.Count >= 4);
        }

        [Fact]
        public void EnumerateFiles_NonRecursive_ShouldOnlyFindTopLevel()
        {
            // Act
            var files = _enumerator.EnumerateFiles(_testDir, recursive: false).ToList();

            // Assert
            Assert.Equal(3, files.Count);
        }

        [Fact]
        public void EnumerateFiles_SingleFile_ShouldReturnIt()
        {
            // Arrange
            var filePath = Path.Combine(_testDir, "file1.txt");

            // Act
            var files = _enumerator.EnumerateFiles(filePath).ToList();

            // Assert
            Assert.Single(files);
            Assert.Equal("file1.txt", files[0].Name);
        }

        [Fact]
        public void EnumerateFiles_NonExistentPath_ShouldReturnEmpty()
        {
            // Act
            var files = _enumerator.EnumerateFiles(@"C:\NonExistent\Path").ToList();

            // Assert
            Assert.Empty(files);
        }

        [Fact]
        public void CountFiles_ShouldReturnCorrectCount()
        {
            // Act
            var count = _enumerator.CountFiles(_testDir);

            // Assert
            Assert.True(count >= 4);
        }

        [Fact]
        public void EnumerateFiles_ShouldNotThrowOnAccessDenied()
        {
            // Act & Assert - should not throw
            var files = _enumerator.EnumerateFiles(@"C:\Windows\System32").Take(100).ToList();
            // Just checking it doesn't crash
        }

        [Fact]
        public void EstimateFileCount_ShouldReturnReasonableEstimate()
        {
            // Act
            var count = _enumerator.EstimateFileCount(new[] { _testDir });

            // Assert
            Assert.True(count >= 4);
        }

        [Fact]
        public void EnumerateFiles_ShouldReturnFileInfo()
        {
            // Act
            var files = _enumerator.EnumerateFiles(_testDir).ToList();

            // Assert
            foreach (var file in files)
            {
                Assert.NotNull(file.FullName);
                Assert.True(file.Exists);
            }
        }
    }
}
