// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/ScannerTests.cs
// اختبارات الماسح
// =====================================================

using ShieldAI.Core.Scanning;
using ShieldAI.Core.Models;
using Xunit;

namespace ShieldAI.Tests
{
    /// <summary>
    /// اختبارات وحدة للماسح
    /// </summary>
    public class ScannerTests
    {
        private readonly FileScanner _scanner;
        private readonly string _testDirectory;

        public ScannerTests()
        {
            _scanner = new FileScanner();
            _testDirectory = Path.Combine(Path.GetTempPath(), "ShieldAI_Tests");
            Directory.CreateDirectory(_testDirectory);
        }

        [Fact]
        public void FileScanner_Creation_Succeeds()
        {
            // Assert
            Assert.NotNull(_scanner);
        }

        [Fact]
        public async Task ScanFileAsync_WithCleanFile_ReturnsResult()
        {
            // Arrange
            var testFile = Path.Combine(_testDirectory, "clean_test.txt");
            File.WriteAllText(testFile, "This is a clean test file");
            
            try
            {
                // Act
                var result = await _scanner.ScanFileAsync(testFile);
                
                // Assert
                Assert.NotNull(result);
            }
            finally
            {
                if (File.Exists(testFile))
                    File.Delete(testFile);
            }
        }

        [Fact]
        public async Task ScanFileAsync_WithNonExistentFile_HandlesGracefully()
        {
            // Arrange
            var nonExistentFile = Path.Combine(_testDirectory, "non_existent.exe");
            
            // Act
            var result = await _scanner.ScanFileAsync(nonExistentFile);
            
            // Assert - يجب أن يتعامل مع الملف غير الموجود بشكل صحيح
            Assert.NotNull(result);
        }

        [Fact]
        public async Task ScanDirectoryAsync_WithEmptyDirectory_ReturnsResults()
        {
            // Arrange
            var emptyDir = Path.Combine(_testDirectory, "empty_dir");
            if (!Directory.Exists(emptyDir))
                Directory.CreateDirectory(emptyDir);
            
            try
            {
                // Act
                var results = await _scanner.ScanDirectoryAsync(emptyDir);
                
                // Assert
                Assert.NotNull(results);
            }
            finally
            {
                if (Directory.Exists(emptyDir))
                    Directory.Delete(emptyDir);
            }
        }
    }
}
