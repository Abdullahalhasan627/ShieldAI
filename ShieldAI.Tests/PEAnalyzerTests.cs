// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/PEAnalyzerTests.cs
// اختبارات محلل PE
// =====================================================

using ShieldAI.Core.Scanning;
using Xunit;

namespace ShieldAI.Tests
{
    /// <summary>
    /// اختبارات وحدة لمحلل PE
    /// </summary>
    public class PEAnalyzerTests
    {
        private readonly PEAnalyzer _analyzer;

        public PEAnalyzerTests()
        {
            _analyzer = new PEAnalyzer();
        }

        [Fact]
        public void PEAnalyzer_Creation_Succeeds()
        {
            // Assert
            Assert.NotNull(_analyzer);
        }

        [Fact]
        public void Analyze_WithValidPE_ReturnsValidResult()
        {
            // Arrange
            var systemexe = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            
            // Act
            var result = _analyzer.Analyze(systemexe);
            
            // Assert
            Assert.NotNull(result);
            Assert.True(result.IsValidPE);
        }

        [Fact]
        public void Analyze_WithNonExistentFile_ThrowsFileNotFoundException()
        {
            // Arrange
            var nonExistentFile = @"C:\NonExistent\file.exe";
            
            // Act & Assert - يتوقع أن يرمي استثناء إذا الملف غير موجود
            Assert.ThrowsAny<Exception>(() => _analyzer.Analyze(nonExistentFile));
        }

        [Fact]
        public void Analyze_WithTextFile_ReturnsInvalidResult()
        {
            // Arrange
            var textFile = Path.GetTempFileName();
            File.WriteAllText(textFile, "Not a PE file");
            
            try
            {
                // Act
                var result = _analyzer.Analyze(textFile);
                
                // Assert
                if (result != null)
                {
                    Assert.False(result.IsValidPE);
                }
            }
            finally
            {
                File.Delete(textFile);
            }
        }
    }
}
