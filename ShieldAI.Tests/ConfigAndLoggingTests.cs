// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/ConfigAndLoggingTests.cs
// اختبارات التكوين والتسجيل
// =====================================================

using ShieldAI.Core.Configuration;
using ShieldAI.Core.Logging;
using ShieldAI.Core.Models;
using Xunit;

namespace ShieldAI.Tests
{
    /// <summary>
    /// اختبارات وحدة للتكوين والتسجيل
    /// </summary>
    public class ConfigAndLoggingTests
    {
        #region AppSettings Tests
        [Fact]
        public void AppSettings_DefaultValues_AreCorrect()
        {
            // Act
            var settings = new AppSettings();
            
            // Assert
            Assert.True(settings.EnableRealTimeProtection);
            Assert.Equal(0.7f, settings.MalwareThreshold);
            Assert.Equal(100, settings.MaxFileSizeMB);
        }

        [Fact]
        public void AppSettings_Properties_CanBeModified()
        {
            // Arrange
            var settings = new AppSettings();
            
            // Act
            settings.EnableRealTimeProtection = false;
            settings.MalwareThreshold = 0.5f;
            
            // Assert
            Assert.False(settings.EnableRealTimeProtection);
            Assert.Equal(0.5f, settings.MalwareThreshold);
        }
        #endregion

        #region ScanProfile Tests
        [Fact]
        public void ScanProfile_QuickScan_HasCorrectDefaults()
        {
            // Act
            var profile = ScanProfile.QuickScan;
            
            // Assert
            Assert.NotNull(profile);
            Assert.Equal(ScanType.Quick, profile.Type);
        }

        [Fact]
        public void ScanProfile_FullScan_HasCorrectDefaults()
        {
            // Act
            var profile = ScanProfile.FullScan;
            
            // Assert
            Assert.NotNull(profile);
            Assert.Equal(ScanType.Full, profile.Type);
        }
        #endregion

        #region ConfigManager Tests
        [Fact]
        public void ConfigManager_Instance_IsNotNull()
        {
            // Act
            var instance = ConfigManager.Instance;
            
            // Assert
            Assert.NotNull(instance);
        }

        [Fact]
        public void ConfigManager_Instance_IsSingleton()
        {
            // Act
            var instance1 = ConfigManager.Instance;
            var instance2 = ConfigManager.Instance;
            
            // Assert
            Assert.Same(instance1, instance2);
        }

        [Fact]
        public void ConfigManager_Settings_AreNotNull()
        {
            // Act
            var settings = ConfigManager.Instance.Settings;
            
            // Assert
            Assert.NotNull(settings);
        }
        #endregion

        #region LogEvent Tests
        [Fact]
        public void LogEvent_Info_CreatesCorrectEvent()
        {
            // Act
            var logEvent = LogEvent.Info("Test message");
            
            // Assert
            Assert.NotNull(logEvent);
            Assert.Equal(LogLevel.Information, logEvent.Level);
            Assert.Equal("Test message", logEvent.Message);
        }

        [Fact]
        public void LogEvent_Error_CreatesCorrectEvent()
        {
            // Arrange
            var exception = new Exception("Test exception");
            
            // Act
            var logEvent = LogEvent.Error("Error occurred", exception);
            
            // Assert
            Assert.NotNull(logEvent);
            Assert.Equal(LogLevel.Error, logEvent.Level);
        }
        #endregion

        #region FileLogger Tests
        [Fact]
        public void FileLogger_Creation_Succeeds()
        {
            // Act
            var logger = new FileLogger();
            
            // Assert
            Assert.NotNull(logger);
        }

        [Fact]
        public void FileLogger_LogInformation_DoesNotThrow()
        {
            // Arrange
            var logger = new FileLogger();
            
            // Act & Assert
            var exception = Record.Exception(() => logger.Information("Test log message"));
            Assert.Null(exception);
        }

        [Fact]
        public void FileLogger_LogError_DoesNotThrow()
        {
            // Arrange
            var logger = new FileLogger();
            var testException = new Exception("Test exception");
            
            // Act & Assert
            var exception = Record.Exception(() => logger.Error(testException, "Error message"));
            Assert.Null(exception);
        }
        #endregion
    }
}
