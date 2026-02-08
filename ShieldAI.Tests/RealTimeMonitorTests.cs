// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/RealTimeMonitorTests.cs
// اختبارات المراقبة الفورية
// =====================================================

using ShieldAI.Core.Monitoring;
using Xunit;

namespace ShieldAI.Tests
{
    /// <summary>
    /// اختبارات وحدة للمراقبة الفورية
    /// </summary>
    public class RealTimeMonitorTests
    {
        [Fact]
        public void RealTimeMonitor_Creation_Succeeds()
        {
            // Act
            var monitor = new RealTimeMonitor();
            
            // Assert
            Assert.NotNull(monitor);
            Assert.False(monitor.IsRunning);
        }

        [Fact]
        public void RealTimeMonitor_Start_SetsIsRunningTrue()
        {
            // Arrange
            var monitor = new RealTimeMonitor();
            
            // Act
            monitor.Start();
            
            try
            {
                // Assert
                Assert.True(monitor.IsRunning);
            }
            finally
            {
                monitor.Stop();
            }
        }

        [Fact]
        public void RealTimeMonitor_Stop_SetsIsRunningFalse()
        {
            // Arrange
            var monitor = new RealTimeMonitor();
            monitor.Start();
            
            // Act
            monitor.Stop();
            
            // Assert
            Assert.False(monitor.IsRunning);
        }

        [Fact]
        public void RealTimeMonitor_Dispose_DoesNotThrow()
        {
            // Arrange
            var monitor = new RealTimeMonitor();
            monitor.Start();
            
            // Act & Assert
            var exception = Record.Exception(() =>
            {
                monitor.Stop();
                monitor.Dispose();
            });
            Assert.Null(exception);
        }

        [Fact]
        public void RealTimeMonitor_MultipleStartStop_DoesNotThrow()
        {
            // Arrange
            var monitor = new RealTimeMonitor();
            
            // Act & Assert
            var exception = Record.Exception(() =>
            {
                monitor.Start();
                monitor.Stop();
                monitor.Start();
                monitor.Stop();
            });
            Assert.Null(exception);
        }
    }
}
