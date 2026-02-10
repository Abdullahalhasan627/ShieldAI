// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/EventCoalescerTests.cs
// اختبارات EventCoalescer - تجميع الأحداث والتأخير
// =====================================================

using ShieldAI.Core.Monitoring.Pipeline;
using Xunit;

namespace ShieldAI.Tests
{
    public class EventCoalescerTests : IDisposable
    {
        private readonly FileEventQueue _queue;
        private readonly string _testDir;

        public EventCoalescerTests()
        {
            _queue = new FileEventQueue();
            _testDir = Path.Combine(Path.GetTempPath(), $"ShieldAI_ECTest_{Guid.NewGuid()}");
            Directory.CreateDirectory(_testDir);
        }

        public void Dispose()
        {
            _queue.Dispose();
            if (Directory.Exists(_testDir))
            {
                try { Directory.Delete(_testDir, true); } catch { }
            }
        }

        [Fact]
        public async Task Coalescer_ShouldDebounceMultipleEvents()
        {
            // Arrange
            int coalesceMs = 300;
            using var coalescer = new EventCoalescer(_queue, coalesceMs);

            var testFile = Path.Combine(_testDir, "debounce.txt");
            File.WriteAllText(testFile, "content");

            // Act - fire multiple events for same file rapidly
            for (int i = 0; i < 10; i++)
            {
                coalescer.Add(testFile, WatcherChangeTypes.Changed);
                await Task.Delay(20); // 20ms between events
            }

            // Wait for coalesce period + flush timer
            await Task.Delay(coalesceMs + 500);

            // Assert - should produce only 1 event (debounced)
            int eventCount = 0;
            while (_queue.TryDequeue(out _))
            {
                eventCount++;
            }

            Assert.Equal(1, eventCount);
        }

        [Fact]
        public async Task Coalescer_DifferentFiles_ShouldProduceSeparateEvents()
        {
            // Arrange
            int coalesceMs = 300;
            using var coalescer = new EventCoalescer(_queue, coalesceMs);

            var file1 = Path.Combine(_testDir, "file1.txt");
            var file2 = Path.Combine(_testDir, "file2.txt");
            var file3 = Path.Combine(_testDir, "file3.txt");
            File.WriteAllText(file1, "content1");
            File.WriteAllText(file2, "content2");
            File.WriteAllText(file3, "content3");

            // Act - add events for different files
            coalescer.Add(file1, WatcherChangeTypes.Created);
            coalescer.Add(file2, WatcherChangeTypes.Created);
            coalescer.Add(file3, WatcherChangeTypes.Created);

            // Wait for coalesce + flush
            await Task.Delay(coalesceMs + 500);

            // Assert - should produce 3 separate events
            int eventCount = 0;
            while (_queue.TryDequeue(out _))
            {
                eventCount++;
            }

            Assert.Equal(3, eventCount);
        }

        [Fact]
        public async Task Coalescer_NonExistentFile_ShouldNotEnqueue()
        {
            // Arrange
            int coalesceMs = 200;
            using var coalescer = new EventCoalescer(_queue, coalesceMs);

            var fakePath = Path.Combine(_testDir, "nonexistent.txt");

            // Act
            coalescer.Add(fakePath, WatcherChangeTypes.Created);

            // Wait for coalesce + flush
            await Task.Delay(coalesceMs + 500);

            // Assert - non-existent file should not be enqueued
            Assert.False(_queue.TryDequeue(out _));
        }

        [Fact]
        public void Coalescer_PendingCount_ShouldTrack()
        {
            // Arrange
            using var coalescer = new EventCoalescer(_queue, 5000); // long coalesce

            var file1 = Path.Combine(_testDir, "pending1.txt");
            var file2 = Path.Combine(_testDir, "pending2.txt");
            File.WriteAllText(file1, "c1");
            File.WriteAllText(file2, "c2");

            // Act
            coalescer.Add(file1, WatcherChangeTypes.Created);
            coalescer.Add(file2, WatcherChangeTypes.Created);

            // Assert
            Assert.Equal(2, coalescer.PendingCount);
        }

        [Fact]
        public void Coalescer_Clear_ShouldRemoveAllPending()
        {
            // Arrange
            using var coalescer = new EventCoalescer(_queue, 5000);

            var file = Path.Combine(_testDir, "clear.txt");
            File.WriteAllText(file, "c");

            coalescer.Add(file, WatcherChangeTypes.Created);
            Assert.Equal(1, coalescer.PendingCount);

            // Act
            coalescer.Clear();

            // Assert
            Assert.Equal(0, coalescer.PendingCount);
        }
    }

    public class FileEventQueueTests : IDisposable
    {
        private readonly FileEventQueue _queue;

        public FileEventQueueTests()
        {
            _queue = new FileEventQueue();
        }

        public void Dispose()
        {
            _queue.Dispose();
        }

        [Fact]
        public void TryEnqueue_ShouldSucceed()
        {
            var result = _queue.TryEnqueue(new FileEvent
            {
                FilePath = "test.txt",
                ChangeType = WatcherChangeTypes.Created
            });

            Assert.True(result);
            Assert.Equal(1, _queue.PendingCount);
        }

        [Fact]
        public void TryDequeue_ShouldReturnEnqueued()
        {
            // Arrange
            _queue.TryEnqueue(new FileEvent
            {
                FilePath = "test.txt",
                ChangeType = WatcherChangeTypes.Changed
            });

            // Act
            var success = _queue.TryDequeue(out var fileEvent);

            // Assert
            Assert.True(success);
            Assert.NotNull(fileEvent);
            Assert.Equal("test.txt", fileEvent.FilePath);
            Assert.Equal(WatcherChangeTypes.Changed, fileEvent.ChangeType);
        }

        [Fact]
        public void TryDequeue_Empty_ShouldReturnFalse()
        {
            var success = _queue.TryDequeue(out _);
            Assert.False(success);
        }

        [Fact]
        public void PendingCount_ShouldTrack()
        {
            Assert.Equal(0, _queue.PendingCount);

            _queue.TryEnqueue(new FileEvent { FilePath = "a.txt" });
            Assert.Equal(1, _queue.PendingCount);

            _queue.TryEnqueue(new FileEvent { FilePath = "b.txt" });
            Assert.Equal(2, _queue.PendingCount);

            _queue.TryDequeue(out _);
            Assert.Equal(1, _queue.PendingCount);
        }
    }
}
