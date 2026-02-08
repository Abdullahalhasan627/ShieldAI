// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Core/Scanning/StreamingHasher.cs
// حساب Hash بدون تحميل الملف كاملاً
// =====================================================

using System.Security.Cryptography;

namespace ShieldAI.Core.Scanning
{
    /// <summary>
    /// حساب SHA256/MD5 بشكل Streaming
    /// لا يحمّل الملف كاملاً في الذاكرة
    /// </summary>
    public static class StreamingHasher
    {
        private const int BufferSize = 81920; // 80KB - optimal for disk I/O

        /// <summary>
        /// حساب SHA256 من ملف
        /// </summary>
        public static async Task<string> ComputeSHA256Async(string filePath, CancellationToken cancellationToken = default)
        {
            await using var stream = new FileStream(
                filePath, 
                FileMode.Open, 
                FileAccess.Read, 
                FileShare.Read, 
                BufferSize, 
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            
            return await ComputeSHA256Async(stream, cancellationToken);
        }

        /// <summary>
        /// حساب SHA256 من Stream
        /// </summary>
        public static async Task<string> ComputeSHA256Async(Stream stream, CancellationToken cancellationToken = default)
        {
            using var sha256 = SHA256.Create();
            var buffer = new byte[BufferSize];
            int bytesRead;

            while ((bytesRead = await stream.ReadAsync(buffer, cancellationToken)) > 0)
            {
                sha256.TransformBlock(buffer, 0, bytesRead, null, 0);
            }
            
            sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            
            return BitConverter.ToString(sha256.Hash!).Replace("-", "").ToLowerInvariant();
        }

        /// <summary>
        /// حساب MD5 من ملف
        /// </summary>
        public static async Task<string> ComputeMD5Async(string filePath, CancellationToken cancellationToken = default)
        {
            await using var stream = new FileStream(
                filePath, 
                FileMode.Open, 
                FileAccess.Read, 
                FileShare.Read, 
                BufferSize, 
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            
            return await ComputeMD5Async(stream, cancellationToken);
        }

        /// <summary>
        /// حساب MD5 من Stream
        /// </summary>
        public static async Task<string> ComputeMD5Async(Stream stream, CancellationToken cancellationToken = default)
        {
            using var md5 = MD5.Create();
            var buffer = new byte[BufferSize];
            int bytesRead;

            while ((bytesRead = await stream.ReadAsync(buffer, cancellationToken)) > 0)
            {
                md5.TransformBlock(buffer, 0, bytesRead, null, 0);
            }
            
            md5.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            
            return BitConverter.ToString(md5.Hash!).Replace("-", "").ToLowerInvariant();
        }

        /// <summary>
        /// حساب SHA256 و MD5 معاً (أكثر كفاءة)
        /// </summary>
        public static async Task<(string SHA256, string MD5)> ComputeBothAsync(
            string filePath, 
            CancellationToken cancellationToken = default)
        {
            await using var stream = new FileStream(
                filePath, 
                FileMode.Open, 
                FileAccess.Read, 
                FileShare.Read, 
                BufferSize, 
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            using var sha256 = SHA256.Create();
            using var md5 = MD5.Create();
            
            var buffer = new byte[BufferSize];
            int bytesRead;

            while ((bytesRead = await stream.ReadAsync(buffer, cancellationToken)) > 0)
            {
                sha256.TransformBlock(buffer, 0, bytesRead, null, 0);
                md5.TransformBlock(buffer, 0, bytesRead, null, 0);
            }
            
            sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            md5.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

            return (
                BitConverter.ToString(sha256.Hash!).Replace("-", "").ToLowerInvariant(),
                BitConverter.ToString(md5.Hash!).Replace("-", "").ToLowerInvariant()
            );
        }

        /// <summary>
        /// حساب Hash متزامن (للملفات الصغيرة)
        /// </summary>
        public static string ComputeSHA256(string filePath)
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        /// <summary>
        /// حساب MD5 متزامن
        /// </summary>
        public static string ComputeMD5(string filePath)
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var md5 = MD5.Create();
            var hash = md5.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
    }
}
