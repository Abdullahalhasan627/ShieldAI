// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/Services/DispatcherService.cs
// خدمة إدارة الـ Dispatcher
// =====================================================

using System.Windows;
using System.Windows.Threading;

namespace ShieldAI.UI.Services
{
    /// <summary>
    /// خدمة الـ Dispatcher - تدير تنفيذ الكود على UI Thread
    /// </summary>
    public interface IDispatcherService
    {
        /// <summary>
        /// تنفيذ على UI Thread
        /// </summary>
        void Invoke(Action action);

        /// <summary>
        /// تنفيذ على UI Thread بشكل غير متزامن
        /// </summary>
        Task InvokeAsync(Action action);

        /// <summary>
        /// تنفيذ على UI Thread مع نتيجة
        /// </summary>
        T Invoke<T>(Func<T> func);

        /// <summary>
        /// تنفيذ على UI Thread بشكل غير متزامن مع نتيجة
        /// </summary>
        Task<T> InvokeAsync<T>(Func<T> func);

        /// <summary>
        /// هل على UI Thread
        /// </summary>
        bool CheckAccess();
    }

    /// <summary>
    /// تنفيذ خدمة الـ Dispatcher
    /// </summary>
    public class DispatcherService : IDispatcherService
    {
        private readonly Dispatcher _dispatcher;

        public DispatcherService()
        {
            _dispatcher = Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher;
        }

        public void Invoke(Action action)
        {
            if (CheckAccess())
            {
                action();
            }
            else
            {
                _dispatcher.Invoke(action);
            }
        }

        public async Task InvokeAsync(Action action)
        {
            if (CheckAccess())
            {
                action();
            }
            else
            {
                await _dispatcher.InvokeAsync(action);
            }
        }

        public T Invoke<T>(Func<T> func)
        {
            if (CheckAccess())
            {
                return func();
            }
            else
            {
                return _dispatcher.Invoke(func);
            }
        }

        public async Task<T> InvokeAsync<T>(Func<T> func)
        {
            if (CheckAccess())
            {
                return func();
            }
            else
            {
                return await _dispatcher.InvokeAsync(func);
            }
        }

        public bool CheckAccess()
        {
            return _dispatcher.CheckAccess();
        }
    }
}
