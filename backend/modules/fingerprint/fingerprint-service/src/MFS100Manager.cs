using System;
using MANTRA;

namespace FingerprintService
{
    public sealed class CaptureResult
    {
        public byte[] IsoTemplate { get; set; }
        public int Quality { get; set; }
        public int Nfiq { get; set; }
        public int StatusCode { get; set; }
        public string StatusMessage { get; set; }
    }

    public sealed class MatchResult
    {
        public int StatusCode { get; set; }
        public string StatusMessage { get; set; }
        public int Score { get; set; }
    }

    // Owns one MFS100 scanner session. Use from a 32-bit process only.
    public sealed class MFS100Manager : IDisposable
    {
        private readonly MANTRA.MFS100 scanner;
        private bool initialized;
        private bool disposed;

        public MFS100Manager()
        {
            scanner = new MANTRA.MFS100();
        }

        public void Initialize()
        {
            ThrowIfDisposed();

            int code = scanner.Init();
            if (code != 0)
                throw new InvalidOperationException(
                    "MFS100 initialization failed: " + scanner.GetErrorMsg(code));

            initialized = true;
        }

        public bool IsConnected
        {
            get { return initialized && scanner.IsConnected(); }
        }

        public CaptureResult Capture(int timeoutMilliseconds = 30000)
        {
            ThrowIfDisposed();
            if (!initialized)
                throw new InvalidOperationException("Initialize the scanner before capture.");

            FingerData data = new FingerData();

            // IsDetectFinger=false is intentional: this is the setting that
            // successfully produced ISO templates on this installation.
            int code = scanner.AutoCapture(
                ref data, timeoutMilliseconds, true, false);

            var result = new CaptureResult
            {
                StatusCode = code,
                StatusMessage = scanner.GetErrorMsg(code),
                Quality = data.Quality,
                Nfiq = data.Nfiq,
                IsoTemplate = data.ISOTemplate
            };

            if (code == 0 && (result.IsoTemplate == null || result.IsoTemplate.Length == 0))
                throw new InvalidOperationException("Capture succeeded but returned an empty ISO template.");

            return result;
        }

        public MatchResult MatchIso(byte[] probe, byte[] gallery)
        {
            ThrowIfDisposed();
            if (!initialized)
                throw new InvalidOperationException("Initialize the scanner before matching.");
            if (probe == null || probe.Length == 0)
                throw new ArgumentException("Probe ISO template is empty.", "probe");
            if (gallery == null || gallery.Length == 0)
                throw new ArgumentException("Gallery ISO template is empty.", "gallery");

            int score = 0;
            int code = scanner.MatchISO(probe, gallery, ref score);

            return new MatchResult
            {
                StatusCode = code,
                StatusMessage = scanner.GetErrorMsg(code),
                Score = score
            };
        }

        private void ThrowIfDisposed()
        {
            if (disposed)
                throw new ObjectDisposedException("MFS100Manager");
        }

        public void Dispose()
        {
            if (disposed) return;

            try
            {
                if (initialized)
                    scanner.Uninit();
            }
            finally
            {
                scanner.Dispose();
                initialized = false;
                disposed = true;
            }
        }
    }
}
