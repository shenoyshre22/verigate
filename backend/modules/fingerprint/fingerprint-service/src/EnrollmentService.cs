using System;

namespace FingerprintService
{
    public enum EnrollmentStatus
    {
        Enrolled,
        EnrolledWithCleanupWarning,
        InvalidUserId,
        AlreadyEnrolled,
        DeviceInitializationFailed,
        DeviceDisconnected,
        CaptureFailed,
        InvalidCapture,
        StorageFailed
    }

    public sealed class EnrollmentResult
    {
        public string UserId { get; private set; }
        public EnrollmentStatus Status { get; private set; }
        public bool Success { get; private set; }
        public int? CaptureQuality { get; private set; }
        public int? Nfiq { get; private set; }
        public int? ScannerStatusCode { get; private set; }
        public string ErrorMessage { get; private set; }
        public DateTime TimestampUtc { get; private set; }

        internal EnrollmentResult(
            string userId, EnrollmentStatus status, bool success,
            int? quality, int? nfiq, int? scannerStatusCode, string errorMessage)
        {
            UserId = userId;
            Status = status;
            Success = success;
            CaptureQuality = quality;
            Nfiq = nfiq;
            ScannerStatusCode = scannerStatusCode;
            ErrorMessage = errorMessage;
            TimestampUtc = DateTime.UtcNow;
        }
    }

    // Small hardware boundary so enrollment logic can be exercised without a
    // physical scanner. Production calls use the adapter around MFS100Manager.
    public interface IEnrollmentCaptureDevice : IDisposable
    {
        void Initialize();
        bool IsConnected { get; }
        CaptureResult Capture();
        MatchResult MatchIso(byte[] probe, byte[] gallery);
    }

    internal sealed class Mfs100EnrollmentCaptureDevice : IEnrollmentCaptureDevice
    {
        private readonly MFS100Manager manager;

        public Mfs100EnrollmentCaptureDevice()
        {
            manager = new MFS100Manager();
        }

        public void Initialize() { manager.Initialize(); }
        public bool IsConnected { get { return manager.IsConnected; } }
        public CaptureResult Capture() { return manager.Capture(); }
        public MatchResult MatchIso(byte[] probe, byte[] gallery)
        {
            return manager.MatchIso(probe, gallery);
        }
        public void Dispose() { manager.Dispose(); }
    }

    public sealed class EnrollmentService
    {
        private readonly FingerprintStorage storage;
        private readonly Func<IEnrollmentCaptureDevice> deviceFactory;

        public EnrollmentService(FingerprintStorage storage)
            : this(storage, delegate { return new Mfs100EnrollmentCaptureDevice(); })
        {
        }

        public EnrollmentService(
            FingerprintStorage storage,
            Func<IEnrollmentCaptureDevice> deviceFactory)
        {
            if (storage == null)
                throw new ArgumentNullException("storage");
            if (deviceFactory == null)
                throw new ArgumentNullException("deviceFactory");

            this.storage = storage;
            this.deviceFactory = deviceFactory;
        }

        public EnrollmentResult Enroll(string userId)
        {
            // Validate before even checking the storage directory or creating
            // a hardware session.
            if (!FingerprintStorage.IsValidUserId(userId))
                return Result(userId, EnrollmentStatus.InvalidUserId, false,
                    null, null, null, "User ID is invalid.");

            try
            {
                if (storage.EnrollmentExists(userId))
                    return Result(userId, EnrollmentStatus.AlreadyEnrolled, false,
                        null, null, null, "An enrollment already exists for this user.");
            }
            catch (Exception)
            {
                return Result(userId, EnrollmentStatus.StorageFailed, false,
                    null, null, null, "Could not check local enrollment storage.");
            }

            IEnrollmentCaptureDevice device = null;
            CaptureResult capture = null;
            byte[] template = null;
            EnrollmentResult result = null;

            try
            {
                try
                {
                    device = deviceFactory();
                    if (device == null)
                        throw new InvalidOperationException();
                    device.Initialize();
                }
                catch (Exception)
                {
                    result = Result(userId, EnrollmentStatus.DeviceInitializationFailed,
                        false, null, null, null,
                        "Could not initialize the fingerprint scanner.");
                }

                if (result == null)
                {
                    bool connected;
                    try { connected = device.IsConnected; }
                    catch (Exception) { connected = false; }

                    if (!connected)
                        result = Result(userId, EnrollmentStatus.DeviceDisconnected,
                            false, null, null, null, "Fingerprint scanner is not connected.");
                }

                if (result == null)
                {
                    try
                    {
                        capture = device.Capture();
                    }
                    catch (Exception)
                    {
                        result = Result(userId, EnrollmentStatus.CaptureFailed, false,
                            null, null, null,
                            "Fingerprint capture failed or timed out.");
                    }
                }

                if (result == null)
                {
                    int? quality = capture == null ? (int?)null : capture.Quality;
                    int? nfiq = capture == null ? (int?)null : capture.Nfiq;
                    int? statusCode = capture == null ? (int?)null : capture.StatusCode;

                    if (capture == null || capture.StatusCode != 0)
                    {
                        result = Result(userId, EnrollmentStatus.CaptureFailed, false,
                            quality, nfiq, statusCode,
                            "Fingerprint capture failed or timed out.");
                    }
                    else if (capture.IsoTemplate == null || capture.IsoTemplate.Length == 0)
                    {
                        result = Result(userId, EnrollmentStatus.InvalidCapture, false,
                            quality, nfiq, statusCode,
                            "Scanner returned no usable ISO template.");
                    }
                    else
                    {
                        template = capture.IsoTemplate;
                        try
                        {
                            storage.Save(userId, template);
                            result = Result(userId, EnrollmentStatus.Enrolled, true,
                                quality, nfiq, statusCode, null);
                        }
                        catch (FingerprintStorageException ex)
                        {
                            if (ex.Error == FingerprintStorageError.EnrollmentAlreadyExists)
                                result = Result(userId, EnrollmentStatus.AlreadyEnrolled,
                                    false, quality, nfiq, statusCode,
                                    "An enrollment already exists for this user.");
                            else
                                result = Result(userId, EnrollmentStatus.StorageFailed,
                                    false, quality, nfiq, statusCode,
                                    "Could not securely save the enrollment.");
                        }
                        catch (Exception)
                        {
                            result = Result(userId, EnrollmentStatus.StorageFailed, false,
                                quality, nfiq, statusCode,
                                "Could not securely save the enrollment.");
                        }
                    }
                }
            }
            finally
            {
                if (template != null)
                    Array.Clear(template, 0, template.Length);

                if (device != null)
                {
                    try
                    {
                        device.Dispose();
                    }
                    catch (Exception)
                    {
                        if (result != null && result.Success)
                            result = Result(userId,
                                EnrollmentStatus.EnrolledWithCleanupWarning, true,
                                result.CaptureQuality, result.Nfiq,
                                result.ScannerStatusCode,
                                "Enrollment was saved, but scanner cleanup reported an error.");
                    }
                }
            }

            return result ?? Result(userId, EnrollmentStatus.CaptureFailed, false,
                null, null, null, "Enrollment could not be completed.");
        }

        private static EnrollmentResult Result(
            string userId, EnrollmentStatus status, bool success,
            int? quality, int? nfiq, int? scannerStatusCode, string error)
        {
            return new EnrollmentResult(
                userId, status, success, quality, nfiq, scannerStatusCode, error);
        }
    }
}
