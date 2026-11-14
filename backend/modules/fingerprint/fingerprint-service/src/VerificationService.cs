using System;

namespace FingerprintService
{
    public enum VerificationStatus
    {
        Verified,
        NotVerified,
        Indeterminate
    }

    public sealed class VerificationResult
    {
        public string UserId { get; private set; }
        public VerificationStatus Status { get; private set; }
        public int? MatchApiStatusCode { get; private set; }
        public int? MatchingScore { get; private set; }
        public int? CaptureQuality { get; private set; }
        public int? Nfiq { get; private set; }
        public bool MatchThresholdConfigured { get; private set; }
        public bool MatchThresholdValidated { get; private set; }
        public string DiagnosticMessage { get; private set; }
        public DateTime TimestampUtc { get; private set; }

        internal VerificationResult(
            string userId, VerificationStatus status, int? apiStatusCode,
            int? score, int? quality, int? nfiq, bool thresholdConfigured,
            bool thresholdValidated, string diagnosticMessage)
        {
            UserId = userId;
            Status = status;
            MatchApiStatusCode = apiStatusCode;
            MatchingScore = score;
            CaptureQuality = quality;
            Nfiq = nfiq;
            MatchThresholdConfigured = thresholdConfigured;
            MatchThresholdValidated = thresholdValidated;
            DiagnosticMessage = diagnosticMessage;
            TimestampUtc = DateTime.UtcNow;
        }
    }

    public sealed class VerificationService
    {
        private readonly FingerprintStorage storage;
        private readonly Func<IEnrollmentCaptureDevice> deviceFactory;
        private readonly FingerprintConfiguration configuration;

        public VerificationService(FingerprintStorage storage)
            : this(storage, FingerprintConfiguration.Default,
                delegate { return new Mfs100EnrollmentCaptureDevice(); })
        {
        }

        public VerificationService(
            FingerprintStorage storage,
            FingerprintConfiguration configuration)
            : this(storage, configuration,
                delegate { return new Mfs100EnrollmentCaptureDevice(); })
        {
        }

        public VerificationService(
            FingerprintStorage storage,
            FingerprintConfiguration configuration,
            Func<IEnrollmentCaptureDevice> deviceFactory)
        {
            if (storage == null)
                throw new ArgumentNullException("storage");
            if (configuration == null)
                throw new ArgumentNullException("configuration");
            if (deviceFactory == null)
                throw new ArgumentNullException("deviceFactory");

            this.storage = storage;
            this.configuration = configuration;
            this.deviceFactory = deviceFactory;
        }

        public VerificationResult Verify(string userId)
        {
            if (!FingerprintStorage.IsValidUserId(userId))
                return Result(userId, VerificationStatus.Indeterminate,
                    null, null, null, null, "User ID is invalid.");

            byte[] enrolledTemplate = null;
            byte[] probeTemplate = null;
            CaptureResult capture = null;
            IEnrollmentCaptureDevice device = null;
            VerificationResult result = null;

            try
            {
                try
                {
                    enrolledTemplate = storage.GetEnrollment(userId);
                }
                catch (FingerprintStorageException ex)
                {
                    string message = ex.Error == FingerprintStorageError.EnrollmentNotFound
                        ? "No enrollment exists for this user."
                        : "The enrollment is corrupted or cannot be decrypted.";
                    result = Result(userId, VerificationStatus.Indeterminate,
                        null, null, null, null, message);
                }
                catch (Exception)
                {
                    result = Result(userId, VerificationStatus.Indeterminate,
                        null, null, null, null, "Could not read the local enrollment.");
                }

                if (result == null && (enrolledTemplate == null || enrolledTemplate.Length == 0))
                {
                    result = Result(userId, VerificationStatus.Indeterminate,
                        null, null, null, null, "Enrollment contains no usable ISO template.");
                }

                if (result == null)
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
                        result = Result(userId, VerificationStatus.Indeterminate,
                            null, null, null, null,
                            "Could not initialize the fingerprint scanner.");
                    }
                }

                if (result == null)
                {
                    bool connected;
                    try { connected = device.IsConnected; }
                    catch (Exception) { connected = false; }

                    if (!connected)
                        result = Result(userId, VerificationStatus.Indeterminate,
                            null, null, null, null,
                            "Fingerprint scanner is not connected.");
                }

                if (result == null)
                {
                    try
                    {
                        capture = device.Capture();
                    }
                    catch (Exception)
                    {
                        result = Result(userId, VerificationStatus.Indeterminate,
                            null, null, null, null,
                            "Fingerprint capture failed or timed out.");
                    }
                }

                if (result == null)
                {
                    int? quality = capture == null ? (int?)null : capture.Quality;
                    int? nfiq = capture == null ? (int?)null : capture.Nfiq;

                    if (capture == null || capture.StatusCode != 0)
                    {
                        result = Result(userId, VerificationStatus.Indeterminate,
                            null, null, quality, nfiq,
                            "Fingerprint capture failed or timed out.");
                    }
                    else if (capture.IsoTemplate == null || capture.IsoTemplate.Length == 0)
                    {
                        result = Result(userId, VerificationStatus.Indeterminate,
                            null, null, quality, nfiq,
                            "Scanner returned no usable ISO template.");
                    }
                    else
                    {
                        probeTemplate = capture.IsoTemplate;
                        MatchResult match = null;
                        try
                        {
                            match = device.MatchIso(probeTemplate, enrolledTemplate);
                        }
                        catch (Exception)
                        {
                            result = Result(userId, VerificationStatus.Indeterminate,
                                null, null, quality, nfiq,
                                "Fingerprint comparison could not be completed.");
                        }

                        if (result == null && match == null)
                        {
                            result = Result(userId, VerificationStatus.Indeterminate,
                                null, null, quality, nfiq,
                                "Fingerprint comparison returned no result.");
                        }
                        else if (result == null && match.StatusCode != 0)
                        {
                            result = Result(userId, VerificationStatus.Indeterminate,
                                match.StatusCode, null, quality, nfiq,
                                "Fingerprint comparison API failed.");
                        }
                        else if (result == null)
                        {
                            VerificationStatus status = VerificationStatus.Indeterminate;
                            string message;

                            if (!configuration.MatchThresholdValidated ||
                                !configuration.MatchThreshold.HasValue)
                            {
                                message = configuration.MatchThresholdConfigured
                                    ? "Comparison completed; configured threshold is unvalidated."
                                    : "Comparison completed; no calibrated threshold is configured.";
                            }
                            else
                            {
                                status = match.Score >= configuration.MatchThreshold.Value
                                    ? VerificationStatus.Verified
                                    : VerificationStatus.NotVerified;
                                message = "Comparison completed using the configured validated threshold.";
                            }

                            result = Result(userId, status, match.StatusCode,
                                match.Score, quality, nfiq, message);
                        }
                    }
                }
            }
            catch (Exception)
            {
                result = Result(userId, VerificationStatus.Indeterminate,
                    null, null,
                    capture == null ? (int?)null : capture.Quality,
                    capture == null ? (int?)null : capture.Nfiq,
                    "Verification could not be completed safely.");
            }
            finally
            {
                Clear(enrolledTemplate);
                if (capture != null)
                    Clear(capture.IsoTemplate);
                if (probeTemplate != null &&
                    (capture == null || !Object.ReferenceEquals(probeTemplate, capture.IsoTemplate)))
                    Clear(probeTemplate);

                if (device != null)
                {
                    try
                    {
                        device.Dispose();
                    }
                    catch (Exception)
                    {
                        if (result != null)
                            result = Result(userId, result.Status,
                                result.MatchApiStatusCode, result.MatchingScore,
                                result.CaptureQuality, result.Nfiq,
                                AppendDiagnostic(result.DiagnosticMessage,
                                    "Scanner cleanup reported an error."));
                    }
                }
            }

            return result ?? Result(userId, VerificationStatus.Indeterminate,
                null, null, null, null, "Verification could not be completed.");
        }

        private VerificationResult Result(
            string userId, VerificationStatus status, int? apiStatusCode,
            int? score, int? quality, int? nfiq, string message)
        {
            return new VerificationResult(userId, status, apiStatusCode,
                score, quality, nfiq, configuration.MatchThresholdConfigured,
                configuration.MatchThresholdValidated, message);
        }

        private static void Clear(byte[] bytes)
        {
            if (bytes != null)
                Array.Clear(bytes, 0, bytes.Length);
        }

        private static string AppendDiagnostic(string existing, string addition)
        {
            return String.IsNullOrEmpty(existing) ? addition : existing + " " + addition;
        }
    }
}
