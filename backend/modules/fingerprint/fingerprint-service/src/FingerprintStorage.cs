using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;

namespace FingerprintService
{
    public enum FingerprintStorageError
    {
        InvalidUserId,
        EnrollmentAlreadyExists,
        EnrollmentNotFound,
        EnrollmentUnreadable
    }

    // Contains only the DPAPI-protected ISO payload on disk. No metadata or
    // plaintext template is serialized alongside the protected bytes.
    public sealed class FingerprintStorageException : Exception
    {
        public FingerprintStorageError Error { get; private set; }

        internal FingerprintStorageException(FingerprintStorageError error, string message)
            : base(message)
        {
            Error = error;
        }
    }

    public sealed class FingerprintStorage
    {
        public const string StoragePathEnvironmentVariable = "HID_BIOMETRIC_FINGERPRINT_DIR";
        private const string Purpose = "HIDBiometricAuth/ISO-fingerprint-template/v1";
        private static readonly Regex ValidUserId = new Regex(
            @"\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\z",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private readonly string directoryPath;

        public FingerprintStorage() : this(ResolveDefaultPath())
        {
        }

        public FingerprintStorage(string storageDirectory)
        {
            if (String.IsNullOrWhiteSpace(storageDirectory))
                throw new ArgumentException("A fingerprint storage directory is required.", "storageDirectory");

            directoryPath = Path.GetFullPath(storageDirectory);
        }

        public string StorageDirectory { get { return directoryPath; } }

        public static bool IsValidUserId(string userId)
        {
            return !String.IsNullOrWhiteSpace(userId) && ValidUserId.IsMatch(userId);
        }

        public static string ResolveDefaultPath()
        {
            string configured = Environment.GetEnvironmentVariable(StoragePathEnvironmentVariable);
            if (!String.IsNullOrWhiteSpace(configured))
                return Path.GetFullPath(configured);

            // Executable is built at <repo>/fingerprint-service/bin. Walk to
            // the repository root so local records live at <repo>/data.
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            return Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "data", "fingerprints"));
        }

        public bool EnrollmentExists(string userId)
        {
            string path = GetRecordPath(userId);
            EnsureDirectory();
            return File.Exists(path);
        }

        public void Save(string userId, byte[] isoTemplate)
        {
            string targetPath = GetRecordPath(userId);
            if (isoTemplate == null || isoTemplate.Length == 0)
                throw new ArgumentException("ISO template must not be empty.", "isoTemplate");

            EnsureDirectory();
            byte[] protectedBytes = null;
            byte[] entropy = null;
            string temporaryPath = Path.Combine(directoryPath, "." + Guid.NewGuid().ToString("N") + ".tmp");

            try
            {
                entropy = CreateEntropy(userId);
                protectedBytes = ProtectedData.Protect(
                    isoTemplate, entropy, DataProtectionScope.CurrentUser);

                // CreateNew prevents temporary-name collisions. File.Move on
                // the same volume is atomic and fails if target already exists.
                using (var stream = new FileStream(
                    temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(protectedBytes, 0, protectedBytes.Length);
                    stream.Flush(true);
                }

                ApplyFilePermissions(temporaryPath);
                File.Move(temporaryPath, targetPath);
            }
            catch (IOException)
            {
                if (File.Exists(targetPath))
                    throw new FingerprintStorageException(
                        FingerprintStorageError.EnrollmentAlreadyExists,
                        "An enrollment record already exists for this user.");
                throw;
            }
            finally
            {
                if (File.Exists(temporaryPath))
                    File.Delete(temporaryPath);
                Clear(protectedBytes);
                Clear(entropy);
            }
        }

        public byte[] GetEnrollment(string userId)
        {
            string path = GetRecordPath(userId);
            EnsureDirectory();
            if (!File.Exists(path))
                throw new FingerprintStorageException(
                    FingerprintStorageError.EnrollmentNotFound,
                    "No enrollment record exists for this user.");

            byte[] protectedBytes = null;
            byte[] entropy = null;
            try
            {
                protectedBytes = File.ReadAllBytes(path);
                if (protectedBytes.Length == 0)
                    throw new CryptographicException();

                entropy = CreateEntropy(userId);
                return ProtectedData.Unprotect(
                    protectedBytes, entropy, DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException)
            {
                // DPAPI reports malformed data and wrong user/entropy context
                // as decryption failures. Do not expose cryptographic details.
                throw new FingerprintStorageException(
                    FingerprintStorageError.EnrollmentUnreadable,
                    "The enrollment record is corrupted or cannot be decrypted.");
            }
            finally
            {
                Clear(protectedBytes);
                Clear(entropy);
            }
        }

        public void DeleteEnrollment(string userId)
        {
            string path = GetRecordPath(userId);
            EnsureDirectory();
            if (!File.Exists(path))
                throw new FingerprintStorageException(
                    FingerprintStorageError.EnrollmentNotFound,
                    "No enrollment record exists for this user.");
            File.Delete(path);
        }

        private string GetRecordPath(string userId)
        {
            if (!IsValidUserId(userId))
                throw new FingerprintStorageException(
                    FingerprintStorageError.InvalidUserId,
                    "User ID must contain 1 to 64 letters, digits, underscores, or hyphens, and begin with a letter or digit.");

            return Path.Combine(directoryPath, userId + ".enc");
        }

        private void EnsureDirectory()
        {
            Directory.CreateDirectory(directoryPath);
            if ((File.GetAttributes(directoryPath) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Fingerprint storage directory cannot be a reparse point.");
            ApplyDirectoryPermissions(directoryPath);
        }

        private static void ApplyDirectoryPermissions(string path)
        {
            SecurityIdentifier currentUser = WindowsIdentity.GetCurrent().User;
            if (currentUser == null)
                throw new SecurityException("Could not determine the current Windows user.");

            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(
                currentUser, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            Directory.SetAccessControl(path, security);
        }

        private static void ApplyFilePermissions(string path)
        {
            SecurityIdentifier currentUser = WindowsIdentity.GetCurrent().User;
            if (currentUser == null)
                throw new SecurityException("Could not determine the current Windows user.");

            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(
                currentUser, FileSystemRights.FullControl, AccessControlType.Allow));
            File.SetAccessControl(path, security);
        }

        private static byte[] CreateEntropy(string userId)
        {
            return Encoding.UTF8.GetBytes(Purpose + "\n" + userId);
        }

        private static void Clear(byte[] bytes)
        {
            if (bytes != null)
                Array.Clear(bytes, 0, bytes.Length);
        }
    }
}
