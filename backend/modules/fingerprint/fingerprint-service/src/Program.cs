using System;
using System.IO;

namespace FingerprintService
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (Environment.Is64BitProcess)
            {
                Console.Error.WriteLine("ERROR: Run this service as x86.");
                return 2;
            }

            return RunConsole(
                new FingerprintStorage(),
                delegate { return new Mfs100EnrollmentCaptureDevice(); },
                Console.In,
                Console.Out);
        }

        // Kept injectable so menu behavior can be tested without scanner hardware.
        internal static int RunConsole(
            FingerprintStorage storage,
            Func<IEnrollmentCaptureDevice> deviceFactory,
            TextReader input,
            TextWriter output)
        {
            if (storage == null) throw new ArgumentNullException("storage");
            if (deviceFactory == null) throw new ArgumentNullException("deviceFactory");
            if (input == null) throw new ArgumentNullException("input");
            if (output == null) throw new ArgumentNullException("output");

            output.WriteLine("HID BIOMETRIC AUTHENTICATION");
            output.WriteLine("MFS100 FINGERPRINT SERVICE");

            while (true)
            {
                output.WriteLine();
                output.WriteLine("1. Check scanner connection");
                output.WriteLine("2. Enroll fingerprint");
                output.WriteLine("3. Verify fingerprint");
                output.WriteLine("4. Exit");
                output.Write("Select an option: ");

                string choice = input.ReadLine();
                if (choice == null)
                {
                    output.WriteLine("\nInput closed. Exiting.");
                    return 0;
                }

                switch (choice.Trim())
                {
                    case "1": CheckScanner(deviceFactory, output); break;
                    case "2": Enroll(storage, deviceFactory, input, output); break;
                    case "3": Verify(storage, deviceFactory, input, output); break;
                    case "4":
                        output.WriteLine("Exiting fingerprint service.");
                        return 0;
                    default:
                        output.WriteLine("Please select 1, 2, 3, or 4.");
                        break;
                }
            }
        }

        private static void CheckScanner(
            Func<IEnrollmentCaptureDevice> deviceFactory,
            TextWriter output)
        {
            output.WriteLine("\nChecking MFS100 scanner...");
            try
            {
                using (IEnrollmentCaptureDevice device = deviceFactory())
                {
                    if (device == null)
                    {
                        output.WriteLine("Scanner check failed: device could not be created.");
                        return;
                    }

                    device.Initialize();
                    if (device.IsConnected)
                        output.WriteLine("MFS100 scanner initialized and connected.");
                    else
                        output.WriteLine("Scanner initialized, but no connected MFS100 was detected.");
                }

                output.WriteLine("Scanner resources released.");
            }
            catch (Exception)
            {
                output.WriteLine("Scanner check failed. Check the USB connection and MFS100 driver, then retry.");
            }
        }

        private static void Enroll(
            FingerprintStorage storage,
            Func<IEnrollmentCaptureDevice> deviceFactory,
            TextReader input,
            TextWriter output)
        {
            output.Write("Enter user ID: ");
            string userId = input.ReadLine();
            if (userId == null)
            {
                output.WriteLine("Input closed; returning to the menu.");
                return;
            }

            output.WriteLine("Place your finger on the MFS100 scanner when capture begins.");
            try
            {
                var service = new EnrollmentService(storage, deviceFactory);
                EnrollmentResult result = service.Enroll(userId.Trim());

                output.WriteLine("Enrollment status: " + FormatStatus(result.Status));
                if (!String.IsNullOrEmpty(result.UserId))
                    output.WriteLine("User ID: " + result.UserId);
                WriteOptional("Capture quality", result.CaptureQuality, output);
                WriteOptional("NFIQ", result.Nfiq, output);
                output.WriteLine("Timestamp (UTC): " + result.TimestampUtc.ToString("o"));
                if (!String.IsNullOrEmpty(result.ErrorMessage))
                    output.WriteLine("Message: " + result.ErrorMessage);
            }
            catch (Exception)
            {
                output.WriteLine("Enrollment could not be completed. Check storage and scanner status, then retry.");
            }
        }

        private static void Verify(
            FingerprintStorage storage,
            Func<IEnrollmentCaptureDevice> deviceFactory,
            TextReader input,
            TextWriter output)
        {
            output.Write("Enter user ID: ");
            string userId = input.ReadLine();
            if (userId == null)
            {
                output.WriteLine("Input closed; returning to the menu.");
                return;
            }

            output.WriteLine("Place your finger on the MFS100 scanner when capture begins.");
            try
            {
                var service = new VerificationService(
                    storage, FingerprintConfiguration.Default, deviceFactory);
                VerificationResult result = service.Verify(userId.Trim());

                output.WriteLine("Verification status: " + FormatStatus(result.Status));
                if (!String.IsNullOrEmpty(result.UserId))
                    output.WriteLine("User ID: " + result.UserId);
                WriteOptional("Match API status code", result.MatchApiStatusCode, output);
                WriteOptional("Comparison score", result.MatchingScore, output);
                WriteOptional("Capture quality", result.CaptureQuality, output);
                WriteOptional("NFIQ", result.Nfiq, output);
                output.WriteLine("Threshold configured: " + result.MatchThresholdConfigured);
                output.WriteLine("Threshold validated: " + result.MatchThresholdValidated);
                output.WriteLine("Timestamp (UTC): " + result.TimestampUtc.ToString("o"));

                if (result.Status == VerificationStatus.Indeterminate)
                    output.WriteLine("No authentication decision was made.");
                if (!String.IsNullOrEmpty(result.DiagnosticMessage))
                    output.WriteLine("Message: " + result.DiagnosticMessage);
            }
            catch (Exception)
            {
                output.WriteLine("Verification could not be completed. Check enrollment, storage and scanner status, then retry.");
            }
        }

        private static void WriteOptional(string label, int? value, TextWriter output)
        {
            output.WriteLine(label + ": " + (value.HasValue ? value.Value.ToString() : "N/A"));
        }

        private static string FormatStatus(Enum status)
        {
            string name = status.ToString();
            var formatted = new System.Text.StringBuilder(name.Length + 8);
            for (int i = 0; i < name.Length; i++)
            {
                if (i > 0 && Char.IsUpper(name[i]) &&
                    (Char.IsLower(name[i - 1]) || Char.IsDigit(name[i - 1])))
                    formatted.Append('_');
                formatted.Append(Char.ToUpperInvariant(name[i]));
            }
            return formatted.ToString();
        }
    }
}
