using System;

namespace FingerprintService
{
    public sealed class FingerprintConfiguration
    {
        public int? MatchThreshold { get; private set; }
        public bool MatchThresholdValidated { get; private set; }
        public bool MatchThresholdConfigured { get { return MatchThreshold.HasValue; } }

        public FingerprintConfiguration(int? matchThreshold, bool matchThresholdValidated)
        {
            if (matchThresholdValidated && !matchThreshold.HasValue)
                throw new ArgumentException(
                    "A threshold must be configured before it can be marked validated.",
                    "matchThresholdValidated");

            MatchThreshold = matchThreshold;
            MatchThresholdValidated = matchThresholdValidated;
        }

        public static FingerprintConfiguration Default
        {
            get { return new FingerprintConfiguration(null, false); }
        }
    }
}
