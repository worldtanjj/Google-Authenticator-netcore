using System;
using System.Collections.Generic;
using System.Text;

namespace Google_Authenticator_netcore
{
    // Google.Authenticator.SetupCode
    public class SetupCode
    {
        public string Account
        {
            get;
            internal set;
        }

        public string AccountSecretKey
        {
            get;
            internal set;
        }

        public string ManualEntryKey
        {
            get;
            internal set;
        }

        public string QrCodeSetupImageUrl
        {
            get;
            internal set;
        }
    }
}
