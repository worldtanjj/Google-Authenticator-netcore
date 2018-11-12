using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace Google_Authenticator_netcore
{
    public class TwoFactorAuthenticator
    {
        public static DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public TimeSpan DefaultClockDriftTolerance
        {
            get;
            set;
        }

        public bool UseManagedSha1Algorithm
        {
            get;
            set;
        }

        public bool TryUnmanagedAlgorithmOnFailure
        {
            get;
            set;
        }

        public TwoFactorAuthenticator()
            : this(true, true)
        {
        }

        public TwoFactorAuthenticator(bool useManagedSha1, bool useUnmanagedOnFail)
        {
            DefaultClockDriftTolerance = TimeSpan.FromMinutes(5.0);
            UseManagedSha1Algorithm = useManagedSha1;
            TryUnmanagedAlgorithmOnFailure = useUnmanagedOnFail;
        }

        public SetupCode GenerateSetupCode(string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth, int qrCodeHeight)
        {
            return GenerateSetupCode(null, accountTitleNoSpaces, accountSecretKey, qrCodeWidth, qrCodeHeight);
        }

        public SetupCode GenerateSetupCode(string issuer, string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth, int qrCodeHeight)
        {
            return GenerateSetupCode(issuer, accountTitleNoSpaces, accountSecretKey, qrCodeWidth, qrCodeHeight, false);
        }

        public SetupCode GenerateSetupCode(string issuer, string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth, int qrCodeHeight, bool useHttps)
        {
            if (accountTitleNoSpaces == null)
            {
                throw new NullReferenceException("Account Title is null");
            }
            accountTitleNoSpaces = accountTitleNoSpaces.Replace(" ", "");
            SetupCode setupCode = new SetupCode();
            setupCode.Account = accountTitleNoSpaces;
            setupCode.AccountSecretKey = accountSecretKey;
            string arg = setupCode.ManualEntryKey = EncodeAccountSecretKey(accountSecretKey);
            string text2 = null;
            text2 = ((!string.IsNullOrEmpty(issuer)) ? UrlEncode($"otpauth://totp/{accountTitleNoSpaces}?secret={arg}&issuer={UrlEncode(issuer)}") : UrlEncode($"otpauth://totp/{accountTitleNoSpaces}?secret={arg}"));
            string text3 = useHttps ? "https" : "http";
            string text5 = setupCode.QrCodeSetupImageUrl = $"{text3}://chart.googleapis.com/chart?cht=qr&chs={qrCodeWidth}x{qrCodeHeight}&chl={text2}";
            return setupCode;
        }

        private string UrlEncode(string value)
        {
            StringBuilder stringBuilder = new StringBuilder();
            string text = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
            foreach (char c in value)
            {
                if (text.IndexOf(c) != -1)
                {
                    stringBuilder.Append(c);
                }
                else
                {
                    stringBuilder.Append("%" + $"{(int)c:X2}");
                }
            }
            return stringBuilder.ToString().Replace(" ", "%20");
        }

        private string EncodeAccountSecretKey(string accountSecretKey)
        {
            return Base32Encode(Encoding.Default.GetBytes(accountSecretKey));
        }

        private string Base32Encode(byte[] data)
        {
            int num = 8;
            int num2 = 5;
            char[] array = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();
            int num3 = 0;
            int num4 = 0;
            int num5 = 0;
            StringBuilder stringBuilder = new StringBuilder((data.Length + 7) * num / num2);
            while (num3 < data.Length)
            {
                int num6 = (data[num3] >= 0) ? data[num3] : (data[num3] + 256);
                if (num4 > num - num2)
                {
                    int num7 = (num3 + 1 < data.Length) ? ((data[num3 + 1] >= 0) ? data[num3 + 1] : (data[num3 + 1] + 256)) : 0;
                    num5 = (num6 & (255 >> num4));
                    num4 = (num4 + num2) % num;
                    num5 <<= num4;
                    num5 |= num7 >> num - num4;
                    num3++;
                }
                else
                {
                    num5 = ((num6 >> num - (num4 + num2)) & 0x1F);
                    num4 = (num4 + num2) % num;
                    if (num4 == 0)
                    {
                        num3++;
                    }
                }
                stringBuilder.Append(array[num5]);
            }
            return stringBuilder.ToString();
        }

        public string GeneratePINAtInterval(string accountSecretKey, long counter, int digits = 6)
        {
            return GenerateHashedCode(accountSecretKey, counter, digits);
        }

        internal string GenerateHashedCode(string secret, long iterationNumber, int digits = 6)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(secret);
            return GenerateHashedCode(bytes, iterationNumber, digits);
        }

        internal string GenerateHashedCode(byte[] key, long iterationNumber, int digits = 6)
        {
            byte[] bytes = BitConverter.GetBytes(iterationNumber);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            HMACSHA1 hMACSha1Algorithm = getHMACSha1Algorithm(key);
            byte[] array = hMACSha1Algorithm.ComputeHash(bytes);
            int num = array[array.Length - 1] & 0xF;
            int num2 = ((array[num] & 0x7F) << 24) | (array[num + 1] << 16) | (array[num + 2] << 8) | array[num + 3];
            return (num2 % (int)Math.Pow(10.0, (double)digits)).ToString(new string('0', digits));
        }

        private long GetCurrentCounter()
        {
            return GetCurrentCounter(DateTime.UtcNow, _epoch, 30);
        }

        private long GetCurrentCounter(DateTime now, DateTime epoch, int timeStep)
        {
            return (long)(now - epoch).TotalSeconds / timeStep;
        }

        private HMACSHA1 getHMACSha1Algorithm(byte[] key)
        {
            try
            {
                return new HMACSHA1(key, UseManagedSha1Algorithm);
            }
            catch (InvalidOperationException ex2)
            {
                if (UseManagedSha1Algorithm && TryUnmanagedAlgorithmOnFailure)
                {
                    try
                    {
                        return new HMACSHA1(key, false);
                    }
                    catch (InvalidOperationException ex)
                    {
                        throw ex;
                    }
                }
                throw ex2;
            }
        }

        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient)
        {
            return ValidateTwoFactorPIN(accountSecretKey, twoFactorCodeFromClient, DefaultClockDriftTolerance);
        }

        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient, TimeSpan timeTolerance)
        {
            string[] currentPINs = GetCurrentPINs(accountSecretKey, timeTolerance);
            return currentPINs.Any((string c) => c == twoFactorCodeFromClient);
        }

        public string GetCurrentPIN(string accountSecretKey)
        {
            return GeneratePINAtInterval(accountSecretKey, GetCurrentCounter(), 6);
        }

        public string GetCurrentPIN(string accountSecretKey, DateTime now)
        {
            return GeneratePINAtInterval(accountSecretKey, GetCurrentCounter(now, _epoch, 30), 6);
        }

        public string[] GetCurrentPINs(string accountSecretKey)
        {
            return GetCurrentPINs(accountSecretKey, DefaultClockDriftTolerance);
        }

        public string[] GetCurrentPINs(string accountSecretKey, TimeSpan timeTolerance)
        {
            List<string> list = new List<string>();
            long currentCounter = GetCurrentCounter();
            int num = 0;
            if (timeTolerance.TotalSeconds > 30.0)
            {
                num = Convert.ToInt32(timeTolerance.TotalSeconds / 30.0);
            }
            long num2 = currentCounter - num;
            long num3 = currentCounter + num;
            for (long num4 = num2; num4 <= num3; num4++)
            {
                list.Add(GeneratePINAtInterval(accountSecretKey, num4, 6));
            }
            return list.ToArray();
        }
    }
}