namespace PasswordHash
{
    using System;
    using System.Linq;
    using System.Text;
    using System.Security.Cryptography;

    public class Program
    {
        public static void Main(string[] args)
        {
            var salt1 = "908D C60A";
            var password1 = "test12";
            var passwordHash = GetPasswordHash(salt1, password1);
            Console.WriteLine("-------------------------------");

            var salt2 = GetSalt(8);
            var password2 = "M3ssW1thTheBul";
            var passwordHash2 = GetPasswordHash(salt2, password2);
            Console.WriteLine("-------------------------------");

            Console.ReadLine();
        }

        public static string GetPasswordHash(string salt, string password)
        {
            Console.WriteLine("Salt: {0}", salt);
            Console.WriteLine("Password: {0}", password);
            // UTF8 of password 
            System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();
            var utf8Encoded = encoding.GetBytes(password);

            // Concatenate salt with password
            var concat = $"{salt} {ByteArrayToString(utf8Encoded)}";

            // SHA256
            var sha256 = ByteArrayToString(GetSha256(concat));

            // Concat again
            var concat2 = $"{salt} {sha256}";

            // Convert to base 64
            var bytes = StringToByteArray(concat2);
            var passwordHash = ConvertToBase64(bytes);

            Console.WriteLine("Password Hash: {0}", passwordHash);
            return passwordHash;
        }

        public static string GetSalt(int length)
        {
            var random = new Random();
            var buffer = new byte[length / 2];
            random.NextBytes(buffer);
            var result = string.Concat(buffer.Select(x => x.ToString("X2")).ToArray());
            if (length % 2 == 0)
                return result;
            return result + random.Next(16).ToString("X");
        }

        public static byte[] StringToByteArray(string hex)
        {
            var cleanHex = RemoveWhitespace(hex);
            var numberChars = cleanHex.Length;
            var bytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(cleanHex.Substring(i, 2), 16);
            }

            return bytes;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            var hex = new StringBuilder(ba.Length * 2);
            var isEven = true;
            foreach (byte b in ba)
            {
                if (isEven)
                {
                    hex.AppendFormat("{0:x2}", b);
                    isEven = false;
                }
                else
                {
                    hex.AppendFormat("{0:x2} ", b);
                    isEven = true;
                }

            }

            return hex.ToString();
        }

        public static byte[] GetSha256(string text)
        {
            var crypt = SHA256.Create();
            var bytes = StringToByteArray(text);
            var hashedValue = crypt.ComputeHash(bytes);
            return hashedValue;
        }

        public static string ConvertToBase64(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        public static string RemoveWhitespace(string input)
        {
            return new string(input.ToCharArray()
                .Where(c => !Char.IsWhiteSpace(c))
                .ToArray());
        }
    }
}
