using System;
using System.IO;
using System.Security;
using GMax.Security;

namespace TestPPKConverting
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1 || args.Length > 2) {
                Console.WriteLine("Usage: TestPPKConverting <input.ppk> [<password>]");
            }
            else
            {
                var ppkpath = args[0];
                var password = args.Length == 2 ? args[1] : "";
                var lines = File.ReadAllLines(ppkpath);
                Console.WriteLine($" Read PPK from {ppkpath}");
                SecureString secpass = new SecureString();
                foreach (char c in password)
                {
                    secpass.AppendChar(c);
                }
                var ppk = new KeyConverter();
                ppk.ImportPPK(lines, secpass);

                var cert1 = ppk.ExportPrivateKey();
                var cert2 = ppk.ExportOpenSSH();

                Console.WriteLine(cert1);
                Console.WriteLine(cert2);
            }
        }
    }
}
