using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Encrypt
{
    class Program
    {
        private static Random random = new Random();

        static void Main(string[] args)
        {
            if (args.Length == 2)
            {
                if (args[0].ToLower().Equals("cpp") || args[0].ToLower().Equals("cs"))
                {
                    Run(args[0].ToLower(), args[1]);
                }
                else
                {
                    Console.WriteLine("\n[!] encrypt.exe <mode: cs | cpp> <input: file or string>");
                    Environment.Exit(1);
                }
            }
            else
            {
                Console.WriteLine("\n[!] encrypt.exe <mode: cs | cpp> <input: file | string>");
                Environment.Exit(2);
            }
        } // end Main

        public static void Run(string mode, string input)
        {

            byte[] shellcode = new byte[] { };
            bool isFile;
            string path = "";

            if (File.Exists(input) == false)
            {
                Console.WriteLine("\n[+] String encryption mode.\n");
                isFile = false;
            }
            else
            {
                Console.WriteLine("\n[+] File encryption mode.\n");
                isFile = true;

                // Read binary file into byte array
                shellcode = System.IO.File.ReadAllBytes(input);

                // Full path of input file with the extension removed.
                path = Path.GetFullPath(input);
                path = path.Substring(0, path.LastIndexOf('\\')) + "\\" + Path.GetFileNameWithoutExtension(input);
            }

            string password = RandomString();
            string salt = RandomString();
            string iv = RandomString();

            // Convert the password into bytes and then SHA-256 hash
            byte[] passwordBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));

            // Convert the salt into bytes and then SHA-256 hash
            byte[] saltBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(salt));

            // Convert the iv into bytes and then MD5 hash (16 byte IV required for C++s)
            byte[] ivBytes = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(iv));

            // Path of templates directory, which should be same dir where the exe is + templates
            string templatesPath = AppDomain.CurrentDomain.BaseDirectory + "/templates/";

            //This will take a file which has raw position independant shellcode and create 1) an encrypted raw shellcode file (.bin) and 2) a sample C# template
            if (mode == "cs" && isFile == true)
            {
                byte[] encryptedShellcode = EncryptCSharp(shellcode, passwordBytes, saltBytes);
                string decryptTemplate = File.ReadAllText(templatesPath + "decrypt.cs");
                decryptTemplate = decryptTemplate.Replace("FILENAME_TEMPLATE", path + "-encrypted");
                decryptTemplate = decryptTemplate.Replace("AES_KEY_TEMPLATE", PrintByteArray(passwordBytes));
                decryptTemplate = decryptTemplate.Replace("AES_SALT_TEMPLATE", PrintByteArray(saltBytes));
                decryptTemplate = decryptTemplate.Replace("PAYLOAD_TEMPLATE", PrintByteArray(encryptedShellcode));
                File.WriteAllBytes(path + "-encrypted.bin", encryptedShellcode);
                File.WriteAllText(path + "-encrypted.cs", decryptTemplate);
                Console.WriteLine("[+] Encrypted raw shellcode file created: " + path + "-encrypted.bin");
                Console.WriteLine("[+] C# Template file created: " + path + "-encrypted.cs");
            }
            //This will take one or more strings create a C# template file which decrypts the strings
            else if (mode == "cs" && isFile == false)
            {
                string[] words = input.Split(',');
                string insert = "";
                string spaces = new string(' ', 12);
                path = AppDomain.CurrentDomain.BaseDirectory + words[0] + "-strings";
                string decryptTemplate = File.ReadAllText(templatesPath + "decrypt_s.cs");
                decryptTemplate = decryptTemplate.Replace("FILENAME_TEMPLATE", path + "-encrypted");
                decryptTemplate = decryptTemplate.Replace("AES_KEY_TEMPLATE", PrintByteArray(passwordBytes));
                decryptTemplate = decryptTemplate.Replace("AES_SALT_TEMPLATE", PrintByteArray(saltBytes));

                foreach (var word in words)
                {
                    byte[] encryptedShellcode = EncryptCSharp(Encoding.ASCII.GetBytes(word), passwordBytes, saltBytes);
                    insert += "\n" + spaces + "byte[] " + word + "_enc = new byte[] " + PrintByteArray(encryptedShellcode);
                    insert += "\n" + spaces + "byte[] " + word + " = DecryptShellcode(passwordBytes, saltBytes, " + word + "_enc);\n";
                    Console.WriteLine("[+] Encrypted: " + word);
                }

                decryptTemplate = decryptTemplate.Replace("SHELLCODE_TEMPLATE", insert);
                File.WriteAllText(path + "-encrypted.cs", decryptTemplate);
                Console.WriteLine("\n[+] C# Template file created: " + path + "-encrypted.cs");
            }
            //This will take a file which has raw position independant shellcode and create 1) an encrypted raw shellcode file (.bin) and 2) a sample C++ template
            else if (mode == "cpp" && isFile == true)
            {
                byte[] encryptedShellcode = EncryptC(shellcode, passwordBytes, ivBytes);
                string decryptTemplate = File.ReadAllText(templatesPath + "decrypt.cpp");
                decryptTemplate = decryptTemplate.Replace("FILENAME_TEMPLATE", path + "-encrypted");
                decryptTemplate = decryptTemplate.Replace("AES_IV_TEMPLATE", "{ 0x" + BitConverter.ToString(ivBytes).Replace("-", ", 0x") + " };");
                decryptTemplate = decryptTemplate.Replace("AES_KEY_TEMPLATE", "{ 0x" + BitConverter.ToString(Encoding.UTF8.GetBytes(password)).Replace("-", ", 0x") + " };");
                decryptTemplate = decryptTemplate.Replace("PAYLOAD_TEMPLATE", "{ 0x" + BitConverter.ToString(encryptedShellcode).Replace("-", ", 0x") + " };");
                File.WriteAllBytes(path + "-encrypted.bin", encryptedShellcode);
                File.WriteAllText(path + "-encrypted.cpp", decryptTemplate);
                Console.WriteLine("[+] Encrypted raw shellcode file created: " + path + "-encrypted.bin");
                Console.WriteLine("[+] C++ Template file created: " + path + "-encrypted.cpp");
            }
            //This will take one or more strings create a C++ template file which decrypts the strings
            else if (mode == "cpp" && isFile == false)
            {
                string[] words = input.Split(',');
                string insert = "";
                string spaces = new string(' ', 8);
                path = AppDomain.CurrentDomain.BaseDirectory + words[0] + "-strings";
                string decryptTemplate = File.ReadAllText(templatesPath + "decrypt_s.cpp");
                decryptTemplate = decryptTemplate.Replace("FILENAME_TEMPLATE", path + "-encrypted");
                decryptTemplate = decryptTemplate.Replace("AES_IV_TEMPLATE", "{ 0x" + BitConverter.ToString(ivBytes).Replace("-", ", 0x") + " };");
                decryptTemplate = decryptTemplate.Replace("AES_KEY_TEMPLATE", "{ 0x" + BitConverter.ToString(Encoding.UTF8.GetBytes(password)).Replace("-", ", 0x") + " };");

                foreach (var word in words)
                {
                    byte[] encryptedShellcode = EncryptC(Encoding.ASCII.GetBytes(word), passwordBytes, ivBytes);
                    insert += "\n" + spaces + "unsigned char " + word + "[] = { 0x" + BitConverter.ToString(encryptedShellcode).Replace("-", ", 0x") + " };";
                    insert += "\n" + spaces + "unsigned int " + word + "_len = sizeof(" + word + ");";
                    insert += "\n" + spaces + "Decrypt((char*)" + word + ", " + word + "_len, key, sizeof(key), iv);\n";
                    Console.WriteLine("[+] Encrypted: " + word);
                }

                decryptTemplate = decryptTemplate.Replace("SHELLCODE_TEMPLATE", insert);
                File.WriteAllText(path + "-encrypted.cpp", decryptTemplate);
                Console.WriteLine("\n[+] C++ Template file created: " + path + "-encrypted.cpp");
            }
            else
            {
                Console.WriteLine("\n[!] Specify a language and either an input file or string");
                Environment.Exit(1);
            }
        } //end Run

        //https://stackoverflow.com/questions/1344221/how-can-i-generate-random-alphanumeric-strings        
        public static string RandomString()
        {
            // select a random number between 16 - 64 to use as the length of the random string
            int length = random.Next(16, 64);
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        } //end RandomString

        static byte[] EncryptCSharp(byte[] shellcode, byte[] passwordBytes, byte[] saltBytes)
        {
            byte[] encryptedBytes = null;
            RijndaelManaged rj = new RijndaelManaged();
            rj.KeySize = 256;
            rj.BlockSize = 128;

            var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
            rj.Key = key.GetBytes(rj.KeySize / 8);
            rj.IV = key.GetBytes(rj.BlockSize / 8);
            rj.Mode = CipherMode.CBC;

            MemoryStream ms = new MemoryStream();
            using (CryptoStream cs = new CryptoStream(ms, rj.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(shellcode, 0, shellcode.Length);
                cs.FlushFinalBlock();
                encryptedBytes = ms.ToArray();
            }

            rj.Clear();

            return encryptedBytes;
        } //end EncryptCSharp

        static byte[] EncryptC(byte[] shellcode, byte[] passwordBytes, byte[] ivBytes)
        {
            byte[] encryptedBytes = null;
            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;

            //As passwordBytes has already been SHA-256 hashed, it is 32 bytes, which conforms to expected AES key size.
            aes.Key = passwordBytes;

            //As ivBytes has already been MD5 hashed, it is 16 bytes, which conforms to the expected IV size.
            aes.IV = ivBytes;
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            MemoryStream ms = new MemoryStream();
            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                cs.Write(shellcode, 0, shellcode.Length);
                cs.FlushFinalBlock();
                encryptedBytes = ms.ToArray();
            }
            return encryptedBytes;
        } //end EncryptC

        //https://stackoverflow.com/questions/10940883/c-converting-byte-array-to-string-and-printing-out-to-console
        static string PrintByteArray(byte[] bytes)
        {
            var sb = new StringBuilder("{ ");
            foreach (var b in bytes)
            {
                sb.Append(b + ", ");
            }
            sb.Append("};");
            return sb.ToString();
        } //end PrintByteArray
    }
}
