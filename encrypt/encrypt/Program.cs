using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Encrypt
{
    class Program
    {
        private static Random random = new Random();

        // Path of templates directory, which should be same dir where the exe is + templates
        private static string templatesPath = AppDomain.CurrentDomain.BaseDirectory + "templates\\";

        static void Main(string[] args)
        {
            // Path of templates directory, which should be same dir where the exe is + templates
            if (!Directory.Exists(templatesPath))
            {
                Console.WriteLine("\n[!] ERROR: Ensure the templates directory and encrypt.exe are in the same directory.\n");
                Console.WriteLine("[!] Path should be: " + templatesPath);
                return;
            }

            Dictionary<string, string> argDict = ParseTheArguments(args);

            // print help if no arguments are supplied
            if ((args.Length > 0 && argDict.Count == 0) || argDict.ContainsKey("h"))
            {
                Console.WriteLine("encrypt.exe");
                Console.WriteLine("");

                Console.WriteLine("Examples:");
                Console.WriteLine("\tencrypt.exe -l cs -m file -i C:\\test\\beacon.bin -e random -o file");
                Console.WriteLine("\tencrypt.exe -l cpp -m string -i VirtualAlloc,LoadLibrary -e manual -k oC95@#Qy -s 2cVMpO!0 -v cf8U4v%M -o cli");
                Console.WriteLine("");

                Console.WriteLine("Language (-l):");
                Console.WriteLine("\t-l cpp - Create C/C++ encrypted output");
                Console.WriteLine("\t-l cs - Create C# encrypted output");
                Console.WriteLine("");

                Console.WriteLine("Mode (-m):");
                Console.WriteLine("\t-m file -a FILE- Read in a raw/binary position independent shellcode file");
                Console.WriteLine("\t-m string -a - Read in one or more comma-seperated strings");
                Console.WriteLine("");

                Console.WriteLine("Input (-i):");
                Console.WriteLine("\t-i C:\\test\\beacon.bin");
                Console.WriteLine("\t-i VirtualAlloc,LoadLibrary");
                Console.WriteLine("");

                Console.WriteLine("Encryption Type (-e):");
                Console.WriteLine("\t-e random - Randomly generate a alphanyumeric key, salt and initialization value");
                Console.WriteLine("\t-e manual - Manually supply a alphanumeric key, salt and initialization value. This requires the following three arguments:");
                Console.WriteLine("\t\t -k Password123");
                Console.WriteLine("\t\t -s Salt123");
                Console.WriteLine("\t\t -i InitVal123");
                Console.WriteLine("");

                Console.WriteLine("Ouput (-o):");
                Console.WriteLine("\t-o cli - Ouput to CLI");
                Console.WriteLine("\t-o file - Output to template files");
                Console.WriteLine("");

                return;
            }
            // declare variables for argument parsing
            string lang = "";
            string mode = "";
            string input = "";
            string enc = "";
            string password = "";
            string salt = "";
            string iv = "";
            string output = "";

            // ensure that the l flag is supplied with argument cs or cpp
            if (argDict.ContainsKey("l"))
            {
                if (argDict["l"].ToLower().Equals("cpp") || argDict["l"].ToLower().Equals("cs"))
                {
                    lang = argDict["l"].ToString().ToLower();
                }
                else
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a language type (-l cpp or -l cs)");
                    return;
                }
            }
            else if (!argDict.ContainsKey("l"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a valid language type (-l cpp or -l cs)");
                return;
            }

            // ensure that the m flag is supplied with argument file or string
            if (argDict.ContainsKey("m"))
            {
                if (argDict["m"].ToLower().Equals("file") || argDict["m"].ToLower().Equals("string"))
                {
                    mode = argDict["m"].ToString().ToLower();
                }
                else
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a valid mode (-m string or -m file)");
                    return;
                }
            }
            else if (!argDict.ContainsKey("m"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a mode (-m string or -m file)");
                return;
            }

            // ensure that the o flag is supplied with argument cli or file
            if (argDict.ContainsKey("o"))
            {
                if (argDict["o"].ToLower().Equals("cli") || argDict["o"].ToLower().Equals("file"))
                {
                    output = argDict["o"].ToString().ToLower();
                }
                else
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a valid output type (-o cli or -o file)");
                    return;
                }
            }
            else if (!argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply an output type (-o cli or -o file)");
                return;
            }

            // command line parsing logic
            if (argDict.ContainsKey("l") && argDict.ContainsKey("m") && argDict.ContainsKey("i") && argDict.ContainsKey("e") && argDict.ContainsKey("o"))
            {
                input = argDict["i"];
                enc = argDict["e"].ToLower();

                // check to see if random encryption was selected
                if (enc.Equals("random"))
                {
                    // set random values
                    password = RandomString();
                    salt = RandomString();
                    iv = RandomString();
                }
                // check to see if manual encryption was selected
                else if (enc.Equals("manual"))
                {
                    if (argDict.ContainsKey("k") && argDict.ContainsKey("s") && argDict.ContainsKey("v"))
                    {
                        // set user-supplied values
                        password = argDict["k"];
                        salt = argDict["s"];
                        iv = argDict["v"];
                    }
                    else
                    {
                        Console.WriteLine("\n[!] ERROR: Must supply a key (-k), salt (-s) and iv (-v)");
                        return;
                    }
                }
                else
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a valid encryption type (-e random or -e manual)");
                    return;
                }
                
                if (mode.Equals("file"))
                {
                    Console.WriteLine("\n[+] File encryption mode");
                }
                else if (mode.Equals("string"))
                {
                    Console.WriteLine("\n[+] String encryption mode");
                }
                
                // begin the encryption process
                Encrypt(lang, mode, input, password, salt, iv, output);
            }
            else if (argDict.ContainsKey("l") && mode.Equals("file") && argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a file (-i) and encryption type (-e) ");
                return;
            }
            else if (argDict.ContainsKey("l") && mode.Equals("string") && argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply one more comma-seperated strings (-i) and encryption type (-e)");
                return;
            }

        } // end Main

        // ParseTheArguments
        public static Dictionary<string, string> ParseTheArguments(string[] args)
        {
            try
            {
                Dictionary<string, string> ret = new Dictionary<string, string>();
                if (args.Length % 2 == 0 || args.Length % 3 == 0 && args.Length > 0)
                {
                    for (int i = 0; i < args.Length; i = i + 2)
                    {
                        ret.Add(args[i].Substring(1, args[i].Length - 1).ToLower(), args[i + 1]);
                    }
                }
                return ret;
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine("");
                Console.WriteLine("\n[!] You specified duplicate switches. Check your command again.\n");
                return null;
            }
        } // end ParseTheArguments

        // Encrypt
        public static void Encrypt(string lang, string mode, string input, string password, string salt, string iv, string output)
        {                    
            byte[] shellcode = new byte[] { };
            string path = "";

            if (mode.Equals("file"))
            {
                if (!File.Exists(input))
                {
                    Console.WriteLine("[!] ERROR: File not found");
                    return;
                }
                else
                {
                    // Read binary file into byte array
                    shellcode = System.IO.File.ReadAllBytes(input);

                    // Full path of input file with the extension removed.
                    path = Path.GetFullPath(input);
                    path = path.Substring(0, path.LastIndexOf('\\')) + "\\" + Path.GetFileNameWithoutExtension(input);
                }
            }

            // Convert the password into bytes and then SHA-256 hash
            byte[] passwordBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));

            // Convert the salt into bytes and then SHA-256 hash
            byte[] saltBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(salt));

            // Convert the iv into bytes and then MD5 hash (16 byte IV required for C++s)
            byte[] ivBytes = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(iv));

            //This will take a file which has raw position independant shellcode and create 1) an encrypted raw shellcode file (.bin) and 2) a sample C# template
            if (lang == "cs" && mode.Equals("file"))
            {
                byte[] encryptedShellcode = EncryptCSharp(shellcode, passwordBytes, saltBytes);
                string decryptTemplate = File.ReadAllText(templatesPath + "decrypt.cs");
                decryptTemplate = decryptTemplate.Replace("FILENAME_TEMPLATE", path + "-encrypted");
                decryptTemplate = decryptTemplate.Replace("AES_KEY_TEMPLATE", PrintByteArray(passwordBytes));
                decryptTemplate = decryptTemplate.Replace("AES_SALT_TEMPLATE", PrintByteArray(saltBytes));
                decryptTemplate = decryptTemplate.Replace("PAYLOAD_TEMPLATE", PrintByteArray(encryptedShellcode));

                Console.WriteLine("[+] Lang: " + lang);
                Console.WriteLine("[+] Key: " + password);
                Console.WriteLine("[+] Salt: " + salt + "\n");

                if (output.Equals("file"))
                {
                    File.WriteAllBytes(path + "-encrypted.bin", encryptedShellcode);
                    File.WriteAllText(path + "-encrypted.cs", decryptTemplate);
                    Console.WriteLine("[+] Encrypted raw shellcode file created: " + path + "-encrypted.bin");
                    Console.WriteLine("[+] C# Template file created: " + path + "-encrypted.cs");
                }
                else 
                {
                    // output is set to cli
                    Console.WriteLine("byte[] passwordBytes = new byte[] " + PrintByteArray(passwordBytes));
                    Console.WriteLine("\nbyte[] saltBytes = new byte[] " + PrintByteArray(saltBytes));
                    Console.WriteLine("\nbyte[] encryptedShellcode = new byte[] " + PrintByteArray(encryptedShellcode));
                }
            }
            //This will take one or more strings create a C# template file which decrypts the strings
            else if (lang == "cs" && mode.Equals("string"))
            {
                string[] words = input.Split(',');
                string insert = "";
                string insert_cli = "";
                string spaces = new string(' ', 12);
                path = AppDomain.CurrentDomain.BaseDirectory + words[0] + "-strings";
                string decryptTemplate = File.ReadAllText(templatesPath + "decrypt_s.cs");
                decryptTemplate = decryptTemplate.Replace("FILENAME_TEMPLATE", path + "-encrypted");
                decryptTemplate = decryptTemplate.Replace("AES_KEY_TEMPLATE", PrintByteArray(passwordBytes));
                decryptTemplate = decryptTemplate.Replace("AES_SALT_TEMPLATE", PrintByteArray(saltBytes));

                Console.WriteLine("[+] Lang: " + lang);
                Console.WriteLine("[+] Key: " + password);
                Console.WriteLine("[+] Salt: " + salt + "\n");

                foreach (var word in words)
                {
                    byte[] encryptedShellcode = EncryptCSharp(Encoding.ASCII.GetBytes(word), passwordBytes, saltBytes);
                    insert += "\n" + spaces + "byte[] " + word + "_enc = new byte[] " + PrintByteArray(encryptedShellcode);
                    insert += "\n" + spaces + "byte[] " + word + " = DecryptShellcode(passwordBytes, saltBytes, " + word + "_enc);";
                    insert += "\n" + spaces + "string " + word + "_str = Encoding.Default.GetString(" + word + ").Substring(0," + word.Length + ");\n";

                    insert_cli += "\n" + "byte[] " + word + "_enc = new byte[] " + PrintByteArray(encryptedShellcode);
                    insert_cli += "\n" + "byte[] " + word + " = DecryptShellcode(passwordBytes, saltBytes, " + word + "_enc);\n";

                    Console.WriteLine("[+] Encrypted: " + word);
                }

                if (output.Equals("file"))
                {
                    decryptTemplate = decryptTemplate.Replace("SHELLCODE_TEMPLATE", insert);
                    File.WriteAllText(path + "-encrypted.cs", decryptTemplate);
                    Console.WriteLine("\n[+] C# Template file created: " + path + "-encrypted.cs");
                }
                else
                {
                    // output is set to cli
                    Console.WriteLine("\nbyte[] passwordBytes = new byte[] " + PrintByteArray(passwordBytes));
                    Console.WriteLine("\nbyte[] saltBytes = new byte[] " + PrintByteArray(saltBytes));
                    Console.WriteLine(insert_cli);
                }                
            }
            //This will take a file which has raw position independant shellcode and create 1) an encrypted raw shellcode file (.bin) and 2) a sample C++ template
            else if (lang == "cpp" && mode.Equals("file"))
            {
                byte[] encryptedShellcode = EncryptC(shellcode, passwordBytes, ivBytes);
                string decryptTemplate = File.ReadAllText(templatesPath + "decrypt.cpp");
                decryptTemplate = decryptTemplate.Replace("FILENAME_TEMPLATE", path + "-encrypted");
                decryptTemplate = decryptTemplate.Replace("AES_IV_TEMPLATE", "{ 0x" + BitConverter.ToString(ivBytes).Replace("-", ", 0x") + " };");
                decryptTemplate = decryptTemplate.Replace("AES_KEY_TEMPLATE", "{ 0x" + BitConverter.ToString(Encoding.UTF8.GetBytes(password)).Replace("-", ", 0x") + " };");
                decryptTemplate = decryptTemplate.Replace("PAYLOAD_TEMPLATE", "{ 0x" + BitConverter.ToString(encryptedShellcode).Replace("-", ", 0x") + " };");

                Console.WriteLine("[+] Lang: " + lang);
                Console.WriteLine("[+] IV: " + iv);
                Console.WriteLine("[+] Key: " + password + "\n");

                if (output.Equals("file"))
                {
                    File.WriteAllBytes(path + "-encrypted.bin", encryptedShellcode);
                    File.WriteAllText(path + "-encrypted.cpp", decryptTemplate);
                    Console.WriteLine("[+] Encrypted raw shellcode file created: " + path + "-encrypted.bin");
                    Console.WriteLine("[+] C++ Template file created: " + path + "-encrypted.cpp");
                }
                else
                {
                    // output is set to cli
                    Console.WriteLine("char iv[] = " + "{ 0x" + BitConverter.ToString(ivBytes).Replace("-", ", 0x") + " };");
                    Console.WriteLine("\nchar key[] = " + "{ 0x" + BitConverter.ToString(Encoding.UTF8.GetBytes(password)).Replace("-", ", 0x") + " };");
                    Console.WriteLine("\nunsigned char payload[] = " + "{ 0x" + BitConverter.ToString(encryptedShellcode).Replace("-", ", 0x") + " };");
                }
            }
            //This will take one or more strings create a C++ template file which decrypts the strings
            else if (lang == "cpp" && mode.Equals("string"))
            {
                string[] words = input.Split(',');
                string insert = "";
                string insert_cli = "";
                string spaces = new string(' ', 8);
                path = AppDomain.CurrentDomain.BaseDirectory + words[0] + "-strings";
                string decryptTemplate = File.ReadAllText(templatesPath + "decrypt_s.cpp");
                decryptTemplate = decryptTemplate.Replace("FILENAME_TEMPLATE", path + "-encrypted");
                decryptTemplate = decryptTemplate.Replace("AES_IV_TEMPLATE", "{ 0x" + BitConverter.ToString(ivBytes).Replace("-", ", 0x") + " };");
                decryptTemplate = decryptTemplate.Replace("AES_KEY_TEMPLATE", "{ 0x" + BitConverter.ToString(Encoding.UTF8.GetBytes(password)).Replace("-", ", 0x") + " };");

                Console.WriteLine("[+] Lang: " + lang);
                Console.WriteLine("[+] IV: " + iv);
                Console.WriteLine("[+] Key: " + password + "\n");

                foreach (var word in words)
                {
                    byte[] encryptedShellcode = EncryptC(Encoding.ASCII.GetBytes(word), passwordBytes, ivBytes);
                    insert += "\n" + spaces + "unsigned char " + word + "[] = { 0x" + BitConverter.ToString(encryptedShellcode).Replace("-", ", 0x") + " };";
                    insert += "\n" + spaces + "unsigned int " + word + "_len = sizeof(" + word + ");";
                    insert += "\n" + spaces + "Decrypt((char*)" + word + ", " + word + "_len, key, sizeof(key), iv);\n";
                    
                    insert_cli += "\nunsigned char " + word + "[] = { 0x" + BitConverter.ToString(encryptedShellcode).Replace("-", ", 0x") + " };";
                    insert_cli += "\nunsigned int " + word + "_len = sizeof(" + word + ");\n";
                    Console.WriteLine("[+] Encrypted: " + word);
                }

                if (output.Equals("file"))
                {
                    decryptTemplate = decryptTemplate.Replace("SHELLCODE_TEMPLATE", insert);
                    File.WriteAllText(path + "-encrypted.cpp", decryptTemplate);
                    Console.WriteLine("\n[+] C++ Template file created: " + path + "-encrypted.cpp");
                }
                else
                {
                    // output is set to cli
                    Console.WriteLine("\nchar iv[] = " + "{ 0x" + BitConverter.ToString(ivBytes).Replace("-", ", 0x") + " };");
                    Console.WriteLine("\nchar key[] = " + "{ 0x" + BitConverter.ToString(Encoding.UTF8.GetBytes(password)).Replace("-", ", 0x") + " };");
                    Console.WriteLine(insert_cli);
                }
            }
            else
            {
                Console.WriteLine("\n[!] Specify a language and either an input file or string");
                Environment.Exit(1);
            }
        } //end Encrypt

        // RandomString https://stackoverflow.com/questions/1344221/how-can-i-generate-random-alphanumeric-strings        
        public static string RandomString()
        {
            // select a random number between 16 - 64 to use as the length of the random string
            int length = random.Next(16, 64);
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        } //end RandomString

        // EncryptCSharp
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

        // EncryptC
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

        // PrintByteArray https://stackoverflow.com/questions/10940883/c-converting-byte-array-to-string-and-printing-out-to-console
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
