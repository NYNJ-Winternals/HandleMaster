using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace HandleMaster
{
    class Program
    {
        [DllImport("ntdll.dll")]
        public static extern uint NtQuerySystemInformation(int
            SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength,
            ref int returnLength);

        [DllImport("kernel32.dll", EntryPoint = "RtlCopyMemory")]
        static extern void CopyMemory(byte[] Destination, IntPtr Source, uint Length);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SYSTEM_HANDLE_INFORMATION
        { // Information Class 16
            public int ProcessID;
            public byte ObjectTypeNumber;
            public byte Flags; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
            public ushort Handle;
            public int Object_Pointer;
            public UInt32 GrantedAccess;
        }

        const int CNST_SYSTEM_HANDLE_INFORMATION = 16;
        const uint STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;

        static void Main(string[] args)
        {

            foreach (var proc in Process.GetProcessesByName("chrome"))
            {
                var handles = GetHandles(proc);

                var oldColor = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.WriteLine("Process: {0}({1})", proc.ProcessName, proc.Id);
                Console.ForegroundColor = oldColor;

                foreach (var handle in handles)
                {
                    var output = string.Format("Handle: {0}, Flags: {1}, Pid: {2} Access: {3}", handle.Handle,
                                               handle.Flags, handle.ProcessID, handle.GrantedAccess);
                    if (handle.ProcessID != proc.Id)
                    {
                        oldColor = Console.ForegroundColor;
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(output);
                        Console.ForegroundColor = oldColor;
                    }
                    else
                    {
                        Console.WriteLine(output);
                    }
                }
            }

            Console.WriteLine();
            Console.ReadLine();
        }

        private static List<SYSTEM_HANDLE_INFORMATION> GetHandles(Process process)
        {
            uint nStatus;
            int nHandleInfoSize = 0x10000;
            IntPtr ipHandlePointer = Marshal.AllocHGlobal(nHandleInfoSize);
            int nLength = 0;
            IntPtr ipHandle = IntPtr.Zero;

            while ((nStatus = NtQuerySystemInformation(CNST_SYSTEM_HANDLE_INFORMATION, ipHandlePointer, nHandleInfoSize, ref nLength)) == STATUS_INFO_LENGTH_MISMATCH)
            {
                nHandleInfoSize = nLength;
                Marshal.FreeHGlobal(ipHandlePointer);
                ipHandlePointer = Marshal.AllocHGlobal(nLength);
            }

            byte[] baTemp = new byte[nLength];
            CopyMemory(baTemp, ipHandlePointer, (uint)nLength);

            long lHandleCount = 0;
            if (Is64Bits())
            {
                lHandleCount = Marshal.ReadInt64(ipHandlePointer);
                ipHandle = new IntPtr(ipHandlePointer.ToInt64() + 8);
            }
            else
            {
                lHandleCount = Marshal.ReadInt32(ipHandlePointer);
                ipHandle = new IntPtr(ipHandlePointer.ToInt32() + 4);
            }

            SYSTEM_HANDLE_INFORMATION shHandle;
            List<SYSTEM_HANDLE_INFORMATION> lstHandles = new List<SYSTEM_HANDLE_INFORMATION>();

            for (long lIndex = 0; lIndex < lHandleCount; lIndex++)
            {
                shHandle = new SYSTEM_HANDLE_INFORMATION();
                if (Is64Bits())
                {
                    shHandle = (SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                    ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle) + 8);
                }
                else
                {
                    ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle));
                    shHandle = (SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                }
                if (shHandle.ProcessID != process.Id) continue;
                lstHandles.Add(shHandle);
            }
            return lstHandles;

        }

        static bool Is64Bits()
        {
            return Marshal.SizeOf(typeof(IntPtr)) == 8 ? true : false;
        }
    }
}