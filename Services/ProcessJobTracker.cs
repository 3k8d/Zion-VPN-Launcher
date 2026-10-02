using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Zion.Services;

public static class ProcessJobTracker
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryLimit;
        public nuint PeakJobMemoryLimit;
    }

    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;

    private static IntPtr _jobHandle = IntPtr.Zero;
    private static bool _isSupervisorConfigured = false;
    private static int _initErrorCode;
    private static string _initErrorMessage = "";

    static ProcessJobTracker()
    {
        try
        {
            _jobHandle = CreateJobObject(IntPtr.Zero, null);
            if (_jobHandle == IntPtr.Zero)
            {
                _initErrorCode = Marshal.GetLastWin32Error();
                _initErrorMessage = $"CreateJobObject failed with Win32 error {_initErrorCode}";
                System.Diagnostics.Debug.WriteLine($"[ProcessJobTracker] {_initErrorMessage}");
                return;
            }

            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
            {
                BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
                {
                    LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                }
            };

            int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr extendedInfoPtr = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(info, extendedInfoPtr, false);
                if (!SetInformationJobObject(_jobHandle, JobObjectExtendedLimitInformation, extendedInfoPtr, (uint)length))
                {
                    _initErrorCode = Marshal.GetLastWin32Error();
                    _initErrorMessage = $"SetInformationJobObject failed with Win32 error {_initErrorCode}";
                    System.Diagnostics.Debug.WriteLine($"[ProcessJobTracker] {_initErrorMessage}");

                    // Supervisor initialization FAILED -> Invalidate handle so we never claim active supervision
                    CloseHandle(_jobHandle);
                    _jobHandle = IntPtr.Zero;
                    _isSupervisorConfigured = false;
                    return;
                }

                _isSupervisorConfigured = true;
            }
            finally
            {
                Marshal.FreeHGlobal(extendedInfoPtr);
            }
        }
        catch (Exception ex)
        {
            _initErrorMessage = ex.Message;
            if (_jobHandle != IntPtr.Zero)
            {
                CloseHandle(_jobHandle);
                _jobHandle = IntPtr.Zero;
            }
            _isSupervisorConfigured = false;
            System.Diagnostics.Debug.WriteLine($"[ProcessJobTracker] Initialization exception: {ex.Message}");
        }
    }

    public static (bool Success, string Error) TrackProcess(Process process)
    {
        if (process == null || process.HasExited)
        {
            return (false, "Процесс не запущен или уже завершился.");
        }

        if (!_isSupervisorConfigured || _jobHandle == IntPtr.Zero)
        {
            return (false, $"Process Supervisor не инициализирован (KILL_ON_JOB_CLOSE не активен): {_initErrorMessage}");
        }

        try
        {
            bool assigned = AssignProcessToJobObject(_jobHandle, process.Handle);
            if (!assigned)
            {
                int err = Marshal.GetLastWin32Error();
                string msg = $"AssignProcessToJobObject failed (Win32 Error: {err})";
                System.Diagnostics.Debug.WriteLine($"[ProcessJobTracker] {msg}");
                return (false, msg);
            }
            return (true, "");
        }
        catch (Exception ex)
        {
            string msg = $"Исключение при привязке к Job Object: {ex.Message}";
            System.Diagnostics.Debug.WriteLine($"[ProcessJobTracker] {msg}");
            return (false, msg);
        }
    }
}

