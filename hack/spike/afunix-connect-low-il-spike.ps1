<#
  izba spike #248 -- does Windows AF_UNIX connect() need WRITE access on the
  socket file?

  Context. On every default Windows start izba stamps the per-sandbox run dir
  (`VmSpec::confined_write_surfaces`) with an inheritable Low mandatory-
  integrity label (`procmgr::jail_windows::set_low_integrity_recursive`:
  SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, OBJECT_INHERIT | CONTAINER_INHERIT) so
  the Low-IL VMM can write there. The egress listener `vsock.sock_1027` and
  the USB broker `vsock.sock_1028` live in that dir and inherit the label.
  Windows has no SO_PEERCRED, so MIC's no-write-up rule is one of the last
  same-user barriers on those planes -- IF connect() requests write access on
  the socket file. That is undocumented. This script measures it.

  Method. For each condition below the (Medium-IL) parent binds two AF_UNIX
  listeners named exactly like izba's, plus a plain `probe.txt`, then runs the
  SAME client script twice as a child process built the way izba builds its
  VMM token (CreateRestrictedToken(DISABLE_MAX_PRIVILEGE) +
  SetTokenInformation(TokenIntegrityLevel) + CreateProcessAsUserW): once at
  Low IL (S-1-16-4096), once at Medium IL (S-1-16-8192, the control). The
  client reports, per file: the label it sees, whether it can open the file
  for READ_CONTROL / FILE_WRITE_DATA / GENERIC_WRITE, and whether connect()
  succeeds and completes a ping/pong round trip.

    unlabelled    dir carries no explicit label (implicit Medium)  -> the barrier
    label-before  dir labelled Low BEFORE the sockets are bound    -> inherit
    label-after   sockets bound, THEN the dir is labelled Low       -> propagate
                  (izba's SetNamedSecurityInfoW path re-labels an existing
                  subtree, so both orders that can occur in izbad are covered)

  Verdict logic (printed at the end, exit 0 when conclusive, 2 otherwise):
    controls: Low client sees FILE_WRITE_DATA denied (5) on the unlabelled
              sockets, Medium client ping/pongs everywhere, Low client
              ping/pongs on the Low-labelled sockets, ILs read back as 4096/8192
    YES  = Low client's connect() FAILS on the unlabelled sockets
           (connect needs write access; izba's default label removes a barrier)
    NO   = Low client's connect() SUCCEEDS on the unlabelled sockets
           (connect needs no write access; the label removes nothing)

  Run (from WSL, unsandboxed; no elevation needed -- neither does izba):
    cp hack/spike/afunix-connect-low-il-spike.ps1 /mnt/c/Users/<you>/
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Users\<you>\afunix-connect-low-il-spike.ps1'
  Everything lands under %LOCALAPPDATA%\izba-spike-afunix (wiped on re-run);
  the transcript path is printed last.
#>
[CmdletBinding()]
param(
  # Internal: child mode. Probes every file in -SocketDir and prints RESULT lines.
  [switch]$Client,
  [string]$Helper,
  [string]$SocketDir,
  # Parent mode: where to stage everything. Defaults to %LOCALAPPDATA%\izba-spike-afunix.
  [string]$Root
)
$ErrorActionPreference = 'Stop'

$LOW_SID = 'S-1-16-4096'
$MED_SID = 'S-1-16-8192'

# ---------------------------------------------------------------------------
# Native helper. Compiled ONCE by the parent into a DLL and loaded by path in
# the Low-IL child, so the child never needs to compile (csc writes to %TEMP%).
# The label and token code mirrors crates/izba-core/src/procmgr/jail_windows.rs
# call-for-call so the experiment measures izba's actual mechanism.
# ---------------------------------------------------------------------------
$helperSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace IzbaSpike
{
    public static class Native
    {
        public const int AF_UNIX = 1;
        public const int SOCK_STREAM = 1;
        public const int SUN_PATH_LEN = 108;
        public static readonly IntPtr INVALID_SOCKET = new IntPtr(-1);
        public static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

        public const uint READ_CONTROL = 0x00020000;
        public const uint FILE_WRITE_DATA = 0x00000002;
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint FILE_SHARE_ALL = 0x7;
        public const uint CREATE_ALWAYS = 2;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        public const int SE_FILE_OBJECT = 1;
        public const int LABEL_SECURITY_INFORMATION = 0x10;
        public const int ACL_REVISION = 2;
        public const int OBJECT_INHERIT_ACE = 0x1;
        public const int CONTAINER_INHERIT_ACE = 0x2;
        public const int SYSTEM_MANDATORY_LABEL_NO_WRITE_UP = 0x1;
        public const int SDDL_REVISION_1 = 1;

        public const int TokenIntegrityLevel = 25;
        public const uint SE_GROUP_INTEGRITY = 0x20;
        public const uint DISABLE_MAX_PRIVILEGE = 0x1;
        public const uint TOKEN_QUERY = 0x8;
        public const uint TOKEN_ALL_ACCESS = 0xF01FF;
        public const uint STARTF_USESTDHANDLES = 0x100;
        public const uint CREATE_NO_WINDOW = 0x08000000;

        // ---- ws2_32 ---------------------------------------------------------
        [DllImport("ws2_32.dll")] public static extern int WSAStartup(ushort ver, IntPtr data);
        [DllImport("ws2_32.dll")] public static extern IntPtr socket(int af, int type, int protocol);
        [DllImport("ws2_32.dll")] public static extern int bind(IntPtr s, byte[] name, int namelen);
        [DllImport("ws2_32.dll")] public static extern int listen(IntPtr s, int backlog);
        [DllImport("ws2_32.dll")] public static extern IntPtr accept(IntPtr s, IntPtr addr, IntPtr addrlen);
        [DllImport("ws2_32.dll")] public static extern int connect(IntPtr s, byte[] name, int namelen);
        [DllImport("ws2_32.dll")] public static extern int send(IntPtr s, byte[] buf, int len, int flags);
        [DllImport("ws2_32.dll")] public static extern int recv(IntPtr s, byte[] buf, int len, int flags);
        [DllImport("ws2_32.dll")] public static extern int closesocket(IntPtr s);
        [DllImport("ws2_32.dll")] public static extern int WSAGetLastError();

        // ---- kernel32 -------------------------------------------------------
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES sa, uint disp, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
        [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr h, out int code);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);

        // ---- advapi32 -------------------------------------------------------
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertStringSidToSidW(string s, out IntPtr sid);
        [DllImport("advapi32.dll")] static extern int GetLengthSid(IntPtr sid);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool InitializeAcl(IntPtr acl, int len, int rev);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AddMandatoryAce(IntPtr acl, int rev, int aceFlags, int policy, IntPtr sid);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int SetNamedSecurityInfoW(string name, int type, int info, IntPtr o, IntPtr g, IntPtr d, IntPtr s);
        [DllImport("advapi32.dll")]
        static extern int GetSecurityInfo(IntPtr h, int type, int info, IntPtr o, IntPtr g, IntPtr d, IntPtr s, out IntPtr sd);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, int rev, int info, out IntPtr str, out int len);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr tok);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr info, int len, out int ret);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetTokenInformation(IntPtr tok, int cls, ref TOKEN_MANDATORY_LABEL info, int len);
        [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, int idx);
        [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CreateRestrictedToken(IntPtr tok, uint flags, uint n1, IntPtr p1, uint n2, IntPtr p2, uint n3, IntPtr p3, out IntPtr newTok);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUserW(IntPtr tok, string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit,
            uint flags, IntPtr env, string cwd, ref STARTUPINFOW si, out PROCESS_INFORMATION pi);

        [StructLayout(LayoutKind.Sequential)]
        struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }
        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOW
        {
            public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

        static bool _wsa;
        public static void EnsureWsa()
        {
            if (_wsa) return;
            IntPtr buf = Marshal.AllocHGlobal(1024);
            int rc = WSAStartup(0x0202, buf);
            Marshal.FreeHGlobal(buf);
            if (rc != 0) throw new Exception("WSAStartup: " + rc);
            _wsa = true;
        }

        public static byte[] SockAddrUn(string path)
        {
            byte[] p = Encoding.UTF8.GetBytes(path);
            if (p.Length >= SUN_PATH_LEN) throw new Exception("socket path too long: " + path);
            byte[] sa = new byte[2 + SUN_PATH_LEN];
            sa[0] = AF_UNIX; sa[1] = 0;
            Array.Copy(p, 0, sa, 2, p.Length);
            return sa;
        }

        /// Win32 error of opening `path` for `access` (0 = opened fine). Opens
        /// the reparse point itself (AF_UNIX socket files are reparse points).
        public static int TryOpen(string path, uint access)
        {
            IntPtr h = CreateFileW(path, access, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (h == INVALID_HANDLE) return Marshal.GetLastWin32Error();
            CloseHandle(h);
            return 0;
        }

        /// The mandatory label on `path` as SDDL (`S:` part only), or "(none)".
        public static string ReadLabel(string path)
        {
            IntPtr h = CreateFileW(path, READ_CONTROL, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (h == INVALID_HANDLE) return "<open-failed:" + Marshal.GetLastWin32Error() + ">";
            try
            {
                IntPtr sd;
                int rc = GetSecurityInfo(h, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd);
                if (rc != 0) return "<GetSecurityInfo:" + rc + ">";
                IntPtr str; int len;
                if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, out str, out len))
                { LocalFree(sd); return "<sddl-failed:" + Marshal.GetLastWin32Error() + ">"; }
                string s = Marshal.PtrToStringUni(str);
                LocalFree(str); LocalFree(sd);
                return s.Length == 0 ? "(none)" : s;
            }
            finally { CloseHandle(h); }
        }

        /// izba's apply_inheritable_integrity_label, verbatim: one
        /// SYSTEM_MANDATORY_LABEL_ACE (no-write-up, OI|CI) applied with
        /// SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION), which propagates
        /// over the existing subtree.
        public static void ApplyInheritableLabel(string path, string sidStr)
        {
            IntPtr sid;
            if (!ConvertStringSidToSidW(sidStr, out sid)) throw new Exception("ConvertStringSidToSidW: " + Marshal.GetLastWin32Error());
            int aclSize = 64 + GetLengthSid(sid);
            IntPtr acl = Marshal.AllocHGlobal(aclSize);
            try
            {
                if (!InitializeAcl(acl, aclSize, ACL_REVISION)) throw new Exception("InitializeAcl: " + Marshal.GetLastWin32Error());
                if (!AddMandatoryAce(acl, ACL_REVISION, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid))
                    throw new Exception("AddMandatoryAce: " + Marshal.GetLastWin32Error());
                int rc = SetNamedSecurityInfoW(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, acl);
                if (rc != 0) throw new Exception("SetNamedSecurityInfoW(" + path + "): WIN32_ERROR " + rc);
            }
            finally { Marshal.FreeHGlobal(acl); LocalFree(sid); }
        }

        /// The calling process's integrity RID (4096 Low, 8192 Medium, ...).
        public static int CurrentIntegrityRid()
        {
            IntPtr tok;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out tok)) throw new Exception("OpenProcessToken: " + Marshal.GetLastWin32Error());
            try
            {
                int len;
                GetTokenInformation(tok, TokenIntegrityLevel, IntPtr.Zero, 0, out len);
                IntPtr buf = Marshal.AllocHGlobal(len);
                try
                {
                    if (!GetTokenInformation(tok, TokenIntegrityLevel, buf, len, out len)) throw new Exception("GetTokenInformation: " + Marshal.GetLastWin32Error());
                    IntPtr sid = Marshal.ReadIntPtr(buf);
                    int count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                    return Marshal.ReadInt32(GetSidSubAuthority(sid, count - 1));
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { CloseHandle(tok); }
        }

        /// One client-side measurement of `path`. `isSocket` adds the connect()
        /// + ping/pong leg. Output is a single parseable RESULT line.
        public static string Probe(string path, bool isSocket)
        {
            EnsureWsa();
            int il = CurrentIntegrityRid();
            string label = ReadLabel(path);
            int rd = TryOpen(path, READ_CONTROL);
            int wr = TryOpen(path, FILE_WRITE_DATA);
            int gw = TryOpen(path, GENERIC_WRITE);
            string crc = "n/a", werr = "n/a", pong = "n/a";
            if (isSocket)
            {
                IntPtr s = socket(AF_UNIX, SOCK_STREAM, 0);
                if (s == INVALID_SOCKET) throw new Exception("socket: " + WSAGetLastError());
                byte[] sa = SockAddrUn(path);
                int c = connect(s, sa, sa.Length);
                crc = c.ToString();
                werr = (c == 0 ? 0 : WSAGetLastError()).ToString();
                pong = "-";
                if (c == 0)
                {
                    send(s, Encoding.ASCII.GetBytes("ping"), 4, 0);
                    byte[] b = new byte[4];
                    int n = recv(s, b, 4, 0);
                    pong = n == 4 ? Encoding.ASCII.GetString(b) : ("recv=" + n + "/" + WSAGetLastError());
                }
                closesocket(s);
            }
            return string.Format("RESULT|{0}|il={1}|label={2}|open_read_control={3}|open_write_data={4}|open_generic_write={5}|connect={6}|wsaerr={7}|pong={8}",
                path, il, label, rd, wr, gw, crc, werr, pong);
        }

        /// izba's build_confined_token + spawn_confined, reduced to what the
        /// measurement needs: CreateRestrictedToken(DISABLE_MAX_PRIVILEGE) on the
        /// caller's token, SetTokenInformation(TokenIntegrityLevel = ilSid), then
        /// CreateProcessAsUserW with stdout+stderr on an inherited file handle.
        /// Returns the child's exit code (-999 on a 120 s timeout).
        public static int RunConfined(string cmdline, string ilSid, string outFile, string cwd)
        {
            IntPtr baseTok, tok;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, out baseTok)) throw new Exception("OpenProcessToken: " + Marshal.GetLastWin32Error());
            bool ok = CreateRestrictedToken(baseTok, DISABLE_MAX_PRIVILEGE, 0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out tok);
            int err = Marshal.GetLastWin32Error();
            CloseHandle(baseTok);
            if (!ok) throw new Exception("CreateRestrictedToken: " + err);
            IntPtr sid;
            if (!ConvertStringSidToSidW(ilSid, out sid)) throw new Exception("ConvertStringSidToSidW: " + Marshal.GetLastWin32Error());
            TOKEN_MANDATORY_LABEL lbl = new TOKEN_MANDATORY_LABEL();
            lbl.Label.Sid = sid; lbl.Label.Attributes = SE_GROUP_INTEGRITY;
            if (!SetTokenInformation(tok, TokenIntegrityLevel, ref lbl, Marshal.SizeOf(lbl))) throw new Exception("SetTokenInformation(IL): " + Marshal.GetLastWin32Error());
            LocalFree(sid);

            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(sa); sa.bInheritHandle = true;
            IntPtr hOut = CreateFileW(outFile, GENERIC_WRITE, FILE_SHARE_ALL, ref sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (hOut == INVALID_HANDLE) throw new Exception("CreateFileW(out): " + Marshal.GetLastWin32Error());
            IntPtr hIn = CreateFileW("NUL", GENERIC_READ, FILE_SHARE_ALL, ref sa, OPEN_EXISTING, 0, IntPtr.Zero);

            STARTUPINFOW si = new STARTUPINFOW();
            si.cb = Marshal.SizeOf(si);
            si.dwFlags = (int)STARTF_USESTDHANDLES;
            si.hStdInput = hIn; si.hStdOutput = hOut; si.hStdError = hOut;
            PROCESS_INFORMATION pi;
            StringBuilder cmd = new StringBuilder(cmdline);
            ok = CreateProcessAsUserW(tok, null, cmd, IntPtr.Zero, IntPtr.Zero, true, CREATE_NO_WINDOW, IntPtr.Zero, cwd, ref si, out pi);
            err = Marshal.GetLastWin32Error();
            CloseHandle(hOut); CloseHandle(hIn); CloseHandle(tok);
            if (!ok) throw new Exception("CreateProcessAsUserW: " + err);
            int code = -999;
            if (WaitForSingleObject(pi.hProcess, 120000) == 0) GetExitCodeProcess(pi.hProcess, out code);
            else TerminateProcess(pi.hProcess, 999);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            return code;
        }
    }

    /// A minimal AF_UNIX listener: accepts forever, answers "ping" with "pong".
    public class Server
    {
        IntPtr _l = Native.INVALID_SOCKET;
        Thread _t;
        public int Served;
        public string Path;

        public void Bind(string path)
        {
            Native.EnsureWsa();
            Path = path;
            _l = Native.socket(Native.AF_UNIX, Native.SOCK_STREAM, 0);
            if (_l == Native.INVALID_SOCKET) throw new Exception("socket: " + Native.WSAGetLastError());
            byte[] sa = Native.SockAddrUn(path);
            if (Native.bind(_l, sa, sa.Length) != 0) throw new Exception("bind(" + path + "): " + Native.WSAGetLastError());
            if (Native.listen(_l, 8) != 0) throw new Exception("listen: " + Native.WSAGetLastError());
        }

        public void Serve()
        {
            IntPtr l = _l;
            _t = new Thread(delegate ()
            {
                while (true)
                {
                    IntPtr c = Native.accept(l, IntPtr.Zero, IntPtr.Zero);
                    if (c == Native.INVALID_SOCKET) return;
                    byte[] b = new byte[4];
                    int n = Native.recv(c, b, 4, 0);
                    if (n == 4) Native.send(c, Encoding.ASCII.GetBytes("pong"), 4, 0);
                    Native.closesocket(c);
                    Interlocked.Increment(ref Served);
                }
            });
            _t.IsBackground = true;
            _t.Start();
        }

        public void Close()
        {
            if (_l != Native.INVALID_SOCKET) { Native.closesocket(_l); _l = Native.INVALID_SOCKET; }
        }
    }
}
'@

# ---------------------------------------------------------------------------
# Child (client) mode.
# ---------------------------------------------------------------------------
if ($Client) {
  Add-Type -Path $Helper
  Write-Output ("CLIENT pid={0} il={1} ps={2} user={3}" -f $PID, [IzbaSpike.Native]::CurrentIntegrityRid(), $PSVersionTable.PSVersion, $env:USERNAME)
  foreach ($f in ([IO.Directory]::GetFiles($SocketDir) | Sort-Object)) {
    $isSock = ([IO.Path]::GetFileName($f)) -like 'vsock.sock_*'
    Write-Output ([IzbaSpike.Native]::Probe($f, $isSock))
  }
  exit 0
}

# ---------------------------------------------------------------------------
# Parent mode.
# ---------------------------------------------------------------------------
if (-not $Root) { $Root = Join-Path $env:LOCALAPPDATA 'izba-spike-afunix' }
if (Test-Path -LiteralPath $Root) {
  # AF_UNIX socket files are reparse points Remove-Item may refuse; rmdir handles them.
  cmd /c rmdir /s /q "$Root" | Out-Null
}
$helperDir = Join-Path $Root 'helper'
$outDir    = Join-Path $Root 'out'
New-Item -ItemType Directory -Force -Path $Root, $helperDir, $outDir | Out-Null
# A Low-IL child needs a Low-writable TEMP; %LOCALAPPDATA%\..\LocalLow is the
# OS convention for exactly that, and we label it explicitly regardless.
$lowTmp = Join-Path $env:USERPROFILE 'AppData\LocalLow\izba-spike-afunix-tmp'
New-Item -ItemType Directory -Force -Path $lowTmp | Out-Null

$transcript = Join-Path $Root 'transcript.txt'
Start-Transcript -Path $transcript -Force | Out-Null
try {
  $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  Write-Output ("izba #248 AF_UNIX connect() write-access spike -- host {0} -- {1}" -f $env:COMPUTERNAME, (Get-Date -Format o))
  Write-Output ("Windows: {0} {1} build {2}.{3} ({4}); PowerShell {5}; user {6}" -f `
    $v.ProductName, $v.DisplayVersion, $v.CurrentBuild, $v.UBR, [Environment]::OSVersion.VersionString, $PSVersionTable.PSVersion, $env:USERNAME)

  $dll = Join-Path $helperDir 'IzbaAfUnixSpike.dll'
  Add-Type -TypeDefinition $helperSource -OutputAssembly $dll -OutputType Library | Out-Null
  Add-Type -Path $dll
  $script = Join-Path $helperDir 'spike.ps1'
  Copy-Item -LiteralPath $PSCommandPath -Destination $script -Force
  [IzbaSpike.Native]::ApplyInheritableLabel($lowTmp, $LOW_SID)
  Write-Output ("parent IL rid = {0}; low temp = {1} label {2}" -f [IzbaSpike.Native]::CurrentIntegrityRid(), $lowTmp, [IzbaSpike.Native]::ReadLabel($lowTmp))

  $conditions = @(
    @{ Name = 'unlabelled';   LabelBefore = $false; LabelAfter = $false },
    @{ Name = 'label-before'; LabelBefore = $true;  LabelAfter = $false },
    @{ Name = 'label-after';  LabelBefore = $false; LabelAfter = $true  }
  )
  $sockNames = @('vsock.sock_1027', 'vsock.sock_1028')
  $clients   = @(@{ Name = 'low'; Sid = $LOW_SID }, @{ Name = 'medium'; Sid = $MED_SID })
  $pwsh      = Join-Path $PSHOME 'powershell.exe'
  $results   = @()

  foreach ($c in $conditions) {
    $dir = Join-Path $Root $c.Name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    if ($c.LabelBefore) { [IzbaSpike.Native]::ApplyInheritableLabel($dir, $LOW_SID) }
    $servers = @()
    foreach ($n in $sockNames) {
      $s = New-Object IzbaSpike.Server
      $s.Bind((Join-Path $dir $n))
      $s.Serve()
      $servers += $s
    }
    Set-Content -LiteralPath (Join-Path $dir 'probe.txt') -Value 'x'
    if ($c.LabelAfter) { [IzbaSpike.Native]::ApplyInheritableLabel($dir, $LOW_SID) }

    Write-Output ''
    Write-Output ("== condition {0}: dir label = {1}" -f $c.Name, [IzbaSpike.Native]::ReadLabel($dir))
    foreach ($f in [IO.Directory]::GetFiles($dir)) {
      Write-Output ("   {0,-16} label (parent view) = {1}" -f [IO.Path]::GetFileName($f), [IzbaSpike.Native]::ReadLabel($f))
    }

    foreach ($cl in $clients) {
      $out = Join-Path $outDir ("{0}-{1}.txt" -f $c.Name, $cl.Name)
      $cmd = ('"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{1}" -Client -Helper "{2}" -SocketDir "{3}"' -f $pwsh, $script, $dll, $dir)
      $oldTemp = $env:TEMP; $oldTmp = $env:TMP
      $env:TEMP = $lowTmp; $env:TMP = $lowTmp
      try { $code = [IzbaSpike.Native]::RunConfined($cmd, $cl.Sid, $out, $lowTmp) }
      finally { $env:TEMP = $oldTemp; $env:TMP = $oldTmp }
      $text = Get-Content -LiteralPath $out -Raw
      Write-Output ("-- client {0} (token IL {1}) exit={2}" -f $cl.Name, $cl.Sid, $code)
      Write-Output $text.TrimEnd()
      foreach ($line in ($text -split "`r?`n" | Where-Object { $_ -like 'RESULT|*' })) {
        $parts = $line -split '\|'
        $kv = [ordered]@{ condition = $c.Name; client = $cl.Name; file = [IO.Path]::GetFileName($parts[1]) }
        foreach ($p in ($parts | Select-Object -Skip 2)) {
          $i = $p.IndexOf('='); $kv[$p.Substring(0, $i)] = $p.Substring($i + 1)
        }
        $results += [pscustomobject]$kv
      }
    }
    foreach ($s in $servers) { $s.Close() }
    Write-Output ("   connections served by the two listeners: {0}" -f (($servers | ForEach-Object { $_.Served } | Measure-Object -Sum).Sum))
  }

  Write-Output ''
  Write-Output '== SUMMARY (open_* columns are Win32 errors, 0 = opened, 5 = ACCESS_DENIED; wsaerr 10013 = WSAEACCES) =='
  Write-Output ($results | Sort-Object condition, client, file |
    Format-Table condition, client, file, il, label, open_read_control, open_write_data, open_generic_write, connect, wsaerr, pong -AutoSize |
    Out-String -Width 400).TrimEnd()

  # ---- verdict --------------------------------------------------------------
  $socks   = $results | Where-Object { $_.file -like 'vsock.sock_*' }
  $lowUnl  = $socks | Where-Object { $_.condition -eq 'unlabelled' -and $_.client -eq 'low' }
  $medAll  = $socks | Where-Object { $_.client -eq 'medium' }
  $lowLbl  = $socks | Where-Object { $_.condition -ne 'unlabelled' -and $_.client -eq 'low' }
  $problems = @()
  if (($results | Where-Object { $_.client -eq 'low' -and $_.il -ne '4096' }).Count) { $problems += 'a low client did not run at IL 4096' }
  if (($results | Where-Object { $_.client -eq 'medium' -and $_.il -ne '8192' }).Count) { $problems += 'a medium client did not run at IL 8192' }
  if ($lowUnl.Count -ne 2) { $problems += 'missing low/unlabelled socket results' }
  if (($lowUnl | Where-Object { $_.open_write_data -ne '5' }).Count) { $problems += 'the Low client was NOT denied FILE_WRITE_DATA on an unlabelled socket file (no MIC barrier to measure)' }
  if (($medAll | Where-Object { $_.pong -ne 'pong' }).Count) { $problems += 'the Medium control client failed to ping/pong somewhere' }
  if (($lowLbl | Where-Object { $_.pong -ne 'pong' }).Count) { $problems += 'the Low client failed to ping/pong on a Low-labelled socket' }

  Write-Output ''
  if ($problems.Count) {
    Write-Output 'VERDICT: INCONCLUSIVE -- a control failed:'
    $problems | ForEach-Object { Write-Output ("  - {0}" -f $_) }
    $exit = 2
  } elseif (($lowUnl | Where-Object { $_.pong -ne 'pong' }).Count -eq 0) {
    Write-Output 'VERDICT: NO -- AF_UNIX connect() does NOT require write access on the socket file.'
    Write-Output '  A Low-IL process connected (and completed a round trip) to sockets whose files it could not open for write.'
    Write-Output '  The inheritable Low label izba stamps on the run dir therefore removes no MIC barrier on vsock.sock_1027/1028.'
    $exit = 0
  } elseif (($lowUnl | Where-Object { $_.connect -eq '0' }).Count -eq 0) {
    Write-Output 'VERDICT: YES -- AF_UNIX connect() REQUIRES write access on the socket file.'
    Write-Output ("  A Low-IL process was refused (wsaerr {0}) on unlabelled sockets but succeeded on Low-labelled ones." -f (($lowUnl | Select-Object -ExpandProperty wsaerr -Unique) -join ','))
    Write-Output '  izba''s default Low label on the run dir removes a same-user MIC no-write-up barrier on vsock.sock_1027/1028.'
    $exit = 0
  } else {
    Write-Output 'VERDICT: INCONCLUSIVE -- mixed results across the two unlabelled sockets; see the table.'
    $exit = 2
  }
  Write-Output ("transcript: {0}" -f $transcript)
} finally {
  Stop-Transcript | Out-Null
  cmd /c rmdir /s /q "$lowTmp" | Out-Null
}
exit $exit
