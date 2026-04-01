use ::core::time::Duration;
use ::std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use ::nix::{
    sys::time::TimeSpec,
    time::{ClockId, clock_settime},
};

#[cfg(windows)]
use ::windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, SYSTEMTIME,
    },
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
            PIPE_TYPE_MESSAGE, PIPE_WAIT,
        },
        SystemInformation::SetSystemTime,
        Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcessToken},
    },
    UI::{
        Shell::{SE_ERR_ACCESSDENIED, SE_ERR_FNF, ShellExecuteW},
        WindowsAndMessaging::SW_HIDE,
    },
};

/// 辅助函数模块
mod utils {
    #[inline]
    pub fn get_args() -> impl Iterator<Item = String> {
        let mut args = ::std::env::args();
        args.next();
        args
    }

    #[cfg(windows)]
    #[inline]
    pub fn to_wide_string(s: &str) -> Vec<u16> {
        use ::std::os::windows::ffi::OsStrExt;
        ::std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(::core::iter::once(0))
            .collect()
    }

    #[cfg(target_os = "macos")]
    #[inline]
    pub fn build_args_string<I>(args: I) -> String
    where
        I: Iterator<Item = String>,
    {
        args.map(|arg| {
            if arg.contains(' ') {
                format!(r#""{arg}""#)
            } else {
                arg
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
    }
}

/// IPC通信模块 - Windows命名管道实现
#[cfg(windows)]
mod ipc {
    use super::*;
    use crate::utils::to_wide_string;

    const BUFFER_SIZE: u32 = 512;

    #[inline]
    pub fn pipe_name() -> String {
        unsafe { format!(r"\\.\pipe\ntp_sync_{}", GetCurrentProcessId()) }
    }

    pub struct PipeServer {
        handle: HANDLE,
    }

    impl PipeServer {
        pub fn create(name: &str) -> Result<Self, AppError> {
            let wide_name = to_wide_string(name);
            unsafe {
                let handle = CreateNamedPipeW(
                    wide_name.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    1,
                    BUFFER_SIZE,
                    BUFFER_SIZE,
                    0,
                    ::core::ptr::null_mut(),
                );
                if handle == INVALID_HANDLE_VALUE {
                    return Err(AppError::Ipc("无法创建命名管道"));
                }
                Ok(Self { handle })
            }
        }

        pub fn wait_connection(&self) -> Result<(), AppError> {
            unsafe {
                if ConnectNamedPipe(self.handle, ::core::ptr::null_mut()) == 0 {
                    if GetLastError() != ERROR_PIPE_CONNECTED {
                        return Err(AppError::Ipc("等待管道连接失败"));
                    }
                }
            }
            Ok(())
        }

        pub fn read_message(&self) -> Result<String, AppError> {
            let mut buffer = [0u8; BUFFER_SIZE as usize];
            let mut bytes_read = 0u32;
            unsafe {
                if ReadFile(
                    self.handle,
                    buffer.as_mut_ptr() as *mut _,
                    BUFFER_SIZE,
                    &mut bytes_read,
                    ::core::ptr::null_mut(),
                ) == 0
                {
                    return Err(AppError::Ipc("读取管道消息失败"));
                }
            }
            String::from_utf8(buffer[..bytes_read as usize].to_vec())
                .map_err(|_| AppError::Ipc("消息编码错误"))
        }
    }

    impl Drop for PipeServer {
        #[inline]
        fn drop(&mut self) {
            unsafe {
                DisconnectNamedPipe(self.handle);
                CloseHandle(self.handle);
            }
        }
    }

    pub struct PipeClient {
        handle: HANDLE,
    }

    impl PipeClient {
        pub fn connect(name: &str) -> Result<Self, AppError> {
            let wide_name = to_wide_string(name);
            unsafe {
                let handle = CreateFileW(
                    wide_name.as_ptr(),
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    FILE_SHARE_NONE,
                    ::core::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    ::core::ptr::null_mut(),
                );
                if handle == INVALID_HANDLE_VALUE {
                    return Err(AppError::Ipc("无法连接到命名管道"));
                }
                Ok(Self { handle })
            }
        }

        pub fn send_message(&self, msg: &str) -> Result<(), AppError> {
            let bytes = msg.as_bytes();
            if bytes.len() > BUFFER_SIZE as usize {
                return Err(AppError::Ipc("消息过长"));
            }
            let mut bytes_written = 0u32;
            unsafe {
                if WriteFile(
                    self.handle,
                    bytes.as_ptr() as *const _,
                    bytes.len() as u32,
                    &mut bytes_written,
                    ::core::ptr::null_mut(),
                ) == 0
                {
                    return Err(AppError::Ipc("发送管道消息失败"));
                }
            }
            Ok(())
        }
    }

    impl Drop for PipeClient {
        #[inline]
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(windows)]
static mut IPC_CLIENT: Option<ipc::PipeClient> = None;

macro_rules! __println {
    () => {
        __println!("")
    };
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        println!("{}", &msg);
        #[cfg(windows)]
        unsafe {
            if let Some(ref client) = IPC_CLIENT {
                let _ = client.send_message(&msg);
            }
        }
    }};
}

/// NTP协议常量
mod ntp {
    pub const SERVERS: &[&str] = &["time.cloudflare.com", "ntp1.aliyun.com", "time.windows.com"];
    pub const PORT: u16 = 123;
    pub const TIMEOUT_SECS: u64 = 5;
    pub const PACKET_SIZE: usize = 48;
    pub const VERSION: u8 = 4;
    pub const MODE_CLIENT: u8 = 3;
    pub const MODE_SERVER: u8 = 4;
    /// 1900-01-01 到 1970-01-01 的秒数差
    pub const EPOCH_DELTA: i64 = 2_208_988_800;
}

// ─── NTP时间戳 ──────────────────────────────────────────────

/// NTP 64位时间戳（高32位=秒, 低32位=小数秒, 自1900年起）
#[derive(Clone, Copy)]
struct NtpTimestamp(u64);

impl NtpTimestamp {
    /// 从数据包指定偏移处解析
    #[inline(always)]
    fn from_packet(packet: &[u8], offset: usize) -> Self {
        Self(u64::from_be_bytes([
            packet[offset],
            packet[offset + 1],
            packet[offset + 2],
            packet[offset + 3],
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]))
    }

    #[inline(always)]
    fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// 转换为Unix纳秒（i128确保中间计算无溢出）
    #[inline(always)]
    fn to_unix_nanos(self) -> i128 {
        let secs = (self.0 >> 32) as i64 - ntp::EPOCH_DELTA;
        let frac = self.0 as u32;
        // NTP小数 → 纳秒: frac × 10⁹ / 2³²
        let nanos = ((frac as u64 * 1_000_000_000) >> 32) as i64;
        secs as i128 * 1_000_000_000 + nanos as i128
    }
}

// ─── NTP查询结果 ────────────────────────────────────────────

/// 包含所有计算中间值，供后续输出使用
struct NtpResult {
    server: &'static str,
    version: u8,
    stratum: u8,
    /// 网络往返时间（纳秒，来自单调时钟）
    rtt_ns: i128,
    /// 服务器处理耗时 T3-T2（纳秒）
    server_proc_ns: i128,
    /// 网络传输延迟 = RTT - 服务器处理（纳秒）
    net_delay_ns: i128,
    /// 单程延迟估算 = 网络延迟/2（纳秒）
    one_way_ns: i128,
    /// 本地时钟偏移 = 真实时间 - 本地时间（纳秒，正=落后）
    offset_ns: i128,
    /// t4时刻的真实时间（Unix纳秒）
    true_at_t4_ns: i128,
    /// t4时刻的单调时钟锚点
    mono_t4: Instant,
}

impl NtpResult {
    /// 基于单调时钟推算当前真实时间
    #[inline(always)]
    fn true_time_now_ns(&self) -> i128 {
        self.true_at_t4_ns + self.mono_t4.elapsed().as_nanos() as i128
    }
}

// ─── 错误类型 ───────────────────────────────────────────────

enum AppError {
    ElevationFailed(&'static str),
    Network(::std::io::Error),
    Protocol(&'static str),
    SystemTime(&'static str),
    TimeParse,
    #[cfg(windows)]
    Ipc(&'static str),
}

impl ::core::fmt::Display for AppError {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        match self {
            Self::ElevationFailed(msg) => write!(f, "权限提升失败: {msg}"),
            Self::Network(e) => write!(f, "网络错误: {e}"),
            Self::Protocol(msg) => write!(f, "NTP协议错误: {msg}"),
            Self::SystemTime(msg) => write!(f, "系统时间设置失败: {msg}"),
            Self::TimeParse => write!(f, "时间解析失败"),
            #[cfg(windows)]
            Self::Ipc(msg) => write!(f, "IPC通信错误: {msg}"),
        }
    }
}

impl From<::std::io::Error> for AppError {
    #[inline]
    fn from(err: ::std::io::Error) -> Self {
        Self::Network(err)
    }
}

// ─── 辅助函数 ───────────────────────────────────────────────

/// 当前系统时间 → Unix纳秒
#[inline(always)]
fn system_time_unix_nanos() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i128)
}

/// 总纳秒 → (秒, 纳秒)，确保纳秒 ∈ [0, 999_999_999]
#[inline(always)]
fn split_nanos(total_ns: i128) -> (i64, i32) {
    let mut secs = (total_ns / 1_000_000_000) as i64;
    let mut nanos = (total_ns % 1_000_000_000) as i32;
    if nanos < 0 {
        secs -= 1;
        nanos += 1_000_000_000;
    }
    (secs, nanos)
}

/// Unix纳秒 → jiff Zoned (UTC)
#[inline]
fn nanos_to_zoned(ns: i128) -> Result<jiff::Zoned, AppError> {
    let (secs, nanos) = split_nanos(ns);
    let ts = jiff::Timestamp::new(secs, nanos).map_err(|_| AppError::TimeParse)?;
    Ok(ts.to_zoned(jiff::tz::TimeZone::UTC))
}

// ─── 入口 ───────────────────────────────────────────────────

fn main() {
    ::std::panic::set_hook(Box::new(|info| {
        if let Some(msg) = info.payload().downcast_ref::<String>() {
            eprintln!("{msg}");
        } else if let Some(msg) = info.payload().downcast_ref::<&str>() {
            eprintln!("{msg}");
        }
    }));

    if let Err(e) = run() {
        eprintln!("错误: {e}");
        ::std::process::exit(1);
    }
}

fn run() -> Result<(), AppError> {
    #[cfg(windows)]
    {
        for arg in utils::get_args() {
            if let Some(pipe_name) = arg.strip_prefix("--pipe=") {
                unsafe {
                    IPC_CLIENT = ipc::PipeClient::connect(pipe_name).ok();
                }
                break;
            }
        }
    }

    if !is_admin()? {
        __println!("检测到无管理员权限，尝试请求权限提升...");
        return elevate_privileges();
    }

    let socket = create_udp_socket()?;
    let result = ntp_query(&socket)?;

    // ── 关键路径：先设置时间，后输出 ──
    let synced_ns = sync_system_time(&result)?;

    // ── 设置完成，安全地打印所有信息 ──
    print_results(&result, synced_ns);

    Ok(())
}

// ─── 权限提升 ───────────────────────────────────────────────

#[cfg(windows)]
fn elevate_privileges() -> Result<(), AppError> {
    let exe_path =
        ::std::env::current_exe().map_err(|_| AppError::ElevationFailed("无法获取程序路径"))?;

    let exe_str = exe_path
        .to_str()
        .ok_or(AppError::ElevationFailed("路径包含无效字符"))?;

    let pipe_name = ipc::pipe_name();
    let pipe_server = ipc::PipeServer::create(&pipe_name)?;
    let params = format!("--pipe={pipe_name}");

    unsafe {
        let result = ShellExecuteW(
            ::core::ptr::null_mut(),
            utils::to_wide_string("runas").as_ptr(),
            utils::to_wide_string(exe_str).as_ptr(),
            utils::to_wide_string(&params).as_ptr(),
            ::core::ptr::null(),
            SW_HIDE,
        );

        let code = result as usize;
        if code <= 32 {
            return Err(match code as u32 {
                SE_ERR_FNF => AppError::ElevationFailed("找不到指定的文件"),
                SE_ERR_ACCESSDENIED => AppError::ElevationFailed("用户拒绝了权限提升请求"),
                _ => AppError::ElevationFailed("无法启动提升权限的进程"),
            });
        }
    }

    println!("等待管理员进程响应...");
    pipe_server.wait_connection()?;

    loop {
        match pipe_server.read_message() {
            Ok(msg) => {
                if msg.is_empty() {
                    break;
                }
                println!("{msg}");
            }
            Err(_) => break,
        }
    }

    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn elevate_privileges() -> Result<(), AppError> {
    use ::std::process::Command;

    let exe_path =
        ::std::env::current_exe().map_err(|_| AppError::ElevationFailed("无法获取程序路径"))?;
    let args: Vec<String> = utils::get_args().collect();

    if which_command("pkexec") {
        __println!("使用pkexec请求管理员权限...");
        let status = Command::new("pkexec")
            .arg(&exe_path)
            .args(&args)
            .status()
            .map_err(|_| AppError::ElevationFailed("无法执行pkexec"))?;
        if !status.success() {
            return Err(AppError::ElevationFailed("权限提升被拒绝"));
        }
        return Ok(());
    }

    if which_command("sudo") {
        __println!("使用sudo请求管理员权限...");
        let status = Command::new("sudo")
            .arg(&exe_path)
            .args(&args)
            .status()
            .map_err(|_| AppError::ElevationFailed("无法执行sudo"))?;
        if !status.success() {
            return Err(AppError::ElevationFailed("权限提升被拒绝"));
        }
        return Ok(());
    }

    Err(AppError::ElevationFailed("系统中未找到sudo或pkexec"))
}

#[cfg(target_os = "macos")]
fn elevate_privileges() -> Result<(), AppError> {
    use ::std::process::Command;

    let exe_path =
        ::std::env::current_exe().map_err(|_| AppError::ElevationFailed("无法获取程序路径"))?;
    let args_str = utils::build_args_string(utils::get_args());

    __println!("请求管理员权限...");

    let script = format!(
        r#"do shell script "{} {}" with administrator privileges"#,
        exe_path.display(),
        args_str
    );

    let status = Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .status()
        .map_err(|_| AppError::ElevationFailed("无法执行osascript"))?;

    if !status.success() {
        if which_command("sudo") {
            __println!("降级使用sudo请求管理员权限...");
            let status = Command::new("sudo")
                .arg(&exe_path)
                .args(utils::get_args())
                .status()
                .map_err(|_| AppError::ElevationFailed("无法执行sudo"))?;
            if !status.success() {
                return Err(AppError::ElevationFailed("权限提升被拒绝"));
            }
            return Ok(());
        }
        return Err(AppError::ElevationFailed("权限提升被用户拒绝"));
    }

    Ok(())
}

#[cfg(unix)]
#[inline]
fn which_command(cmd: &str) -> bool {
    ::std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── 权限检查 ───────────────────────────────────────────────

#[cfg(windows)]
fn is_admin() -> Result<bool, AppError> {
    struct QueryAccessToken(HANDLE);

    impl QueryAccessToken {
        fn from_current_process() -> Result<Self, ::std::io::Error> {
            unsafe {
                let mut handle = ::core::ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) != 0 {
                    Ok(Self(handle))
                } else {
                    Err(::std::io::Error::last_os_error())
                }
            }
        }

        fn is_elevated(&self) -> Result<bool, ::std::io::Error> {
            unsafe {
                let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                let size = ::core::mem::size_of::<TOKEN_ELEVATION>() as u32;
                let mut ret_size = size;
                if GetTokenInformation(
                    self.0,
                    TokenElevation,
                    &mut elevation as *mut _ as *mut _,
                    size,
                    &mut ret_size,
                ) != 0
                {
                    Ok(elevation.TokenIsElevated != 0)
                } else {
                    Err(::std::io::Error::last_os_error())
                }
            }
        }
    }

    impl Drop for QueryAccessToken {
        #[inline]
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    let token = QueryAccessToken::from_current_process()?;
    Ok(token.is_elevated()?)
}

#[cfg(unix)]
#[inline]
fn is_admin() -> Result<bool, AppError> {
    Ok(::nix::unistd::geteuid().is_root())
}

// ─── UDP套接字 ──────────────────────────────────────────────

#[inline]
fn create_udp_socket() -> Result<UdpSocket, AppError> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(ntp::TIMEOUT_SECS)))?;
    socket.set_write_timeout(Some(Duration::from_secs(ntp::TIMEOUT_SECS)))?;
    Ok(socket)
}

// ─── NTP查询（核心） ────────────────────────────────────────

/// 遍历服务器列表，返回第一个成功的查询结果
fn ntp_query(socket: &UdpSocket) -> Result<NtpResult, AppError> {
    for &server in ntp::SERVERS {
        if socket.connect((server, ntp::PORT)).is_err() {
            continue;
        }
        match ntp_exchange(socket, server) {
            Ok(result) => return Ok(result),
            Err(_) => continue,
        }
    }
    Err(AppError::Protocol("无法连接到任何NTP服务器"))
}

/// 与单个服务器完成一次NTP交换
///
/// 时序:
///   T1 = 本地发送时刻 (Instant + SystemTime)
///   T2 = 服务器收到时刻 (NTP receive timestamp, 包偏移32)
///   T3 = 服务器发送时刻 (NTP transmit timestamp, 包偏移40)
///   T4 = 本地收到时刻 (Instant + SystemTime)
///
/// 偏移 θ = ((T2-T1) + (T3-T4)) / 2
/// 真实时间@T4 = T3 + 单程延迟 = T3 + (RTT - (T3-T2)) / 2
#[inline]
fn ntp_exchange(socket: &UdpSocket, server: &'static str) -> Result<NtpResult, AppError> {
    let mut packet = [0u8; ntp::PACKET_SIZE];
    packet[0] = (ntp::VERSION << 3) | ntp::MODE_CLIENT;

    // ── T1: 记录本地发送时刻 ──
    let sys_t1 = system_time_unix_nanos();
    let mono_t1 = Instant::now();
    socket.send(&packet)?;

    // ── T4: 记录本地接收时刻 ──
    let n = socket.recv(&mut packet).unwrap_or(0);
    let mono_t4 = Instant::now();
    let sys_t4 = sys_t1 + mono_t4.duration_since(mono_t1).as_nanos() as i128;

    if n < ntp::PACKET_SIZE {
        return Err(AppError::Protocol("响应包长度不足"));
    }

    // ── 验证响应 ──
    let mode = packet[0] & 0x07;
    let version = (packet[0] >> 3) & 0x07;
    let stratum = packet[1];

    if mode != ntp::MODE_SERVER {
        return Err(AppError::Protocol("响应模式不正确"));
    }
    if stratum == 0 || stratum >= 16 {
        return Err(AppError::Protocol(
            "服务器层级无效 (kiss-o'-death 或未同步)",
        ));
    }

    // ── 解析服务器时间戳 ──
    let t2 = NtpTimestamp::from_packet(&packet, 32); // receive timestamp
    let t3 = NtpTimestamp::from_packet(&packet, 40); // transmit timestamp

    if t3.is_zero() {
        return Err(AppError::Protocol("服务器传输时间戳为零"));
    }

    let t2_ns = t2.to_unix_nanos();
    let t3_ns = t3.to_unix_nanos();

    // ── 计算 ──
    // RTT 使用单调时钟（不受本地时钟偏差影响）
    let rtt_ns = mono_t4.duration_since(mono_t1).as_nanos() as i128;

    // 服务器处理耗时
    let server_proc_ns = t3_ns - t2_ns;

    // 网络传输延迟 = RTT - 服务器处理时间（钳位到 ≥0）
    let net_delay_ns = (rtt_ns - server_proc_ns).max(0);

    // 单程延迟估算
    let one_way_ns = net_delay_ns / 2;

    // T4时刻的真实时间 = T3 + 单程延迟
    let true_at_t4_ns = t3_ns + one_way_ns;

    // 本地时钟偏移（正=本地落后，负=本地超前）
    let offset_ns = true_at_t4_ns - sys_t4;

    Ok(NtpResult {
        server,
        version,
        stratum,
        rtt_ns,
        server_proc_ns,
        net_delay_ns,
        one_way_ns,
        offset_ns,
        true_at_t4_ns,
        mono_t4,
    })
}

// ─── 同步系统时间 ───────────────────────────────────────────

/// 返回实际写入的Unix纳秒值
#[cfg(windows)]
fn sync_system_time(result: &NtpResult) -> Result<i128, AppError> {
    // 尽量贴近syscall：先算好时间，再一次性设置
    let now_ns = result.true_time_now_ns();
    let zoned = nanos_to_zoned(now_ns)?;

    let system_time = SYSTEMTIME {
        wYear: zoned.year() as u16,
        wMonth: zoned.month() as u16,
        wDay: zoned.day() as u16,
        wHour: zoned.hour() as u16,
        wMinute: zoned.minute() as u16,
        wSecond: zoned.second() as u16,
        wDayOfWeek: weekday_sunday_zero(zoned.weekday()),
        wMilliseconds: zoned.millisecond() as u16,
    };

    unsafe {
        if SetSystemTime(&system_time) == 0 {
            return Err(AppError::SystemTime("SetSystemTime调用失败"));
        }
    }
    Ok(now_ns)
}

#[cfg(windows)]
#[inline]
fn weekday_sunday_zero(wd: jiff::civil::Weekday) -> u16 {
    use jiff::civil::Weekday::*;
    match wd {
        Sunday => 0,
        Monday => 1,
        Tuesday => 2,
        Wednesday => 3,
        Thursday => 4,
        Friday => 5,
        Saturday => 6,
    }
}

#[cfg(unix)]
fn sync_system_time(result: &NtpResult) -> Result<i128, AppError> {
    let now_ns = result.true_time_now_ns();
    let (secs, nanos) = split_nanos(now_ns);
    let timespec = TimeSpec::new(secs, nanos as i64);
    clock_settime(ClockId::CLOCK_REALTIME, timespec)
        .map_err(|_| AppError::SystemTime("clock_settime调用失败"))?;
    Ok(now_ns)
}

// ─── 输出 ───────────────────────────────────────────────────

fn print_results(result: &NtpResult, synced_ns: i128) {
    __println!("─── NTP时间同步完成 ───");
    __println!();
    __println!(
        "服务器: {} (NTPv{}, stratum {})",
        result.server,
        result.version,
        result.stratum
    );
    __println!();

    // 延迟分解
    __println!("── 延迟分析 ──");
    __println!(
        "  网络往返(RTT):   {:>8.3} ms",
        result.rtt_ns as f64 / 1_000_000.0
    );
    __println!(
        "  服务器处理:      {:>8.3} ms",
        result.server_proc_ns as f64 / 1_000_000.0
    );
    __println!(
        "  网络传输:        {:>8.3} ms",
        result.net_delay_ns as f64 / 1_000_000.0
    );
    __println!(
        "  单程延迟估算:    {:>8.3} ms",
        result.one_way_ns as f64 / 1_000_000.0
    );
    __println!();

    // 偏移
    let offset_ms = result.offset_ns as f64 / 1_000_000.0;
    let direction = if result.offset_ns >= 0 {
        "落后"
    } else {
        "超前"
    };
    __println!("── 时钟偏移 ──");
    __println!(
        "  本地时钟{direction}: {:.3} ms ({:.1} μs)",
        offset_ms.abs(),
        (result.offset_ns as f64).abs() / 1_000.0
    );

    // 同步前的本地时间
    let local_before_ns = synced_ns - result.offset_ns;
    if let Ok(before) = nanos_to_zoned(local_before_ns) {
        __println!("  同步前(本地): {}", format_zoned(&before));
    }

    // 同步后的时间
    if let Ok(after) = nanos_to_zoned(synced_ns) {
        __println!("  同步后(NTP):  {}", format_zoned(&after));
    }
    __println!();

    // 时间戳
    let (secs, nanos) = split_nanos(synced_ns);
    let millis = secs * 1000 + (nanos / 1_000_000) as i64;
    __println!("NTP时间毫秒时间戳: {millis}");
    __println!();

    // 组件详情
    if let Ok(z) = nanos_to_zoned(synced_ns) {
        __println!("── 时间详情 (UTC) ──");
        __println!(
            "  {:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            z.year(),
            z.month(),
            z.day(),
            z.hour(),
            z.minute(),
            z.second(),
            z.millisecond()
        );
        __println!("  星期: {:?}", z.weekday());
    }

    __println!();
    __println!("系统时间已通过NTP成功同步!");
}

#[inline]
fn format_zoned(z: &jiff::Zoned) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} UTC",
        z.year(),
        z.month(),
        z.day(),
        z.hour(),
        z.minute(),
        z.second(),
        z.millisecond()
    )
}
