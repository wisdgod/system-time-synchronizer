use ::core::time::Duration;
use ::std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

use ::chrono::{Datelike as _, TimeZone as _, Timelike as _, Utc};

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
    /// 获取程序参数（不包含程序名）
    #[inline]
    pub fn get_args() -> impl Iterator<Item = String> {
        let mut args = ::std::env::args();
        args.next(); // 跳过程序名
        args
    }

    /// Windows UTF-16编码辅助
    #[cfg(windows)]
    #[inline]
    pub fn to_wide_string(s: &str) -> Vec<u16> {
        use ::std::os::windows::ffi::OsStrExt;
        ::std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(::core::iter::once(0))
            .collect()
    }

    /// 构建带引号的参数字符串（用于shell命令）
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

    /// 管道缓冲区大小 - 512字节足够传输所有输出信息
    const BUFFER_SIZE: u32 = 512;

    /// 生成唯一的管道名称
    #[inline]
    pub fn pipe_name() -> String {
        unsafe { format!(r"\\.\pipe\ntp_sync_{}", GetCurrentProcessId()) }
    }

    /// 管道服务端 - 父进程使用
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
                    let error = GetLastError();
                    if error != ERROR_PIPE_CONNECTED {
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

    /// 管道客户端 - 子进程使用
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

/// 全局IPC客户端句柄
#[cfg(windows)]
static mut IPC_CLIENT: Option<ipc::PipeClient> = None;

/// 内部打印宏 - 支持IPC传输
macro_rules! __println {
    () => {
        __println!("")
    };
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        println!("{}", &msg);

        // Windows下尝试通过IPC发送消息
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
    /// 1900年1月1日到1970年1月1日的秒数差
    pub const EPOCH_DELTA: i64 = 0x83AA7E80;
}

/// 应用程序错误类型
enum AppError {
    /// 权限提升失败
    ElevationFailed(&'static str),
    /// 网络IO错误
    Network(::std::io::Error),
    /// NTP协议错误
    Protocol(&'static str),
    /// 系统时间设置失败
    SystemTime(&'static str),
    /// 时间解析错误
    TimeParse,
    /// IPC通信错误
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

// impl ::std::error::Error for AppError {}

impl From<::std::io::Error> for AppError {
    #[inline]
    fn from(err: ::std::io::Error) -> Self {
        Self::Network(err)
    }
}

fn main() {
    // 设置panic处理器
    ::std::panic::set_hook(Box::new(|info| {
        if let Some(msg) = info.payload().downcast_ref::<String>() {
            eprintln!("{msg}");
        } else if let Some(msg) = info.payload().downcast_ref::<&str>() {
            eprintln!("{msg}");
        }
    }));

    // 执行主逻辑并处理结果
    if let Err(e) = run() {
        eprintln!("错误: {e}");
        ::std::process::exit(1);
    }
}

fn run() -> Result<(), AppError> {
    // Windows下检查是否是子进程（通过管道参数）
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

    // 检查是否需要提升权限
    if !is_admin()? {
        __println!("检测到无管理员权限，尝试请求权限提升...");
        return elevate_privileges();
    }

    let socket = create_udp_socket()?;
    let server = connect_to_ntp_server(&socket)?;
    __println!("已连接到NTP服务器: {server}");

    let (ntp_packet, rtt) = send_and_receive_ntp_packet(&socket)?;
    validate_ntp_response(&ntp_packet)?;

    __println!("网络往返时间: {rtt:?}");
    let ntp_time = NtpTime::from_packet(&ntp_packet, rtt)?;
    __println!("NTP时间毫秒时间戳: {}", ntp_time.timestamp_millis());

    sync_system_time(&ntp_time)?;
    print_time_details(&ntp_time);

    Ok(())
}

/// 提升进程权限 - Windows实现（支持IPC）
#[cfg(windows)]
fn elevate_privileges() -> Result<(), AppError> {
    let exe_path =
        ::std::env::current_exe().map_err(|_| AppError::ElevationFailed("无法获取程序路径"))?;

    let exe_str = exe_path
        .to_str()
        .ok_or(AppError::ElevationFailed("路径包含无效字符"))?;

    // 创建命名管道服务器
    let pipe_name = ipc::pipe_name();
    let pipe_server = ipc::PipeServer::create(&pipe_name)?;

    // 构建带管道参数的命令行
    let params = format!("--pipe={pipe_name}");

    // 启动提升权限的子进程
    unsafe {
        let result = ShellExecuteW(
            ::core::ptr::null_mut(),
            utils::to_wide_string("runas").as_ptr(),
            utils::to_wide_string(&exe_str).as_ptr(),
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

    // 等待子进程连接并接收消息
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

/// 提升进程权限 - Unix/Linux实现
#[cfg(all(unix, not(target_os = "macos")))]
fn elevate_privileges() -> Result<(), AppError> {
    use ::std::process::Command;

    let exe_path =
        ::std::env::current_exe().map_err(|_| AppError::ElevationFailed("无法获取程序路径"))?;

    let args: Vec<String> = utils::get_args().collect();

    // 优先尝试pkexec
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

    // 降级到sudo
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

/// 提升进程权限 - macOS实现
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
        // 降级到sudo
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

/// 检查命令是否存在
#[cfg(unix)]
#[inline]
fn which_command(cmd: &str) -> bool {
    ::std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// 检查是否具有管理员权限
#[cfg(windows)]
fn is_admin() -> Result<bool, AppError> {
    /// Windows访问令牌查询封装
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

/// 创建UDP套接字
#[inline]
fn create_udp_socket() -> Result<UdpSocket, AppError> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(ntp::TIMEOUT_SECS)))?;
    socket.set_write_timeout(Some(Duration::from_secs(ntp::TIMEOUT_SECS)))?;
    Ok(socket)
}

/// 连接到NTP服务器
fn connect_to_ntp_server(socket: &UdpSocket) -> Result<&'static str, AppError> {
    for &server in ntp::SERVERS {
        if socket.connect((server, ntp::PORT)).is_ok() {
            return Ok(server);
        }
    }
    Err(AppError::Protocol("无法连接到任何NTP服务器"))
}

/// 发送并接收NTP数据包
fn send_and_receive_ntp_packet(
    socket: &UdpSocket,
) -> Result<([u8; ntp::PACKET_SIZE], Duration), AppError> {
    let mut packet = [0u8; ntp::PACKET_SIZE];
    packet[0] = (ntp::VERSION << 3) | ntp::MODE_CLIENT;

    let t1 = ::std::time::Instant::now();
    socket.send(&packet)?;
    socket.recv(&mut packet)?;
    let t2 = ::std::time::Instant::now();

    Ok((packet, t2.duration_since(t1)))
}

/// 验证NTP响应的有效性
#[inline]
fn validate_ntp_response(packet: &[u8]) -> Result<(), AppError> {
    let mode = packet[0] & 0x7;
    let version = (packet[0] & 0x38) >> 3;

    __println!("NTP响应: 版本={version}, 模式={mode}");

    if mode != ntp::MODE_SERVER {
        return Err(AppError::Protocol("响应模式不正确"));
    }
    Ok(())
}

/// NTP同步时间 - 封装已验证的时间数据
struct NtpTime {
    /// 缓存的时间组件
    year: u16,
    month: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    weekday: u16,
    /// 缓存的时间戳值
    timestamp_secs: i64,
    subsec_millis: u16,
}

impl NtpTime {
    /// 从NTP数据包创建
    fn from_packet(packet: &[u8; ntp::PACKET_SIZE], rtt: Duration) -> Result<Self, AppError> {
        let secs = u32::from_be_bytes([packet[40], packet[41], packet[42], packet[43]]);
        let frac = u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]);

        // 直接转换为毫秒（NTP的实际精度）
        let millis = ((frac as u64 * 1000) >> 32) as u32;
        let unix_timestamp = secs as i64 - ntp::EPOCH_DELTA;

        // 补偿网络延迟（RTT的一半，转换为毫秒）
        let compensation = (rtt.as_millis() / 2) as u32;
        let adjusted_millis = millis.saturating_add(compensation);

        // 处理毫秒溢出
        let (final_timestamp, final_millis) = if adjusted_millis >= 1000 {
            (unix_timestamp + 1, (adjusted_millis - 1000) as u16)
        } else {
            (unix_timestamp, adjusted_millis as u16)
        };

        // 创建DateTime只是为了提取组件，使用毫秒转纳秒
        let dt = Utc
            .timestamp_opt(final_timestamp, final_millis as u32 * 1_000_000)
            .single()
            .ok_or(AppError::TimeParse)?;

        Ok(Self {
            year: dt.year() as u16,
            month: dt.month() as u16,
            day: dt.day() as u16,
            hour: dt.hour() as u16,
            minute: dt.minute() as u16,
            second: dt.second() as u16,
            weekday: dt.weekday().num_days_from_sunday() as u16,
            timestamp_secs: final_timestamp,
            subsec_millis: final_millis,
        })
    }

    /// 获取完整的毫秒时间戳
    #[inline]
    fn timestamp_millis(&self) -> i64 {
        self.timestamp_secs * 1000 + self.subsec_millis as i64
    }
}

/// 同步系统时间
#[cfg(windows)]
fn sync_system_time(ntp_time: &NtpTime) -> Result<(), AppError> {
    let system_time = SYSTEMTIME {
        wYear: ntp_time.year,
        wMonth: ntp_time.month,
        wDay: ntp_time.day,
        wHour: ntp_time.hour,
        wMinute: ntp_time.minute,
        wSecond: ntp_time.second,
        wDayOfWeek: ntp_time.weekday,
        wMilliseconds: ntp_time.subsec_millis,
    };

    unsafe {
        if SetSystemTime(&system_time) == 0 {
            return Err(AppError::SystemTime("SetSystemTime调用失败"));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn sync_system_time(ntp_time: &NtpTime) -> Result<(), AppError> {
    // Unix系统需要纳秒，从毫秒转换
    let timespec = TimeSpec::new(
        ntp_time.timestamp_secs,
        (ntp_time.subsec_millis as i64) * 1_000_000,
    );

    clock_settime(ClockId::CLOCK_REALTIME, timespec)
        .map_err(|_| AppError::SystemTime("clock_settime调用失败"))
}

/// 打印时间详情
fn print_time_details(ntp_time: &NtpTime) {
    __println!("同步后的系统时间详情:");
    __println!("年份: {}", ntp_time.year);
    __println!("月份: {}", ntp_time.month);
    __println!("星期: {}", ntp_time.weekday);
    __println!("日期: {}", ntp_time.day);
    __println!("小时: {}", ntp_time.hour);
    __println!("分钟: {}", ntp_time.minute);
    __println!("秒数: {}", ntp_time.second);
    __println!("毫秒: {}", ntp_time.subsec_millis);
    __println!("系统时间已通过NTP成功同步!");
}
