use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use bluer::AdapterEvent;
use chrono::Local;
use dirs;
use futures::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use qrcode::QrCode;
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use walkdir::WalkDir;
use wpactrl::{WpaCtrl, WpaError};

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB
const PORT_SIGNAL: &str = "PORT:";

#[derive(Error, Debug)]
enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Bluetooth error: {0}")]
    Bluetooth(#[from] bluer::Error),
    #[error("Wi-Fi Direct error: {0}")]
    WifiDirect(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Timeout error")]
    Timeout,
    #[error("User cancelled operation")]
    UserCancelled,
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Device not found")]
    DeviceNotFound,
    #[error("Connection failed")]
    ConnectionFailed,
    #[error("Transfer failed: {0}")]
    TransferFailed(String),
    #[error("Task join error: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),
}

type Result<T> = std::result::Result<T, AppError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Device {
    name: String,
    address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransferRequest {
    paths: Vec<PathBuf>,
    total_size: u64,
    file_hashes: HashMap<PathBuf, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileChunk {
    path: PathBuf,
    offset: u64,
    data: Vec<u8>,
}

async fn start_discovery(devices: Arc<Mutex<HashMap<String, Device>>>) -> Result<()> {
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    let mut events = adapter.discover_devices().await?;
    while let Some(event) = events.next().await {
        match event {
            AdapterEvent::DeviceAdded(addr) => {
                if let Ok(device) = adapter.device(addr) {
                    if let Ok(Some(name)) = device.name().await {
                        let new_device = Device {
                            name: name.clone(),
                            address: addr.to_string(),
                        };
                        devices.lock().unwrap().insert(addr.to_string(), new_device);
                        debug!("New device discovered: {} ({})", name, addr);
                    }
                }
            }
            AdapterEvent::DeviceRemoved(addr) => {
                devices.lock().unwrap().remove(&addr.to_string());
                debug!("Device removed: {}", addr);
            }
            _ => {}
        }
    }

    Ok(())
}

async fn transfer_files(request: &TransferRequest, recipient: &Device, wpa: &mut WpaCtrl) -> Result<()> {
    // Establish Wi-Fi Direct connection
    if let Err(e) = wpa.request(&format!("P2P_CONNECT {} pbc", recipient.address)) {
        return Err(AppError::WifiDirect(e.to_string()));
    }

    // Wait for connection to be established
    let connection_timeout = Duration::from_secs(30);
    let connection_result = timeout(connection_timeout, async {
        loop {
            match wpa.request("STATUS") {
                Ok(status) => {
                    if status.contains("P2P-GROUP-STARTED") {
                        return Ok(());
                    }
                },
                Err(e) => return Err(AppError::WifiDirect(e.to_string())),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
        .await;

    match connection_result {
        Ok(Ok(())) => info!("Wi-Fi Direct connection established"),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(AppError::Timeout),
    }

    // Get group information
    let group_info = match wpa.request("P2P_GROUP_INFO") {
        Ok(info) => info,
        Err(e) => return Err(AppError::WifiDirect(e.to_string())),
    };
    let _ip_address = group_info.lines()
        .find(|line| line.contains("IP address"))
        .and_then(|line| line.split_whitespace().last())
        .ok_or(AppError::ConnectionFailed)?;

    // Start TCP server for file transfer
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)).await?;
    let server_port = listener.local_addr()?.port();

    // Signal the server port to the peer
    if let Err(e) = wpa.request(&format!("P2P_SERVICE_ADD bonjour {} {}", PORT_SIGNAL, server_port)) {
        return Err(AppError::WifiDirect(e.to_string()));
    }

    // Accept incoming connection
    let accept_timeout = Duration::from_secs(30);
    let (mut stream, _) = timeout(accept_timeout, listener.accept()).await
        .map_err(|_| AppError::Timeout)??;

    // Generate encryption key
    let key = generate_encryption_key();

    // Send encryption key
    stream.write_all(&key).await?;

    // Send transfer request
    let request_json = serde_json::to_string(&request)?;
    let encrypted_request = encrypt_data(&key, request_json.as_bytes())?;
    stream.write_all(&(encrypted_request.len() as u32).to_be_bytes()).await?;
    stream.write_all(&encrypted_request).await?;

    // Create progress bars
    let multi_progress = MultiProgress::new();
    let total_pb = multi_progress.add(ProgressBar::new(request.total_size));
    total_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let file_pbs: HashMap<_, _> = request.paths.iter().map(|path| {
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let pb = multi_progress.add(ProgressBar::new(size));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.set_message(path.to_string_lossy().to_string());
        (path, pb)
    }).collect();

    // Start progress bar thread
    let progress_handle = tokio::task::spawn_blocking(move || {
        multi_progress.clear().unwrap();
    });

    // Transfer files
    for path in &request.paths {
        let mut file = TokioFile::open(path).await?;
        let metadata = file.metadata().await?;
        let file_size = metadata.len();

        let mut sent = 0;
        while sent < file_size {
            let mut buffer = vec![0u8; CHUNK_SIZE];
            let n = file.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            buffer.truncate(n);

            let chunk = FileChunk {
                path: path.clone(),
                offset: sent,
                data: buffer,
            };

            let chunk_json = serde_json::to_string(&chunk)?;
            let encrypted_chunk = encrypt_data(&key, chunk_json.as_bytes())?;
            stream.write_all(&(encrypted_chunk.len() as u32).to_be_bytes()).await?;
            stream.write_all(&encrypted_chunk).await?;

            sent += n as u64;
            total_pb.inc(n as u64);
            if let Some(pb) = file_pbs.get(path) {
                pb.set_position(sent);
            }
        }
    }

    // Wait for progress bars to finish
    progress_handle.await?;

    // Clean up Wi-Fi Direct connection
    if let Err(e) = wpa.request("P2P_GROUP_REMOVE wlan0-p2p-0") {
        warn!("Error removing Wi-Fi Direct group: {}", e);
    }

    Ok(())
}

fn get_paths() -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    loop {
        println!("Enter the path of a file or directory to share (or 'done' to finish):");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.eq_ignore_ascii_case("done") {
            if paths.is_empty() {
                println!("You must select at least one file or directory.");
                continue;
            }
            break;
        }

        let path = PathBuf::from(input);
        if path.exists() {
            paths.push(path);
        } else {
            println!("Path not found. Please try again.");
        }
    }
    Ok(paths)
}

fn get_available_recipients(devices: &Arc<Mutex<HashMap<String, Device>>>) -> Vec<Device> {
    devices.lock().unwrap().values().cloned().collect()
}

fn select_recipient(recipients: &[Device]) -> Result<Device> {
    println!("Available recipients:");
    for (i, recipient) in recipients.iter().enumerate() {
        println!("{}. {} ({})", i + 1, recipient.name, recipient.address);
    }

    loop {
        println!("Enter the number of the recipient (or 'c' to cancel):");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.eq_ignore_ascii_case("c") {
            return Err(AppError::UserCancelled);
        }

        if let Ok(index) = input.parse::<usize>() {
            if index > 0 && index <= recipients.len() {
                return Ok(recipients[index - 1].clone());
            }
        }
        println!("Invalid selection. Please try again.");
    }
}

fn generate_qr_code_and_pin() -> (String, u32) {
    let mut rng = thread_rng();
    let pin: u32 = rng.gen_range(100000..999999);
    let qr_data = format!("WIFI:T:WPA;S:LinuxAirDrop;P:{};;", pin);
    let code = QrCode::new(qr_data).unwrap();
    let qr_string = code.render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();
    (qr_string, pin)
}

fn display_qr_code_and_pin(qr_code: &str, pin: u32) {
    println!("Scan this QR code to connect to this device:");
    println!("{}", qr_code);
    println!("PIN: {}", pin);
}

fn log_transfer(path: &Path, recipient: &str) -> Result<()> {
    let log_path = dirs::home_dir()
        .ok_or_else(|| AppError::Io(io::Error::new(io::ErrorKind::NotFound, "Home directory not found")))?
        .join(".linux_airdrop_history");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;

    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    writeln!(file, "{} - Sent {} to {}", timestamp, path.display(), recipient)?;

    Ok(())
}

fn compute_file_hashes_and_size(paths: &[PathBuf]) -> Result<(HashMap<PathBuf, String>, u64)> {
    let mut file_hashes = HashMap::new();
    let mut total_size = 0;

    for path in paths {
        if path.is_dir() {
            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    let (hash, size) = compute_single_file_hash_and_size(entry_path)?;
                    file_hashes.insert(entry_path.to_path_buf(), hash);
                    total_size += size;
                }
            }
        } else if path.is_file() {
            let (hash, size) = compute_single_file_hash_and_size(path)?;
            file_hashes.insert(path.to_path_buf(), hash);
            total_size += size;
        }
    }

    Ok((file_hashes, total_size))
}

fn compute_single_file_hash_and_size(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0; 8192];
    let mut size = 0;

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
        size += count as u64;
    }

    let digest = context.finish();
    Ok((hex::encode(digest.as_ref()), size))
}

fn continue_prompt() -> Result<bool> {
    loop {
        print!("Do you want to send more files? (y/n): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        match input.trim().to_lowercase().as_str() {
            "y" => return Ok(true),
            "n" => return Ok(false),
            _ => println!("Invalid input. Please enter 'y' or 'n'."),
        }
    }
}

fn generate_encryption_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    key
}

fn encrypt_data(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&[0u8; 12]); // In a real application, use a unique nonce for each encryption
    cipher.encrypt(nonce, data)
        .map_err(|e| AppError::Encryption(e.to_string()))
}

fn decrypt_data(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&[0u8; 12]); // Use the same nonce as for encryption
    cipher.decrypt(nonce, data)
        .map_err(|e| AppError::Encryption(e.to_string()))
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("Linux AirDrop-like File Sharing Tool (Wi-Fi Direct version)");
    let devices = Arc::new(Mutex::new(HashMap::new()));
    let devices_clone = devices.clone();

    // Start Bluetooth discovery
    tokio::spawn(async move {
        if let Err(e) = start_discovery(devices_clone).await {
            error!("Error in discovery: {}", e);
        }
    });

    // Start Wi-Fi Direct
    let socket_path = Path::new("/var/run/wpa_supplicant/wlan0");

    let mut wpa = match WpaCtrl::new(socket_path) {
        Ok(ctrl) => ctrl,
        Err(e) => return Err(AppError::WifiDirect(format!("Failed to connect to WPA supplicant: {}", e))),
    };
    if let Err(e) = wpa.request("P2P_FIND") {
        error!("Failed to start Wi-Fi Direct discovery: {}", e);
        return Err(AppError::WifiDirect(e.to_string()));
    }

    // Generate and display QR code for pairing
    let (qr_code, pin) = generate_qr_code_and_pin();
    display_qr_code_and_pin(&qr_code, pin);

    loop {
        // Get file/directory paths from user
        let paths = get_paths()?;

        // Get available recipients
        let recipients = get_available_recipients(&devices);

        // Display recipients and get user selection
        let selected_recipient = select_recipient(&recipients)?;

        // Compute file hashes and total size
        let (file_hashes, total_size) = compute_file_hashes_and_size(&paths)?;

        // Initiate file transfer
        let transfer_request = TransferRequest {
            paths,
            total_size,
            file_hashes,
        };

        match transfer_files(&transfer_request, &selected_recipient, &mut wpa).await {
            Ok(()) => {
                for path in &transfer_request.paths {
                    if let Err(e) = log_transfer(path, &selected_recipient.name) {
                        warn!("Error logging transfer: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("Error transferring files: {}", e);
            }
        }

        if !continue_prompt()? {
            break;
        }
    }

    // Clean up Wi-Fi Direct
    if let Err(e) = wpa.request("P2P_STOP_FIND") {
        warn!("Error stopping Wi-Fi Direct discovery: {}", e);
    }

    Ok(())
}
