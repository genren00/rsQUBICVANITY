// main.rs - High-Performance Qubic Vanity Address Generator
// Optimized for batch processing and parallel helper instances

use std::process::Command;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use reqwest;
use std::fs;
use std::env;
use std::collections::VecDeque;

// Constants
const SEED_LENGTH: usize = 55;
const PUBLIC_ID_LENGTH: usize = 60;
const QUBIC_HELPER_PATH: &str = "./qubic-helper-linux";
const QUBIC_HELPER_DOWNLOAD_URL: &str = "https://github.com/Qubic-Hub/qubic-helper-utils/releases/download/3.0.5/qubic-helper-linux-x64-3_0_5";
const DEFAULT_HELPERS: usize = 8;
const DEFAULT_BATCH_SIZE: usize = 50;
const MAX_QUEUE_SIZE: usize = 1000;

// Struct for Qubic Helper response
#[derive(Debug, Deserialize, Clone)]
struct QubicResponse {
    #[serde(rename = "publicId")]
    public_id: Option<String>,
    #[serde(rename = "publicKeyB64")]
    public_key_b64: Option<String>,
    #[serde(rename = "privateKeyB64")]
    private_key_b64: Option<String>,
    status: String,
    error: Option<String>, // Used for error handling in worker threads
}

// Struct for batch response
#[derive(Debug, Deserialize)]
struct BatchResponse {
    results: Vec<QubicResponse>,
}

// Struct for vanity generation result
#[derive(Debug, Serialize, Clone)]
struct VanityResult {
    status: String,
    seed: Option<String>,
    #[serde(rename = "publicId")]
    public_id: Option<String>,
    #[serde(rename = "publicKeyB64")]
    public_key_b64: Option<String>,
    #[serde(rename = "privateKeyB64")]
    private_key_b64: Option<String>,
    attempts: u64,
    error: Option<String>,
    hashes_per_second: f64,
}

// Struct for progress tracking
#[derive(Debug)]
struct ProgressTracker {
    start_time: Instant,
    attempts: u64,
    last_update_time: Instant,
    last_hashes: u64,
}

impl ProgressTracker {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            attempts: 0,
            last_update_time: Instant::now(),
            last_hashes: 0,
        }
    }

    fn update(&mut self, attempts: u64) -> u64 {
        self.attempts = attempts;
        let current_time = Instant::now();
        
        // Print progress every 5 seconds
        if current_time.duration_since(self.last_update_time).as_secs() >= 5 {
            self.print_progress();
            self.last_update_time = current_time;
            self.last_hashes = attempts;
        }
        
        attempts
    }

    fn print_progress(&self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let hashes_per_second = if elapsed > 0.0 {
            self.attempts as f64 / elapsed
        } else {
            0.0
        };
        
        let recent_hashes = self.attempts - self.last_hashes;
        let recent_elapsed = self.last_update_time.elapsed().as_secs_f64();
        let recent_rate = if recent_elapsed > 0.0 {
            recent_hashes as f64 / recent_elapsed
        } else {
            0.0
        };
        
        println!("Progress: {} attempts | {:.1} total/s | {:.1} recent/s | {:.1}s elapsed", 
                 self.attempts, hashes_per_second, recent_rate, elapsed);
    }

    fn get_stats(&self) -> (u64, f64, f64) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let hashes_per_second = if elapsed > 0.0 {
            self.attempts as f64 / elapsed
        } else {
            0.0
        };
        
        (self.attempts, elapsed, hashes_per_second)
    }
}

// High-performance Seed Generator
struct SeedGenerator;

impl SeedGenerator {
    fn generate() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(SEED_LENGTH)
            .map(|c| c as char)
            .map(|c| c.to_ascii_lowercase())
            .collect()
    }

    fn generate_batch(size: usize) -> Vec<String> {
        (0..size).map(|_| Self::generate()).collect()
    }
}

// Address Validator
struct AddressValidator;

impl AddressValidator {
    fn validate_seed(seed: &str) -> Result<(), String> {
        if seed.len() != SEED_LENGTH {
            return Err(format!("Seed must be exactly {} characters", SEED_LENGTH));
        }
        
        if !seed.chars().all(|c| c.is_ascii_lowercase()) {
            return Err("Seed must contain only lowercase letters a-z".to_string());
        }
        
        Ok(())
    }

    fn validate_public_id(public_id: &str) -> Result<(), String> {
        if public_id.len() != PUBLIC_ID_LENGTH {
            return Err(format!("Public ID must be exactly {} characters", PUBLIC_ID_LENGTH));
        }
        
        if !public_id.chars().all(|c| c.is_ascii_uppercase()) {
            return Err("Public ID must contain only uppercase letters A-Z".to_string());
        }
        
        Ok(())
    }
}

// Execute Qubic Helper batch command
fn execute_qubic_batch_command(seeds: &[String], helper_path: &str) -> Result<Vec<QubicResponse>, String> {
    if seeds.is_empty() {
        return Ok(Vec::new());
    }

    // Create temporary file
    let temp_file = format!("/tmp/qubic_batch_{}_{}.txt", std::process::id(), thread_rng().gen::<u32>());
    
    // Write seeds to temp file
    {
        let mut file = fs::File::create(&temp_file)
            .map_err(|e| format!("Failed to create temp file: {}", e))?;
        
        for seed in seeds {
            writeln!(file, "{}", seed)
                .map_err(|e| format!("Failed to write seed: {}", e))?;
        }
    }

    // Execute batch command
    let output = Command::new(helper_path)
        .args(&["batchCreatePublicIds", &temp_file])
        .output()
        .map_err(|e| format!("Failed to execute batch command: {}", e))?;

    // Clean up temp file
    let _ = fs::remove_file(&temp_file);

    if !output.status.success() {
        return Err(format!("Batch command failed: {:?}", String::from_utf8_lossy(&output.stderr)));
    }

    // Parse response
    let response_str = String::from_utf8_lossy(&output.stdout);
    
    // Try to parse as batch response first
    if let Ok(batch_response) = serde_json::from_str::<BatchResponse>(&response_str) {
        return Ok(batch_response.results);
    }
    
    // Fallback: parse as individual responses
    let lines: Vec<&str> = response_str.lines().collect();
    let mut results = Vec::new();
    
    for line in lines {
        if let Ok(response) = serde_json::from_str::<QubicResponse>(line) {
            results.push(response);
        }
    }
    
    if results.is_empty() {
        return Err(format!("Failed to parse batch response: {}", response_str));
    }
    
    Ok(results)
}

// Validate vanity pattern
fn validate_vanity_pattern(pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }

    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return prefix.chars().all(|c| c.is_ascii_uppercase());
    }

    pattern.chars().all(|c| c.is_ascii_uppercase())
}

// Check if public ID matches pattern
fn matches_pattern(public_id: &str, pattern: &str) -> bool {
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return public_id.starts_with(prefix);
    }

    public_id.starts_with(pattern)
}

// Download Qubic Helper
fn download_qubic_helper() -> Result<(), String> {
    println!("Downloading Qubic Helper Utilities from {}...", QUBIC_HELPER_DOWNLOAD_URL);

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build() {
        Ok(client) => client,
        Err(e) => return Err(format!("Failed to create HTTP client: {}", e)),
    };

    let response = match client.get(QUBIC_HELPER_DOWNLOAD_URL).send() {
        Ok(response) => response,
        Err(e) => return Err(format!("Download failed: {}", e)),
    };

    if !response.status().is_success() {
        return Err(format!("Download failed with status: {}", response.status()));
    }

    let mut file = match fs::File::create(QUBIC_HELPER_PATH) {
        Ok(file) => file,
        Err(e) => return Err(format!("Failed to create file: {}", e)),
    };

    let content = match response.bytes() {
        Ok(content) => content,
        Err(e) => return Err(format!("Failed to read response: {}", e)),
    };

    if let Err(e) = file.write_all(&content) {
        return Err(format!("Failed to write file: {}", e));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(QUBIC_HELPER_PATH, fs::Permissions::from_mode(0o755)) {
            return Err(format!("Failed to set permissions: {}", e));
        }
    }

    println!("Qubic Helper Utilities downloaded successfully!");
    Ok(())
}

// Create multiple helper instances
fn create_helper_instances(num_helpers: usize) -> Result<Vec<String>, String> {
    let mut helper_paths = Vec::new();
    
    for i in 0..num_helpers {
        let helper_path = format!("./qubic-helper-{}", i);
        
        if !Path::new(&helper_path).exists() {
            fs::copy(QUBIC_HELPER_PATH, &helper_path)
                .map_err(|e| format!("Failed to copy helper binary {}: {}", i, e))?;
            
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o755))
                    .map_err(|e| format!("Failed to set permissions for {}: {}", i, e))?;
            }
        }
        
        helper_paths.push(helper_path);
    }
    
    Ok(helper_paths)
}

// Worker thread for high-performance generation
fn worker_thread(
    helper_path: String,
    seed_queue: Arc<Mutex<VecDeque<String>>>,
    result_queue: Arc<Mutex<Vec<(String, QubicResponse)>>>,
    shutdown_flag: Arc<Mutex<bool>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            // Check shutdown flag
            if *shutdown_flag.lock().unwrap() {
                break;
            }

            // Get batch of seeds
            let batch = {
                let mut queue = seed_queue.lock().unwrap();
                let mut batch = Vec::new();
                
                while batch.len() < DEFAULT_BATCH_SIZE && !queue.is_empty() {
                    if let Some(seed) = queue.pop_front() {
                        batch.push(seed);
                    }
                }
                
                batch
            };

            if batch.is_empty() {
                thread::sleep(Duration::from_millis(10));
                continue;
            }

            // Process batch
            match execute_qubic_batch_command(&batch, &helper_path) {
                Ok(responses) => {
                    let mut results = Vec::new();
                    for (i, response) in responses.into_iter().enumerate() {
                        results.push((batch[i].clone(), response));
                    }
                    
                    let mut result_queue = result_queue.lock().unwrap();
                    result_queue.extend(results);
                },
                Err(e) => {
                    eprintln!("Worker {} error: {}", helper_path, e);
                }
            }
        }
    })
}

// Ultra-high-performance vanity address generator
fn generate_vanity_address_ultra_fast(
    pattern: &str, 
    max_attempts: Option<u64>, 
    num_helpers: usize
) -> VanityResult {
    if !validate_vanity_pattern(pattern) {
        return VanityResult {
            status: "error".to_string(),
            seed: None,
            public_id: None,
            public_key_b64: None,
            private_key_b64: None,
            attempts: 0,
            error: Some("Invalid vanity pattern".to_string()),
            hashes_per_second: 0.0,
        };
    }

    println!("Starting ultra-fast vanity generation for pattern: {}", pattern);
    println!("Using {} helper instances with batch size {}", num_helpers, DEFAULT_BATCH_SIZE);

    let _start_time = Instant::now(); // Fixed: prefixed with underscore
    let mut progress_tracker = ProgressTracker::new();
    let mut attempts = 0;

    // Create helper instances
    let helper_paths = match create_helper_instances(num_helpers) {
        Ok(paths) => paths,
        Err(e) => {
            return VanityResult {
                status: "error".to_string(),
                seed: None,
                public_id: None,
                public_key_b64: None,
                private_key_b64: None,
                attempts: 0,
                error: Some(format!("Failed to create helper instances: {}", e)),
                hashes_per_second: 0.0,
            };
        }
    };

    // Create shared queues
    let seed_queue = Arc::new(Mutex::new(VecDeque::new()));
    let result_queue = Arc::new(Mutex::new(Vec::new()));
    let shutdown_flag = Arc::new(Mutex::new(false));

    // Pre-generate initial seed batch
    {
        let mut queue = seed_queue.lock().unwrap();
        for _ in 0..(num_helpers * DEFAULT_BATCH_SIZE * 10) {
            queue.push_back(SeedGenerator::generate());
        }
    }

    // Start worker threads
    let mut handles = Vec::new();
    for helper_path in helper_paths {
        let handle = worker_thread(
            helper_path,
            Arc::clone(&seed_queue),
            Arc::clone(&result_queue),
            Arc::clone(&shutdown_flag),
        );
        handles.push(handle);
    }

    // Seed generator thread
    let seed_generator_handle = {
        let seed_queue = Arc::clone(&seed_queue);
        let shutdown_flag = Arc::clone(&shutdown_flag);
        
        thread::spawn(move || {
            while !*shutdown_flag.lock().unwrap() {
                let mut queue = seed_queue.lock().unwrap();
                if queue.len() < MAX_QUEUE_SIZE {
                    let batch = SeedGenerator::generate_batch(DEFAULT_BATCH_SIZE * 2);
                    for seed in batch {
                        queue.push_back(seed);
                    }
                }
                drop(queue);
                thread::sleep(Duration::from_millis(1));
            }
        })
    };

    // Main processing loop
    loop {
        // Check max attempts
        if let Some(max) = max_attempts {
            if attempts >= max {
                break;
            }
        }

        // Process results
        let results = {
            let mut queue = result_queue.lock().unwrap();
            queue.drain(..).collect::<Vec<_>>()
        };

        for (seed, response) in results {
            attempts += 1;
            
            if response.status == "ok" {
                if let Some(ref public_id) = response.public_id {
                    if matches_pattern(public_id, pattern) {
                        // Shutdown all threads
                        *shutdown_flag.lock().unwrap() = true;
                        
                        let (total_attempts, _elapsed, hashes_per_second) = progress_tracker.get_stats(); // Fixed: prefixed with underscore
                        
                        return VanityResult {
                            status: "success".to_string(),
                            seed: Some(seed),
                            public_id: Some(public_id.clone()),
                            public_key_b64: response.public_key_b64.clone(),
                            private_key_b64: response.private_key_b64.clone(),
                            attempts: total_attempts,
                            error: None,
                            hashes_per_second,
                        };
                    }
                }
            }
        }

        // Update progress
        progress_tracker.update(attempts);

        // Small delay to prevent busy waiting
        thread::sleep(Duration::from_millis(10));
    }

    // Shutdown all threads
    *shutdown_flag.lock().unwrap() = true;

    // Wait for all threads to finish
    for handle in handles {
        let _ = handle.join();
    }
    let _ = seed_generator_handle.join();

    let (total_attempts, _elapsed, hashes_per_second) = progress_tracker.get_stats(); // Fixed: prefixed with underscore

    VanityResult {
        status: "error".to_string(),
        seed: None,
        public_id: None,
        public_key_b64: None,
        private_key_b64: None,
        attempts: total_attempts,
        error: Some("No match found".to_string()),
        hashes_per_second,
    }
}

// Run validation tests
fn run_validation_tests() {
    println!("Running validation tests...");

    let valid_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let invalid_seed = "InvalidSeed123";

    assert!(AddressValidator::validate_seed(valid_seed).is_ok());
    assert!(AddressValidator::validate_seed(invalid_seed).is_err());

    let valid_id = "BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK";
    let invalid_id = "InvalidID123";

    assert!(AddressValidator::validate_public_id(valid_id).is_ok());
    assert!(AddressValidator::validate_public_id(invalid_id).is_err());

    assert!(matches_pattern(valid_id, "BZBQ*"));
    assert!(matches_pattern(valid_id, "BZBQFLL"));
    assert!(!matches_pattern(valid_id, "INVALID"));

    println!("All validation tests passed!");
}

// Interactive mode
fn interactive_mode() {
    println!("Ultra-Fast Qubic Vanity Address Generator - Interactive Mode");
    println!("{}", "=".repeat(60));

    loop {
        println!("\n{}", "=".repeat(60));
        println!("Choose an option:");
        println!("1. Generate vanity address");
        println!("2. Run tests");
        println!("3. Performance benchmark");
        println!("4. Exit");
        print!("Enter choice (1-4): ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        let choice = choice.trim();

        match choice {
            "1" => {
                print!("Enter vanity pattern (e.g., 'HELLO*' or 'TEST'): ");
                io::stdout().flush().unwrap();
                
                let mut pattern = String::new();
                io::stdin().read_line(&mut pattern).unwrap();
                let pattern = pattern.trim().to_uppercase();
                
                if validate_vanity_pattern(&pattern) {
                    print!("Enter maximum attempts (press Enter for unlimited): ");
                    io::stdout().flush().unwrap();
                    
                    let mut max_attempts_str = String::new();
                    io::stdin().read_line(&mut max_attempts_str).unwrap();
                    let max_attempts = if max_attempts_str.trim().is_empty() {
                        None
                    } else {
                        max_attempts_str.trim().parse().ok()
                    };
                    
                    print!("Enter number of helpers (press Enter for default 8): ");
                    io::stdout().flush().unwrap();
                    
                    let mut num_helpers_str = String::new();
                    io::stdin().read_line(&mut num_helpers_str).unwrap();
                    let num_helpers = if num_helpers_str.trim().is_empty() {
                        DEFAULT_HELPERS
                    } else {
                        num_helpers_str.trim().parse().unwrap_or(DEFAULT_HELPERS)
                    };
                    
                    let result = generate_vanity_address_ultra_fast(&pattern, max_attempts, num_helpers);
                    
                    if result.status == "success" {
                        println!("\n🎉 SUCCESS! Found vanity address:");
                        println!("Public ID: {}", result.public_id.unwrap());
                        println!("Seed: {}", result.seed.unwrap());
                        println!("Public Key: {}", result.public_key_b64.unwrap());
                        println!("Private Key: {}", result.private_key_b64.unwrap());
                        println!("Attempts: {}", result.attempts);
                        println!("Speed: {:.0} hashes/second", result.hashes_per_second);
                    } else {
                        println!("\n❌ Failed: {:?}", result.error);
                        println!("Speed: {:.0} hashes/second", result.hashes_per_second);
                    }
                } else {
                    println!("Invalid pattern. Please use uppercase letters A-Z only, optionally ending with *");
                }
            },
            "2" => {
                run_validation_tests();
            },
            "3" => {
                println!("Running performance benchmark...");
                let result = generate_vanity_address_ultra_fast("A*", Some(10000), 8);
                println!("Benchmark completed:");
                println!("Attempts: {}", result.attempts);
                println!("Speed: {:.0} hashes/second", result.hashes_per_second);
            },
            "4" => {
                println!("Goodbye!");
                break;
            },
            _ => {
                println!("Invalid choice. Please enter 1, 2, 3, or 4.");
            }
        }
    }
}

// Main function
fn main() {
    println!("🚀 Ultra-Fast Qubic Vanity Address Generator");
    println!("{}", "=".repeat(60));

    if !Path::new(QUBIC_HELPER_PATH).exists() {
        println!("Qubic Helper Utilities binary not found.");
        print!("Would you like to download it now? (y/n): ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let download_choice = input.trim().to_lowercase();

        if download_choice == "y" {
            match download_qubic_helper() {
                Ok(_) => {
                    println!("✅ Download successful! You can now generate vanity addresses.");
                },
                Err(e) => {
                    println!("❌ Download failed: {}", e);
                    println!("Please download manually from:");
                    println!("{}", QUBIC_HELPER_DOWNLOAD_URL);
                    println!("And save it as 'qubic-helper-linux' in the current directory.");
                }
            }
        } else {
            println!("Please download the Qubic Helper Utilities binary from:");
            println!("{}", QUBIC_HELPER_DOWNLOAD_URL);
            println!("And save it as 'qubic-helper-linux' in the current directory.");
        }
    }

    if Path::new(QUBIC_HELPER_PATH).exists() {
        println!("\nRunning validation tests...");
        run_validation_tests();

        let args: Vec<String> = env::args().collect();
        if args.len() == 1 {
            interactive_mode();
        } else {
            let mut pattern = None;
            let mut max_attempts = None;
            let mut num_helpers = Some(DEFAULT_HELPERS);

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--pattern" | "-p" => {
                        if i + 1 < args.len() {
                            pattern = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --pattern requires a value");
                            return;
                        }
                    },
                    "--max-attempts" | "-m" => {
                        if i + 1 < args.len() {
                            if let Ok(attempts) = args[i + 1].parse() {
                                max_attempts = Some(attempts);
                                i += 2;
                            } else {
                                eprintln!("Error: --max-attempts requires a number");
                                return;
                            }
                        } else {
                            eprintln!("Error: --max-attempts requires a value");
                            return;
                        }
                    },
                    "--helpers" | "-H" => {
                        if i + 1 < args.len() {
                            if let Ok(helpers) = args[i + 1].parse() {
                                num_helpers = Some(helpers);
                                i += 2;
                            } else {
                                eprintln!("Error: --helpers requires a number");
                                return;
                            }
                        } else {
                            eprintln!("Error: --helpers requires a value");
                            return;
                        }
                    },
                    "--help" | "-h" => {
                        println!("Usage: {} [OPTIONS]", args[0]);
                        println!("Options:");
                        println!("  -p, --pattern PATTERN     Vanity pattern to search for");
                        println!("  -m, --max-attempts NUM    Maximum number of attempts");
                        println!("  -H, --helpers NUM         Number of helper instances (default: 8)");
                        println!("  -h, --help               Print this help");
                        println!("\nExamples:");
                        println!("  {} -p 'HELLO*'                    # Basic usage", args[0]);
                        println!("  {} -p 'CRYPTO*' -H 16             # 16 helpers", args[0]);
                        println!("  {} -p 'VANITY*' -m 1000000 -H 32  # Max performance", args[0]);
                        return;
                    },
                    _ => {
                        eprintln!("Error: Unknown argument {}", args[i]);
                        return;
                    }
                }
            }

            if let Some(pattern) = pattern {
                let start_time = Instant::now();
                let result = generate_vanity_address_ultra_fast(&pattern, max_attempts, num_helpers.unwrap_or(DEFAULT_HELPERS));
                let duration = start_time.elapsed();
                
                if result.status == "success" {
                    println!("🎉 SUCCESS! Found vanity address:");
                    println!("Public ID: {}", result.public_id.unwrap());
                    println!("Seed: {}", result.seed.unwrap());
                    println!("Public Key: {}", result.public_key_b64.unwrap());
                    println!("Private Key: {}", result.private_key_b64.unwrap());
                    println!("Attempts: {}", result.attempts);
                    println!("Time: {:.2}s", duration.as_secs_f64());
                    println!("Speed: {:.0} hashes/second", result.hashes_per_second);
                } else {
                    println!("❌ Failed: {:?}", result.error);
                    println!("Speed: {:.0} hashes/second", result.hashes_per_second);
                }
            }
        }
    } else {
        println!("\nPlease download the Qubic Helper Utilities binary to use this generator.");
    }
}
