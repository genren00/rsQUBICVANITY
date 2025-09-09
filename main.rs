// main.rs
// Qubic Vanity Address Generator in Rust
// A high-performance implementation for generating custom Qubic addresses

use std::process::Command;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use reqwest;
use std::fs;
use std::env;

// Constants
const SEED_LENGTH: usize = 55;
const PUBLIC_ID_LENGTH: usize = 60;
const QUBIC_HELPER_PATH: &str = "./qubic-helper-linux";
const QUBIC_HELPER_VERSION: &str = "3.0.5";
const QUBIC_HELPER_DOWNLOAD_URL: &str = "https://github.com/Qubic-Hub/qubic-helper-utils/releases/download/3.0.5/qubic-helper-linux-x64-3_0_5";

// Struct for Qubic Helper response
#[derive(Debug, Deserialize)]
struct QubicResponse {
    public_id: Option<String>,
    public_key_b64: Option<String>,
    private_key_b64: Option<String>,
    status: String,
    error: Option<String>,
}

// Struct for vanity generation result
#[derive(Debug, Serialize, Clone)]
struct VanityResult {
    status: String,
    seed: Option<String>,
    public_id: Option<String>,
    public_key_b64: Option<String>,
    private_key_b64: Option<String>,
    attempts: u64,
    error: Option<String>,
}

// Struct for progress tracking
#[derive(Debug)]
struct ProgressTracker {
    start_time: Instant,
    attempts: u64,
    last_update_time: Instant,
}

impl ProgressTracker {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            attempts: 0,
            last_update_time: Instant::now(),
        }
    }

    fn update(&mut self, attempts: u64) {
        self.attempts = attempts;
        let current_time = Instant::now();
        
        // Print progress every 10 seconds
        if current_time.duration_since(self.last_update_time).as_secs() >= 10 {
            self.print_progress();
            self.last_update_time = current_time;
        }
    }

    fn print_progress(&self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let attempts_per_second = if elapsed > 0.0 {
            self.attempts as f64 / elapsed
        } else {
            0.0
        };
        
        println!("Progress: {} attempts in {:.1}s ({:.1} attempts/second)", 
                 self.attempts, elapsed, attempts_per_second);
    }

    fn get_stats(&self) -> (u64, f64, f64) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let attempts_per_second = if elapsed > 0.0 {
            self.attempts as f64 / elapsed
        } else {
            0.0
        };
        
        (self.attempts, elapsed, attempts_per_second)
    }
}

// Seed Generator
struct SeedGenerator;

impl SeedGenerator {
    fn generate() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(SEED_LENGTH)
            .map(|c| c.to_ascii_lowercase())
            .collect()
    }

    fn generate_from_entropy(entropy: &[u8]) -> String {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&entropy[..32.min(entropy.len())]);
        let mut rng = StdRng::from_seed(seed_bytes);
        
        rng.sample_iter(&Alphanumeric)
            .take(SEED_LENGTH)
            .map(|c| c.to_ascii_lowercase())
            .collect()
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

    fn verify_seed_address_consistency(seed: &str, expected_public_id: &str) -> bool {
        match execute_qubic_command(&format!("{} createPublicId {}", QUBIC_HELPER_PATH, seed)) {
            Ok(response) => {
                if let Some(public_id) = response.public_id {
                    public_id == expected_public_id
                } else {
                    false
                }
            },
            Err(_) => false,
        }
    }
}

// Execute Qubic Helper command
fn execute_qubic_command(command: &str) -> Result<QubicResponse, String> {
    // Check if the helper binary exists
    if !Path::new(QUBIC_HELPER_PATH).exists() {
        return Err(format!("Qubic Helper binary not found at {}", QUBIC_HELPER_PATH));
    }

    // Parse command
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Invalid command format".to_string());
    }

    // Execute the command
    let output = Command::new(parts[0])
        .args(&parts[1..])
        .output();

    match output {
        Ok(output) => {
            if !output.status.success() {
                return Err(format!("Command failed with exit code: {}", output.status));
            }

            // Parse the JSON response
            let response_str = String::from_utf8_lossy(&output.stdout);
            let response: Value = match serde_json::from_str(&response_str) {
                Ok(v) => v,
                Err(e) => return Err(format!("Invalid JSON response: {}", e)),
            };

            // Extract fields
            let status = response["status"].as_str().unwrap_or("error").to_string();
            let public_id = response["publicId"].as_str().map(|s| s.to_string());
            let public_key_b64 = response["publicKeyB64"].as_str().map(|s| s.to_string());
            let private_key_b64 = response["privateKeyB64"].as_str().map(|s| s.to_string());
            let error = response["error"].as_str().map(|s| s.to_string());

            Ok(QubicResponse {
                public_id,
                public_key_b64,
                private_key_b64,
                status,
                error,
            })
        },
        Err(e) => Err(format!("Failed to execute command: {}", e)),
    }
}

// Validate vanity pattern
fn validate_vanity_pattern(pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }

    // Check for wildcard pattern
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return prefix.chars().all(|c| c.is_ascii_uppercase());
    }

    // Check for exact prefix pattern
    pattern.chars().all(|c| c.is_ascii_uppercase())
}

// Check if public ID matches pattern
fn matches_pattern(public_id: &str, pattern: &str) -> bool {
    // Simple prefix matching
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return public_id.starts_with(prefix);
    }

    // Exact match
    public_id.starts_with(pattern)
}

// Download Qubic Helper
fn download_qubic_helper() -> Result<(), String> {
    println!("Downloading Qubic Helper Utilities from {}...", QUBIC_HELPER_DOWNLOAD_URL);

    // Create HTTP client
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build() {
        Ok(client) => client,
        Err(e) => return Err(format!("Failed to create HTTP client: {}", e)),
    };

    // Download the file
    let response = match client.get(QUBIC_HELPER_DOWNLOAD_URL).send() {
        Ok(response) => response,
        Err(e) => return Err(format!("Download failed: {}", e)),
    };

    if !response.status().is_success() {
        return Err(format!("Download failed with status: {}", response.status()));
    }

    // Write to file
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

    // Make it executable
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

// Generate vanity address (single-threaded)
fn generate_vanity_address_single_thread(pattern: &str, max_attempts: Option<u64>) -> VanityResult {
    if !validate_vanity_pattern(pattern) {
        return VanityResult {
            status: "error".to_string(),
            seed: None,
            public_id: None,
            public_key_b64: None,
            private_key_b64: None,
            attempts: 0,
            error: Some("Invalid vanity pattern".to_string()),
        };
    }

    let mut progress_tracker = ProgressTracker::new();
    let mut attempts = 0;

    loop {
        // Check max attempts
        if let Some(max) = max_attempts {
            if attempts >= max {
                return VanityResult {
                    status: "error".to_string(),
                    seed: None,
                    public_id: None,
                    public_key_b64: None,
                    private_key_b64: None,
                    attempts,
                    error: Some(format!("No match found after {} attempts", max)),
                };
            }
        }

        // Generate a random seed
        let seed = SeedGenerator::generate();

        // Convert seed to public ID
        match execute_qubic_command(&format!("{} createPublicId {}", QUBIC_HELPER_PATH, seed)) {
            Ok(response) => {
                if response.status == "ok" {
                    if let Some(public_id) = response.public_id {
                        // Check if the address matches the pattern
                        if matches_pattern(&public_id, pattern) {
                            return VanityResult {
                                status: "success".to_string(),
                                seed: Some(seed),
                                public_id: Some(public_id),
                                public_key_b64: response.public_key_b64,
                                private_key_b64: response.private_key_b64,
                                attempts: attempts + 1,
                                error: None,
                            };
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!("Error executing command: {}", e);
            }
        }

        // Update progress
        attempts += 1;
        progress_tracker.update(attempts);

        // Print progress periodically
        if attempts % 1000 == 0 {
            println!("Attempt {}: No match yet...", attempts);
        }
    }
}

// Generate vanity address (multi-threaded)
fn generate_vanity_address_multithreaded(pattern: &str, max_attempts: Option<u64>, num_threads: usize) -> VanityResult {
    if !validate_vanity_pattern(pattern) {
        return VanityResult {
            status: "error".to_string(),
            seed: None,
            public_id: None,
            public_key_b64: None,
            private_key_b64: None,
            attempts: 0,
            error: Some("Invalid vanity pattern".to_string()),
        };
    }

    println!("Starting vanity generation for pattern: {}", pattern);
    println!("Using {} threads for generation", num_threads);

    // Shared state between threads
    let found = Arc::new(Mutex::new(false));
    let result = Arc::new(Mutex::new(None));
    let progress_tracker = Arc::new(Mutex::new(ProgressTracker::new()));

    // Spawn worker threads
    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let pattern = pattern.to_string();
        let found = Arc::clone(&found);
        let result = Arc::clone(&result);
        let progress_tracker = Arc::clone(&progress_tracker);

        let handle = thread::spawn(move || {
            let mut attempts = 0;
            let local_max_attempts = max_attempts.map(|m| m / num_threads as u64);

            loop {
                // Check if another thread found a match
                if *found.lock().unwrap() {
                    break;
                }

                // Check max attempts
                if let Some(max) = local_max_attempts {
                    if attempts >= max {
                        break;
                    }
                }

                // Generate a random seed
                let seed = SeedGenerator::generate();

                // Convert seed to public ID
                match execute_qubic_command(&format!("{} createPublicId {}", QUBIC_HELPER_PATH, seed)) {
                    Ok(response) => {
                        if response.status == "ok" {
                            if let Some(public_id) = response.public_id {
                                // Check if the address matches the pattern
                                if matches_pattern(&public_id, &pattern) {
                                    let mut found_guard = found.lock().unwrap();
                                    if !*found_guard {
                                        *found_guard = true;
                                        *result.lock().unwrap() = Some(VanityResult {
                                            status: "success".to_string(),
                                            seed: Some(seed),
                                            public_id: Some(public_id),
                                            public_key_b64: response.public_key_b64,
                                            private_key_b64: response.private_key_b64,
                                            attempts: attempts * num_threads as u64 + thread_id as u64,
                                            error: None,
                                        });
                                    }
                                    break;
                                }
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("Error executing command: {}", e);
                    }
                }

                // Update progress
                attempts += 1;
                let total_attempts = attempts * num_threads as u64 + thread_id as u64;
                if let Ok(mut tracker) = progress_tracker.lock() {
                    tracker.update(total_attempts);
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let _ = handle.join();
    }

    // Get the result
    let result_guard = result.lock().unwrap();
    if let Some(ref result) = *result_guard {
        result.clone()
    } else {
        VanityResult {
            status: "error".to_string(),
            seed: None,
            public_id: None,
            public_key_b64: None,
            private_key_b64: None,
            attempts: max_attempts.unwrap_or(0),
            error: Some("No match found".to_string()),
        }
    }
}

// Generate vanity address (main function)
fn generate_vanity_address(pattern: &str, max_attempts: Option<u64>, num_threads: Option<usize>) -> VanityResult {
    let num_threads = num_threads.unwrap_or_else(|| num_cpus::get());
    
    if num_threads > 1 {
        generate_vanity_address_multithreaded(pattern, max_attempts, num_threads)
    } else {
        generate_vanity_address_single_thread(pattern, max_attempts)
    }
}

// Run validation tests
fn run_validation_tests() {
    println!("Running validation tests...");

    // Test seed validation
    let valid_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let invalid_seed = "InvalidSeed123";

    assert!(AddressValidator::validate_seed(valid_seed).is_ok());
    assert!(AddressValidator::validate_seed(invalid_seed).is_err());

    // Test public ID validation
    let valid_id = "BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK";
    let invalid_id = "InvalidID123";

    assert!(AddressValidator::validate_public_id(valid_id).is_ok());
    assert!(AddressValidator::validate_public_id(invalid_id).is_err());

    // Test seed-address consistency (requires qubic-helper binary)
    if Path::new(QUBIC_HELPER_PATH).exists() {
        assert!(AddressValidator::verify_seed_address_consistency(valid_seed, valid_id));
    }

    // Test pattern matching
    assert!(matches_pattern(valid_id, "BZBQ*"));
    assert!(matches_pattern(valid_id, "BZBQFLL"));
    assert!(!matches_pattern(valid_id, "INVALID"));

    println!("All validation tests passed!");
}

// Test full vanity generation
fn test_full_vanity_generation() {
    println!("Testing full vanity generation process...");

    // Use a simple pattern that should be found quickly
    let pattern = "A*";

    if !Path::new(QUBIC_HELPER_PATH).exists() {
        println!("Qubic Helper binary not found. Skipping full generation test.");
        return;
    }

    let result = generate_vanity_address(pattern, Some(10000), None);

    if result.status == "success" {
        // Verify the result
        assert!(AddressValidator::validate_seed(&result.seed.unwrap()).is_ok());
        assert!(AddressValidator::validate_public_id(&result.public_id.unwrap()).is_ok());
        assert!(matches_pattern(&result.public_id.unwrap(), pattern));

        // Verify consistency
        assert!(AddressValidator::verify_seed_address_consistency(
            &result.seed.unwrap(),
            &result.public_id.unwrap()
        ));

        println!("Test passed: Found {} in {} attempts", 
                 result.public_id.unwrap(), result.attempts);
    } else {
        println!("Test failed: {:?}", result.error);
    }
}

// Print usage examples
fn print_usage_examples() {
    println!(
        r#"
Qubic Vanity Address Generator - Usage Examples
===============================================

1. Basic Usage:
   let result = generate_vanity_address("HELLO*", None, None);
   
2. With limited attempts:
   let result = generate_vanity_address("TEST*", Some(100000), None);
   
3. Multi-threaded generation:
   let result = generate_vanity_address("CRYPTO*", None, Some(8));
   
4. Download Qubic Helper:
   download_qubic_helper();
   
5. Run validation tests:
   run_validation_tests();
   
6. Test full generation:
   test_full_vanity_generation();

Pattern Formats:
- "HELLO*" : Matches addresses starting with "HELLO"
- "TEST"   : Exact match for prefix "TEST"
- "A*"     : Matches addresses starting with "A" (fast to find)

Note: Longer patterns take exponentially longer to find!
"#
    );
}

// Interactive mode
fn interactive_mode() {
    println!("Qubic Vanity Address Generator - Interactive Mode");
    println!("=" * 50);

    loop {
        println!("\n{}", "=".repeat(50));
        println!("Choose an option:");
        println!("1. Generate vanity address");
        println!("2. Run tests");
        println!("3. Exit");
        print!("Enter choice (1-3): ");
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
                    
                    print!("Enter number of threads (press Enter for default): ");
                    io::stdout().flush().unwrap();
                    
                    let mut num_threads_str = String::new();
                    io::stdin().read_line(&mut num_threads_str).unwrap();
                    let num_threads = if num_threads_str.trim().is_empty() {
                        None
                    } else {
                        num_threads_str.trim().parse().ok()
                    };
                    
                    let result = generate_vanity_address(&pattern, max_attempts, num_threads);
                    
                    if result.status == "success" {
                        println!("\nSuccess! Found vanity address:");
                        println!("Public ID: {}", result.public_id.unwrap());
                        println!("Seed: {}", result.seed.unwrap());
                        println!("Public Key: {}", result.public_key_b64.unwrap());
                        println!("Private Key: {}", result.private_key_b64.unwrap());
                        println!("Attempts: {}", result.attempts);
                    } else {
                        println!("\nFailed: {:?}", result.error);
                    }
                } else {
                    println!("Invalid pattern. Please use uppercase letters A-Z only, optionally ending with *");
                }
            },
            "2" => {
                test_full_vanity_generation();
            },
            "3" => {
                println!("Goodbye!");
                break;
            },
            _ => {
                println!("Invalid choice. Please enter 1, 2, or 3.");
            }
        }
    }
}

// Main function
fn main() {
    println!("Qubic Vanity Address Generator");
    println!("{}", "=".repeat(40));

    // Check if Qubic Helper binary exists
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
                    println!("Download successful! You can now generate vanity addresses.");
                },
                Err(e) => {
                    println!("Download failed: {}", e);
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

    // Run validation tests if binary is available
    if Path::new(QUBIC_HELPER_PATH).exists() {
        println!("\nRunning validation tests...");
        run_validation_tests();

        // Show usage examples
        print_usage_examples();

        // Check if we should run in interactive mode
        let args: Vec<String> = env::args().collect();
        if args.len() == 1 {
            // No command line arguments, run interactive mode
            interactive_mode();
        } else {
            // Parse command line arguments
            let mut pattern = None;
            let mut max_attempts = None;
            let mut num_threads = None;

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
                    "--threads" | "-t" => {
                        if i + 1 < args.len() {
                            if let Ok(threads) = args[i + 1].parse() {
                                num_threads = Some(threads);
                                i += 2;
                            } else {
                                eprintln!("Error: --threads requires a number");
                                return;
                            }
                        } else {
                            eprintln!("Error: --threads requires a value");
                            return;
                        }
                    },
                    "--help" | "-h" => {
                        println!("Usage: {} [OPTIONS]", args[0]);
                        println!("Options:");
                        println!("  -p, --pattern PATTERN     Vanity pattern to search for");
                        println!("  -m, --max-attempts NUM    Maximum number of attempts");
                        println!("  -t, --threads NUM         Number of threads to use");
                        println!("  -h, --help               Print this help");
                        return;
                    },
                    _ => {
                        eprintln!("Error: Unknown argument {}", args[i]);
                        return;
                    }
                }
            }

            if let Some(pattern) = pattern {
                let result = generate_vanity_address(&pattern, max_attempts, num_threads);
                
                if result.status == "success" {
                    println!("Success! Found vanity address:");
                    println!("Public ID: {}", result.public_id.unwrap());
                    println!("Seed: {}", result.seed.unwrap());
                    println!("Public Key: {}", result.public_key_b64.unwrap());
                    println!("Private Key: {}", result.private_key_b64.unwrap());
                    println!("Attempts: {}", result.attempts);
                } else {
                    println!("Failed: {:?}", result.error);
                }
            }
        }
    } else {
        println!("\nPlease download the Qubic Helper Utilities binary to use this generator.");
    }
}
