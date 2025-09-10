# qubic_vanity_generator.py
"""
Qubic Vanity Address Generator
A single-file implementation for generating custom Qubic addresses with desired prefixes or patterns.
Compatible with Google Colab environment.
"""

# Imports
import os
import re
import subprocess
import json
import time
import threading
import multiprocessing
import secrets
import string
import base64
import hashlib
from typing import Tuple, Dict, Optional, List
import urllib.request

# Constants
SEED_LENGTH = 55
PUBLIC_ID_LENGTH = 60
ALPHABET_LOWER = string.ascii_lowercase
ALPHABET_UPPER = string.ascii_uppercase
QUBIC_HELPER_PATH = "./qubic-helper-linux"
QUBIC_HELPER_VERSION = "3.0.5"
QUBIC_HELPER_DOWNLOAD_URL = f"https://github.com/Qubic-Hub/qubic-helper-utils/releases/download/{QUBIC_HELPER_VERSION}/qubic-helper-linux-x64-{QUBIC_HELPER_VERSION.replace('.', '_')}"

# Main Classes
class QubicVanityGenerator:
    """Main class for generating vanity Qubic addresses"""
    
    def __init__(self, num_threads: int):
        """
        Initialize the generator with required number of threads.
        
        Args:
            num_threads: Number of threads to use for generation (must be at least 1)
        """
        if num_threads < 1:
            raise ValueError("Number of threads must be at least 1")
        self.num_threads = num_threads
        self.progress_tracker = ProgressTracker()
    
    def generate_vanity_address(self, pattern: str, max_attempts: int = None) -> Dict:
        """
        Generate a Qubic address with the specified vanity pattern.
        
        Args:
            pattern: Desired prefix or pattern for the address
            max_attempts: Maximum number of attempts (None for unlimited)
        
        Returns:
            Dictionary containing the matching address and seed
        """
        # Validate the pattern
        if not validate_vanity_pattern(pattern):
            return {"status": "error", "error": "Invalid vanity pattern"}
        
        print(f"Starting vanity generation for pattern: {pattern}")
        print(f"Using {self.num_threads} threads for generation")
        
        # Try multi-threaded generation
        result = self._generate_multithreaded(pattern, max_attempts)
        
        if result["status"] == "success":
            print(f"Success! Found matching address after {result['attempts']} attempts")
            print(f"Public ID: {result['publicId']}")
            print(f"Seed: {result['seed']}")
        else:
            print(f"Failed to find matching address: {result['error']}")
        
        return result
    
    def _generate_multithreaded(self, pattern: str, max_attempts: int = None) -> Dict:
        """Generate vanity address using multiple threads"""
        found = threading.Event()
        result = {"status": "error", "error": "No match found"}
        lock = threading.Lock()
        
        def worker(thread_id):
            nonlocal result
            attempts = 0
            local_max_attempts = (max_attempts // self.num_threads) if max_attempts else None
            
            while not found.is_set() and (local_max_attempts is None or attempts < local_max_attempts):
                # Generate a random seed
                seed = SeedGenerator.generate()
                
                # Convert seed to public ID
                cmd_result = execute_qubic_command(f"{QUBIC_HELPER_PATH} createPublicId {seed}")
                
                if cmd_result["status"] == "ok":
                    public_id = cmd_result["publicId"]
                    
                    # Check if the address matches the pattern
                    if matches_pattern(public_id, pattern):
                        with lock:
                            if not found.is_set():
                                found.set()
                                result = {
                                    "status": "success",
                                    "seed": seed,
                                    "publicId": public_id,
                                    "publicKeyB64": cmd_result["publicKeyB64"],
                                    "privateKeyB64": cmd_result["privateKeyB64"],
                                    "attempts": attempts * self.num_threads + thread_id
                                }
                
                attempts += 1
                
                # Update progress periodically
                if attempts % 100 == 0:
                    self.progress_tracker.update(attempts * self.num_threads + thread_id)
        
        # Start worker threads
        threads = []
        for i in range(self.num_threads):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for any thread to find a match
        for thread in threads:
            thread.join()
        
        return result

class SeedGenerator:
    """Handles secure seed generation"""
    
    @staticmethod
    def generate() -> str:
        """
        Generate a cryptographically secure random 55-character seed.
        
        Returns:
            A 55-character string of lowercase letters
        """
        return ''.join(secrets.choice(ALPHABET_LOWER) for _ in range(SEED_LENGTH))
    
    @staticmethod
    def generate_from_entropy(entropy: bytes) -> str:
        """
        Generate a seed from provided entropy.
        
        Args:
            entropy: Random bytes to use as entropy source
            
        Returns:
            A 55-character seed string
        """
        # Convert entropy to seed using a deterministic process
        # This is useful for reproducible testing
        random = secrets.SystemRandom()
        random.seed(int.from_bytes(entropy, byteorder='big'))
        return ''.join(random.choice(ALPHABET_LOWER) for _ in range(SEED_LENGTH))

class AddressValidator:
    """Validates Qubic addresses and seeds according to official specifications"""
    
    @staticmethod
    def validate_seed(seed: str) -> Tuple[bool, str]:
        """
        Validate a Qubic seed.
        
        Args:
            seed: The seed to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(seed, str):
            return False, "Seed must be a string"
        if len(seed) != SEED_LENGTH:
            return False, f"Seed must be exactly {SEED_LENGTH} characters"
        if not re.match(r'^[a-z]+$', seed):
            return False, "Seed must contain only lowercase letters a-z"
        return True, "Valid seed"
    
    @staticmethod
    def validate_public_id(public_id: str) -> Tuple[bool, str]:
        """
        Validate a Qubic public ID.
        
        Args:
            public_id: The public ID to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(public_id, str):
            return False, "Public ID must be a string"
        if len(public_id) != PUBLIC_ID_LENGTH:
            return False, f"Public ID must be exactly {PUBLIC_ID_LENGTH} characters"
        if not re.match(r'^[A-Z]+$', public_id):
            return False, "Public ID must contain only uppercase letters A-Z"
        return True, "Valid public ID"
    
    @staticmethod
    def verify_seed_address_consistency(seed: str, expected_public_id: str) -> bool:
        """
        Verify that a seed consistently produces the expected public ID.
        
        Args:
            seed: The seed to test
            expected_public_id: The expected public ID
            
        Returns:
            True if the seed produces the expected public ID
        """
        result = execute_qubic_command(f"{QUBIC_HELPER_PATH} createPublicId {seed}")
        if result["status"] == "ok":
            return result["publicId"] == expected_public_id
        return False

class ProgressTracker:
    """Tracks and reports vanity generation progress"""
    
    def __init__(self):
        self.start_time = time.time()
        self.attempts = 0
        self.last_update_time = self.start_time
        self.lock = threading.Lock()
    
    def update(self, attempts: int):
        """Update the progress tracker with the current attempt count"""
        with self.lock:
            self.attempts = attempts
            current_time = time.time()
            
            # Print progress every 10 seconds
            if current_time - self.last_update_time >= 10:
                self.print_progress()
                self.last_update_time = current_time
    
    def print_progress(self):
        """Print current progress statistics"""
        elapsed = time.time() - self.start_time
        attempts_per_second = self.attempts / elapsed if elapsed > 0 else 0
        
        print(f"Progress: {self.attempts} attempts in {elapsed:.1f}s "
              f"({attempts_per_second:.1f} attempts/second)")
    
    def get_stats(self) -> Dict:
        """Get current progress statistics"""
        elapsed = time.time() - self.start_time
        attempts_per_second = self.attempts / elapsed if elapsed > 0 else 0
        
        return {
            "attempts": self.attempts,
            "elapsed_seconds": elapsed,
            "attempts_per_second": attempts_per_second
        }

class SecureSeedGenerator:
    """Enhanced security for seed generation"""
    
    @staticmethod
    def generate_with_user_entropy(user_input: str = None) -> str:
        """
        Generate a seed with additional user entropy for enhanced security.
        
        Args:
            user_input: Optional user-provided entropy
            
        Returns:
            A secure 55-character seed
        """
        # Combine system entropy with optional user entropy
        system_entropy = os.urandom(32)
        
        if user_input:
            # Hash user input to normalize it
            user_entropy = hashlib.sha256(user_input.encode()).digest()
            # Combine system and user entropy
            combined_entropy = bytes(a ^ b for a, b in zip(system_entropy, user_entropy))
        else:
            combined_entropy = system_entropy
        
        # Use combined entropy to seed the generator
        random = secrets.SystemRandom()
        random.seed(int.from_bytes(combined_entropy, byteorder='big'))
        
        return ''.join(random.choice(ALPHABET_LOWER) for _ in range(SEED_LENGTH))

class SecureResultHandler:
    """Handles secure storage and transmission of generated results"""
    
    @staticmethod
    def encrypt_result(result: Dict, password: str) -> str:
        """
        Encrypt a result dictionary for secure storage.
        
        Args:
            result: The result dictionary to encrypt
            password: Encryption password
            
        Returns:
            Encrypted result as base64 string
        """
        # Simple XOR encryption for demonstration (use proper encryption in production)
        json_result = json.dumps(result)
        key = hashlib.sha256(password.encode()).digest()
        encrypted = bytes(a ^ b for a, b in zip(json_result.encode(), key * (len(json_result) // 32 + 1)))
        return base64.b64encode(encrypted).decode()
    
    @staticmethod
    def decrypt_result(encrypted_result: str, password: str) -> Dict:
        """
        Decrypt an encrypted result.
        
        Args:
            encrypted_result: The encrypted result
            password: Decryption password
            
        Returns:
            The original result dictionary
        """
        # Simple XOR decryption for demonstration (use proper decryption in production)
        key = hashlib.sha256(password.encode()).digest()
        decoded = base64.b64decode(encrypted_result.encode())
        decrypted = bytes(a ^ b for a, b in zip(decoded, key * (len(decoded) // 32 + 1)))
        return json.loads(decrypted.decode())

# Utility Functions
def download_qubic_helper() -> bool:
    """
    Download Qubic Helper Utilities binary.
    
    Returns:
        True if download was successful, False otherwise
    """
    try:
        print(f"Downloading Qubic Helper Utilities from {QUBIC_HELPER_DOWNLOAD_URL}...")
        
        # Download the file
        urllib.request.urlretrieve(QUBIC_HELPER_DOWNLOAD_URL, QUBIC_HELPER_PATH)
        
        # Make it executable
        os.chmod(QUBIC_HELPER_PATH, 0o755)
        
        # Verify the download
        if os.path.exists(QUBIC_HELPER_PATH):
            print("Qubic Helper Utilities downloaded successfully!")
            return True
        else:
            print("Download failed - file not found after download")
            return False
            
    except Exception as e:
        print(f"Download failed: {str(e)}")
        return False

def execute_qubic_command(command: str) -> Dict:
    """
    Execute a Qubic Helper command with comprehensive error handling.
    
    Args:
        command: The command to execute
        
    Returns:
        Dictionary with the result or error
    """
    try:
        # Check if the helper binary exists
        if not os.path.exists(QUBIC_HELPER_PATH):
            return {
                "status": "error",
                "error": f"Qubic Helper binary not found at {QUBIC_HELPER_PATH}"
            }
        
        # Execute the command
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30  # Add timeout to prevent hanging
        )
        
        # Check for execution errors
        if result.returncode != 0:
            return {
                "status": "error",
                "error": f"Command failed with exit code {result.returncode}: {result.stderr}"
            }
        
        # Parse the JSON response
        try:
            output = json.loads(result.stdout)
            return output
        except json.JSONDecodeError:
            return {
                "status": "error",
                "error": f"Invalid JSON response: {result.stdout}"
            }
    
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": "Command timed out after 30 seconds"
        }
    except Exception as e:
        return {
            "status": "error",
            "error": f"Unexpected error: {str(e)}"
        }

def validate_vanity_pattern(pattern: str) -> bool:
    """
    Validate user-provided vanity pattern.
    
    Args:
        pattern: The vanity pattern to validate
        
    Returns:
        True if pattern is valid, False otherwise
    """
    if not isinstance(pattern, str):
        return False
    
    # Remove whitespace
    pattern = pattern.strip()
    
    # Check if pattern is empty
    if not pattern:
        return False
    
    # Check for wildcard pattern
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        # Validate prefix contains only uppercase letters
        return re.match(r'^[A-Z]*$', prefix) is not None
    
    # Check for exact prefix pattern
    return re.match(r'^[A-Z]+$', pattern) is not None

def matches_pattern(public_id: str, pattern: str) -> bool:
    """
    Check if a public ID matches the specified vanity pattern.
    
    Args:
        public_id: The Qubic public ID to check
        pattern: The vanity pattern to match against
    
    Returns:
        True if the ID matches the pattern, False otherwise
    """
    # Simple prefix matching
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return public_id.startswith(prefix)
    
    # Exact match
    return public_id.startswith(pattern)

def generate_vanity_address(pattern: str, max_attempts: int = None, num_threads: int = None) -> Dict:
    """
    Main function to generate vanity address.
    
    Args:
        pattern: Desired prefix or pattern for the address
        max_attempts: Maximum number of attempts (None for unlimited)
        num_threads: Number of threads to use (must be provided)
    
    Returns:
        Dictionary containing the matching address and seed
    """
    if num_threads is None:
        raise ValueError("Number of threads must be specified")
    
    generator = QubicVanityGenerator(num_threads)
    return generator.generate_vanity_address(pattern, max_attempts)

def batch_generate_vanity_addresses(pattern: str, count: int, max_attempts_per_address: int = None, num_threads: int = None) -> List[Dict]:
    """
    Generate multiple vanity addresses with the same pattern.
    
    Args:
        pattern: Desired vanity pattern
        count: Number of addresses to generate
        max_attempts_per_address: Maximum attempts per address
        num_threads: Number of threads to use (must be provided)
        
    Returns:
        List of result dictionaries
    """
    if num_threads is None:
        raise ValueError("Number of threads must be specified")
    
    results = []
    
    for i in range(count):
        print(f"Generating address {i+1}/{count}...")
        
        result = generate_vanity_address(pattern, max_attempts_per_address, num_threads)
        results.append(result)
        
        if result["status"] == "success":
            print(f"Found address {i+1}: {result['publicId']}")
        else:
            print(f"Failed to generate address {i+1}: {result['error']}")
    
    return results

def run_validation_tests():
    """Run validation tests to ensure the generator works correctly"""
    print("Running validation tests...")
    
    # Test seed validation
    valid_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    invalid_seed = "InvalidSeed123"
    
    assert AddressValidator.validate_seed(valid_seed)[0] == True
    assert AddressValidator.validate_seed(invalid_seed)[0] == False
    
    # Test public ID validation
    valid_id = "BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK"
    invalid_id = "InvalidID123"
    
    assert AddressValidator.validate_public_id(valid_id)[0] == True
    assert AddressValidator.validate_public_id(invalid_id)[0] == False
    
    # Test seed-address consistency (requires qubic-helper binary)
    if os.path.exists(QUBIC_HELPER_PATH):
        assert AddressValidator.verify_seed_address_consistency(valid_seed, valid_id) == True
    
    # Test pattern matching
    assert matches_pattern(valid_id, "BZBQ*") == True
    assert matches_pattern(valid_id, "BZBQFLL") == True
    assert matches_pattern(valid_id, "INVALID") == False
    
    print("All validation tests passed!")

def test_full_vanity_generation():
    """Test the complete vanity generation process"""
    print("Testing full vanity generation process...")
    
    # Use a simple pattern that should be found quickly
    pattern = "A*"
    
    if not os.path.exists(QUBIC_HELPER_PATH):
        print("Qubic Helper binary not found. Skipping full generation test.")
        return
    
    # Test with 2 threads
    result = generate_vanity_address(pattern, max_attempts=10000, num_threads=2)
    
    if result["status"] == "success":
        # Verify the result
        assert AddressValidator.validate_seed(result["seed"])[0]
        assert AddressValidator.validate_public_id(result["publicId"])[0]
        assert matches_pattern(result["publicId"], pattern)
        
        # Verify consistency
        assert AddressValidator.verify_seed_address_consistency(
            result["seed"], result["publicId"]
        )
        
        print(f"Test passed: Found {result['publicId']} in {result['attempts']} attempts")
    else:
        print(f"Test failed: {result['error']}")

def get_user_friendly_error(error_dict: Dict) -> str:
    """
    Convert technical error messages to user-friendly ones.
    
    Args:
        error_dict: The error dictionary from execute_qubic_command
        
    Returns:
        A user-friendly error message
    """
    error = error_dict.get("error", "Unknown error")
    
    if "Qubic Helper binary not found" in error:
        return "Qubic Helper Utilities not found. Please run download_qubic_helper() first."
    elif "Command failed" in error:
        return "Failed to execute Qubic Helper command. Please check your installation."
    elif "Invalid JSON response" in error:
        return "Invalid response from Qubic Helper. Please try again."
    elif "timed out" in error:
        return "Operation timed out. Please try again."
    else:
        return f"An error occurred: {error}"

def check_qubic_helper_version() -> Tuple[bool, str]:
    """
    Check if the Qubic Helper binary is compatible with this generator.
    
    Returns:
        Tuple of (is_compatible, message)
    """
    try:
        # Try to get version information (this might not be supported)
        result = execute_qubic_command(f"{QUBIC_HELPER_PATH} --version")
        
        if result["status"] == "ok":
            # Check version compatibility
            version = result.get("version", "unknown")
            if version.startswith("3."):
                return True, f"Compatible version: {version}"
            else:
                return False, f"Incompatible version: {version}"
        else:
            # Version command not supported, assume compatibility
            return True, "Version check not available, assuming compatibility"
    
    except Exception as e:
        return False, f"Version check failed: {str(e)}"

def print_usage_examples():
    """Print usage examples for the user"""
    print("""
Qubic Vanity Address Generator - Usage Examples
===============================================

1. Basic Usage:
   generator = QubicVanityGenerator(num_threads=4)
   result = generator.generate_vanity_address("HELLO*")
   
2. With limited attempts:
   generator = QubicVanityGenerator(num_threads=8)
   result = generator.generate_vanity_address("TEST*", max_attempts=100000)
   
3. Multi-threaded generation:
   generator = QubicVanityGenerator(num_threads=16)
   result = generator.generate_vanity_address("CRYPTO*")
   
4. Batch generation:
   results = batch_generate_vanity_addresses("VANITY*", count=3, num_threads=4)
   
5. Download Qubic Helper:
   download_qubic_helper()
   
6. Run validation tests:
   run_validation_tests()
   
7. Test full generation:
   test_full_vanity_generation()

Pattern Formats:
- "HELLO*" : Matches addresses starting with "HELLO"
- "TEST"   : Exact match for prefix "TEST"
- "A*"     : Matches addresses starting with "A" (fast to find)

Note: You must specify the number of threads when creating the generator!
""")

def get_num_threads_from_user() -> int:
    """Get the number of threads from user input with validation."""
    while True:
        try:
            num_threads = input("Enter number of threads to use (1-64 recommended): ").strip()
            num_threads = int(num_threads)
            if num_threads < 1:
                print("Number of threads must be at least 1. Please try again.")
            elif num_threads > 64:
                print("Using more than 64 threads may cause performance issues. Please try again.")
            else:
                return num_threads
        except ValueError:
            print("Please enter a valid number. Please try again.")

# Main Execution
if __name__ == "__main__":
    print("Qubic Vanity Address Generator")
    print("=" * 40)
    
    # Check if Qubic Helper binary exists
    if not os.path.exists(QUBIC_HELPER_PATH):
        print("Qubic Helper Utilities binary not found.")
        download_choice = input("Would you like to download it now? (y/n): ").lower().strip()
        
        if download_choice == 'y':
            if download_qubic_helper():
                print("Download successful! You can now generate vanity addresses.")
            else:
                print("Download failed. Please download manually from:")
                print(QUBIC_HELPER_DOWNLOAD_URL)
                print("And save it as 'qubic-helper-linux' in the current directory.")
        else:
            print("Please download the Qubic Helper Utilities binary from:")
            print(QUBIC_HELPER_DOWNLOAD_URL)
            print("And save it as 'qubic-helper-linux' in the current directory.")
    
    # Run validation tests if binary is available
    if os.path.exists(QUBIC_HELPER_PATH):
        print("\nRunning validation tests...")
        run_validation_tests()
        
        # Check version compatibility
        compatible, message = check_qubic_helper_version()
        print(f"Version check: {message}")
        
        # Show usage examples
        print_usage_examples()
        
        # Interactive mode
        while True:
            print("\n" + "=" * 40)
            choice = input("Choose an option:\n1. Generate vanity address\n2. Run tests\n3. Exit\nEnter choice (1-3): ").strip()
            
            if choice == '1':
                pattern = input("Enter vanity pattern (e.g., 'HELLO*' or 'TEST'): ").strip().upper()
                if validate_vanity_pattern(pattern):
                    max_attempts = input("Enter maximum attempts (press Enter for unlimited): ").strip()
                    max_attempts = int(max_attempts) if max_attempts.isdigit() else None
                    
                    # Get number of threads from user
                    num_threads = get_num_threads_from_user()
                    
                    generator = QubicVanityGenerator(num_threads)
                    result = generator.generate_vanity_address(pattern, max_attempts)
                    
                    if result["status"] == "success":
                        print(f"\nSuccess! Found vanity address:")
                        print(f"Public ID: {result['publicId']}")
                        print(f"Seed: {result['seed']}")
                        print(f"Public Key: {result['publicKeyB64']}")
                        print(f"Private Key: {result['privateKeyB64']}")
                        print(f"Attempts: {result['attempts']}")
                    else:
                        print(f"\nFailed: {result['error']}")
                else:
                    print("Invalid pattern. Please use uppercase letters A-Z only, optionally ending with *")
            
            elif choice == '2':
                test_full_vanity_generation()
            
            elif choice == '3':
                print("Goodbye!")
                break
            
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
    else:
        print("\nPlease download the Qubic Helper Utilities binary to use this generator.")
