# watcher.py
import time
import os
import hashlib
import subprocess
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description='Watch dependency files for changes and scan for vulnerabilities')
    parser.add_argument('--directory', '-d', default='.', help='Directory to watch')
    parser.add_argument('--interval', '-i', type=int, default=5, help='Check interval in seconds')
    parser.add_argument('--scan', '-s', action='store_true', help='Scan immediately on startup')
    args = parser.parse_args()
    
    watcher = DependencyWatcher(
        directory=args.directory, 
        scan_immediately=args.scan
    )
    watcher.start(interval=args.interval)

class DependencyWatcher:
    """Watch for changes in dependency files and trigger security scans."""
    
    def __init__(self, directory='.', scan_immediately=False):
        self.directory = Path(directory)
        self.scan_immediately = scan_immediately
        
        # Files to watch
        self.dependency_files = [
            "requirements.txt",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "pyproject.toml",
            "setup.py"
        ]
        self.file_hashes = {}
    
    def start(self, interval=5):
        """Start watching for changes."""
        print(f"Watching {self.directory} for dependency file changes...")
        
        # First, find all existing dependency files and compute their hashes
        self.update_file_list()
        
        # Scan immediately if requested
        if self.scan_immediately:
            print("Performing initial scan...")
            self.scan_all_files()
        
        # Start the watch loop
        try:
            while True:
                time.sleep(interval)
                changes = self.check_for_changes()
                if changes:
                    print(f"Changes detected in: {', '.join(changes)}")
                    self.scan_files(changes)
        except KeyboardInterrupt:
            print("\nStopping watcher...")
    
    def update_file_list(self):
        """Find all dependency files in the directory and store their hashes."""
        for filename in self.dependency_files:
            file_path = self.directory / filename
            if file_path.exists():
                self.file_hashes[str(file_path)] = self.get_file_hash(file_path)
    
    def get_file_hash(self, file_path):
        """Compute the hash of a file to detect changes."""
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()
    
    def check_for_changes(self):
        """Check if any dependency files have changed."""
        changes = []
        
        # Check existing files for changes
        for file_path, old_hash in list(self.file_hashes.items()):
            path = Path(file_path)
            if path.exists():
                new_hash = self.get_file_hash(path)
                if new_hash != old_hash:
                    changes.append(file_path)
                    self.file_hashes[file_path] = new_hash
            else:
                # File was deleted
                del self.file_hashes[file_path]
        
        # Check for new dependency files
        for filename in self.dependency_files:
            file_path = self.directory / filename
            path_str = str(file_path)
            if file_path.exists() and path_str not in self.file_hashes:
                changes.append(path_str)
                self.file_hashes[path_str] = self.get_file_hash(file_path)
        
        return changes
    
    def scan_all_files(self):
        """Scan all tracked dependency files."""
        self.scan_files(list(self.file_hashes.keys()))
    
    def scan_files(self, file_paths):
        """Scan specific dependency files for vulnerabilities."""
        for file_path in file_paths:
            print(f"Scanning {file_path}...")
            
            # Create output file path
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_file = Path(f"security_report_{Path(file_path).stem}_{timestamp}.md")
            
            # Run the scan using app.py
            subprocess.run([
                "python", "app.py",
                "--file", file_path,
                "--check-deps",
                "--output", str(output_file)
            ])
            
            print(f"Scan report saved to {output_file}")

if __name__ == "__main__":
    main()