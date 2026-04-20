from bcc import BPF
import os
import time
from collections import defaultdict

prog = """
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>

// Reduced structure size to fit within 512 byte stack limit
struct file_event {
    u32 pid;
    char comm[16];
    char filename[64];  // Reduced from 256
    // Removed full_path to save stack space
};

// Use separate map for tracking instead of stack variables
BPF_PERF_OUTPUT(file_events);
BPF_HASH(seen_files, u64, u32);

int trace_vfs_open(struct pt_regs *ctx, struct path *path) {
    struct file_event event = {};
    struct dentry *de;
    
    // Initialize event
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get dentry safely
    bpf_probe_read_kernel(&de, sizeof(de), &path->dentry);
    if (!de) return 0;
    
    // Get filename with bounds checking
    bpf_probe_read_kernel_str(&event.filename,
                              sizeof(event.filename),
                              (void *)&(de->d_name.name));
    
    // Use hash to rate limit (avoid flooding)
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 *exists = seen_files.lookup(&pid_tgid);
    if (!exists) {
        u32 zero = 0;
        seen_files.update(&pid_tgid, &zero);
        file_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}
"""

class HiddenFileDetector:
    def __init__(self):
        self.kernel_seen_hidden = set()
        self.kernel_seen_all = set()
        self.userspace_hidden = {}
        self.suspicious_activity = defaultdict(list)
        # Expanded watch directories
        self.watch_dirs = ['/tmp', '/dev/shm', '/var/tmp', '/home', '/root', '/var/run']
        self.known_safe = ['.X', '.ICE', '.Test', '.font', '.XIM', '.cache', 
                          '.config', '.local', '.ssh', '.bashrc', '.profile',
                          '.bash_history', '.viminfo', '.lesshst', '.mysql_history']
        
    def handle_event(self, cpu, data, size):
        """Process events from eBPF"""
        try:
            event = b["file_events"].event(data)
            filename = event.filename.decode('utf-8', errors='replace').strip('\x00')
            comm = event.comm.decode('utf-8', errors='replace').strip('\x00')
            pid = event.pid
            
            if not filename:
                return
            
            # Track all files
            self.kernel_seen_all.add(filename)
            
            # Check for hidden files (starts with .)
            if filename.startswith('.') and len(filename) > 2 and filename not in ['.', '..']:
                self.kernel_seen_hidden.add(filename)
                self.suspicious_activity[filename].append({
                    'pid': pid,
                    'process': comm,
                    'time': time.time(),
                    'filename': filename
                })
                
                # Keep only last 10 entries per file
                if len(self.suspicious_activity[filename]) > 10:
                    self.suspicious_activity[filename] = self.suspicious_activity[filename][-10:]
                    
        except Exception as e:
            pass  # Silent fail for malformed events
    
    def scan_userspace_hidden(self):
        """Scan directories for visible hidden files"""
        self.userspace_hidden = {}
        
        for directory in self.watch_dirs:
            if not os.path.exists(directory):
                continue
                
            try:
                visible_files = set(os.listdir(directory))
                hidden_files = [f for f in visible_files if f.startswith('.') and len(f) > 2]
                
                suspicious = []
                for hf in hidden_files:
                    # Check if it's a known safe file
                    is_safe = False
                    for safe_pattern in self.known_safe:
                        if hf.startswith(safe_pattern) or hf == safe_pattern:
                            is_safe = True
                            break
                    
                    # Also check for common safe dotfiles
                    if not is_safe and len(hf) > 2:
                        suspicious.append(hf)
                
                if suspicious:
                    self.userspace_hidden[directory] = suspicious
                    
            except PermissionError:
                continue
            except Exception as e:
                print(f"    [!] Error scanning {directory}: {e}")
    
    def detect_hidden_discrepancies(self):
        """DETECT HIDDEN FILES - Compare kernel vs userspace"""
        print("\n" + "="*80)
        print("🔍 HIDDEN FILE DISCREPANCY DETECTION")
        print("="*80)
        
        kernel_only_hidden = []
        
        # Check each hidden file kernel saw
        for hidden_file in self.kernel_seen_hidden:
            found_in_userspace = False
            
            # Try to find if this file exists in any directory
            for directory in self.watch_dirs:
                if not os.path.exists(directory):
                    continue
                    
                try:
                    full_path = os.path.join(directory, hidden_file)
                    # Check if file exists at all
                    if os.path.exists(full_path):
                        # Check if it's visible in directory listing
                        visible = set(os.listdir(directory))
                        if hidden_file in visible:
                            found_in_userspace = True
                            break
                        else:
                            # File exists but hidden from directory listing!
                            kernel_only_hidden.append((hidden_file, directory, full_path))
                            found_in_userspace = True
                            break
                except:
                    pass
            
            # If never found in any directory
            if not found_in_userspace:
                kernel_only_hidden.append((hidden_file, "unknown", "unknown"))
        
        # Report discrepancies
        if kernel_only_hidden:
            print("\n⚠️  CRITICAL: Hidden files accessed by kernel but not visible in userspace!")
            print("⚠️  Possible rootkit or file hiding detected!\n")
            
            for filename, directory, full_path in kernel_only_hidden[:20]:  # Limit output
                print(f"  🕵️  {filename}")
                if directory != "unknown":
                    print(f"     📁 Directory: {directory}")
                    print(f"     📍 Path: {full_path}")
                
                # Show which processes accessed it
                if filename in self.suspicious_activity:
                    print(f"     🔄 Accessed by:")
                    for access in self.suspicious_activity[filename][-3:]:
                        print(f"       - PID {access['pid']}: {access['process']}")
                print()
            
            if len(kernel_only_hidden) > 20:
                print(f"  ... and {len(kernel_only_hidden) - 20} more hidden files")
        else:
            print("\n✅ No hidden file discrepancies detected")
        
        return kernel_only_hidden
    
    def detect_kernel_hidden_files(self):
        """Detect hidden files that kernel has accessed"""
        print("\n" + "="*80)
        print("🎯 KERNEL-ACCESSED HIDDEN FILES")
        print("="*80)
        
        if self.kernel_seen_hidden:
            print(f"\n⚠️  Kernel has accessed {len(self.kernel_seen_hidden)} hidden files:\n")
            # Show most recent/suspicious ones
            for hf in sorted(self.kernel_seen_hidden)[:30]:
                access_count = len(self.suspicious_activity.get(hf, []))
                print(f"  📄 {hf}")
                if access_count > 0:
                    print(f"     (Accessed {access_count} times)")
            
            if len(self.kernel_seen_hidden) > 30:
                print(f"\n  ... and {len(self.kernel_seen_hidden) - 30} more hidden files")
        else:
            print("\n✅ No hidden files accessed by kernel detected")
    
    def detect_userspace_hidden(self):
        """Detect hidden files visible in userspace"""
        print("\n" + "="*80)
        print("👁️  USERSPACE-VISIBLE HIDDEN FILES")
        print("="*80)
        
        if self.userspace_hidden:
            total_suspicious = sum(len(files) for files in self.userspace_hidden.values())
            print(f"\n⚠️  Found {total_suspicious} suspicious hidden files in directories:\n")
            
            for directory, files in self.userspace_hidden.items():
                print(f"  📁 {directory}:")
                for filename in files[:10]:  # Limit per directory
                    full_path = os.path.join(directory, filename)
                    print(f"    📄 {filename}")
                    
                    # Check file details
                    try:
                        stat = os.stat(full_path)
                        size = stat.st_size
                        mtime = time.ctime(stat.st_mtime)
                        print(f"       📏 Size: {size} bytes, 🕒 Modified: {mtime}")
                    except:
                        pass
                
                if len(files) > 10:
                    print(f"    ... and {len(files) - 10} more files")
                print()
        else:
            print("\n✅ No suspicious hidden files found in userspace")
    
    def real_time_alert(self):
        """Check for real-time suspicious activity"""
        if self.suspicious_activity:
            recent_activity = []
            current_time = time.time()
            
            for filename, accesses in self.suspicious_activity.items():
                # Check for accesses in last 5 seconds
                recent = [a for a in accesses if current_time - a['time'] <= 5]
                if recent:
                    recent_activity.append((filename, recent))
            
            if recent_activity:
                print("\n🚨 REAL-TIME ALERT: Hidden file access detected!")
                for filename, accesses in recent_activity:
                    print(f"  🔥 {filename} - accessed by {accesses[0]['process']} (PID: {accesses[0]['pid']})")
    
    def full_scan(self):
        """Perform complete hidden file detection"""
        self.scan_userspace_hidden()
        self.detect_userspace_hidden()
        self.detect_kernel_hidden_files()
        self.detect_hidden_discrepancies()
        self.real_time_alert()
        
        # Summary
        print("\n" + "="*80)
        print("📊 SUMMARY")
        print("="*80)
        print(f"  • Kernel-accessed hidden files: {len(self.kernel_seen_hidden)}")
        print(f"  • Userspace-visible hidden files: {sum(len(v) for v in self.userspace_hidden.values())}")
        print(f"  • Total unique files seen by kernel: {len(self.kernel_seen_all)}")
        print(f"  • Suspicious activities tracked: {len(self.suspicious_activity)}")

print("🛡️  SENTINEL - Advanced Hidden File Detector")
print("="*80)
print("[✓] Using eBPF to monitor kernel-level file access")
print("[✓] Comparing kernel view vs userspace view")
print("[✓] Detecting hidden files and potential rootkits")
print("[✓] Real-time suspicious activity monitoring")
print("="*80)

# Initialize eBPF
try:
    b = BPF(text=prog)
    b.attach_kprobe(event="vfs_open", fn_name="trace_vfs_open")
    print("[✓] eBPF program loaded successfully")
except Exception as e:
    print(f"[✗] Failed to load eBPF: {e}")
    print("    Make sure you have root privileges and BCC installed")
    exit(1)

# Initialize detector
detector = HiddenFileDetector()
b["file_events"].open_perf_buffer(detector.handle_event)

# Create test files to demonstrate detection
print("\n[*] Creating test files for demonstration...")
try:
    os.system("touch /tmp/.normal_hidden_file 2>/dev/null")
    os.system("touch /tmp/.suspicious_malware 2>/dev/null")
    os.system("echo 'test' > /tmp/.kernel_only_file 2>/dev/null")
    print("[✓] Test files created")
except:
    print("[!] Could not create test files (permission issues)")

# Access the test file so kernel sees it
try:
    with open('/tmp/.kernel_only_file', 'r') as f:
        pass
    with open('/tmp/.suspicious_malware', 'r') as f:
        pass
    print("[✓] Simulated access to test files")
except:
    pass

print("\n[*] Monitoring for hidden file activity...")
print("[*] Press CTRL+C to stop and see full report\n")
print("-"*80)

# Monitoring loop
scan_counter = 0
try:
    while True:
        # Poll eBPF events with timeout
        b.perf_buffer_poll(timeout=1000)
        scan_counter += 1
        
        # Every 15 seconds, do a full scan
        if scan_counter % 15 == 0:
            print(f"\n[SCAN #{scan_counter//15}] Running hidden file detection...")
            detector.full_scan()
            print("\n" + "-"*80)
            print("[*] Continuing monitoring (press Ctrl+C to stop)...")
            
except KeyboardInterrupt:
    print("\n\n" + "="*80)
    print("📋 FINAL REPORT")
    print("="*80)
    
    # Final comprehensive scan
    detector.full_scan()
    
    # Cleanup
    print("\n[*] Cleaning up test files...")
    try:
        os.remove('/tmp/.normal_hidden_file')
        os.remove('/tmp/.suspicious_malware')
        os.remove('/tmp/.kernel_only_file')
        print("[✓] Test files removed")
    except:
        pass
    
    print("\n[*] SENTINEL stopped.")
