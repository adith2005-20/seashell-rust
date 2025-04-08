#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/seq_file.h> // For seq_file procfs interface
#include <linux/uaccess.h>  // For copy_from_user/copy_to_user
#include <linux/slab.h>     // For kmalloc/kfree
#include <linux/list.h>     // For kernel linked lists
#include <linux/mutex.h>    // For mutex locking
#include <linux/timekeeping.h>// For ktime_get_real_ns
#include <linux/sched.h>    // For 'current' task struct
#include <linux/cred.h>     // For current_uid()
#include <linux/atomic.h>   // For atomic types
#include <linux/string.h>   // For strstr, strlen, etc. (use carefully in kernel)

// --- Configuration ---
#define MAX_LOGS 100
#define MAX_CMD_LEN 256
#define PROC_STATUS_FILE "cmd_monitor"
#define PROC_CMD_FILE "cmd_monitor_cmd"

// --- Data Structures ---

// Command severity levels
enum severity {
    LOW = 0,
    MEDIUM = 1,
    HIGH = 2,
    CRITICAL = 3
};

// Helper to convert severity to string
static const char *severity_to_str(enum severity s) {
    switch (s) {
        case LOW:      return "LOW";
        case MEDIUM:   return "MEDIUM";
        case HIGH:     return "HIGH";
        case CRITICAL: return "CRITICAL";
        default:       return "UNKNOWN";
    }
}

// Command log entry structure
typedef struct {
    pid_t pid;
    uid_t uid;
    u64 timestamp; // nanoseconds
    char cmd[MAX_CMD_LEN];
    size_t cmd_len;
    enum severity severity;
    struct list_head list; // Kernel linked list node
} cmd_log_entry_t;

// Structure for dangerous command patterns
typedef struct {
    const char *pattern;
    enum severity severity;
    // Add flag for case sensitivity if needed later
} dangerous_command_t;

// Monitor statistics structure
typedef struct {
    atomic64_t commands_analyzed;
    atomic64_t dangerous_commands;
    atomic64_t by_severity[4]; // Indexed by enum severity
} monitor_stats_t;

// --- Global State ---

// Linked list head for log entries
static LIST_HEAD(g_cmd_log_list);
// Count of items in the list
static size_t g_log_count = 0;
// Mutex to protect access to the list and count
static DEFINE_MUTEX(g_log_mutex);

// Monitor statistics
static monitor_stats_t g_stats = {
    .commands_analyzed = ATOMIC64_INIT(0),
    .dangerous_commands = ATOMIC64_INIT(0),
    .by_severity = { ATOMIC64_INIT(0), ATOMIC64_INIT(0), ATOMIC64_INIT(0), ATOMIC64_INIT(0) },
};

// Predefined dangerous commands
static const dangerous_command_t g_dangerous_commands[] = {
    {"rm -rf /", CRITICAL},
    {"rm -rf /*", CRITICAL},
    {"rm -rf ~", HIGH},
    {"rm -rf .*", HIGH},
    {"dd if=/dev/zero of=/dev/sda", CRITICAL}, // Be careful with device names
    {"dd if=/dev/urandom of=/dev/sda", CRITICAL}, // Be careful with device names
    {":(){ :|:& };:", CRITICAL}, // Fork bomb
    {"wget -O - http", MEDIUM},
    {"curl -s http", MEDIUM},
    {"chmod -R 777 /", HIGH},
    {"chmod -R 777 /*", HIGH},
    {"mkfs", HIGH},
    {"> /etc/passwd", CRITICAL},
    {"> /boot/grub", HIGH}, // Be careful with boot paths
    {"sudo su", LOW},
    {"sudo -i", LOW},
    // Add more patterns here
};
static const size_t g_dangerous_commands_count = ARRAY_SIZE(g_dangerous_commands);

// Procfs entries
static struct proc_dir_entry *g_proc_status_entry = NULL;
static struct proc_dir_entry *g_proc_cmd_entry = NULL;


// --- Command Analysis & Logging ---

// Analyze command, return severity if dangerous, -1 otherwise
static enum severity analyze_command(const char *cmd, size_t cmd_len) {
    size_t i;
    // Simple substring search (case-sensitive).
    // Consider strcasestr or manual lowercase conversion if case-insensitivity is needed.
    // Be mindful of performance implications in kernel context.
    for (i = 0; i < g_dangerous_commands_count; ++i) {
        if (strstr(cmd, g_dangerous_commands[i].pattern) != NULL) {
            return g_dangerous_commands[i].severity;
        }
    }
    return -1; // Not found / Not dangerous based on patterns
}

// Process and potentially log a command
static void process_command(const char *cmd_buffer, size_t len) {
    enum severity severity;
    cmd_log_entry_t *new_entry = NULL;
    cmd_log_entry_t *oldest_entry = NULL;
    char *trimmed_cmd;

    // Basic trimming (leading/trailing whitespace) - simplistic example
    // A more robust trim might be needed. Ensure buffer isn't only whitespace.
    while (len > 0 && isspace(cmd_buffer[len - 1])) {
        len--;
    }
    while (len > 0 && isspace(*cmd_buffer)) {
        cmd_buffer++;
        len--;
    }

    // Null-terminate the relevant part for analysis functions like strstr
    // Need a mutable copy or be very careful
    trimmed_cmd = kmalloc(len + 1, GFP_KERNEL);
    if (!trimmed_cmd) {
         pr_err("cmd_monitor: Failed to allocate memory for trimmed command\n");
         return;
    }
    memcpy(trimmed_cmd, cmd_buffer, len);
    trimmed_cmd[len] = '\0';

    atomic64_inc(&g_stats.commands_analyzed);

    if (len == 0 || len >= MAX_CMD_LEN) {
        kfree(trimmed_cmd);
        return; // Ignore empty or overly long commands
    }

    severity = analyze_command(trimmed_cmd, len);

    if (severity != -1) { // Found a dangerous pattern
        atomic64_inc(&g_stats.dangerous_commands);
        if (severity >= LOW && severity <= CRITICAL) {
            atomic64_inc(&g_stats.by_severity[severity]);
        }

        // Log the command
        new_entry = kmalloc(sizeof(cmd_log_entry_t), GFP_KERNEL);
        if (!new_entry) {
            pr_err("cmd_monitor: Failed to allocate memory for log entry\n");
            kfree(trimmed_cmd);
            return;
        }

        new_entry->pid = current->pid;
        new_entry->uid = from_kuid(&init_user_ns, current_uid()); // Get UID
        new_entry->timestamp = ktime_get_real_ns();
        memcpy(new_entry->cmd, trimmed_cmd, len);
        new_entry->cmd[len] = '\0'; // Ensure null termination
        new_entry->cmd_len = len;
        new_entry->severity = severity;
        INIT_LIST_HEAD(&new_entry->list);

        mutex_lock(&g_log_mutex);
        // Enforce MAX_LOGS limit: remove oldest if necessary
        if (g_log_count >= MAX_LOGS) {
            if (!list_empty(&g_cmd_log_list)) {
                oldest_entry = list_first_entry(&g_cmd_log_list, cmd_log_entry_t, list);
                list_del(&oldest_entry->list);
                kfree(oldest_entry); // Free the memory of the removed entry
                g_log_count--;
            }
        }
        // Add the new entry to the tail of the list
        list_add_tail(&new_entry->list, &g_cmd_log_list);
        g_log_count++;
        mutex_unlock(&g_log_mutex);

        // Kernel log message for high/critical severity
        if (severity >= HIGH) {
            pr_alert("DANGEROUS COMMAND: [%s] %s (PID: %d, UID: %d)\n",
                     severity_to_str(severity), trimmed_cmd, new_entry->pid, new_entry->uid);
        }
         pr_info("cmd_monitor: Logged command (Severity: %s, PID: %d)\n", severity_to_str(severity), new_entry->pid);
    } else {
         pr_debug("cmd_monitor: Analyzed safe command (PID: %d)\n", current->pid);
    }
    kfree(trimmed_cmd);
}


// --- Procfs Handlers ---

// Handler for reading /proc/cmd_monitor (using seq_file)
static int cmd_monitor_show(struct seq_file *m, void *v) {
    cmd_log_entry_t *entry;
    u64 ts_sec;

    mutex_lock(&g_log_mutex);

    seq_puts(m, "Command Monitor Status\n");
    seq_puts(m, "=====================\n\n");

    seq_printf(m, "Commands analyzed:  %lld\n", atomic64_read(&g_stats.commands_analyzed));
    seq_printf(m, "Dangerous commands: %lld\n", atomic64_read(&g_stats.dangerous_commands));
    seq_printf(m, "  - Low severity:     %lld\n", atomic64_read(&g_stats.by_severity[LOW]));
    seq_printf(m, "  - Medium severity:  %lld\n", atomic64_read(&g_stats.by_severity[MEDIUM]));
    seq_printf(m, "  - High severity:    %lld\n", atomic64_read(&g_stats.by_severity[HIGH]));
    seq_printf(m, "  - Critical severity:%lld\n", atomic64_read(&g_stats.by_severity[CRITICAL]));

    seq_puts(m, "\nRecent Dangerous Commands:\n");
    seq_puts(m, "=========================\n");

    if (list_empty(&g_cmd_log_list)) {
        seq_puts(m, "No dangerous commands logged yet.\n");
    } else {
        // Iterate through the list (safely, in case of concurrent modification issues - though mutex helps)
        list_for_each_entry(entry, &g_cmd_log_list, list) {
             ts_sec = entry->timestamp / NSEC_PER_SEC; // Convert ns to s
             seq_printf(m, "[%s] PID: %d, UID: %d, Time: %llu, Command: %s\n",
                 severity_to_str(entry->severity),
                 entry->pid,
                 entry->uid,
                 ts_sec,
                 entry->cmd);
        }
    }

    mutex_unlock(&g_log_mutex);
    return 0;
}

// Open handler for /proc/cmd_monitor
static int cmd_monitor_open(struct inode *inode, struct file *file) {
    // Use single_open for simple seq_file usage
    return single_open(file, cmd_monitor_show, NULL);
}

// File operations for /proc/cmd_monitor
static const struct proc_ops cmd_monitor_status_ops = {
    .proc_open    = cmd_monitor_open,
    .proc_read    = seq_read,         // Use standard seq_file read
    .proc_lseek   = seq_lseek,        // Use standard seq_file seek
    .proc_release = single_release,   // Use standard single_open release
};


// Write handler for /proc/cmd_monitor_cmd
static ssize_t cmd_monitor_cmd_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
    char *kernel_buffer;

    if (count == 0 || count >= MAX_CMD_LEN) {
        pr_warn("cmd_monitor: Invalid write size to cmd input: %zu\n", count);
        return -EINVAL; // Invalid argument
    }

    // Allocate buffer in kernel space (+1 for null terminator if needed by processing)
    kernel_buffer = kmalloc(count + 1 , GFP_KERNEL);
    if (!kernel_buffer) {
        pr_err("cmd_monitor: Failed to allocate buffer for command input\n");
        return -ENOMEM; // Out of memory
    }

    // Copy data from user space
    if (copy_from_user(kernel_buffer, buffer, count)) {
        pr_err("cmd_monitor: Failed to copy command from user space\n");
        kfree(kernel_buffer);
        return -EFAULT; // Bad address
    }
    // Null-terminate for safety, although process_command takes length
    kernel_buffer[count] = '\0';

    // Process the received command
    process_command(kernel_buffer, count);

    kfree(kernel_buffer);

    // Return the number of bytes written
    return count;
}

// File operations for /proc/cmd_monitor_cmd
static const struct proc_ops cmd_monitor_cmd_ops = {
    .proc_write = cmd_monitor_cmd_write,
    // Add .proc_open, .proc_release if needed (often NULL is fine for simple write-only)
};


// --- Module Init & Exit ---

static int __init cmd_monitor_init(void) {
    pr_info("Command Monitor: Initializing\n"); // Use compile date

    // Create /proc/cmd_monitor (readable status file)
    g_proc_status_entry = proc_create(PROC_STATUS_FILE, 0444, NULL, &cmd_monitor_status_ops); // Read-only for users
    if (!g_proc_status_entry) {
        pr_err("cmd_monitor: Failed to create /proc/%s\n", PROC_STATUS_FILE);
        return -ENOMEM;
    }
    pr_info("cmd_monitor: Created /proc/%s\n", PROC_STATUS_FILE);

    // Create /proc/cmd_monitor_cmd (writable command input file)
    // Permissions: 0222 (write-only for users), 0666 (read/write for all) - choose carefully.
    // Using 0622 (owner read/write, group write, other write) might be safer. Start with root-only write (0200).
    g_proc_cmd_entry = proc_create(PROC_CMD_FILE, 0200, NULL, &cmd_monitor_cmd_ops); // Write-only for root initially
     if (!g_proc_cmd_entry) {
        pr_err("cmd_monitor: Failed to create /proc/%s\n", PROC_CMD_FILE);
        // Clean up the status entry if cmd entry fails
        proc_remove(g_proc_status_entry);
        return -ENOMEM;
    }
    pr_info("cmd_monitor: Created /proc/%s\n", PROC_CMD_FILE);


    pr_info("Command Monitor: Initialization complete.\n");
    return 0; // Success
}

static void __exit cmd_monitor_exit(void) {
    cmd_log_entry_t *entry, *tmp;

    pr_info("Command Monitor: Exiting\n");

    // Remove procfs entries
    if (g_proc_cmd_entry) {
        proc_remove(g_proc_cmd_entry);
         pr_info("cmd_monitor: Removed /proc/%s\n", PROC_CMD_FILE);
    }
    if (g_proc_status_entry) {
        proc_remove(g_proc_status_entry);
         pr_info("cmd_monitor: Removed /proc/%s\n", PROC_STATUS_FILE);
    }

    // Clean up the log list - free all allocated entries
    mutex_lock(&g_log_mutex);
    list_for_each_entry_safe(entry, tmp, &g_cmd_log_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    g_log_count = 0; // Reset count
    mutex_unlock(&g_log_mutex);
     pr_info("cmd_monitor: Cleared command log list.\n");

    // No need to destroy statically defined mutex (DEFINE_MUTEX)

    pr_info("Command Monitor: Cleanup finished.\n");
}

// Register module init and exit functions
module_init(cmd_monitor_init);
module_exit(cmd_monitor_exit);

// --- Module Metadata ---
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Kernel Module Developer (C Port)");
MODULE_DESCRIPTION("Monitor potentially dangerous shell commands (C Version)");
MODULE_VERSION("0.1");
