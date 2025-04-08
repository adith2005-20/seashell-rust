use std::io::{stdin, stdout, Write};
use std::fs::File;
use std::process::{Command, Stdio, Child};
use std::env;
use std::path::Path;
use ansi_term::Colour;
use reqwest::Client;
use crate::chat::chat;
use std::io::Write as IoWrite;
use std::fs::OpenOptions;
use std::io::Read;
mod chat;

// Global tracking of kernel module status to avoid repeated warnings
static mut KERNEL_MODULE_WARNING_SHOWN: bool = false;

// New function to check if kernel module is loaded
fn is_kernel_module_loaded() -> bool {
    Path::new("/proc/cmd_monitor").exists()
}

// New function to handle kernel module integration
async fn send_to_kernel_monitor(command: &str) -> Result<Option<String>, std::io::Error> {
    // 1) Early-out if module isn’t loaded
    if !is_kernel_module_loaded() {
        unsafe {
            if !KERNEL_MODULE_WARNING_SHOWN {
                eprintln!("{}", Colour::Yellow.bold().paint(
                    "⚠️ WARNING: Security kernel module not detected!"));
                KERNEL_MODULE_WARNING_SHOWN = true;
            }
        }
        return Ok(None);
    }

    // 2) Write the raw command into the procfs interface
    let mut file = OpenOptions::new()
        .write(true)
        .open("/proc/cmd_monitor_cmd")?;
    file.write_all(command.trim().as_bytes())?;

    // 3) Read back the status file and look for *any* severity
    let mut status = String::new();
    File::open("/proc/cmd_monitor")?
        .read_to_string(&mut status)?;

    // scan lines in reverse so we hit the most recent first
    for line in status.lines().rev() {
        // stop once we leave the “Recent Dangerous Commands” block
        if line.contains("Recent Dangerous Commands:") {
            break;
        }
        // if this line mentions our exact command…
        if line.contains(command.trim()) {
            // …and it has “[XXX]” in it, it’s flagged at some severity
            if let (Some(start), Some(end)) = (line.find('['), line.find(']')) {
                let sev = &line[start+1..end];
                // Block on any severity (LOW, MEDIUM, HIGH, CRITICAL)
                match sev {
                    "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" => {
                        return Ok(Some(line.to_string()));
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(None)
}

#[tokio::main]
async fn main() {
    // Check if kernel module is loaded when shell starts
    if !is_kernel_module_loaded() {
        println!("{}", Colour::Yellow.bold().paint("⚠️ Security kernel module not detected!"));
        println!("{}", Colour::Yellow.paint("Command monitoring is disabled. Your system may be at risk."));
        println!("{}", Colour::Yellow.paint("Run 'sudo insmod cmd_monitor.ko' to enable security features."));
        // Mark warning as shown
        unsafe { KERNEL_MODULE_WARNING_SHOWN = true; }
    }

    loop {
        let user = env::var("USER").unwrap_or_else(|_| "user".to_string());
        let host = env::var("HOSTNAME").unwrap_or_else(|_| "machine".to_string());
        let cwd = env::current_dir().unwrap_or_else(|_| Path::new("/").to_path_buf());
        let user_host = Colour::Purple.bold().paint(format!("[{}@{}] ~", user, host));
        let path = Colour::Cyan.italic().bold().paint(format!("{}", cwd.display()));

        print!("{} {}\n ➥ ", user_host, path);
        let _ = stdout().flush();

        let mut input = String::new();
        stdin().read_line(&mut input).unwrap();

        process_command(input, 0).await;
    }
}

async fn process_command(mut input: String, mut retry_count: u8) {
    const MAX_RETRIES: u8 = 1;

    // Outer loop: retry if any correction is suggested
    while retry_count <= MAX_RETRIES {
        // Send the full command input to kernel monitor before processing
        // This ensures we catch dangerous commands even in pipelines/chains
        if is_kernel_module_loaded() {
            match send_to_kernel_monitor(&input).await {
                Ok(Some(warning)) => {
                    println!("{}", Colour::Red.bold().paint("⚠️ KERNEL SECURITY ALERT ⚠️"));
                    println!("{}", Colour::Yellow.paint(&warning));
                    println!("Continue execution? [y/N]: ");
                    let _ = stdout().flush();
                    
                    let mut confirm = String::new();
                    stdin().read_line(&mut confirm).unwrap();
                    if !confirm.trim().eq_ignore_ascii_case("y") {
                        println!("Command aborted.");
                        return;
                    }
                },
                Err(e) => {
                    // Only show permission error once
                    if e.kind() != std::io::ErrorKind::PermissionDenied {
                        eprintln!("Error communicating with kernel module: {}", e);
                    }
                },
                _ => {}
            }
        }

        // Instead of borrowing, collect the command chains into owned Strings.
        let chains: Vec<String> = input.split(" && ").map(|s| s.to_string()).collect();
        let mut overall_success = true;

        // Process each chain one by one.
        for chain in chains {
            // Within a chain, support pipeline (split by " | ").
            let mut commands = chain.trim().split(" | ").peekable();
            let mut previous_command: Option<Child> = None;
            let mut error_occurred = false;

            while let Some(command_str) = commands.next() {
                let mut parts = command_str.trim().split_whitespace();
                let command = parts.next().unwrap_or("");
                let args: Vec<&str> = parts.collect();

                // Handle output redirection (">")
                let mut output_file = None;
                let mut args_filtered = Vec::new();
                let mut iter = args.iter();
                while let Some(arg) = iter.next() {
                    if *arg == ">" {
                        if let Some(filename) = iter.next() {
                            output_file = Some(filename);
                        }
                    } else {
                        args_filtered.push(*arg);
                    }
                }

                match command {
                    "cd" => {
                        let new_dir = args.first().copied().unwrap_or("/");
                        if let Err(e) = env::set_current_dir(Path::new(new_dir)) {
                            eprintln!("cd error: {}", e);
                        }
                    },
                    "version" => {
                        let ascii_art = r#"
												   _.-''|''-._
												.-'     |     `-.
											  .'\       |       /`.
											.'   \      |      /   `.
											\     \     |     /     /
											 `\    \    |    /    /'
											   `\   \   |   /   /'
												 `\  \  |  /  /'
												_.-`\ \ | / /'-._
											   {_____`\\|//'_____}          
                                         /$$                 /$$ /$$
                                        | $$                | $$| $$
  /$$$$$$$  /$$$$$$   /$$$$$$   /$$$$$$$| $$$$$$$   /$$$$$$ | $$| $$
 /$$_____/ /$$__  $$ |____  $$ /$$_____/| $$__  $$ /$$__  $$| $$| $$
|  $$$$$$ | $$$$$$$$  /$$$$$$$|  $$$$$$ | $$  \ $$| $$$$$$$$| $$| $$
 \____  $$| $$_____/ /$$__  $$ \____  $$| $$  | $$| $$_____/| $$| $$
 /$$$$$$$/|  $$$$$$$|  $$$$$$$ /$$$$$$$/| $$  | $$|  $$$$$$$| $$| $$
|_______/  \_______/ \_______/|_______/ |__/  |__/ \_______/|__/|__/

Seashell  - A lightweight UNIX shell built in Rust
Developed with <3
"#;
                        let styled_ascii_art = Colour::Cyan.paint(ascii_art);
                        print!("{}", styled_ascii_art);
                        
                        // Show security status
                        if is_kernel_module_loaded() {
                            println!("{}", Colour::Green.bold().paint("✓ Kernel security module is active"));
                        } else {
                            println!("{}", Colour::Yellow.bold().paint("⚠️ Kernel security module is NOT loaded"));
                            println!("{}", Colour::Yellow.paint("Run 'sudo insmod cmd_monitor.ko' to enable security features"));
                        }
                    },
                    "security" | "monitor" => {
                        // New command to display security status from kernel module
                        if is_kernel_module_loaded() {
                            match File::open("/proc/cmd_monitor") {
                                Ok(mut file) => {
                                    let mut content = String::new();
                                    if let Err(e) = file.read_to_string(&mut content) {
                                        eprintln!("Error reading security status: {}", e);
                                    } else {
                                        println!("{}", Colour::Green.paint("==== Kernel Security Monitor Status ===="));
                                        println!("{}", content);
                                    }
                                },
                                Err(e) => {
                                    eprintln!("Error accessing security monitor: {}", e);
                                }
                            }
                        } else {
                            println!("{}", Colour::Yellow.bold().paint("⚠️ Kernel security module is NOT loaded"));
                            println!("{}", Colour::Yellow.paint("Run 'sudo insmod cmd_monitor.ko' to enable security features"));
                        }
                    },
                    "exit" | "^C" => return,
                    "" => (), // Handle empty command
                    _ => {
                        // Set up input for the command: use output from previous command if part of a pipeline.
                        let child_stdin = previous_command.map_or(Stdio::inherit(), |child| {
                            Stdio::from(child.stdout.unwrap())
                        });

                        // For commands in a pipeline, pipe the output; if output redirection was specified, use that.
                        let child_stdout = if let Some(file) = output_file {
                            match File::create(file) {
                                Ok(file) => Stdio::from(file),
                                Err(_) => {
                                    eprintln!("Failed to open file: {}", file);
                                    Stdio::inherit()
                                }
                            }
                        } else if commands.peek().is_some() {
                            Stdio::piped()
                        } else {
                            Stdio::inherit()
                        };

                        let output = Command::new(command)
                            .args(&args_filtered)
                            .stdin(child_stdin)
                            .stdout(child_stdout)
                            .spawn();

                        match output {
                            Ok(child) => {
                                previous_command = Some(child);
                            }
                            Err(_) => {
                                previous_command = None;
                                let client = Client::new();
                                let query = format!(
                                    "The command '{}' with arguments {:?} failed. Can you suggest a corrected command?",
                                    command, args_filtered
                                );
                                if let Ok(corrected_command) = chat(&client, &query).await {
                                    println!(
                                        "SeaShell suggests: {}",
                                        Colour::Green.bold().paint(&corrected_command)
                                    );
                                    input = corrected_command.trim().to_string();
                                    retry_count += 1;
                                    error_occurred = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            } // End while processing pipeline commands within the chain

            // If an error occurred (and a correction was suggested), break out of processing all chains.
            if error_occurred {
                overall_success = false;
                break;
            }

            // Wait for the last command in the chain and check its exit status.
            if let Some(mut final_command) = previous_command {
                let status = final_command.wait().expect("failed to wait on child");
                if !status.success() {
                    overall_success = false;
                    break;
                }
            }
        } // End for each chain

        // If all chains executed successfully, break out of the retry loop.
        if overall_success {
            break;
        } else {
            if retry_count > MAX_RETRIES {
                eprintln!("{}", Colour::Red.paint("Stopped after too many failed attempts."));
                return;
            }
            // Otherwise, the loop will continue using the corrected input.
            continue;
        }
    }
}
