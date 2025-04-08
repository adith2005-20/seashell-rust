# Seashell + Kernel Module

## 🐚 Seashell — A Smarter Shell with AI Assistance

**Seashell** is a Rust-based custom shell that helps users execute Linux commands more reliably. It features:

- Command chaining and pipelining
- Retry and correction suggestions for failed commands
- Built-in handling for redirection, environment variables, and more
- AI-powered error explanations (via integration hooks)

## Kernel Module — Command Monitor

This C-based Linux kernel module monitors command executions by watching a `/proc/seashell_monitor` file. It can:

- Detect potentially dangerous commands
- Log them with severity ratings
- Provide runtime stats via `/proc/seashell_stats`

> Think of it as a guardian silently observing your shell from inside the kernel.

## Build & Run Guide

### Prerequisites

- **Rust** (recommended via [rustup.rs](https://rustup.rs))
- **make** and **gcc** (for kernel module)
- **Kernel headers** installed (for compiling the module)
- A Linux system (tested on Fedora, should work on Debian/Ubuntu too)

### 1. Build the Shell

```bash
cd seashell
cargo build --release
```

Run the shell with:

```bash
./target/release/seashell
```

You should now see your custom prompt — try typing normal Linux commands!

### 2. Build the Kernel Module

Requires root privileges and kernel headers.

```bash
cd kernel_module
make
```

Load the module:

```bash
sudo insmod seashell_monitor.ko
```

Check it's running:

```bash
dmesg | tail
```

Check the `/proc` entries:

```bash
cat /proc/seashell_monitor
cat /proc/seashell_stats
```

To remove:

```bash
sudo rmmod seashell_monitor
```

##  Want to Hack on It?

Both components are modular. You can:
* Extend Seashell's command handling (e.g. aliases, built-ins)
* Improve the AI integration logic (e.g. GPT responses or fallback logic)
* Hook the shell to communicate with the kernel module for live alerts

