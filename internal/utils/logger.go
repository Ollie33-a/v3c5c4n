package utils

import (
    "fmt"
    "os"
    "time"

    "github.com/fatih/color"
)

// Logger provides logging utilities
type Logger struct {
    verbose bool
}

var (
    infoColor    = color.New(color.FgCyan)
    successColor = color.New(color.FgGreen)
    warnColor    = color.New(color.FgYellow)
    errorColor   = color.New(color.FgRed)
    debugColor   = color.New(color.FgMagenta)
)

// NewLogger creates a new logger instance
func NewLogger(verbose bool) *Logger {
    return &Logger{verbose: verbose}
}

// Info logs info messages
func (l *Logger) Info(format string, args ...interface{}) {
    infoColor.Printf("[*] %s\n", fmt.Sprintf(format, args...))
}

// Success logs success messages
func (l *Logger) Success(format string, args ...interface{}) {
    successColor.Printf("[+] %s\n", fmt.Sprintf(format, args...))
}

// Warn logs warning messages
func (l *Logger) Warn(format string, args ...interface{}) {
    warnColor.Printf("[!] %s\n", fmt.Sprintf(format, args...))
}

// Error logs error messages
func (l *Logger) Error(format string, args ...interface{}) {
    errorColor.Printf("[-] %s\n", fmt.Sprintf(format, args...))
}

// Debug logs debug messages (only if verbose)
func (l *Logger) Debug(format string, args ...interface{}) {
    if l.verbose {
        debugColor.Printf("[DEBUG] %s\n", fmt.Sprintf(format, args...))
    }
}

// Fatal logs and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
    errorColor.Printf("[FATAL] %s\n", fmt.Sprintf(format, args...))
    os.Exit(1)
}

// Banner prints the tool banner
func (l *Logger) Banner() {
    fmt.Println()
    color.New(color.FgMagenta, color.Bold).Println("╔═══════════════════════════════════════════════════════════════╗")
    color.New(color.FgMagenta, color.Bold).Println("║         VecScan - Advanced Network & Web Vulnerability Scanner   ║")
    color.New(color.FgMagenta, color.Bold).Println("║              By Vectalith Labs | Version 1.0.0                  ║")
    color.New(color.FgMagenta, color.Bold).Println("╚═══════════════════════════════════════════════════════════════╝")
    fmt.Println()
}

// PrintProgress prints scan progress
func (l *Logger) PrintProgress(port, total, open, closed, filtered int, elapsed time.Duration) {
    fmt.Printf("\r[%d/%d] Open: %d | Closed: %d | Filtered: %d | Elapsed: %s",
        port, total, open, closed, filtered, elapsed.Round(time.Second))
}

// PrintNewline prints newline after progress
func (l *Logger) PrintNewline() {
    fmt.Println()
}