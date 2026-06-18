package main

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"
)

type ScanLogger struct {
	mu   sync.Mutex
	path string
}

var globalLogger *ScanLogger

func InitLogger() {
	globalLogger = &ScanLogger{
		path: "scan_logs.txt",
	}
}

func (l *ScanLogger) Log(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] %s\n", timestamp, msg)

	// Print to console
	fmt.Print(line)

	// Append to file
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		_, _ = f.WriteString(line)
	}
}

func (l *ScanLogger) GetLastLogs(n int) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	file, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{"(Không tìm thấy file nhật ký quét)"}, nil
		}
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	start := len(lines) - n
	if start < 0 {
		start = 0
	}

	return lines[start:], nil
}

func LogEvent(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Log(format, args...)
	} else {
		fmt.Printf(format, args...)
	}
}
