package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	mode := flag.String("mode", "api", "run mode: api or worker")
	flag.Parse()

	switch *mode {
	case "api":
		if err := runAPI(); err != nil {
			log.Fatalf("api stopped: %v", err)
		}
	case "worker":
		if err := runWorker(); err != nil {
			log.Fatalf("worker stopped: %v", err)
		}
	default:
		log.Fatalf("invalid mode %q (expected: api|worker)", *mode)
	}
}

func runWorker() error {
	log.Println("worker started (placeholder)")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			log.Println("worker heartbeat")
		case sig := <-sigCh:
			log.Printf("worker received signal: %s", sig)
			return nil
		}
	}
}
