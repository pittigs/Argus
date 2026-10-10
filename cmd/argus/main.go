package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pittigs/argus/internal/audit"
	"github.com/pittigs/argus/internal/auth"
	"github.com/pittigs/argus/internal/db"
	"github.com/pittigs/argus/internal/directory"
	"github.com/pittigs/argus/internal/handler"
	"github.com/pittigs/argus/internal/lifecycle"
	"github.com/pittigs/argus/internal/service"
	"github.com/pittigs/argus/web"
)

func main() {
	var (
		port   = flag.Int("port", 8080, "HTTP server listening port")
		dbPath = flag.String("db", "./data/argus.db", "Path to SQLite database file")
	)
	flag.Parse()

	if envPort := os.Getenv("PORT"); envPort != "" {
		fmt.Sscanf(envPort, "%d", port)
	}
	if envDB := os.Getenv("ARGUS_DB"); envDB != "" {
		*dbPath = envDB
	}

	fmt.Println(`
   ___   ___  ____ _   _ ____  
  / _ \ | _ \/ ___| | | / ___| 
 / /_\ \|   / |  _| | | \___ \ 
 |  _  || |\ \ |_| | |_| |___) |
 |_| |_||_| \_\____|\___/|____/  
 Enterprise IAM & Tamper-Evident Audit Matrix
	`)

	log.Printf("[Argus] Initialisiere Datenbank unter %s (WAL-Modus)...", *dbPath)
	database, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("[Argus] Fehler beim Öffnen der Datenbank: %v", err)
	}
	defer database.Close()
	log.Printf("[Argus] Datenbank erfolgreich migriert und Baseline geladen.")

	auditSvc := audit.NewService(database)
	authSvc := auth.NewService(database)
	mgmtSvc := service.NewManagementService(database, auditSvc)

	dirMgr, err := directory.NewManager(database, auditSvc)
	if err != nil {
		log.Fatalf("[Argus] Fehler beim Initialisieren des Directory Managers: %v", err)
	}
	log.Printf("[Argus] Active Directory & Samba-AD Modul aktiv (Demo/Mock & LDAPS Connector bereit).")

	jitStopChan := make(chan struct{})
	dirMgr.StartJITWorker(30*time.Second, jitStopChan)
	lifecycleSvc := lifecycle.NewService(database, auditSvc, dirMgr, mgmtSvc)
	log.Printf("[Argus] HR & User Lifecycle Automatisierungsmodul initialisiert.")

	staticFS := web.GetStaticFS()
	server := handler.NewServer(authSvc, mgmtSvc, auditSvc, dirMgr, lifecycleSvc, staticFS)

	addr := fmt.Sprintf(":%d", *port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      server.Routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown channel
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[Argus] Web Dashboard & REST-API erreichbar unter: http://localhost:%d", *port)
		log.Printf("[Argus] Standard-Zugangsdaten:")
		log.Printf("[Argus]   - SuperAdmin: admin / admin123")
		log.Printf("[Argus]   - Auditor:    auditor / auditor123")
		log.Printf("[Argus]   - User-Mgr:   sarah.connor / sarah123")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Argus] Server-Fehler: %v", err)
		}
	}()

	<-stopChan
	log.Println("[Argus] Server wird ordnungsgemäß heruntergefahren...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("[Argus] Fehler beim Shutdown: %v", err)
	}
	close(jitStopChan)
	log.Println("[Argus] Beendet.")
}
