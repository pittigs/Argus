package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/pittigs/argus/internal/adserver"
)

func main() {
	var (
		ldapPort  = flag.Int("port", 10389, "Standard LDAP listen port")
		ldapsPort = flag.Int("tls-port", 10636, "Secure LDAPS (TLS) listen port")
		domain    = flag.String("domain", "corp.local", "Active Directory domain name")
		baseDN    = flag.String("base-dn", "DC=corp,DC=local", "Active Directory Base DN")
		adminPass = flag.String("admin-password", "admin123", "Administrator account password")
	)
	flag.Parse()

	fmt.Println(`
   ___   _____   _____                           
  / _ \ |  _  \ /  ___|                          
 / /_\ \| | | | \ '--.  ___ _ ____   _____ _ __  
 |  _  || | | |  '--. \/ _ \ '__\ \ / / _ \ '__| 
 | | | || |/ /  /\__/ /  __/ |   \ V /  __/ |    
 \_| |_/|___/   \____/ \___|_|    \_/ \___|_|    
 Active Directory & Samba-AD Domain Controller
	`)

	log.Printf("[AD Server] Initialisiere Active Directory Instanz für Domäne '%s'...", *domain)
	server, err := adserver.NewADServer(*domain, *baseDN, *adminPass)
	if err != nil {
		log.Fatalf("[AD Server] Fehler beim Erstellen der AD-Instanz: %v", err)
	}

	ldapAddr := fmt.Sprintf("127.0.0.1:%d", *ldapPort)
	ldapsAddr := fmt.Sprintf("127.0.0.1:%d", *ldapsPort)

	if err := server.Start(ldapAddr, ldapsAddr); err != nil {
		log.Fatalf("[AD Server] Fehler beim Starten des Listeners: %v", err)
	}

	log.Printf("[AD Server] Bereit für Anfragen:")
	log.Printf("[AD Server]   - LDAP URL:  ldap://127.0.0.1:%d", *ldapPort)
	log.Printf("[AD Server]   - LDAPS URL: ldaps://127.0.0.1:%d", *ldapsPort)
	log.Printf("[AD Server]   - Base DN:   %s", *baseDN)
	log.Printf("[AD Server]   - Bind DN:   CN=Administrator,CN=Users,%s", *baseDN)
	log.Printf("[AD Server]   - Kennwort:  %s", *adminPass)

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	<-stopChan
	log.Println("[AD Server] Server wird heruntergefahren...")
	server.Stop()
	log.Println("[AD Server] Beendet.")
}
