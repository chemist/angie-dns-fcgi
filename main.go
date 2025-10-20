package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DNSRecordStorage struct {
	records map[string]string // храним в нижнем регистре
	mutex   sync.RWMutex
}

func NewDNSRecordStorage() *DNSRecordStorage {
	return &DNSRecordStorage{
		records: make(map[string]string),
	}
}

func (s *DNSRecordStorage) SetTXTRecord(domain, value string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	normalizedDomain := strings.ToLower(domain)
	s.records[normalizedDomain] = value
	log.Printf("DNS TXT record added: %s -> %s", normalizedDomain, value)
}

func (s *DNSRecordStorage) ClearTXTRecord(domain string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	normalizedDomain := strings.ToLower(domain)
	delete(s.records, normalizedDomain)
	log.Printf("DNS TXT record removed: %s", normalizedDomain)
}

func (s *DNSRecordStorage) GetTXTRecord(domain string) (string, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	normalizedDomain := strings.ToLower(domain)
	value, exists := s.records[normalizedDomain]
	return value, exists
}

// normalizeDomain нормализует доменное имя для сравнения
func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

type DNSServer struct {
	storage *DNSRecordStorage
	servers []*dns.Server
}

func NewDNSServer(storage *DNSRecordStorage) *DNSServer {
	return &DNSServer{
		storage: storage,
		servers: make([]*dns.Server, 0),
	}
}

func (ds *DNSServer) Start(addresses []string) error {
	for _, addr := range addresses {
		// UDP server
		udpServer := &dns.Server{
			Addr:         addr,
			Net:          "udp",
			Handler:      ds,
			UDPSize:      65535,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}

		go func(s *dns.Server, a string) {
			log.Printf("Starting DNS UDP server on %s", a)
			if err := s.ListenAndServe(); err != nil {
				log.Printf("DNS UDP server error on %s: %v", a, err)
			}
		}(udpServer, addr)

		// TCP server  
		tcpServer := &dns.Server{
			Addr:         addr,
			Net:          "tcp",
			Handler:      ds,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}

		go func(s *dns.Server, a string) {
			log.Printf("Starting DNS TCP server on %s", a)
			if err := s.ListenAndServe(); err != nil {
				log.Printf("DNS TCP server error on %s: %v", a, err)
			}
		}(tcpServer, addr)

		ds.servers = append(ds.servers, udpServer, tcpServer)
	}
	return nil
}

func (ds *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Compress = false
	m.RecursionAvailable = false

	for _, question := range r.Question {
		qname := question.Name
		qtype := question.Qtype

		// Нормализуем запрошенное имя для сравнения
		normalizedQname := normalizeDomain(qname)

		log.Printf("DNS Query: %s %s (normalized: %s)", dns.TypeToString[qtype], qname, normalizedQname)

		// Обрабатываем только TXT запросы
		if qtype == dns.TypeTXT {
			if value, exists := ds.storage.GetTXTRecord(qname); exists {
				txtRR := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   qname, // сохраняем оригинальный регистр в ответе
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Txt: []string{value},
				}
				m.Answer = append(m.Answer, txtRR)
				log.Printf("Returning TXT: %s = %s", qname, value)
			} else {
				log.Printf("No TXT record found for: %s", qname)
			}
		} else {
			log.Printf("Ignoring non-TXT query type: %s", dns.TypeToString[qtype])
		}
	}

	// Если нет ответов, возвращаем NOERROR с пустым ответом
	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeSuccess
		log.Printf("No TXT records found for query, returning NOERROR")
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("Failed to write DNS response: %v", err)
	}
}

func (ds *DNSServer) Stop() {
	for _, server := range ds.servers {
		if err := server.Shutdown(); err != nil {
			log.Printf("Error shutting down DNS server: %v", err)
		}
	}
}

type FastCGIHandler struct {
	storage *DNSRecordStorage
}

func (h *FastCGIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("FastCGI Request Headers: %v", r.Header)
	
	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing form: %v", err)
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	hook := r.FormValue("ACME_HOOK")
	domain := r.FormValue("ACME_DOMAIN")
	keyauth := r.FormValue("ACME_KEYAUTH")

	log.Printf("FastCGI Params: hook=%s, domain=%s, keyauth=%s", hook, domain, keyauth)

	if hook == "" || domain == "" {
		http.Error(w, "ACME_HOOK and ACME_DOMAIN are required", http.StatusBadRequest)
		return
	}

	// Создаем полное DNS имя (будет нормализовано при сохранении)
	dnsName := "_acme-challenge." + domain + "."

	switch hook {
	case "add":
		if keyauth == "" {
			http.Error(w, "ACME_KEYAUTH is required for add hook", http.StatusBadRequest)
			return
		}
		h.storage.SetTXTRecord(dnsName, keyauth)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "TXT record added: %s -> %s\n", dnsName, keyauth)
		log.Printf("TXT record added successfully")

	case "remove":
		h.storage.ClearTXTRecord(dnsName)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "TXT record removed: %s\n", dnsName)
		log.Printf("TXT record removed successfully")

	default:
		http.Error(w, "Unknown hook: "+hook, http.StatusBadRequest)
	}
}

func main() {
	fastcgiAddr := flag.String("fastcgi-addr", "127.0.0.1:9000", "FastCGI address to listen on")
	dnsAddr := flag.String("dns-addr", "0.0.0.0:53", "DNS address to listen on")
	
	flag.Parse()

	log.Printf("Starting DNS ACME Server (TXT only)")
	log.Printf("DNS Address: %s", *dnsAddr)
	log.Printf("FastCGI Address: %s", *fastcgiAddr)

	storage := NewDNSRecordStorage()

	// Запуск DNS сервера
	dnsServer := NewDNSServer(storage)
	if err := dnsServer.Start([]string{*dnsAddr}); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
	defer dnsServer.Stop()

	// Запуск FastCGI сервера
	handler := &FastCGIHandler{
		storage: storage,
	}

	go func() {
		listener, err := net.Listen("tcp", *fastcgiAddr)
		if err != nil {
			log.Fatalf("Failed to listen on %s: %v", *fastcgiAddr, err)
		}
		defer listener.Close()

		log.Printf("Starting FastCGI server on %s", *fastcgiAddr)
		if err := fcgi.Serve(listener, handler); err != nil {
			log.Fatalf("Failed to serve FastCGI: %v", err)
		}
	}()

	log.Printf("Server is running. Press Ctrl+C to stop.")
	select {} // Бесконечное ожидание
}
