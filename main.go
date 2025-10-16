package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"sync"

	"github.com/miekg/dns"
)

// DNSRecordStorage хранилище DNS записей
type DNSRecordStorage struct {
	records map[string]string
	mutex   sync.RWMutex
}

// NewDNSRecordStorage создает новое хранилище
func NewDNSRecordStorage() *DNSRecordStorage {
	return &DNSRecordStorage{
		records: make(map[string]string),
	}
}

// SetTXTRecord устанавливает TXT запись
func (s *DNSRecordStorage) SetTXTRecord(domain, value string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.records[domain] = value
	log.Printf("DNS record added: %s -> %s", domain, value)
}

// ClearTXTRecord удаляет TXT запись
func (s *DNSRecordStorage) ClearTXTRecord(domain string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.records, domain)
	log.Printf("DNS record removed: %s", domain)
}

// GetTXTRecord получает TXT запись
func (s *DNSRecordStorage) GetTXTRecord(domain string) (string, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	value, exists := s.records[domain]
	return value, exists
}

// DNSServer DNS сервер
type DNSServer struct {
	storage *DNSRecordStorage
	servers []*dns.Server
}

// NewDNSServer создает новый DNS сервер
func NewDNSServer(storage *DNSRecordStorage) *DNSServer {
	return &DNSServer{
		storage: storage,
		servers: make([]*dns.Server, 0),
	}
}

// Start запускает DNS сервер на указанных адресах
func (ds *DNSServer) Start(addresses []string) error {
	for _, addr := range addresses {
		server := &dns.Server{
			Addr:    addr,
			Net:     "udp",
			Handler: ds,
		}

		go func(s *dns.Server, a string) {
			log.Printf("Starting DNS server on %s", a)
			if err := s.ListenAndServe(); err != nil {
				log.Printf("Failed to start DNS server on %s: %v", a, err)
			}
		}(server, addr)

		ds.servers = append(ds.servers, server)
	}
	return nil
}

// ServeDNS обработчик DNS запросов
func (ds *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, question := range r.Question {
		if question.Qtype == dns.TypeTXT {
			if value, exists := ds.storage.GetTXTRecord(question.Name); exists {
				rr := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Txt: []string{value},
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	}

	w.WriteMsg(m)
}

// Stop останавливает DNS сервер
func (ds *DNSServer) Stop() {
	for _, server := range ds.servers {
		server.Shutdown()
	}
}

// FastCGIHandler обработчик FastCGI запросов
type FastCGIHandler struct {
	storage *DNSRecordStorage
}

// ServeHTTP обрабатывает HTTP/FastCGI запросы
func (h *FastCGIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Парсим форму для доступа к параметрам
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Получаем параметры из формы (передаются через окружение в FastCGI)
	client := r.FormValue("ACME_CLIENT")
	hook := r.FormValue("ACME_HOOK")
	challenge := r.FormValue("ACME_CHALLENGE")
	domain := r.FormValue("ACME_DOMAIN")
	token := r.FormValue("ACME_TOKEN")
	keyauth := r.FormValue("ACME_KEYAUTH")

	log.Printf("Received request: client=%s, hook=%s, domain=%s", client, hook, domain)

	// Обрабатываем hook
	if hook == "add" {
		dnsName := fmt.Sprintf("_acme-challenge.%s.", domain)
		h.storage.SetTXTRecord(dnsName, keyauth)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "TXT record added successfully")
	} else if hook == "remove" {
		dnsName := fmt.Sprintf("_acme-challenge.%s.", domain)
		h.storage.ClearTXTRecord(dnsName)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "TXT record removed successfully")
	} else {
		http.Error(w, "Unknown hook type", http.StatusBadRequest)
		return
	}

	// Логируем для отладки
	log.Printf("Processed: hook=%s, challenge=%s, token=%s", hook, challenge, token)
}

func main() {
	// Параметры командной строки
	fastcgiAddrs := flag.String("fastcgi-addrs", ":9000", "FastCGI addresses to listen on (comma-separated)")
	dnsAddrs := flag.String("dns-addrs", ":53", "DNS addresses to listen on (comma-separated)")
	flag.Parse()

	// Инициализация хранилища
	storage := NewDNSRecordStorage()

	// Запуск DNS сервера
	dnsServer := NewDNSServer(storage)
	dnsAddresses := parseAddresses(*dnsAddrs)
	if err := dnsServer.Start(dnsAddresses); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
	defer dnsServer.Stop()

	// Запуск FastCGI сервера
	handler := &FastCGIHandler{storage: storage}
	fastcgiAddresses := parseAddresses(*fastcgiAddrs)

	// Запускаем FastCGI сервер на каждом указанном адресе
	for _, addr := range fastcgiAddresses {
		go func(address string) {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				log.Fatalf("Failed to listen on %s: %v", address, err)
			}
			defer listener.Close()

			log.Printf("Starting FastCGI server on %s", address)
			if err := fcgi.Serve(listener, handler); err != nil {
				log.Fatalf("Failed to serve FastCGI on %s: %v", address, err)
			}
		}(addr)
	}

	// Бесконечный цикл чтобы главная горутина не завершилась
	log.Printf("Application started. DNS servers: %v, FastCGI servers: %v", dnsAddresses, fastcgiAddresses)
	select {}
}

// parseAddresses парсит строку с адресами
func parseAddresses(addrs string) []string {
	// Простая реализация - разделение по запятым
	// Можно расширить для поддержки разных форматов
	result := []string{}
	start := 0
	for i, ch := range addrs {
		if ch == ',' {
			if i > start {
				result = append(result, addrs[start:i])
			}
			start = i + 1
		}
	}
	if start < len(addrs) {
		result = append(result, addrs[start:])
	}
	
	// Если ничего не нашли, возвращаем оригинальную строку
	if len(result) == 0 {
		result = []string{addrs}
	}
	
	return result
}
