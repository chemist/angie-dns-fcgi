Простой fcgi + dns для валидации владения доменом в angie вебсервере.
Суть в том что используется один fcgi + dns с приватным fcgi и публичным dns
настройка что то типа такого.
+ в dns добавить
_acme-challenge.example.com NS ${ip_address_dns}

```

resolver 127.0.0.53 ipv6=off; 
acme_client example https://acme-v02.api.letsencrypt.org/directory
    challenge=dns;

server {

    listen 80;

    server_name *.example.com;

    acme example;

    ssl_certificate $acme_cert_example;
    ssl_certificate_key $acme_cert_key_example;

    location @acme_hook_location {

        acme_hook example;

        fastcgi_pass localhost:9000;
        fastcgi_param ACME_CLIENT $acme_hook_client;
        fastcgi_param ACME_HOOK $acme_hook_name;
        fastcgi_param ACME_DOMAIN $acme_hook_domain;
        fastcgi_param ACME_KEYAUTH $acme_hook_keyauth;
        fastcgi_param REQUEST_METHOD GET;
        fastcgi_param SERVER_PROTOCOL HTTP/1.1;
        fastcgi_param QUERY_STRING "ACME_HOOK=$acme_hook_name&ACME_DOMAIN=$acme_hook_domain&ACME_KEYAUTH=$acme_hook_keyauth";
    }
}
```

компиляция:
```
go mod tidy
CGO_ENABLED=0 go build -tags netgo -o dns-acme-server

```

запуск:
```
[nix-shell:~/dns-fcgi]$ ./dns-acme-server --help
Usage of ./dns-acme-server:
  -dns-addr string
    	DNS addresses to listen on (comma-separated) (default ":53")
  -fastcgi-addr string
    	FastCGI addresses to listen on (comma-separated) (default ":9000")
       
```
