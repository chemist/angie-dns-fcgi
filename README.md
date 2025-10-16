Простой fcgi + dns для валидации владения доменом в agnie вебсервере.
Суть в том что используется один fcgi + dns с приватным fcgi и публичным dns
настройка что то типа такого.
+ в dns добавить
_acme-challenge.example.com NS ${ip_address_dns}

```
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
        fastcgi_param ACME_CHALLENGE $acme_hook_challenge;
        fastcgi_param ACME_DOMAIN $acme_hook_domain;
        fastcgi_param ACME_TOKEN $acme_hook_token;
        fastcgi_param ACME_KEYAUTH $acme_hook_keyauth;

        include fastcgi.conf;
    }
}
```

компиляция:
```
go mod tidy
go build -o dns-acme-server
```

запуск:
```
[nix-shell:~/dns-fcgi]$ ./dns-acme-server --help
Usage of ./dns-acme-server:
  -dns-addrs string
    	DNS addresses to listen on (comma-separated) (default ":53")
  -fastcgi-addrs string
    	FastCGI addresses to listen on (comma-separated) (default ":9000")
       
```
