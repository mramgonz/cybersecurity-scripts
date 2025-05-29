import requests
from bs4 import BeautifulSoup
import urllib.parse
import validators
import os

def validate_url(url):
    """Verifica si la URL es válida."""
    if not validators.url(url):
        print("[!] URL no válida. Asegúrate de incluir http:// o https://")
        return False
    return True

def check_security_headers(url):
    """Escanea las cabeceras HTTP de seguridad de un sitio web."""
    headers_info = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        security_headers = {
            "Content-Security-Policy": "Protege contra ataques XSS",
            "X-Content-Type-Options": "Evita la interpretación de tipos MIME",
            "X-Frame-Options": "Previene ataques de Clickjacking",
            "Strict-Transport-Security": "Fuerza HTTPS en el sitio",
            "Referrer-Policy": "Controla la información enviada en el encabezado Referer",
            "Permissions-Policy": "Restringe APIs y funciones del navegador"
        }
        
        print(f"\n[+] Analizando cabeceras de seguridad en: {url}\n")
        for header, description in security_headers.items():
            if header in headers:
                info = f"[✔] {header}: {headers[header]}"
            else:
                info = f"[✖] {header} no está presente ({description})"
            print(info)
            headers_info.append(info)
    except requests.RequestException as e:
        error_msg = f"[!] Error al analizar {url}: {str(e)}"
        print(error_msg)
        headers_info.append(error_msg)
    
    return headers_info

def check_xss_sql(url):
    """Prueba inyecciones XSS y SQLi en un sitio web."""
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
    ]
    
    sqli_payloads = [
        "' OR '1'='1", 
        "' OR '1'='1' --", 
        "' OR '1'='1' #", 
        "' OR 'a'='a", 
        "' OR 1=1--"
    ]
    
    detected_vulnerabilities = []
    
    for payload in xss_payloads + sqli_payloads:
        test_url = f"{url}?test={urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                message = f"[!] Posible vulnerabilidad detectada con payload: {payload}"
                print(message)
                detected_vulnerabilities.append(message)
            else:
                print(f"[+] No se detectaron vulnerabilidades con {payload}")
        except requests.RequestException as e:
            error_msg = f"[!] Error al probar {url}: {str(e)}"
            print(error_msg)
            detected_vulnerabilities.append(error_msg)
    
    return detected_vulnerabilities

def save_results(url, headers_info, results):
    """Guarda los resultados en un archivo específico por URL."""
    domain = urllib.parse.urlparse(url).netloc.replace(".", "_")
    filename = f"scan_results_{domain}.txt"
    
    with open(filename, "w", encoding="utf-8") as file:
        file.write(f"Resultados del escaneo para {url}\n\n")
        file.write("Cabeceras de seguridad:\n")
        file.write("\n".join(headers_info) + "\n\n")
        file.write("Pruebas de inyección XSS y SQLi:\n")
        file.write("\n".join(results))
        print(f"\n[+] Resultados guardados en {filename}")

if __name__ == "__main__":
    target_url = input("Ingresa la URL a escanear: ").strip()
    
    if validate_url(target_url):
        results = []
        headers_info = check_security_headers(target_url)
        results.extend(check_xss_sql(target_url))
        save_results(target_url, headers_info, results)