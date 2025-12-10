📘 README – Recon Automation Workflow
🔧 Installation

Bu layihənin işləməsi üçün bütün recon alətlərini avtomatik quraşdıran skripti istifadə edin:

chmod +x install_recon_tools.sh
./install_recon_tools.sh


Bu installer aşağıdakı alətləri quraşdırır:
subfinder, httpx, katana, gospider, waybackurls, LinkFinder, SecretFinder, ParamSpider, ffuf, nuclei, shodan, censys, VirusTotal API dəstəyi və s.


🇦🇿 Recon Automation Workflow

Bu skript domen haqqında maksimal məlumatı toplamaq üçün geniş alətləri birləşdirir.
Məqsəd — subdomain tapmaq, hostları yoxlamaq, URL-ləri toplamaq, JS fayllarını analiz etmək, gizli açarları aşkar etmək, zəiflikləri skan etmək və OSINT məlumatı çıxarmaqdır.

🚀 İnteqrasiya olunan alətlər

Subdomain kəşfiyyatı: subfinder, CIRT.sh

Host yoxlaması: httpx (status, redirect, content-length, fingerprint)

Crawling: katana, gospider

Tarixi URL toplama: waybackurls

JS analizi: LinkFinder, SecretFinder

Zəiflik skanları: nuclei (background), ParamSpider

Fuzzing: ffuf

Kəşfiyyat (OSINT): Shodan, SecurityTrails, Censys, VirusTotal

🔎 Skript nə edir?

Subdomain tapır → filtrləyir

Canlı hostları müəyyən edir

Katana + Gospider + Wayback ilə URL-ləri toplayır

JS fayllarını recursive analiz edir

JS endpointlər + API yolları + sızmış açarları çıxarır

Nuclei ilə zəiflik skanı işə salır (background)

ParamSpider ilə parametrləri tapır

Shodan / Censys / VirusTotal / SecurityTrails ilə OSINT məlumatı çıxarır

Docker & Kubernetes yanlış konfiqurasiyalarını yoxlayır

Səs-küyü (false-positive) azaltmaq üçün content-length + fingerprint filtrasiyası tətbiq edir



🇬🇧 Recon Automation Workflow 

This script combines a full suite of reconnaissance tools into one automated pipeline.
It discovers subdomains, probes live hosts, crawls URLs, analyzes JavaScript, detects secrets, runs vulnerability scans, performs fuzzing, and gathers OSINT.

🚀 Integrated tools

Discovery: subfinder, CIRT.sh

Probing: httpx (status, redirects, content-length, fingerprints)

Crawling: katana, gospider

Historical URLs: waybackurls

JS analysis: LinkFinder, SecretFinder

Scanning: nuclei (background mode), ParamSpider

Fuzzing: ffuf

OSINT: Shodan, SecurityTrails, Censys, VirusTotal

🔎 Workflow highlights

Enumerates and filters subdomains

Detects live hosts with detailed metadata

Collects and cleans URLs

Extracts JS routes, APIs, sensitive endpoints

Detects leaked secrets/tokens

Performs vulnerability scanning automatically

Gathers external intelligence

Reduces false positives using response fingerprinting



🇷🇺 Recon Automation Workflow

Этот скрипт объединяет множество инструментов разведки в один автоматизированный процесс.
Он собирает субдомены, проверяет хосты, краулит URL-адреса, анализирует JS, ищет секреты, выполняет сканирование уязвимостей и OSINT.

🚀 Интегрированные инструменты

Поиск субдоменов: subfinder, CIRT.sh

Проверка хостов: httpx

Краулинг: katana, gospider

Исторические URL: waybackurls

JS анализ: LinkFinder, SecretFinder

Сканирование: nuclei, ParamSpider

Фаззинг: ffuf

Разведка: Shodan, SecurityTrails, Censys, VirusTotal

🔎 Что делает workflow?

Ищет и фильтрует субдомены

Определяет живые хосты

Собирает и обрабатывает URL-адреса

Извлекает JS-эндпоинты и секреты

Запускает сканер уязвимостей

Собирает OSINT-данные

Использует контент-фингерпринты для снижения ложных срабатываний





üçün birbaşa istifadə edilə bilsin.
