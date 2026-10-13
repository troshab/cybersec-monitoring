# Система моніторингу кібербезпеки для малих організацій

Повний набір скриптів та конфігурацій для автоматичного розгортання системи моніторингу кібербезпеки на базі Grafana Stack (Prometheus 3.x, Loki 3.x, Grafana 12, Alertmanager) та інструментів інвентаризації (Netdisco, FleetDM).

**Stack 2025**: Prometheus 3.0.1, Loki 3.3.2, Grafana 12.3.0, Grafana Alloy 1.x

## Філософія

> **Логи та моніторинг, за якими ніхто не слідкує — гірше за їх відсутність.**
> Вони створюють хибне відчуття безпеки.
> Краще мати 5 алертів що працюють, ніж 500 що ігноруються.

### Ключові принципи

- ✅ Все безкоштовне ПЗ
- ✅ 20% зусиль для 80% захисту
- ✅ Виявлення важливіше за запобігання
- ✅ 6 місяців зберігання логів (вимога CERT-UA)
- ✅ Мінімум false positives

## Архітектура

```
┌─────────────────────────────────────────────────────────────────────┐
│                        СЕРВЕР МОНІТОРИНГУ                          │
│                         (Debian 12+)                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Docker Containers                         │   │
│  │  ┌───────────┐ ┌──────┐ ┌─────────┐ ┌──────────────────┐   │   │
│  │  │ Prometheus│ │ Loki │ │ Grafana │ │  Alertmanager    │   │   │
│  │  │  :9090    │ │:3100 │ │ :3000   │ │     :9093        │   │   │
│  │  └───────────┘ └──────┘ └─────────┘ └──────────────────┘   │   │
│  │                                                              │   │
│  │  ┌───────────┐ ┌──────────┐                                 │   │
│  │  │ Netdisco  │ │ FleetDM  │                                 │   │
│  │  │  :5000    │ │  :8080   │                                 │   │
│  │  └───────────┘ └──────────┘                                 │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────┐                                           │
│  │ Alloy (native)      │ ← Syslog UDP:514                          │
│  │ + Node Exporter     │                                           │
│  └─────────────────────┘                                           │
└─────────────────────────────────────────────────────────────────────┘
           ▲                    ▲                    ▲
           │                    │                    │
    ┌──────┴──────┐     ┌──────┴──────┐     ┌──────┴──────┐
    │ Win11 Pro   │     │ Win Server  │     │ Linux       │
    │             │     │ 2025        │     │ Servers     │
    │ - Alloy     │     │ - Alloy     │     │ - Alloy     │
    │ - WinExport │     │ - WinExport │     │ - NodeExport│
    │ - Sysmon    │     │ - Sysmon    │     │             │
    │ - Osquery   │     │ - Osquery   │     │             │
    └─────────────┘     └─────────────┘     └─────────────┘
```

## Компоненти

| Компонент | Призначення | Розгортання |
|-----------|-------------|-------------|
| Prometheus | Збір метрик | Docker |
| Loki | Зберігання логів | Docker |
| Grafana | Візуалізація + алерти | Docker |
| Alertmanager | Маршрутизація сповіщень | Docker |
| Netdisco | Інвентаризація мережі | Docker |
| FleetDM | Інвентаризація endpoints | Docker |
| Grafana Alloy | Агент збору логів | Native |
| Node Exporter | Метрики Linux | Native |
| Windows Exporter | Метрики Windows | Native |
| Sysmon | Детальний моніторинг Windows | Native |

## Системні вимоги

### Сервер моніторингу

| Параметр | Мінімум | Рекомендовано |
|----------|---------|---------------|
| OS | Debian 12+ | Debian 13 |
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 200 GB SSD | 500 GB SSD |
| Network | 100 Mbps | 1 Gbps |

**Формула розрахунку диску:**
```
Disk = (Endpoints × 100MB/day × 180 days × 1.5) + 50GB
```

### Приклади:
- 10 комп'ютерів: ~320 GB
- 50 комп'ютерів: ~1.4 TB
- 100 комп'ютерів: ~2.8 TB

## Швидкий старт

### 1. Підготовка сервера

```bash
# Клонування репозиторію
git clone https://github.com/your-org/cybersec-monitoring.git
cd cybersec-monitoring

# Копіювання та налаштування конфігурації
# .env вже налаштовано для lab environment
nano .env  # Змініть всі паролі!
```

### 2. Запуск серверної частини

```bash
# Запуск головного скрипта встановлення
sudo ./server/01-install.sh
```

### 3. Розгортання на Windows клієнтах

```powershell
# Запуск від адміністратора на Windows 11 (10.0.1.4)
.\windows-11-client\Deploy-Client.ps1 -LokiUrl "http://10.0.1.2:3100"
```

### 4. Розгортання на Windows серверах

```powershell
# Запуск від адміністратора на Windows Server 2025 (10.0.1.3)
.\windows-server-2025\Deploy-Server.ps1 -LokiUrl "http://10.0.1.2:3100"
```

### 5. Харденінг систем (опціонально)

Центральні скрипти харденінгу застосовують базові налаштування безпеки:

```powershell
# Windows 11 клієнт
.\windows-11-client\00-Harden-Client.ps1

# Windows Server 2025 (автоматично визначає ролі: DC, DHCP, DNS, NPS)
.\windows-server-2025\00-Harden-Server.ps1

# Linux
sudo ./linux-agent/00-Harden-Linux.sh
```

**Що включено:**
- Windows: SMB hardening, LLMNR/NetBIOS disable, Pass-the-Hash protection, ASR rules, TLS 1.2/1.3
- Linux: sysctl security, SSH hardening, ufw firewall, auditd rules

### 6. Перевірка роботи

1. Відкрийте Grafana: `http://10.0.1.2:3000`
2. Логін: monadmin / (пароль GRAFANA_ADMIN_PASSWORD з .env)
3. Перевірте дашборд "Security Overview"

> **Примітка щодо FleetDM:** Для lab environment використовуються self-signed сертифікати. 
> При встановленні osquery агентів використовуйте прапорець `-Insecure`:
> ```powershell
> .\Deploy-Client.ps1 -LokiUrl "http://10.0.1.2:3100" -FleetUrl "https://10.0.1.2:8080" -FleetEnrollSecret "..." -Insecure
> ```

## Структура проєкту

```
cybersec-monitoring/
├── .env                      # Конфігурація середовища
├── README.md                 # Документація
├── LICENSE                   # Ліцензія MIT
│
├── server/                   # Серверна частина
│   ├── 01-install.sh         # Головний скрипт встановлення
│   ├── monitoring-stack/     # Grafana, Prometheus, Loki
│   ├── inventory-stack/      # Netdisco, FleetDM
│   └── alloy/                # Grafana Alloy config (server)
│
├── windows-common/           # Спільні скрипти Windows
│   ├── 01-Set-AuditPolicy.ps1
│   ├── 02-Enable-PowerShellLogging.ps1
│   ├── 03-Install-Sysmon.ps1
│   ├── 04-Install-Alloy.ps1      # Grafana Alloy (замінює Promtail)
│   ├── 05-Install-WindowsExporter.ps1
│   └── 06-Install-OsqueryAgent.ps1
│
├── windows-11-client/        # Для робочих станцій
│   ├── 00-Harden-Client.ps1  # Центральний скрипт харденінгу
│   ├── Deploy-Client.ps1
│   └── config.alloy          # Alloy config для клієнтів
│
├── windows-server-2025/      # Для серверів
│   ├── 00-Harden-Server.ps1  # Центральний скрипт харденінгу
│   ├── Deploy-Server.ps1
│   └── config.alloy          # Alloy config для серверів
│
├── linux-agent/              # Для Linux систем
│   ├── 00-Harden-Linux.sh    # Центральний скрипт харденінгу
│   ├── install-agent.sh
│   └── config.alloy          # Alloy config для Linux
│
└── testing/                  # Тести для перевірки моніторингу
    └── detection-testing/    # Об'єднані скрипти по категоріях
        ├── windows/          # 6 PowerShell тестів
        └── kali/             # 7 Bash тестів
```

## Дашборди

| Дашборд | Призначення |
|---------|-------------|
| 00-security-overview | Загальний огляд безпеки |
| 01-windows-security | Windows Security Events + PowerShell + Scheduled Tasks |
| 02-linux-security | Linux Security |
| 03-network-overview | Мережа + Lateral Movement (SMB/RDP/WinRM) |
| 04-authentication | Логіни, RDP |
| 05-alerts-summary | Активні алерти |
| 06-inventory-status | Інвентаризація хостів |
| 07-morning-coffee | Щоденний огляд безпеки (15 хв) |

## Критичні Event IDs

### Найважливіші для виявлення атак:

| Event ID | Опис | Критичність |
|----------|------|-------------|
| 1102 | Журнал аудиту очищено | 🔴 Critical |
| 4624 | Успішний вхід | 🟡 Medium |
| 4625 | Невдалий вхід | 🟠 High |
| 4672 | Вхід з привілеями адміна | 🟠 High |
| 4720 | Створено користувача | 🔴 Critical |
| 4732 | Додано до локальної групи | 🔴 Critical |
| 4697 | Встановлено сервіс | 🔴 Critical |
| 4698 | Створено scheduled task | 🔴 Critical |
| 7045 | Новий сервіс (System log) | 🔴 Critical |

## Тестування

Тестові скрипти згруповані по категоріях в `testing/detection-testing/`.

### Windows тести (PowerShell)

```powershell
# Перейти в папку тестів
cd testing\detection-testing\windows

# Запуск тестів аутентифікації
.\01-Test-Authentication.ps1

# Доступні тести:
# 01-Test-Authentication.ps1  - Failed logins, privilege escalation
# 02-Test-UserManagement.ps1  - User/group creation, admin access
# 03-Test-Persistence.ps1     - Services, scheduled tasks
# 04-Test-DefenseEvasion.ps1  - Log clearing, policy changes
# 05-Test-ProcessExecution.ps1 - Suspicious process creation
# 06-Test-LateralMovement.ps1 - SMB, RDP, WinRM connections
```

### Kali тести (Bash)

```bash
cd testing/detection-testing/kali

# Запуск тестів сканування
./01-test-scanning.sh

# Доступні тести:
# 01-test-scanning.sh      - Port/network scanning
# 02-test-bruteforce.sh    - Password attacks
# 03-test-webattacks.sh    - SQL injection, XSS
# 04-test-exploitation.sh  - Metasploit framework
# 05-test-postexploit.sh   - Post-exploitation
# 06-test-exfiltration.sh  - Data exfiltration
# 07-test-persistence.sh   - Backdoors, C2
```

## Lab Environment

| Host | IP | OS | Credentials |
|------|----|----|-------------|
| Monitoring Server | 10.0.1.2 | Debian 13 | monadmin / Mon!123admin |
| Domain Controller | 10.0.1.3 | Windows Server 2025 | LAB\monadmin / Mon!123admin |
| Windows Client | 10.0.1.4 | Windows 11 | LAB\pc / Mon!123admin |
| Kali Linux | 10.0.1.5 | Kali 2024.x | kali / kali |

**Domain:** LAB (lab.local)

## Ліцензія

MIT License - див. файл [LICENSE](LICENSE)
