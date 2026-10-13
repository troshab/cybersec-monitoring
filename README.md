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
- ✅ 6 місяців зберігання логів - рекомендація (не вимога CERT-UA; строк узгодьте з політикою організації)
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

## Версії компонентів

Версії перевірено 2026-10-13 за датами релізів GitHub (`published_at`) і за пінами в репозиторії.

| Компонент | Версія | Дата релізу | Джерело піна |
|-----------|--------|-------------|--------------|
| Prometheus | v3.15.0 | 2026-09-25 | `server/monitoring-stack/docker-compose.yml` |
| Loki | 3.7.8 | 2026-09-17 | `server/monitoring-stack/docker-compose.yml` |
| Grafana | 13.2.3 | 2026-09-29 | `server/monitoring-stack/docker-compose.yml` |
| Alertmanager | v0.34.1 | 2026-09-17 | `server/monitoring-stack/docker-compose.yml` |
| Mailpit | v1.31.5 | 2026-10-11 | `server/monitoring-stack/docker-compose.yml` |
| FleetDM | v4.93.0 | 2026-10-08 | `server/inventory-stack/docker-compose.yml` |
| Netdisco | 2.111000 | 2026-10-09 | `server/inventory-stack/docker-compose.yml` |
| MySQL (БД Fleet) | 8.4 | не перевірено (образ mysql:8.4) | `server/inventory-stack/docker-compose.yml` |
| Redis | 7.4-alpine | не перевірено (образ redis:7.4-alpine) | `server/inventory-stack/docker-compose.yml` |
| Node Exporter | 1.12.1 | 2026-07-14 | `linux-agent/install-agent.sh` |
| osquery (Linux) | 5.23.1 | 2026-06-24 | `linux-agent/install-agent.sh` |
| Grafana Alloy | v1.20.1 (актуальна на перевірку, не запінена) | 2026-09-28 | встановлюється з репозиторію Grafana |
| Windows Exporter | v0.31.9 | 2026-10-10 | host-agent піни |
| restic | 0.19.1 | 2026-07-05 | `posture/backup/*` (вимога в заголовках) |
| UAC (IR, Linux) | 2.9.1 (піна в репо; актуальна v3.4.0, 2026-09-09) | - | `incident-response/linux/install-uac.sh` |
| Sysmon (Windows) | не запінено, ставиться з Sysinternals | - | `windows-common/03-Install-Sysmon.ps1` |

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

## Posture-шар (CIS IG1)

Posture-шар перевіряє базову лінію CIS Controls v8.1 IG1 (56 завдань). Картки і маппінг на CIS IG1 - у `posture/osquery/ig1-posture.yml` (заголовки містять ID картки і CIS ID).

- **Drift-перевірки пристроїв (Fleet/osquery).** Пакет застосовується командою `fleetctl apply -f posture/osquery/ig1-posture.yml`. Запити названо `ig1_<ID картки>_<платформа>`, наприклад `ig1_BK-02_windows`. Запити, які не покриті цим пакетом (NET-01, LOG-01, LOG-03, BK-01, BK-03, BK-04, AS-02, DA-04), перелічено в коментарі на початку файлу з причиною.
- **Алерти (Prometheus).** `server/monitoring-stack/prometheus/alerts/posture-alerts.yml` підхоплюється через `rule_files` (`/etc/prometheus/alerts/*.yml`). Правила `BackupTooOld` (BK-02, CIS 11.2, більше 48 годин) і `RestoreTestOverdue` (BK-01, CIS 11.1, більше 90 днів).
- **Дашборд Grafana.** `IG1 Posture` (`grafana/dashboards/08-ig1-posture.json`) завантажується через provisioning.
- **Резервні копії (restic).** Встановіть restic 0.19.1. Задайте `RESTIC_REPOSITORY` і `RESTIC_PASSWORD_FILE` з файлом пароля поза репозиторієм: Linux - `0600`, власник root; Windows - файл з обмеженим ACL. Скрипти `posture/backup/linux/backup.sh` і `posture/backup/windows/backup.ps1` записують метрику `backup_last_success_timestamp_seconds`; `restore-test.sh` і `restore-test.ps1` записують `backup_last_restore_test_timestamp_seconds`. Textfile для Windows: `C:\Program Files\windows_exporter\textfile_inputs` (параметр `-TextfileDir`), для Linux: `/var/lib/node_exporter/textfile`. Запускайте backup і restore-test за розкладом.

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
| 08-ig1-posture | Стан CIS IG1: вік резервних копій, перевірка відновлення, алерти posture |

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

## Безпека

- **Скомпрометовано: ключ Fleet і паролі лабораторії.** Раніше в git були закомічені ключ Fleet і паролі лабораторного середовища (`Mon!123admin`, `kali/kali`). Розглядайте їх як скомпрометовані: ротуйте ключ Fleet, JWT-ключі й усі паролі перед будь-яким використанням поза лабораторією. Історія git зберігає їх; для повного усунення потрібно переписати історію або створити новий репозиторій.
- **Секрети.** `.env` не відстежується, шаблон - `.env.example`; значення генеруються `server/gen-env.sh`. Порти моніторингу прив'язані до loopback. `--web.enable-admin-api` вимкнено.
- **Retention Loki 6 місяців.** Це рекомендація, не вимога CERT-UA.
- **Резервні копії.** Пароль restic тримайте поза репозиторієм (див. розділ Posture-шар).

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
