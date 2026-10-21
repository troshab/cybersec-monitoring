# Система моніторингу кібербезпеки для малих організацій

Повний набір скриптів та конфігурацій для автоматичного розгортання системи моніторингу кібербезпеки на базі Grafana Stack (Prometheus, Loki, Grafana, Grafana Alloy, Alertmanager, SNMP Exporter) та інструментів інвентаризації (Netdisco, FleetDM). Точні версії - у таблиці "Версії компонентів" нижче.

Репозиторій - технічна частина програми [«Базовий профіль кібербезпеки організації»](https://bcp.troshab.dev/) (Факультет інформатики НаУКМА). Організаційні завдання й картки-інструкції, на які посилаються запити posture-шару (`AC-07`, `BK-02` тощо), - у [базі знань](https://bcp.troshab.dev/docs/); уроки IT-маршруту, що пояснюють цей репозиторій, - у [курсі](https://bcp.troshab.dev/docs/course/).

## Спробувати за кілька хвилин: демо-стенд

Щоб побачити все в роботі без серверів і робочих станцій, запустіть демо-стенд на своєму комп'ютері з Docker:

```bash
git clone https://github.com/troshab/cybersec-monitoring.git
cd cybersec-monitoring/demo
./up.sh
```

Стенд використовує ті самі образи, дашборди й правила сповіщень, що й робоче розгортання, а журнали Windows і Linux генерує в точному форматі агентів Alloy, з регулярними «хвилями атак». Покроковий огляд з посиланнями на уроки й картки - у [demo/README.md](demo/README.md).

## Як репозиторій пов'язаний з програмою

Кожна тека закриває конкретні завдання базового профілю. Уроки пояснюють, як це розгорнути, картки - навіщо і як перевірити результат.

| Тека | Що там | Уроки | Картки |
|---|---|---|---|
| `demo/` | демо-стенд: усе ядро моніторингу із синтетичними даними на вашому комп'ютері | [IT 2.5](https://bcp.troshab.dev/docs/course/it/2-05), [IT 2.16](https://bcp.troshab.dev/docs/course/it/2-16) | [LOG-02](https://bcp.troshab.dev/docs/baseline/module/log-02) |
| `server/monitoring-stack/` | сервер моніторингу: Prometheus, Loki, Grafana, Alertmanager, дашборди й правила сповіщень | [IT 2.1](https://bcp.troshab.dev/docs/course/it/2-01), [IT 2.2](https://bcp.troshab.dev/docs/course/it/2-02), [IT 2.3](https://bcp.troshab.dev/docs/course/it/2-03), [IT 2.4](https://bcp.troshab.dev/docs/course/it/2-04), [IT 2.5](https://bcp.troshab.dev/docs/course/it/2-05), [IT 2.15](https://bcp.troshab.dev/docs/course/it/2-15) | [LOG-01](https://bcp.troshab.dev/docs/baseline/module/log-01), [LOG-02](https://bcp.troshab.dev/docs/baseline/module/log-02), [LOG-03](https://bcp.troshab.dev/docs/baseline/module/log-03) |
| `server/inventory-stack/` | інвентаризація: Netdisco для мережі, Fleet для пристроїв | [IT 1.2](https://bcp.troshab.dev/docs/course/it/1-02), [IT 1.4](https://bcp.troshab.dev/docs/course/it/1-04) | [AS-01](https://bcp.troshab.dev/docs/baseline/module/as-01), [AS-02](https://bcp.troshab.dev/docs/baseline/module/as-02), [AS-03](https://bcp.troshab.dev/docs/baseline/module/as-03) |
| `windows-common/`, `windows-11-client/`, `windows-server-2025/` | аудит, Sysmon, Alloy, посилення налаштувань Windows | [IT 2.6](https://bcp.troshab.dev/docs/course/it/2-06), [IT 2.7](https://bcp.troshab.dev/docs/course/it/2-07), [IT 2.8](https://bcp.troshab.dev/docs/course/it/2-08), [IT 2.9](https://bcp.troshab.dev/docs/course/it/2-09), [IT 2.14](https://bcp.troshab.dev/docs/course/it/2-14) | [LOG-02](https://bcp.troshab.dev/docs/baseline/module/log-02), [CF-01](https://bcp.troshab.dev/docs/baseline/module/cf-01), [CF-05](https://bcp.troshab.dev/docs/baseline/module/cf-05) |
| `linux-agent/` | агенти й посилення налаштувань Linux | [IT 2.10](https://bcp.troshab.dev/docs/course/it/2-10) | [LOG-02](https://bcp.troshab.dev/docs/baseline/module/log-02), [CF-04](https://bcp.troshab.dev/docs/baseline/module/cf-04) |
| `posture/osquery/` | перевірки базової лінії на пристроях (пакет запитів Fleet) | [IT 2.19](https://bcp.troshab.dev/docs/course/it/2-19) | [AS-03](https://bcp.troshab.dev/docs/baseline/module/as-03), [CF-05](https://bcp.troshab.dev/docs/baseline/module/cf-05), [MW-01](https://bcp.troshab.dev/docs/baseline/module/mw-01) |
| `posture/backup/` | резервні копії restic, перевірка відновлення, метрики віку копій | [IT 3.3](https://bcp.troshab.dev/docs/course/it/3-03), [IT 2.19](https://bcp.troshab.dev/docs/course/it/2-19) | [BK-01](https://bcp.troshab.dev/docs/baseline/module/bk-01), [BK-02](https://bcp.troshab.dev/docs/baseline/module/bk-02), [BK-03](https://bcp.troshab.dev/docs/baseline/module/bk-03) |
| `incident-response/` | збір артефактів під час інциденту: KAPE (Windows), UAC (Linux) | [IT 3.1](https://bcp.troshab.dev/docs/course/it/3-01), [IT 3.2](https://bcp.troshab.dev/docs/course/it/3-02) | [IR-03](https://bcp.troshab.dev/docs/baseline/module/ir-03) |
| `testing/detection-testing/` | тести, що перевіряють ланцюжок від події до сповіщення | [IT 2.18](https://bcp.troshab.dev/docs/course/it/2-18) | [LOG-02](https://bcp.troshab.dev/docs/baseline/module/log-02) |
| `testing/query-check/` | перевірка, що запити дашбордів і правил збігаються з форматом реальних журналів | [IT 2.18](https://bcp.troshab.dev/docs/course/it/2-18) | [LOG-02](https://bcp.troshab.dev/docs/baseline/module/log-02) |

## Філософія

> **Логи та моніторинг, за якими ніхто не стежить, гірші за їх відсутність.**
> Вони створюють хибне відчуття безпеки.
> Краще мати 5 алертів, що працюють, ніж 500, які ігнорують.

### Ключові принципи

- Все безкоштовне ПЗ
- Спершу найвпливовіші заходи, без надмірної складності
- Виявлення важливіше за запобігання
- 6 місяців зберігання логів - рекомендація (не вимога CERT-UA; строк узгодьте з політикою організації)
- Мінімум false positives

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
| SNMP Exporter | v0.30.1 | 2026-01-07 | `server/monitoring-stack/docker-compose.yml` (job `snmp-network` у `prometheus.yml`) |
| Mailpit | v1.31.5 | 2026-10-11 | `server/monitoring-stack/docker-compose.yml` |
| FleetDM | v4.93.0 | 2026-10-08 | `server/inventory-stack/docker-compose.yml` |
| Netdisco | 2.111000 | 2026-10-09 | `server/inventory-stack/docker-compose.yml` |
| MySQL (БД Fleet) | 8.4 | не перевірено (образ mysql:8.4) | `server/inventory-stack/docker-compose.yml` |
| Redis | 7.4-alpine | не перевірено (образ redis:7.4-alpine) | `server/inventory-stack/docker-compose.yml` |
| Node Exporter | 1.12.1 | 2026-07-14 | `linux-agent/install-agent.sh` |
| osquery (Linux) | 5.23.1 | 2026-06-24 | `linux-agent/install-agent.sh` |
| Grafana Alloy | v1.20.1 (не запінено, ставиться актуальна) | 2026-09-28 | встановлюється з репозиторію Grafana |
| Windows Exporter | v0.31.9 | 2026-10-10 | `windows-common/05-Install-WindowsExporter.ps1` |
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
git clone https://github.com/troshab/cybersec-monitoring.git
cd cybersec-monitoring

# Створити .env з випадковими паролями й ключами (наявний .env не перезаписується)
./server/gen-env.sh

# Вписати свої значення: адресу сервера, ім'я організації, Pushover, SNMP community
nano .env
```

### 2. Запуск серверної частини

```bash
sudo ./server/01-install.sh
```

### 3. Розгортання на Windows клієнтах

У прикладах `192.0.2.10` - адреса сервера моніторингу; підставте свою.

```powershell
# Від імені адміністратора на робочій станції Windows 11
.\windows-11-client\Deploy-Client.ps1 -LokiUrl "http://192.0.2.10:3100"
```

### 4. Розгортання на Windows серверах

```powershell
# Від імені адміністратора на Windows Server 2025
.\windows-server-2025\Deploy-Server.ps1 -LokiUrl "http://192.0.2.10:3100"
```

### 5. Харденінг систем (необов'язково)

Центральні скрипти харденінгу застосовують базові налаштування безпеки:

```powershell
# Windows 11 клієнт
.\windows-11-client\00-Harden-Client.ps1

# Windows Server 2025 (автоматично визначає ролі: DC, DHCP, DNS, NPS)
.\windows-server-2025\00-Harden-Server.ps1

# Linux
sudo ./linux-agent/00-Harden-Linux.sh
```

**Що входить:**
- Windows: захист SMB, вимкнення LLMNR/NetBIOS, захист від Pass-the-Hash, правила ASR, TLS 1.2/1.3
- Linux: параметри безпеки sysctl, захист SSH, фаєрвол ufw, правила auditd

### 6. Перевірка роботи

1. Відкрийте Grafana: `http://192.0.2.10:3000`
2. Логін: значення `GRAFANA_ADMIN_USER` і `GRAFANA_ADMIN_PASSWORD` з `.env`
3. Перевірте дашборд "Security Overview"

> **FleetDM і самопідписаний сертифікат.** Якщо сервер використовує самопідписаний сертифікат (як на навчальному стенді), агентам osquery потрібен прапорець `-Insecure`; для реального розгортання краще передати сертифікат через `-CertPath`:
> ```powershell
> .\Deploy-Client.ps1 -LokiUrl "http://192.0.2.10:3100" -FleetUrl "https://192.0.2.10:8080" -FleetEnrollSecret "..." -Insecure
> ```

## Структура проєкту

```
cybersec-monitoring/
├── .env.example              # шаблон конфігурації; .env створює server/gen-env.sh (не в git)
├── README.md, SECURITY.md, LICENSE
├── docs/lab.md               # опис навчального стенду
├── demo/                     # демо-стенд: docker compose, генератор журналів, up.sh/down.sh
│
├── server/                   # серверна частина
│   ├── 01-install.sh         # головний скрипт встановлення
│   ├── gen-env.sh            # генерація .env з випадковими секретами
│   ├── monitoring-stack/     # Prometheus, Loki, Grafana, Alertmanager, SNMP Exporter, Mailpit
│   ├── inventory-stack/      # Netdisco, FleetDM
│   └── alloy/                # конфігурація Grafana Alloy для сервера
│
├── posture/                  # перевірки базової лінії CIS IG1
│   ├── osquery/              # пакет запитів Fleet (ig1-posture.yml)
│   └── backup/               # резервні копії restic і перевірка відновлення
│
├── windows-common/           # спільні скрипти Windows: аудит, журналювання PowerShell,
│                             # Sysmon, Alloy, Windows Exporter, osquery, діагностика
├── windows-11-client/        # робочі станції: харденінг, телеметрія, Deploy-Client.ps1
├── windows-server-2025/      # сервери: харденінг, аудит AD/DHCP/DNS/файлового сервера/NPS,
│                             # Deploy-Server.ps1
├── linux-agent/              # Linux: харденінг, встановлення агентів, config.alloy
│
├── incident-response/        # збір артефактів: KAPE (Windows), UAC (Linux)
│
└── testing/
    ├── detection-testing/
    │   ├── windows/          # 8 тестів PowerShell + Run-AllTests.ps1
    │   ├── linux/            # 4 тести Bash + run-all-tests.sh
    │   └── kali/             # 6 сценаріїв Bash + run-all-tests.sh (лише ізольований стенд)
    └── query-check/          # перевірка запитів дашбордів і правил на зразках журналів
```

## Posture-шар (CIS IG1)

Posture-шар перевіряє базову лінію CIS Controls v8.1 IG1 (56 завдань). Картки і маппінг на CIS IG1 - у `posture/osquery/ig1-posture.yml` (заголовки містять ID картки і CIS ID).

- **Drift-перевірки пристроїв (Fleet/osquery).** Пакет застосовується командою `fleetctl apply -f posture/osquery/ig1-posture.yml`. Запити названо `ig1_<id картки у нижньому регістрі>[_<платформа>]`, наприклад `ig1_bk_02_windows`; повний список за картками - у коментарі на початку файлу. Запити, які не покриті цим пакетом (NET-01, LOG-01, LOG-03, BK-01, BK-03, BK-04, AS-02, DA-04), перелічено там само з причиною.
- **Алерти (Prometheus).** `server/monitoring-stack/prometheus/alerts/posture-alerts.yml` підхоплюється через `rule_files` (`/etc/prometheus/alerts/*.yml`). Правила `BackupTooOld` (BK-02, CIS 11.2, більше 48 годин) і `RestoreTestOverdue` (BK-01, CIS 11.1, більше 90 днів).
- **Дашборд Grafana.** `IG1 Posture` (`grafana/dashboards/08-ig1-posture.json`) завантажується через provisioning.
- **Резервні копії (restic).** Встановіть restic 0.19.1. Задайте `RESTIC_REPOSITORY` і `RESTIC_PASSWORD_FILE` з файлом пароля поза репозиторієм: Linux - `0600`, власник root; Windows - файл з обмеженим ACL. Скрипти `posture/backup/linux/backup.sh` і `posture/backup/windows/backup.ps1` записують метрику `backup_last_success_timestamp_seconds`; `restore-test.sh` і `restore-test.ps1` записують `backup_last_restore_test_timestamp_seconds`. Textfile для Windows: `C:\Program Files\windows_exporter\textfile_inputs` (параметр `-TextfileDir`), для Linux: `/var/lib/node_exporter/textfile`. Запускайте backup і restore-test за розкладом.
- **Append-only резервні копії (BK-03).** Якщо сховище - rest-server з прапорцем `--append-only` (перевірено за README rest-server, гілка master, 2026-10-13), задайте `RESTIC_APPEND_ONLY=1` для `backup.sh` або параметр `-AppendOnly` для `backup.ps1`. Скрипт тоді виконує backup і check та записує метрику, але не запускає forget/prune, тож клієнт не може видалити старі знімки. За замовчуванням forget/prune виконується, як і раніше. Очищення робіть окремо на сервері з іншими обліковими даними: наприклад, другим інстансом rest-server без `--append-only` на іншому порту, доступним лише з сервера:

```sh
# На сервері зберігання, з окремими обліковими даними (не тими, що на клієнтах).
# Спершу без --prune і з --dry-run: forget видаляє знімки безповоротно.
export RESTIC_REPOSITORY=rest:https://backup.example.org:8001/host1
export RESTIC_PASSWORD_FILE=/root/.restic-admin-pass
restic forget --tag restic --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --dry-run
restic forget --tag restic --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
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
| 08-ig1-posture | Стан CIS IG1: вік резервних копій, перевірка відновлення, алерти posture |

## Критичні Event IDs

### Найважливіші для виявлення атак:

| Event ID | Опис | Критичність |
|----------|------|-------------|
| 1102 | Журнал аудиту очищено | Критична |
| 4624 | Успішний вхід | Середня |
| 4625 | Невдалий вхід | Висока |
| 4672 | Вхід з привілеями адміна | Висока |
| 4720 | Створено користувача | Критична |
| 4732 | Додано до локальної групи | Критична |
| 4697 | Встановлено сервіс | Критична |
| 4698 | Створено scheduled task | Критична |
| 7045 | Новий сервіс (System log) | Критична |

## Тестування

Тестові скрипти згруповані по категоріях в `testing/detection-testing/`.

### Windows тести (PowerShell)

```powershell
cd testing\detection-testing\windows
.\Run-AllTests.ps1            # усі тести по черзі

# 01-test-authentication.ps1      - невдалі входи, підвищення привілеїв
# 02-test-account-management.ps1  - створення користувачів і груп
# 03-test-process-execution.ps1   - підозрілі процеси
# 04-test-powershell.ps1          - журналювання PowerShell
# 05-test-service-creation.ps1    - нові служби
# 06-test-scheduled-tasks.ps1     - заплановані завдання
# 07-test-log-clearing.ps1        - очищення журналів
# 08-test-active-directory.ps1    - зміни в AD (події 5136/5137/5141, job windows_adds)
```

### Linux тести (Bash)

```bash
cd testing/detection-testing/linux
./run-all-tests.sh
# 01-test-authentication.sh, 02-test-user-management.sh, 03-test-sudo-activity.sh, 04-test-persistence.sh
```

### Kali сценарії (Bash, лише ізольована лабораторія)

```bash
cd testing/detection-testing/kali
./run-all-tests.sh
# 01-network-discovery.sh, 02-port-scanning.sh, 03-smb-enumeration.sh,
# 04-credential-attacks.sh, 05-lateral-movement.sh, 06-persistence-simulation.sh
```

Запускайте сценарії атак лише у власній лабораторній мережі з письмовим дозволом власника інфраструктури.

### Перевірка запитів

`testing/query-check/` перевіряє, що кожен LogQL-запит дашбордів і правил Grafana знаходить дані у форматі, який реально надсилають агенти Alloy. Запускайте після будь-якої зміни дашбордів, правил або конфігурацій Alloy; інструкція - у [testing/query-check/README.md](testing/query-check/README.md).

## Безпека

- **Секрети.** `.env` не відстежується, шаблон - `.env.example`; паролі й ключі генерує `server/gen-env.sh` під час встановлення, тож кожне розгортання має власні значення. Prometheus, Alertmanager і Mailpit прив'язані до loopback (`LOCAL_BIND_IP`, за замовчуванням `127.0.0.1`). Grafana і Loki за замовчуванням слухають `0.0.0.0` (`GRAFANA_BIND_IP`, `LOKI_BIND_IP`), бо до них звертаються агенти й оператор; обмежте доступ фаєрволом або задайте конкретний IP. Admin API Prometheus вимкнено (прапорець `--web.enable-admin-api` не передається).
- **Значення з навчального стенду.** Ранні версії репозиторію містили паролі навчального стенду й ключ Fleet; в історії git вони лишились. Поточні файли їх не використовують, тож у реальній організації вони не діють, якщо ви не перенесли їх вручну.
- **Строк зберігання логів у Loki - 6 місяців.** Це рекомендація, не вимога CERT-UA.
- **Резервні копії.** Пароль restic тримайте поза репозиторієм (див. розділ Posture-шар).
- Як повідомити про вразливість - у [SECURITY.md](SECURITY.md).

## Навчальний стенд

Адреси й облікові записи стенду, на якому перевірено сценарії курсу, - у [docs/lab.md](docs/lab.md).

## Ліцензія

MIT License - див. файл [LICENSE](LICENSE)
