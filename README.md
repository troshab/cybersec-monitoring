# Система моніторингу кібербезпеки для малих організацій

Повний набір скриптів та конфігурацій для автоматичного розгортання системи моніторингу кібербезпеки на базі Grafana Stack (Prometheus, Loki, Alertmanager) та інструментів інвентаризації (Netdisco, FleetDM).

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
│  │ Promtail (native)   │ ← Syslog UDP:514                          │
│  │ + Node Exporter     │                                           │
│  └─────────────────────┘                                           │
└─────────────────────────────────────────────────────────────────────┘
           ▲                    ▲                    ▲
           │                    │                    │
    ┌──────┴──────┐     ┌──────┴──────┐     ┌──────┴──────┐
    │ Win11 Pro   │     │ Win Server  │     │ Linux       │
    │             │     │ 2025        │     │ Servers     │
    │ - Promtail  │     │ - Promtail  │     │ - Promtail  │
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
| Promtail | Агент збору логів | Native |
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
cp .env.example .env
nano .env  # Змініть всі паролі!
```

### 2. Запуск серверної частини

```bash
# Запуск головного скрипта встановлення
sudo ./server/01-install.sh
```

### 3. Розгортання на Windows клієнтах

```powershell
# Запуск від адміністратора
.\windows-11-client\Deploy-Client.ps1 -LokiUrl "http://monitoring-server:3100"
```

### 4. Розгортання на Windows серверах

```powershell
# Запуск від адміністратора
.\windows-server-2025\Deploy-Server.ps1 -LokiUrl "http://monitoring-server:3100"
```

### 5. Перевірка роботи

1. Відкрийте Grafana: `http://monitoring-server:3000`
2. Логін: admin / (пароль з .env)
3. Перевірте дашборд "Security Overview"

## Структура проєкту

```
cybersec-monitoring/
├── .env.example              # Шаблон змінних
├── README.md                 # Документація
├── LICENSE                   # Ліцензія MIT
│
├── server/                   # Серверна частина
│   ├── 01-install.sh         # Головний скрипт встановлення
│   ├── monitoring-stack/     # Grafana, Prometheus, Loki
│   ├── inventory-stack/      # Netdisco, FleetDM
│   └── promtail/             # Self-monitoring
│
├── windows-common/           # Спільні скрипти Windows
│   ├── 01-Set-AuditPolicy.ps1
│   ├── 02-Enable-PowerShellLogging.ps1
│   ├── 03-Install-Sysmon.ps1
│   ├── 04-Install-Promtail.ps1
│   ├── 05-Install-WindowsExporter.ps1
│   └── 06-Install-OsqueryAgent.ps1
│
├── windows-11-client/        # Для робочих станцій
│   ├── Deploy-Client.ps1
│   └── promtail-client.yml
│
├── windows-server-2025/      # Для серверів
│   ├── Deploy-Server.ps1
│   └── promtail-server.yml
│
├── linux-client/             # Для Linux систем
│   ├── install-agent.sh
│   └── promtail-linux.yml
│
├── win-testing/              # Тести для Windows
│   └── ...                   # PowerShell скрипти
│
└── kali-testing/             # Тести з Kali Linux
    └── ...                   # Bash скрипти
```

## Дашборди

| Дашборд | Призначення |
|---------|-------------|
| 00-security-overview | Загальний огляд безпеки |
| 01-windows-security | Windows Security Events |
| 02-linux-security | Linux Security |
| 03-lateral-movement | Виявлення руху мережею |
| 04-powershell-activity | Моніторинг PowerShell |
| 05-user-management | Зміни користувачів/груп |
| 06-network-equipment | Логи мережевого обладнання |
| 07-morning-coffee | Щоденний огляд (15 хв) |

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

### Windows тести

```powershell
# Запуск всіх тестів
.\win-testing\Run-AllTests.ps1

# Тільки певну категорію
.\win-testing\Run-AllTests.ps1 -Category Auth
```

### Kali тести

```bash
# Налаштування інструментів
./kali-testing/00-setup-tools.sh

# Запуск всіх тестів
./kali-testing/run-all-tests.sh
```

## Troubleshooting

### Логи не надходять в Loki

1. Перевірте що Promtail запущено: `Get-Service Promtail`
2. Перевірте конфіг: шлях до Loki правильний?
3. Перевірте firewall: порт 3100 відкритий?
4. Перегляньте логи Promtail: `C:\ProgramData\Promtail\promtail.log`

### Grafana не показує дані

1. Перевірте datasources: Settings → Data Sources → Test
2. Перевірте що Loki працює: `curl http://localhost:3100/ready`
3. Перевірте часовий діапазон на дашборді

### Alertmanager не надсилає email

1. Перевірте SMTP налаштування в .env
2. Для Gmail потрібен App Password
3. Перевірте логи: `docker logs alertmanager`

## Безпека

⚠️ **Важливо:**

1. **Змініть всі паролі** в .env перед розгортанням
2. **Обмежте доступ** до сервера моніторингу (firewall)
3. **Використовуйте HTTPS** для Grafana в production
4. **Регулярно оновлюйте** всі компоненти
5. **Робіть backup** конфігурації щодня

## Корисні посилання

- [CERT-UA](https://cert.gov.ua/) - Рекомендації з кібербезпеки
- [Grafana Documentation](https://grafana.com/docs/)
- [Loki Documentation](https://grafana.com/docs/loki/)
- [Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK](https://attack.mitre.org/) - Матриця атак

## Підтримка

- 📧 Email: support@example.com
- 🐛 Issues: GitHub Issues
- 📚 Wiki: GitHub Wiki

## Ліцензія

MIT License - див. файл [LICENSE](LICENSE)

---

**Створено:** 2024-12
**Автор:** Cybersecurity Training Course
**Версія:** 1.0
