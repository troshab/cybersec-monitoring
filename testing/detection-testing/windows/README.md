# Windows Detection Testing Scripts

Набір скриптів для тестування виявлення подій безпеки в Windows середовищі.

## Важливо!

**Ці скрипти призначені ТІЛЬКИ для тестування в ізольованому лабораторному середовищі!**

Скрипти симулюють різні типи атак та підозрілу активність для перевірки:
- Налаштування аудиту
- Збору логів (Grafana Alloy)
- Правил алертів
- Дашбордів Grafana

## Структура

```
windows/
├── 01-test-authentication.ps1     # Тести автентифікації (4624, 4625, 4672, 4776)
├── 02-test-account-management.ps1 # Управління акаунтами (4720-4738)
├── 03-test-process-execution.ps1  # Запуск процесів (4688, Sysmon 1)
├── 04-test-powershell.ps1         # PowerShell events (4103, 4104)
├── 05-test-service-creation.ps1   # Створення сервісів (7045, 4697)
├── 06-test-scheduled-tasks.ps1    # Scheduled Tasks (4698-4702)
├── 07-test-log-clearing.ps1       # Очищення журналів (1102, 1100)
├── 08-test-active-directory.ps1   # Active Directory (5136-5141)
├── Run-AllTests.ps1               # Запуск всіх тестів
└── README.md
```

## Використання

### Окремий тест
```powershell
.\01-test-authentication.ps1
```

### Всі тести
```powershell
.\Run-AllTests.ps1
```

### З затримкою між тестами
```powershell
.\Run-AllTests.ps1 -DelaySeconds 30
```

## Перевірка в Grafana

Після виконання тестів:

1. Відкрийте Grafana → Explore → Loki
2. Виконайте запити:

```logql
# Всі події з тестового хоста
{host="TEST-PC"}

# Невдалі логіни
{job="windows_auth"} |= "4625"

# PowerShell events
{job="windows_powershell"}

# Нові сервіси
{job="windows_services"} |= "7045"
```

## Event IDs для моніторингу

| Event ID | Опис | Тест |
|----------|------|------|
| 4624, 4625 | Успішний і невдалий вхід | 01 |
| 4672, 4776 | Привілейовані входи, перевірка облікових даних | 01 |
| 4720, 4732 | Створення акаунта, додавання до групи | 02 |
| 4688, Sysmon 1 | Створення процесу | 03 |
| 4103, 4104 | PowerShell | 04 |
| 7045, 4697 | Встановлення сервісу | 05 |
| 4698-4702 | Заплановані завдання | 06 |
| 1102, 1100 | Очищення журналу | 07 |
| 5136-5141 | Об'єкти Active Directory | 08 |

## Очікувані алерти

Події, які генерують тести, потрапляють під такі правила Grafana Alerting (`server/monitoring-stack/grafana/provisioning/alerting/alert-rules.yml`):
- `CRITICAL: Audit Log Cleared (1102)` - тест 07
- `CRITICAL: New Admin Added (4732)` - тест 02
- `HIGH: New Service Installed (7045)` - тест 05
- `HIGH: Scheduled Task Created (4698)` - тест 06
- `CRITICAL: Suspicious PowerShell Detected` - тест 04
- `HIGH: Failed Login Spike (4625)` - тест 01
- `HIGH: AD Object Modified (5136)` - тест 08

## Безпека

- Виконуйте тільки в ізольованому тестовому середовищі
- Не запускайте на production системах
- Деякі тести створюють тимчасові акаунти/сервіси - вони автоматично видаляються
- Антивірус може блокувати деякі тести (це очікувана поведінка)
