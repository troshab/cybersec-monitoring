# Windows Detection Testing Scripts

Набір скриптів для тестування виявлення подій безпеки в Windows середовищі.

## Важливо!

**Ці скрипти призначені ТІЛЬКИ для тестування в ізольованому лабораторному середовищі!**

Скрипти симулюють різні типи атак та підозрілу активність для перевірки:
- Налаштування аудиту
- Збору логів (Promtail)
- Правил алертів
- Дашбордів Grafana

## Структура

```
windows/
├── 01-test-authentication.ps1     # Тести автентифікації (4624, 4625)
├── 02-test-account-management.ps1 # Управління акаунтами (4720, 4732)
├── 03-test-process-execution.ps1  # Запуск процесів (4688, Sysmon 1)
├── 04-test-powershell.ps1         # PowerShell events (4103, 4104)
├── 05-test-service-creation.ps1   # Створення сервісів (7045, 4697)
├── 06-test-scheduled-tasks.ps1    # Scheduled Tasks (4698-4702)
├── 07-test-network-connections.ps1 # Мережеві підключення (Sysmon 3, 22)
├── 08-test-file-operations.ps1    # Файлові операції (4663, 5140)
├── 09-test-registry-changes.ps1   # Зміни реєстру (Sysmon 12, 13)
├── 10-test-defender-detection.ps1 # Windows Defender alerts
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
| 4624 | Successful logon | 01 |
| 4625 | Failed logon | 01 |
| 4720 | User account created | 02 |
| 4732 | Member added to group | 02 |
| 4688 | Process creation | 03 |
| 4104 | PowerShell script block | 04 |
| 7045 | Service installed | 05 |
| 4698 | Scheduled task created | 06 |
| Sysmon 3 | Network connection | 07 |
| Sysmon 22 | DNS query | 07 |
| 4663 | Object access | 08 |
| Sysmon 12/13 | Registry changes | 09 |
| 1116/1117 | Defender detection | 10 |

## Очікувані алерти

Після виконання тестів мають спрацювати алерти:
- `MultipleFailedLogins` - багато невдалих спроб входу
- `NewServiceInstalled` - створення нового сервісу
- `SuspiciousPowerShell` - підозрілі PowerShell команди
- `AccountCreated` - створення нового акаунту
- `ScheduledTaskCreated` - створення задачі

## Безпека

- Виконуйте тільки в ізольованому тестовому середовищі
- Не запускайте на production системах
- Деякі тести створюють тимчасові акаунти/сервіси - вони автоматично видаляються
- Антивірус може блокувати деякі тести (це очікувана поведінка)
