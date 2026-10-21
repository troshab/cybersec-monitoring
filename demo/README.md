# Демо-стенд

Демо-стенд піднімає ядро моніторингу на вашому комп'ютері за одну команду: Prometheus, Loki, Grafana, Alertmanager і Mailpit з тими самими образами, конфігураціями, дашбордами й правилами сповіщень, що й робоче розгортання з `server/monitoring-stack/`. Нічого не копіюється: файли підключаються з репозиторію лише для читання, тож на стенді видно саме те, що отримає організація.

Справжніх серверів і робочих станцій не потрібно. Дані дає генератор `feeder/feeder.py`: він читає конфігурації Alloy з репозиторію (`windows-server-2025/`, `windows-11-client/`, `linux-agent/`, `server/alloy/`) і пише в Loki рядки точно такого вигляду й з тими самими мітками, які надіслали б справжні агенти. Тому стенд одночасно перевіряє, що запити дашбордів і правил збігаються з реальними даними.

Стенд навчальний. Він слухає лише `127.0.0.1` і не призначений для доступу з мережі.

## Що потрібно

- Docker з Compose v2 (Docker Desktop на Windows і macOS або Docker Engine на Linux).
- Близько 4 ГБ вільної пам'яті й 2 ГБ на диску.
- Вільні порти `3000`, `3100`, `9090`, `9093`, `8025`, `1025` на `127.0.0.1`. Інші порти можна задати у файлі `demo/.env`, наприклад `GRAFANA_PORT=23000`.

## Запуск

Linux, macOS або WSL:

```bash
git clone https://github.com/troshab/cybersec-monitoring.git
cd cybersec-monitoring/demo
./up.sh
```

Скрипт створює `demo/.env` з випадковим паролем адміністратора Grafana (файл у git не потрапляє), запускає контейнери, чекає на Grafana й показує адреси.

Windows (PowerShell, Docker Desktop):

```powershell
cd cybersec-monitoring\demo
docker compose up -d
```

Без `up.sh` пароль адміністратора за замовчуванням - `demo-admin-password`; для перегляду він не потрібен.

| Що | Адреса |
|---|---|
| Grafana | <http://127.0.0.1:3000> - перегляд без входу, вхід `admin` для налаштувань |
| Prometheus | <http://127.0.0.1:9090> - цілі, правила, стан сповіщень |
| Alertmanager | <http://127.0.0.1:9093> - сповіщення, що надійшли |
| Mailpit | <http://127.0.0.1:8025> - листи, які Alertmanager надіслав би команді |

## Що відбувається на стенді

- Одразу після старту генератор додає історію за останню добу, щоб графіки не були порожніми.
- Далі кожні 30 секунд надходить звичайний фон: входи, процеси, мережеві з'єднання, журнали Linux.
- Одразу і потім кожні 15 хвилин (`DEMO_WAVE_MINUTES` у `.env`) іде «хвиля атаки»: перебір паролів на двох Windows-хостах, новий обліковий запис у групі адміністраторів, нова служба і запланове завдання, підозрілий PowerShell, зміни в Active Directory, очищення журналу аудиту, перебір паролів SSH і `sudo` на Linux. Через кілька хвилин після хвилі сповіщення переходять у стан Firing, а між хвилями повертаються в норму.
- Два контейнери `node-exporter` замінюють хости для Prometheus: `DEMO-SRV01` (Linux) і `DEMO-WS01` (Windows, метрики у форматі windows_exporter). На `DEMO-WS01` служба Defender зупинена, а один Linux-хост має застарілу резервну копію і давно не перевірене відновлення, щоб було видно відповідні сповіщення.

Демо-хости: `DEMO-DC01` (контролер домену), `DEMO-WS01` (робоча станція), `DEMO-LNX01` і `DEMO-SRV01` (Linux).

## Що подивитися

Ідіть по порядку. Кожен крок показує, що саме ви маєте побачити, і веде на урок IT-маршруту та картку-інструкцію, де пояснено, навіщо це і як зробити в себе.

| Крок | Де | Що ви маєте побачити | Урок | Картка |
|---|---|---|---|---|
| 1 | Grafana, дашборд «00 - Security Overview» | загальна картина: події безпеки, вхід, хости, що надсилають журнали | [IT 2.5](https://bcp.troshab.dev/docs/course/it/2-05) | [LOG-02](https://bcp.troshab.dev/docs/baseline/module/log-02) |
| 2 | «Morning Coffee - Daily Security Review» | щоденний огляд за 5 хвилин: невдалі входи, нові адміністратори, підозрілий PowerShell | [IT 4.1](https://bcp.troshab.dev/docs/course/it/4-01) | [LOG-02](https://bcp.troshab.dev/docs/baseline/module/log-02) |
| 3 | «Authentication Dashboard» | сплеск невдалих входів 4625 з одних і тих самих адрес після хвилі | [IT 2.6](https://bcp.troshab.dev/docs/course/it/2-06) | [AC-07](https://bcp.troshab.dev/docs/baseline/module/ac-07) |
| 4 | «Windows Security Events» | новий обліковий запис і додавання до адміністраторів (4720, 4732), нова служба 7045, завдання 4698 | [IT 2.9](https://bcp.troshab.dev/docs/course/it/2-09) | [AC-04](https://bcp.troshab.dev/docs/baseline/module/ac-04) |
| 5 | там само, панель підозрілих команд PowerShell | закодовані команди й завантаження скриптів з інтернету | [IT 2.7](https://bcp.troshab.dev/docs/course/it/2-07) | [LOG-02](https://bcp.troshab.dev/docs/baseline/module/log-02) |
| 6 | «Network Overview» | з'єднання на порти 445, 3389, 5985 і доступ до адмінських спільних папок | [IT 2.8](https://bcp.troshab.dev/docs/course/it/2-08) | [CF-05](https://bcp.troshab.dev/docs/baseline/module/cf-05) |
| 7 | Grafana, розділ Explore, запит `{job="windows_adds"}` | зміни, створення й видалення об'єктів AD (5136, 5137, 5141) | [IT 2.14](https://bcp.troshab.dev/docs/course/it/2-14) | [AC-01](https://bcp.troshab.dev/docs/baseline/module/ac-01) |
| 8 | «Linux Security Events» | невдалі входи SSH, `sudo`, новий користувач | [IT 2.10](https://bcp.troshab.dev/docs/course/it/2-10) | [AC-04](https://bcp.troshab.dev/docs/baseline/module/ac-04) |
| 9 | «Inventory Status» | хости, які надсилають метрики, завантаження процесора, пам'ять, диск | [IT 1.2](https://bcp.troshab.dev/docs/course/it/1-02) | [AS-01](https://bcp.troshab.dev/docs/baseline/module/as-01) |
| 10 | «IG1 Posture» | вік резервних копій: `DEMO-SRV01` у нормі, `DEMO-LNX01` - ні; стан сповіщень про резервні копії й Defender | [IT 2.19](https://bcp.troshab.dev/docs/course/it/2-19) | [BK-02](https://bcp.troshab.dev/docs/baseline/module/bk-02), [BK-01](https://bcp.troshab.dev/docs/baseline/module/bk-01), [MW-01](https://bcp.troshab.dev/docs/baseline/module/mw-01) |
| 11 | Grafana, Alerting > Alert rules; Prometheus, вкладка Alerts | правила, що спрацювали після хвилі: перебір паролів, новий адміністратор, очищений журнал, підозрілий PowerShell, `BackupTooOld`, `WindowsDefenderDisabled` | [IT 2.16](https://bcp.troshab.dev/docs/course/it/2-16) | [LOG-01](https://bcp.troshab.dev/docs/baseline/module/log-01) |
| 12 | «Alerts Summary», Alertmanager і Mailpit | які сповіщення активні і як виглядає лист команді | [IT 2.15](https://bcp.troshab.dev/docs/course/it/2-15) | [IR-01](https://bcp.troshab.dev/docs/baseline/module/ir-01) |
| 13 | Grafana, Explore | самостійне розслідування за прикладами запитів з уроку | [IT 3.2](https://bcp.troshab.dev/docs/course/it/3-02) | [LOG-03](https://bcp.troshab.dev/docs/baseline/module/log-03) |

Деякі правила спрацьовують не одразу, а після витримки (`for:` у правилі): `WindowsDefenderDisabled` - за 2 хвилини після старту, `BackupTooOld` - за 15 хвилин, `RestoreTestOverdue` - за годину. Сповіщення Grafana про Windows і Linux спрацьовують за 1-2 хвилини після хвилі.

## Запустити сценарій вручну

Не чекаючи наступної хвилі, будь-який сценарій можна запустити окремо:

```bash
docker compose exec feeder python demo/feeder/feeder.py --repo /repo --loki http://loki:3100 --scenario spray
```

Сценарії: `spray` (перебір паролів Windows), `admin` (новий адміністратор), `persistence` (служба, завдання, PowerShell), `ad` (зміни в AD), `logclear` (очищення журналу аудиту), `ssh` (перебір паролів SSH і `sudo`), `all` (усе разом).

## Зупинити й прибрати

```bash
./down.sh
```

Скрипт зупиняє контейнери й видаляє їхні дані (томи Docker). Файл `demo/.env` лишається; видаліть його вручну, якщо пароль більше не потрібен. На Windows те саме робить `docker compose down -v`.

## Чим стенд відрізняється від робочого розгортання

- Події синтетичні: їх генерує `feeder/feeder.py`, а не справжні агенти. Формат рядків і мітки взято з конфігурацій Alloy у репозиторії; перевірку формату для кожного запиту робить `testing/query-check/`.
- Метрики Windows і резервних копій задає генератор через textfile-колектор `node-exporter`, а не windows_exporter і скрипти `posture/backup/`.
- Prometheus використовує `demo/prometheus.yml`: правила ті самі (`server/monitoring-stack/prometheus/alerts/`), а цілі - демо-контейнери замість адрес вашої мережі.
- Не запускаються SNMP Exporter (немає мережевого обладнання), Fleet і Netdisco (інвентаризація), а також скрипти посилення налаштувань. Як розгорнути їх у себе, описано в головному [README](../README.md) і в [уроках IT-маршруту](https://bcp.troshab.dev/docs/course/).
- Паролі, ключі й адреси стенду не підходять для робочого середовища. Для реального розгортання використовуйте `server/gen-env.sh` і `server/01-install.sh`.
