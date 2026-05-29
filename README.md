# Лабораторная работа №3

## Исходные данные

**Проект:** Flask
**Репозиторий проекта:** https://github.com/pallets/flask
**Версия проекта:** 2.0.2
**Дистрибутив для заданий 4 и 5:** Rocky Linux 9.3

## Структура файлов

Файлы названы в соответствии с номерами заданий:

```text
task1.py      - задание 1: сбор зависимостей проекта
task2.py      - задание 2: проверка зависимостей через GitHub Security Advisory
task3.py      - задание 3: анализ уязвимых зависимостей
task4.py      - задание 4: инвентаризация Rocky Linux и RPM-пакетов
make_bom.py   - подготовка CycloneDX BOM для задания 5
analyze.py    - анализ результатов задания 5
```

## Подготовка окружения

Для выполнения заданий 1–3 требуется Python-окружение и зависимости:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Для анализа Flask использовалась версия `2.0.2`:

```bash
git clone https://github.com/pallets/flask.git source/flask
cd source/flask
git checkout 2.0.2
cd ../../
pip install ./source/flask "Werkzeug<2.1" "Jinja2<3.1" "itsdangerous<2.1" "click<8.1"
```

## Задание 1

`task1.py` собирает runtime-зависимости Flask и формирует файл:

```text
results/result_task_1.json
```

Запуск:

```bash
python3 task1.py
```

## Задание 2

Для работы второго задания нужен GitHub Token с возможностью чтения данных GitHub Security Advisory GraphQL API.

Токен можно сохранить в файл `.env` в папке проекта:

```bash
echo "GITHUB_TOKEN=ТОКЕН" > .env
export $(cat .env | xargs)
```

После этого можно запускать второе задание:

```bash
python3 task2.py
```

Результат:

```text
results/result_task_2.json
```

## Задание 3

`task3.py` формирует таблицу анализа уязвимых зависимостей на основе `result_task_2.json`.

Запуск:

```bash
python3 task3.py
```

После выполнения будут сформированы файлы:

```text
results/result_task_3.csv
results/result_task_3.md
```

## Задание 4

`task4.py` проводит инвентаризацию операционной системы Rocky Linux 9.3 и установленных RPM-пакетов.

Запуск:

```bash
python3 task4.py
```

Результат:

```text
results/result_task_4.json
```

## Задание 5

`make_bom.py` проводит инвентаризацию аналогично четвёртому заданию, но формирует результат в формате CycloneDX BOM, который понимает `osv-scanner`.

`analyze.py` проводит сравнение файлов скана и BOM до/после обновления, после чего выдаёт краткий итог.

## Установка osv-scanner

```bash
wget https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -O osv-scanner
chmod +x osv-scanner
```

## Выполнение заданий 4 и 5

Сначала выполняется инвентаризация системы до обновления:

```bash
python3 task4.py
cp results/result_task_4.json results/result_task_4_before.json
```

Формирование BOM до обновления:

```bash
python3 make_bom.py --output results/bom_before.cdx.json
```

Сканирование до обновления:

```bash
./osv-scanner scan results/bom_before.cdx.json --format json --output-file results/scan_before.json
```

Глобальное обновление системы Rocky Linux:

```bash
sudo dnf update -y
```

Повторная инвентаризация после обновления:

```bash
python3 task4.py
cp results/result_task_4.json results/result_task_4_after.json
```

Формирование BOM после обновления:

```bash
python3 make_bom.py --output results/bom_after.cdx.json
```

Сканирование после обновления:

```bash
./osv-scanner scan results/bom_after.cdx.json --format json --output-file results/scan_after.json
```

Сравнение результатов:

```bash
python3 analyze.py
```

Итоговый файл сравнения:

```text
results/result_task_5_compare.json
```

## Примечание

Итоговые результаты выполнения заданий не выгружаются в репозиторий.
Они передаются отдельно архивом вместе с отчётом.
