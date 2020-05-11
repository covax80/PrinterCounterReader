# PrintCounterReader - программа для чтение через протокол SMNP (через сканирование подсети) параметров принтеров и МФУ (счётчики остатков тонера и др.)

## Описание
Программа создана для чтение параметров SNMP МФУ и принтеров.

### Основные цели использования:
1. Обеспечение информационной безопастности - в связи с тем что часть устойств от фирмы Kyocera передавала пароль от настроек сетевых папок для сканирования (см. подробнее http://habrahabr.ru/sandbox/85521/) нужна была проверка чтобы принтеры не содержали пароли пользователей домена. По исполению программа может выдавать отчёт в формате CSV или HTML c возможностью сортировки (через jquery)
2. Мониторинг остатков тонера в принтерах. Программу подключал к Zabbix агенту для формирования графиков использования принтеров. (В случае если картридж перезаправлен без чипа - параметры остатка тонера не отображаются)

### Поддерживаемые устройства
В данный момент программа поддерживает работу принтеров пречисленных в файле settings.ini



## Установка

### Требования
1. Python 3.xx
2. PySNMP

## Вывод программы без параметров (HELP) 
  **python3 cnt_reader.py** 

 Usage: cnt_reader.py [options]

```
 Options:
  -M MODE, --mode=MODE  Programm mode: 'html', 'plaintext','plaintable','sql',
                        'Tk', 'csv'
  -S BOOLEAN, --scan_mode=BOOLEAN
                        It's try to detect printer model via snmp codes
  -L LIST_OF_ALIASES, --monitoring_list=LIST_OF_ALIASES
                        List of printer aliases for monitoring. Example:
                        vostok-pr11, vostok-pr12
  -E LIST, --extended_list=LIST
                        List of printers for monitoring. Example: 'vostok-
                        pr11;hp1120;172.21.0.212, vostok-
                        pr12;kyocera3920;172.21.0.211'
  -F FILE_PREFFIX, --file_name_preffix=FILE_PREFFIX
                        Name of output file
  -P PARAM_snmp_oid, --values_for_reading=PARAM_snmp_oid
                        Params for reading. E.g.: model_snmp_oid,
                        network_snmp_oid, pagecounter_snmp_oid
  -I BOOLEAN, --pipe=BOOLEAN
                        import printer list from pipe
  -H BOOLEAN, --header=BOOLEAN
                        Enable/disable header in outputs data
  --runtime=BOOLEAN     Print runtime
  -T INTEGER, --threads=INTEGER
                        Print runtime

```

## Примеры использования:

1. запуск програмы c вводными данными из конфига
```	требования:
	         отредактировать  settings.ini
			monitoring_list - список принтеров для опроса по SMNP  (данные берутся из секции [Aliases])
			values_for_reading - параметры для считывания (либо ALL) (данные берутся из секций моделей - к примеру [hp1120])
	запуск:
		cnt_reader.py -M plaintable - вывод в формате таблицы (псевдографика)
		cnt_reader.py -M plaintext - голые данные (особено полезны с опцией -H False (без заголовка)
		cnt_reader.py -M csv - данные для экспорта в Excel
		cnt_reader.py -M html - данные в формате HTML  (полезно с -F output_page.html)
```
2. запуск програмы с вводными данными из командной сроки
```	требования:
		что опрашивать и типы опрашиваемой техники были в settings.ini - нужны секции с моделями ([hp1120],...)
	запуск:
		cnt_reader.py -M plaintable -E printer1;hp1120;172.21.0.201,printer2;kyocer3920;172.21.0.202
```
3. запуск програмы с вводными данными из командной сроки в режиме сканирования
```	требования:
		главное чтобы принтеры в списке при их опросе сошлись с одной из signature в секциях с моделями ([hp1120],...)
	запуск:
		cnt_reader.py -M plaintable -S True -L 172.21.0.201,172.21.0.202,172.21.0.203 
		cnt_reader.py -M plaintable -S True -L 172.21.0.0/24 
```
4. запуск програмы с вводом списка устройств для опроса через pipe ( | )
```	требования:
		разделять устройства либо через запятую, либо с новой строки
	запуск:
		type printer.list.txt | cnt_reader.py -M plaintable -I True
		echo "printer1,printer2" | cnt_reader.py -M plaintable -I True -S True - запуск в режиме сканирования
```
5. запуск програмы для вывода конкретных параметров
```	 cnt_reader.py -M plaintable -P serialnumber_snmp_oid,pagecounter_snmp_oid
```


