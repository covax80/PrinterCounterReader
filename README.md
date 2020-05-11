# PrintCounterReader - ��������� ��� ������ ����� �������� SMNP (����� ������������ �������) ���������� ��������� � ��� (�������� �������� ������ � ��.)

## ��������
��������� ������� ��� ������ ���������� SNMP ��� � ���������.

### �������� ���� �������������:
1. ����������� �������������� ������������� - � ����� � ��� ��� ����� �������� �� ����� Kyocera ���������� ������ �� �������� ������� ����� ��� ������������ (��. ��������� http://habrahabr.ru/sandbox/85521/) ����� ���� �������� ����� �������� �� ��������� ������ ������������� ������. �� ��������� ��������� ����� �������� ����� � ������� CSV ��� HTML c ������������ ���������� (����� jquery)
2. ���������� �������� ������ � ���������. ��������� ��������� � Zabbix ������ ��� ������������ �������� ������������� ���������. (� ������ ���� �������� ������������� ��� ���� - ��������� ������� ������ �� ������������)

### �������������� ����������
� ������ ������ ��������� ������������ ������ ��������� ������������ � ����� settings.ini



## ���������

### ����������
1. Python 3.xx
2. PySNMP

## ����� ��������� ��� ���������� (HELP) 
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

## ������� �������������:

1. ������ �������� c �������� ������� �� �������
```	����������:
	         ���������������  settings.ini
			monitoring_list - ������ ��������� ��� ������ �� SMNP  (������ ������� �� ������ [Aliases])
			values_for_reading - ��������� ��� ���������� (���� ALL) (������ ������� �� ������ ������� - � ������� [hp1120])
	������:
		cnt_reader.py -M plaintable - ����� � ������� ������� (�������������)
		cnt_reader.py -M plaintext - ����� ������ (������� ������� � ������ -H False (��� ���������)
		cnt_reader.py -M csv - ������ ��� �������� � Excel
		cnt_reader.py -M html - ������ � ������� HTML  (������� � -F output_page.html)
```
2. ������ �������� � �������� ������� �� ��������� �����
```	����������:
		��� ���������� � ���� ������������ ������� ���� � settings.ini - ����� ������ � �������� ([hp1120],...)
	������:
		cnt_reader.py -M plaintable -E printer1;hp1120;172.21.0.201,printer2;kyocer3920;172.21.0.202
```
3. ������ �������� � �������� ������� �� ��������� ����� � ������ ������������
```	����������:
		������� ����� �������� � ������ ��� �� ������ ������� � ����� �� signature � ������� � �������� ([hp1120],...)
	������:
		cnt_reader.py -M plaintable -S True -L 172.21.0.201,172.21.0.202,172.21.0.203 
		cnt_reader.py -M plaintable -S True -L 172.21.0.0/24 
```
4. ������ �������� � ������ ������ ��������� ��� ������ ����� pipe ( | )
```	����������:
		��������� ���������� ���� ����� �������, ���� � ����� ������
	������:
		type printer.list.txt | cnt_reader.py -M plaintable -I True
		echo "printer1,printer2" | cnt_reader.py -M plaintable -I True -S True - ������ � ������ ������������
```
5. ������ �������� ��� ������ ���������� ����������
```	 cnt_reader.py -M plaintable -P serialnumber_snmp_oid,pagecounter_snmp_oid
```


