# -*- coding: utf-8 -*-

from netmiko import ConnectHandler
import getpass
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
import subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor
import re
import sys
import tqdm
import os
from tabulate import tabulate
import csv
import datetime


today = datetime.datetime.today().strftime("%d-%m-%Y-%H:%M")

# Функция проверяет устройства по ping на доступность в пареллельных потоках
def ping_check(ip_device):
    ok_ping_list = list()
    ping_result = subprocess.run(['ping', '-c', '3', '-n', ip_device], stdout=subprocess.DEVNULL)
    if ping_result.returncode == 0:
        print('Устройство с ip-адресом',ip_device, 'отвечает на icmp-запросы - OK')
        ok_ping_list.append(ip_device)
    else:
        print('Устройство с ip-адресом',ip_device, 'не отвечает на icmp-запросы - Fail')

    return ok_ping_list


# функиция для многопоточной обработки функции ping_check
def ping_check_threads_conn(function, devices, limit=8):
    with ThreadPoolExecutor(max_workers=limit) as executor:
        f_result = executor.map(function, devices)

    return list(f_result)

# функция добавления данных аутентификации к 'живым' ip-адресам
def add_authentication_data_to_dict(ping_result):
    # Если в списке списков нет записей о доступных устройствах - завершаем скрипт, иначе выполняем
    if ping_result == [[]]:
        print('В проверяемом списке нет доступных устройств')
        print('Работа скрипта завершена')
        sys.exit()
    else:
        # преобразуем список списоков в обычный список с доступными по ping ip-адресами
        checked_ip_list = list()
        for value in ping_result:
            for ip in value:
                checked_ip_list.append(ip)

    print('Введите данные для авторизации на устройствах','\n')

    # Запрашиваем данные для авторизации
    USER = input('Username: ')
    PASSWORD = getpass.getpass()
    #ENABLE_PASSWORD = getpass.getpass(prompt='Enter enable password, if necessary: ')

    list_of_device_params = list()

    # Добавляем введенные данные в словарь с параметрами для подключения к устройствам
    for IP in checked_ip_list:
        device_keys = ['device_type', 'ip', 'username', 'password', 'secret']
        device_params = dict.fromkeys(device_keys)

        device_params['device_type'] = 'cisco_ios'
        device_params['ip'] = IP
        device_params['username'] = USER
        device_params['password'] = PASSWORD
        #device_params['secret'] = ENABLE_PASSWORD

        list_of_device_params.append(device_params)

    return list_of_device_params


def ssh_connect(devices_list_from_ping_def,progress_bar=False):
    '''
    if progress_bar:
        devices_list_from_ping_def = tqdm.tqdm(
            devices_list_from_ping_def, total=len(devices_list_from_ping_def))
    '''

    command_sh_int_status = 'show interfaces status | include notconnect'
    columns = ['Switch', 'Port', 'Last input', 'Last output', 'Port type']

    final_notconnect_list = list()
    devices_list = devices_list_from_ping_def
    authentication_error_list = list()
    uptime_list = list()


    # Проходимся в списке словарей по словарям
    for device in devices_list:
        # Подключаемся к устройствам и выполняем команду
        try:
            with ConnectHandler(**device) as ssh:
                ssh.enable()
                output_from_ssh_sh_ver = ssh.send_command('sh version')

                for line in output_from_ssh_sh_ver.split('\n'):
                    uptime_match = re.search('.+uptime is\s(?P<uptime>.+)',line.strip())
                    system_return_match = re.search('System returned to ROM by .+', line.strip())
                    if uptime_match:
                        uptime = uptime_match.group('uptime')
                        uptime_list.append('\nSwitch ' + device['ip'] + ' uptime - '+ uptime)

                    if system_return_match:
                        system_return = system_return_match.group()
                        uptime_list.append(system_return)

                print('\nСобираю данные с устройства', device['ip'], end='\n')

                output_from_ssh = ssh.send_command(command_sh_int_status)
                for line in output_from_ssh:
                    line_stripped = line.lstrip()
                    if line_stripped.startswith('^'):
                        print('\nПроизошла ошибка, работа скрипта возможна только с Cisco IOS Software')
                        sys.exit()

                components_notconnect_list = list()
                # Добавляем IP адрес коммутатора в список параметров
                # в цикле проходимся по строкам, предворительно их разрезав по \n, чтобы поиск RE был построчным

                for line in output_from_ssh.split('\n'):
                    print('#', end=' ', flush=True)
                    components_notconnect_list = list()
                    notconnect_port_match = re.search('(?P<port>\w+/\d{1,2}\S*)\s+.+', line.strip())
                    if notconnect_port_match:
                        notconnect_port = notconnect_port_match.group('port')
                        components_notconnect_list.append(device['ip'])
                        components_notconnect_list.append(notconnect_port)

                        output_from_ssh_2 = ssh.send_command('sh int {}'.format(notconnect_port))

                        for line in output_from_ssh_2.split('\n'):
                            notconnect_port_type_match = re.search('.+media type is\s(?P<port_type>.+)', line.strip())
                            notconnect_port_input_output_match = re.search('Last input\s(?P<last_input>\d\d:\d\d:\d\d|\w+),\soutput\s(?P<last_output>\d\d:\d\d:\d\d|\w+).+',line.strip())

                            if notconnect_port_type_match:
                                notconnect_port_type = notconnect_port_type_match.group('port_type')

                            if notconnect_port_input_output_match:
                                notconnect_port_last_input = notconnect_port_input_output_match.group('last_input')
                                notconnect_port_last_output = notconnect_port_input_output_match.group('last_output')

                                components_notconnect_list.append(notconnect_port_last_input)
                                components_notconnect_list.append(notconnect_port_last_output)
                                components_notconnect_list.append(notconnect_port_type)

                    final_notconnect_list.append(components_notconnect_list)

        except NetMikoAuthenticationException:

            if authentication_error_list == []:
                print(' Не удалось подключиться')
                print('\n',
                      'Для устройства',device['ip'], 'введены неверные данные авторизации, ввести их заново?',
                      '\n1 - Да, только для устройства с ip',device['ip'],
                      '\n2 - Нет, не вводить новые данные авторизации для других устройств, имеющих проблемы авторизации'
                      '\n3 - Да, для всех остальных устройств, с неправильными данными авторизации'
                      '\n\n0 - Завершить работу скрипта'
                      '\n')
                authentication_repeat = input('Введите 1,2,3 или 0 ')
                print('\n')
                if authentication_repeat == '1':
                    USER = input('Username: ')
                    PASSWORD = getpass.getpass()
                    #ENABLE_PASSWORD = getpass.getpass(prompt='Enter enable password, if necessary: ')

                    device_keys = ['device_type', 'ip', 'username', 'password', 'secret']
                    device_params = dict.fromkeys(device_keys)

                    device_params['device_type'] = 'cisco_ios'
                    device_params['ip'] = device['ip']
                    device_params['username'] = USER
                    device_params['password'] = PASSWORD
                    #device_params['secret'] = ENABLE_PASSWORD
                    devices_list.append(device_params)

                elif authentication_repeat =='2':
                    authentication_error_list.append(device['ip'])
                elif authentication_repeat == '3':
                    USER = input('Username: ')
                    PASSWORD = getpass.getpass()
                    ENABLE_PASSWORD = getpass.getpass(prompt='Enter enable password, if necessary: ')
                    device_keys = ['device_type', 'ip', 'username', 'password', 'secret']
                    device_params = dict.fromkeys(device_keys)

                    device_params['device_type'] = 'cisco_ios'
                    device_params['ip'] = device['ip']
                    device_params['username'] = USER
                    device_params['password'] = PASSWORD
                    #device_params['secret'] = ENABLE_PASSWORD

                    devices_list.append(device_params)
                    authentication_error_list.append(device['ip'])

                elif authentication_repeat == '0':
                    sys.exit()

            else:
                if authentication_repeat == '2':
                    pass
                else:
                    device_keys = ['device_type', 'ip', 'username', 'password', 'secret']
                    device_params = dict.fromkeys(device_keys)

                    device_params['device_type'] = 'cisco_ios'
                    device_params['ip'] = device['ip']
                    device_params['username'] = USER
                    device_params['password'] = PASSWORD
                    #device_params['secret'] = ENABLE_PASSWORD

                    devices_list.append(device_params)

        except NetMikoTimeoutException:
            print(device['ip'], '- ошибка подключения по таймауту или доступ к ssh заблокирован', end='\n')
            sys.exit()
        except ValueError:
            print('Невозможно получить данные, enable secret указан неверно')
            sys.exit()

    print('\n')
    for line in uptime_list:
        print(line)

    print('\n' + tabulate(final_notconnect_list, headers=columns, tablefmt='pipe', stralign='center'))


    return final_notconnect_list


def add_data_to_csv(final_notconnect_list, today):
    columns = ['Switch', 'Port', 'Last input', 'Last output', 'Port type']
    final_notconnect_list.insert(0,columns)

    try:
        if not os.path.exists(args.csv_dir):
            os.mkdir(args.csv_dir)

        with open(args.csv_dir + '/{}_notconnect_ports_{}.csv'.format(today,args.host), 'w') as f:
            writer = csv.writer(f, quoting=csv.QUOTE_NONNUMERIC)
            for row in final_notconnect_list:
                writer.writerow(row)
        print('\n', 'Файл', '{}_notconnect_ports_{}.csv'.format(today, args.host), 'создан в каталоге', os.path.abspath(args.csv_dir))

    except PermissionError:
        print('\n Не хватает прав доступа для директории', os.path.abspath(args.csv_dir))

        if not os.path.exists('results_in_csv_files'):
            os.mkdir('results_in_csv_files')

        with open('./results_in_csv_files/{}_notconnect_ports_{}.csv'.format(today, args.host), 'w') as f:
            writer = csv.writer(f, quoting=csv.QUOTE_NONNUMERIC)
            for row in final_notconnect_list:
                writer.writerow(row)
        print('\n', 'Файл', '{}_notconnect_ports_{}.csv'.format(today, args.host), 'создан в каталоге', os.path.abspath('./results_in_csv_files/'))

parser = argparse.ArgumentParser(description='e.g. python3.6 free_cisco_ports.py 10.10.10.1 -e /home/ivan/my_csv_results')

parser.add_argument('host', nargs='+', action="store", help="IP or name to check")
parser.add_argument('-e',  dest='csv_dir', action="store", metavar="path to the file", help="export csv-file with results in this folder")

args = parser.parse_args()

if __name__ == '__main__':
    ping_result = ping_check_threads_conn(ping_check, args.host, limit=8)
    print('-'*80)
    devices_list = add_authentication_data_to_dict(ping_result)
    notconnect_ports_result = ssh_connect(devices_list)

    if args.csv_dir:
        add_data_to_csv(notconnect_ports_result,today)

print('\n','Работа скрипта завершена')
