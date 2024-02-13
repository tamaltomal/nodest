import requests
import keyboard
import pyshark
import socket
import time
from datetime import datetime
from multiprocessing import Process

def send_mail(msg):
    print(msg)

def capture_packet(host, timeout=5):
    print(f'[{datetime.now()}] Capture started.')
    filename = f'./tcpdumps/{host}_{datetime.now().strftime("%Y%m%d%H%M%S")}.pcap'
    capture = pyshark.LiveCapture(interface='ens32', output_file=filename, bpf_filter=f'host {host}')
    capture.set_debug()
    capture.sniff(timeout=timeout)
    print(f'[{datetime.now()}] Capture stopped.')

if __name__ == '__main__':
    hosts = [
        '10.101.80.32'
        ]
    protocol ='https'
    headers = {}

    with open("logs.txt", "a") as file:
        while True:
            print(f'[{datetime.now()}] >>>>>>>>>> Monitoring Started. <<<<<<<<<<')
            for host in hosts:
                print(f'[{datetime.now()}] Scanning {host}:{socket.gethostbyname(host)}.')
                try:
                    response = requests.get(f'{protocol}://{host}', verify=False, headers=headers)
                    if response.status_code != 200:
                        capture = Process(target=capture_packet, args=(host,))
                        capture.start()
                        time.sleep(4)
                        try:
                            response = requests.get(f'{protocol}://{host}', headers=headers)
                        except:
                            pass
                        capture.join()
                    file.write(f'[{datetime.now()}] {host}:{socket.gethostbyname(host)} Response: {response.status_code}\n')
                except Exception as error:
                    file.write(f'[{datetime.now()}] {host}:{socket.gethostbyname(host)} Response: {error}\n')
                    capture = Process(target=capture_packet, args=(host,))
                    capture.start()
                    time.sleep(2)
                    try:
                        response = requests.get(f'{protocol}://{host}', headers=headers)
                    except:
                        pass
                    capture.join()
            print(f'[{datetime.now()}] >>>>> Monitoring Paused. Press "Ctrl+C" to stop. <<<<<')
            time.sleep(15)