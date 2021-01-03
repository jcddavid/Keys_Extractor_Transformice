from time import perf_counter
from threading import Thread
from ctypes import c_int32
from re import search

import subprocess
import requests
import asyncio
import json


class Parser:
    def __init__(self):
        self.functions = {}
        self.index = 0

        self.version = 0
        self.connection_key = ''
        self.auth_key = 0
        self.packet_keys = [0] * 20
        self.server_ip = ''
        self.server_ports = []

        self.loop = asyncio.get_event_loop()
        self.loop.run_until_complete(self.start())
        self.loop.close()
    
    async def start(self):
        print('Analyzing the data...')
        self.extract_functions()

        self.start_time = perf_counter()
        print('Started getting the encryption keys...')
        await self.get_version()
        await self.get_connection_key()
        await self.get_auth_key()
        await self.get_packet_keys()
        await self.get_server_ip()

    def djb_hash(self, hash, hash_len):
        buf = []

        n = 0x1505  
        for i in range(20):
            n = (n << 5) + n + self.packet_keys[i] + hash[i % hash_len]

        for i in range(20):
            n ^= c_int32(n).value << 13
            n ^= c_int32(n).value >> 17
            n ^= c_int32(n).value << 5
            buf.append(c_int32(n).value)
            
        return buf
        
    def extract_functions(self):
        for i, line in enumerate(dump):
            if 'method <q>[public]::int' in line and '0 params' in line:
                Thread(target=self.get_returnvalue, args=(i,)).start()

    def get_returnvalue(self, line):
        start = line
        value = 0
        while not 'returnvalue' in dump[line]:
            if search('push(int|byte|short)', dump[line]):
                value += int(dump[line].split()[-1])
            line += 1
        
        self.functions[dump[start].split('::')[2].split('=')[0]] = value

    async def find_operators(self, collector_line):
        operators = []
        i = 0
        while not 'returnvoid' in dump[i + collector_line]:
            op = search('(add|subtract|modulo)', dump[i + collector_line])
            if op:
                op = op.group(1)

                value, line = None, i + collector_line
                if 'callproperty' in dump[line - 1]:
                    value = self.functions[search('<q>\[public\]::(.*?), 0 params', dump[line - 1])[1]]
                elif 'getlocal_0' in dump[line - 2]:
                    value = self.functions[search('<q>\[public\]::(.*?), 0 params', dump[line - 3])[1]]

                if value:
                    operators.append(value)
            i += 1

        self.add_1, self.mod, self.sub = operators[:3]
        self.add_2 = operators[-3]
        self.increment = operators[-1]

    async def find_aliases(self, collector):
        self.aliases = []
        for i, line in enumerate(dump):
            if collector in line and 'getproperty' in line:
                if 'initproperty' in dump[i + 1]:
                    alias_name = dump[i + 1].split('::')[1]
                    self.aliases.append(alias_name)
                    if len(self.aliases) == 6:
                        break

    async def get_params(self, line):
        params = []
        while not 'getproperty' in dump[line]:
            if 'callproperty' in dump[line] and 'getlex' in dump[line - 1]:
                varname = dump[line].split('::')[1].split(',')[0]
                param = self.functions[varname]
                if 'negate' in dump[line + 1]:
                    param = -param
                params.insert(0, param)
            line -= 1
        return params

    async def find_calls(self, function, start_line=0, _class=None, constructors=None):
        calls = []
        for i in range(start_line, len(dump)):
            if function + '=(' in dump[i]:
                if _class:
                    for n in range(i, 0, -1):
                        if 'class' in dump[n]:
                            break
                    if not _class in dump[n]:
                        continue
                    
                for j in range(i, len(dump)):
                    if 'returnvoid' in dump[j] and '}' in dump[j + 1][-1]:
                        return calls, j
                    
                    elif 'callpropvoid' in dump[j]:
                        func_name = dump[j].split('::')[1].split(',')[0]
                        if func_name in self.aliases:
                            params = await self.get_params(j)
                            calls.append(params)
                            
                    if constructors:
                        initialization = [c for c in constructors if c in dump[j]]
                        if initialization:
                            initialization = initialization[0]
                            inner_calls = None

                            if 'callpropvoid' in dump[j]:
                                _constructors, _class = (None, None)
                                
                                if initialization == 'Initialisation':
                                    if not 'getlocal_0' in dump[j - 1]:
                                        continue
                                    _constructors = [self.common_function] * 3
                                    
                                elif initialization == self.common_function:
                                    _class = dump[j - 1].split('::')[1]

                                function = dump[j].split('::')[1].split(',')[0]
                                inner_calls = ((await self.find_calls(function, _class=_class,constructors=_constructors))[0])

                            elif 'findpropstrict' in dump[j]:
                                inner_calls = ((await self.find_calls(dump[j].split('::')[1]))[0])

                            if inner_calls:
                                calls.extend(inner_calls)
                            constructors.remove(initialization)

    async def add_key(self, *args):
        self.packet_keys[args[(self.index + self.add_1) % self.mod] - self.sub] += args[(self.index + self.add_2) % self.mod]
        self.index += self.increment

    async def get_version(self):
        for line in dump:
            if 'int' in line:
                self.version = int(search('int = (\d+)', line)[1])
                break

    async def get_connection_key(self):
        i = 0      
        while i < len(dump):
            if 'getscopeobject 1' in dump[i] and 'getslot 7' in dump[i + 1] and 'getlocal_0' in dump[i + 2]:
                while not 'flash.system::Capabilities' in dump[i]:
                    if 'getlex' in dump[i] and 'getproperty <q>[public]' in dump[i + 1]:
                        if 'getscopeobject 1' in dump[i + 2] or "callproperty" in dump[i + 2]:
                            p = dump[i + 1].split('::')[-1].strip()
                            v = 0
                            while v < len(dump):
                                if p in dump[v] and '::String' in dump[v]:
                                    self.connection_key = dump[v].split('=')[-1].strip()
                                    return
                                v+=1
                    i+=1
            i+=1

    async def get_auth_key(self):
        i = 0
        while i < len(dump):
            if 'getlocal_0' in dump[i]:
                if 'convert_i' in dump[i+2]:
                    if 'setlocal_1' in dump[i+3]:                  
                        while not 'returnvalue' in dump[i]:                
                            if 'bitxor' in dump[i]:
                                if 'callproperty' in dump[i-1]:
                                    function = search(r"::([\\0-9]+), 0 params$", dump[i-1].strip())[1]
                                    self.auth_key ^= self.functions[function]

                            elif 'lshift' in dump[i]:
                                if 'callproperty' in dump[i-1] and '0 params' in dump[i-1]:
                                    function = search(r"::([\\0-9]+), 0 params$", dump[i-1].strip())[1]
                                    self.auth_key ^= 1 << self.functions[function]
                            i+=1
                        return
            i+=1

    async def get_packet_keys(self):
        for v in range(len(dump)):
            if 'need_rest' in dump[v] and '(0 params, 0 optional)' in dump[v-1] and not 'final' in dump[v-1]:
                collector = search('void <q>\[public\]::(.*?)=\(\)', dump[v-1]).group(1)
                collector_line = v
                break
        
        await self.find_operators(collector_line)
        await self.find_aliases(collector)

        for i, line in enumerate(dump):
            if 'callpropvoid' in line:
                func_name = line.split('::')[1].split(',')[0]
                if func_name in self.aliases:
                    params = await self.get_params(i)
                    await self.add_key(*params)
                      
            elif 'iffalse' in line and 'getlex' in dump[i + 1]:
                if 'constructprop' in dump[i + 3]:
                    constructor = dump[i + 3].split('::')[1].split(',')[0]        
                    for i, line in enumerate(dump):
                        if constructor in line and 'extends' in line:
                            parent_class = line[:-1].split('::')[2]
                            for x, line in enumerate(dump):
                                if parent_class + '=()' in line:
                                    while not 'returnvoid' in dump[x]:
                                        if 'getlex' in dump[x] and 'call' in dump[x + 1]:
                                            proper_class = dump[x].split('::')[1]
                                            function = dump[x + 1].split('::')[1].split(',')[0]
                                            self.common_function = function
                                            calls = (await self.find_calls(function, x, _class=proper_class))
                                            if calls:
                                                for params in calls[0]:
                                                    await self.add_key(*params)
                                        x += 1
                                    break
                            break

            elif 'ADDED_TO_STAGE' in line and 'getproperty' in dump[i + 2]:
                method_name = dump[i + 2].split('::')[1]
                calls, end_line = await self.find_calls(method_name)
                for params in calls:
                    await self.add_key(*params)
                break

        constructors = ['Initialisation']
        for i in range(end_line, 0, -1):
            if 'getproperty' in dump[i]:
                method_name = dump[i].split('::')[1]
                for i, line in enumerate(dump):
                    if method_name + '=()' in line:
                        start_line = i
                        while not 'returnvoid' in dump[i]:
                            if 'constructprop' in dump[i] and 'pop' in dump[i + 1]:
                                constructors.append(dump[i].split('::')[1].split(', ')[0])
                            i += 1
                        for n in range(i, 0, -1):
                            if 'callpropvoid' in dump[n] and 'getlocal_0' in dump[n - 1]:
                                constructors.append(dump[n].split('::')[1].split(', ')[0])
                                break

                        calls = (await self.find_calls(method_name, start_line, constructors=constructors))[0]
                        for params in calls:
                            await self.add_key(*params)
                        break
                break

    async def get_server_ip(self):
        for i, line in enumerate(dump):
            if 'jump' in line and 'pushtrue' in dump[i + 2] and 'pushstring' in dump[i + 5]:
                string = search('"(.*)"', dump[i + 5])[1]
                self.server_ip = string.split(':')[0]
                self.server_ports = list(map(int, string.split(':')[1].split('-')))



if __name__ == '__main__':
    with open(r'swf\Transformice.swf', 'wb') as f:
        print('Downloading the SWF...')
        swf_bytes = requests.get('https://www.transformice.com/Transformice.swf')
        f.write(swf_bytes.content)
        f.close()

        print('Decrypting the SWF...')
        subprocess.run(r'tools\dumper swf\Transformice.swf swf\tfm.swf', creationflags=0x8000000)
        dump = subprocess.check_output(r"tools\swfdump -a swf\tfm.swf", creationflags=0x8000000)
        dump = dump.decode().split('\r\n')

    data = Parser()
    keys = {
            'version': data.version,
            'connection_key': data.connection_key,
            'auth_key': data.auth_key,
            'packet_keys': data.packet_keys,
            'identification_keys': data.djb_hash(b'identification', 14),
            'msg_keys': [k & 0xff for k in data.djb_hash(b'msg', 3)],
            'server_ip': data.server_ip,
            'server_ports': data.server_ports
           }

    print('\n', keys, sep='')
    print(f'\nKeys found in {round((perf_counter() - data.start_time), 6)}s')
    
    keys_dump = open('keys.json', 'w')
    json.dump(keys, keys_dump)
    keys_dump.close()


