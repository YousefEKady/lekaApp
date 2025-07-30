import os
import re
from datetime import datetime
from telethon import TelegramClient
from telethon.tl.types import MessageMediaDocument
from dotenv import load_dotenv
from tqdm import tqdm

# Load environment variables
load_dotenv()

# Read sensitive data only from .env (no hardcoded values)
api_id = os.getenv('TELEGRAM_API_ID')
api_hash = os.getenv('TELEGRAM_API_HASH')
channel_id = os.getenv('TELEGRAM_CHANNEL_ID')
DOWNLOAD_ROOT = os.getenv('TELEGRAM_DOWNLOAD_ROOT', 'downloads')
MANUAL_DOWNLOADS_FILE = 'downloaded_files.txt'

# Validate required environment variables
if not api_id or not api_hash or not channel_id:
    raise ValueError("Missing required environment variables. Please set TELEGRAM_API_ID, TELEGRAM_API_HASH, and TELEGRAM_CHANNEL_ID in your .env file.")

# Load manually downloaded file names
if os.path.exists(MANUAL_DOWNLOADS_FILE):
    with open(MANUAL_DOWNLOADS_FILE, 'r', encoding='utf-8') as f:
        manually_downloaded = set(line.strip() for line in f if line.strip())
else:
    manually_downloaded = set()


def extract_password_from_message(message_text):
    """Extract password keywords from message text if present."""
    if not message_text:
        return None
    patterns = [
        r'Password\s*[:=]\s*(.+)',
        r'Pwd\s*[:=]\s*(.+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, message_text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


async def download_channel_files(channel_id, session_name='session_name'):
    client = TelegramClient(session_name, int(api_id), api_hash)
    await client.start()
    print("Logged in successfully.")

    try:
        channel = await client.get_entity(int(channel_id))
        print(f"Downloading from: {channel.title} (ID: {channel_id})")
    except Exception as e:
        print(f"Failed to get channel: {e}")
        await client.disconnect()
        return

    messages_by_day = {}
    total_files = 0
    async for message in client.iter_messages(channel):
        if message.media and isinstance(message.media, MessageMediaDocument):
            date_folder = message.date.strftime('%Y-%m-%d')
            messages_by_day.setdefault(date_folder, []).append(message)
            total_files += 1

    print(f"Found {total_files} files in {len(messages_by_day)} day(s). Starting download...")

    with open(MANUAL_DOWNLOADS_FILE, 'a', encoding='utf-8') as manual_file:
        for day_idx, (date_folder, messages) in enumerate(messages_by_day.items(), 1):
            channel_title = ''.join(c for c in channel.title if c.isalnum() or c in (' ', '_', '-')).rstrip()
            save_dir = os.path.join(DOWNLOAD_ROOT, channel_title, date_folder)
            os.makedirs(save_dir, exist_ok=True)

            print(f"[Day {day_idx}/{len(messages_by_day)}] Downloading {len(messages)} file(s) for {date_folder}...")

            with tqdm(total=len(messages), desc=f"{date_folder}", unit="file") as pbar:
                for message in messages:
                    original_file_name = message.file.name if message.file and message.file.name else ''

                    # Skip manually downloaded files
                    if original_file_name in manually_downloaded:
                        pbar.update(1)
                        continue

                    # Generate a safe file name
                    if message.file and message.file.name:
                        file_name = f"{message.id}_{message.file.name}"
                    else:
                        ext = message.file.ext if message.file and message.file.ext else ''
                        file_name = f"{message.id}{ext}"
                    target_path = os.path.join(save_dir, file_name)

                    try:
                        file_path = await message.download_media(file=target_path)

                        # Log manually downloaded files
                        if original_file_name:
                            manual_file.write(original_file_name + "\n")
                            manual_file.flush()

                        # Extract password from message and save it
                        password = extract_password_from_message(message.message)
                        if password:
                            pwd_file_path = file_path + '.pwd.txt'
                            try:
                                with open(pwd_file_path, 'w', encoding='utf-8') as pf:
                                    pf.write(password)
                            except Exception as e:
                                print(f"    Failed to save password file: {e}")

                    except Exception as e:
                        print(f"    Failed to download: {e}")

                    pbar.update(1)

    print("All downloads complete.")
    await client.disconnect()


if __name__ == '__main__':
    import asyncio
    asyncio.run(download_channel_files(channel_id))
