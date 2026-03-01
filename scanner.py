import discord
import re
import asyncio
import aiohttp
import os

intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)

URL_REGEX = r"(https?://[^\s]+)"
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
SCANNER_LOGS_CHANNEL_IDS = [1477328726214578371, 1410480747604742154]

async def scan_with_virustotal(url_to_scan, vt_api_key):
    headers = {
        "x-apikey": vt_api_key
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url_to_scan}) as resp:
            if resp.status != 200:
                return None
            
            result = await resp.json()
            analysis_id = result['data']['id']
            
        for _ in range(6):
            await asyncio.sleep(3)
            async with session.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers) as resp:
                if resp.status == 200:
                    analysis_result = await resp.json()
                    status = analysis_result['data']['attributes']['status']
                    
                    if status == 'completed':
                        return analysis_result['data']['attributes']['stats']
                        
        return None

@client.event
async def on_ready():
    print(f'Logged in as {client.user}')

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    urls = re.findall(URL_REGEX, message.content)
    
    attachment_urls = [
        att.url for att in message.attachments 
        if att.content_type and att.content_type.startswith('image/')
    ]
    
    all_urls_to_scan = urls + attachment_urls

    if all_urls_to_scan:
        status_messages = []
        
        for channel_id in SCANNER_LOGS_CHANNEL_IDS:
            log_channel = client.get_channel(channel_id)
            if log_channel:
                msg = await log_channel.send(f"[System] Initializing scan for a message from {message.author.name} in {message.channel.name}...")
                status_messages.append(msg)

        if not status_messages:
            return

        async def run_animation():
            frames = [
                f"[>.........] Starting scan for {message.author.name}...",
                f"[=>........] Reading links from {message.channel.name}...",
                "[==>.......] Checking images...",
                "[===>......] Sending to VirusTotal...",
                "[====>.....] Searching for malware...",
                "[=====>....] Looking for phishing...",
                "[======>...] Testing security...",
                "[=======>..] Reviewing results...",
                "[========>.] Double-checking...",
                "[=========>] Finishing up..."
            ]
            try:
                while True:
                    for frame in frames:
                        for msg in status_messages:
                            await msg.edit(content=frame)
                        await asyncio.sleep(0.6)
            except asyncio.CancelledError:
                pass

        animation_task = asyncio.create_task(run_animation())

        is_malicious = False
        for url in all_urls_to_scan:
            stats = await scan_with_virustotal(url, VIRUSTOTAL_API_KEY)
            if stats:
                if stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0:
                    is_malicious = True
                    break 

        animation_task.cancel()
        scanned_links_text = "\n".join(all_urls_to_scan)
        
        for msg in status_messages:
            if is_malicious:
                embed = discord.Embed(title="Threat Detected", color=discord.Color.red())
                embed.add_field(name="User", value=message.author.mention, inline=True)
                embed.add_field(name="Channel", value=message.channel.mention, inline=True)
                embed.add_field(name="Message Link", value=f"[Jump to Message]({message.jump_url})", inline=False)
                embed.add_field(name="Scanned Content", value=scanned_links_text, inline=False)
                await msg.edit(content="[ALERT] Malicious payload detected.", embed=embed)
            else:
                embed = discord.Embed(title="Safe Content Scanned", color=discord.Color.green())
                embed.add_field(name="User", value=message.author.mention, inline=True)
                embed.add_field(name="Channel", value=message.channel.mention, inline=True)
                embed.add_field(name="Message Link", value=f"[Jump to Message]({message.jump_url})", inline=False)
                embed.add_field(name="Scanned Content", value=scanned_links_text, inline=False)
                await msg.edit(content="[CLEAR] Content verified as secure.", embed=embed)

client.run(DISCORD_BOT_TOKEN)
