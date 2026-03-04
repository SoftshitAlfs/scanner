import discord
from discord.ext import commands
import re
import asyncio
import aiohttp
import aiosqlite
import os
import datetime
import hashlib
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv('DISCORD_BOT_TOKEN')
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
LOG_CHANNELS = [1410480747604742154, 1477328726214578371]
DB_PATH = "security_cache.db"
URL_REGEX = r"(https?://[^\s]+)"

api_semaphore = asyncio.Semaphore(1)

class SecurityScanner(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)
        self.db = None

    async def setup_hook(self):
        self.db = await aiosqlite.connect(DB_PATH)
        await self.db.execute('''
            CREATE TABLE IF NOT EXISTS scan_logs (
                resource_id TEXT PRIMARY KEY,
                malicious INTEGER,
                suspicious INTEGER,
                scan_date TIMESTAMP,
                type TEXT
            )
        ''')
        await self.db.commit()

    async def get_cached(self, r_id):
        async with self.db.execute("SELECT malicious, suspicious FROM scan_logs WHERE resource_id = ?", (r_id,)) as c:
            return await c.fetchone()

    async def cache_result(self, r_id, m, s, r_type):
        await self.db.execute("INSERT OR REPLACE INTO scan_logs VALUES (?, ?, ?, ?, ?)",
            (r_id, m, s, datetime.datetime.utcnow(), r_type))
        await self.db.commit()

    async def scan_file(self, attachment):
        file_bytes = await attachment.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        cached = await self.get_cached(file_hash)
        if cached:
            return {'malicious': cached[0], 'suspicious': cached[1]}, "CACHE_HIT", file_hash
        async with api_semaphore:
            headers = {"x-apikey": VT_API_KEY}
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers) as resp:
                        if resp.status == 200:
                            stats = (await resp.json())['data']['attributes']['last_analysis_stats']
                            await self.cache_result(file_hash, stats['malicious'], stats['suspicious'], "FILE_HASH")
                            return stats, "VT_GLOBAL_HASH", file_hash
                    form = aiohttp.FormData()
                    form.add_field('file', file_bytes, filename=attachment.filename)
                    async with session.post("https://www.virustotal.com/api/v3/files", headers=headers, data=form) as resp:
                        if resp.status != 200: return None, "ERROR", file_hash
                        analysis_id = (await resp.json())['data']['id']
                    for _ in range(12):
                        await asyncio.sleep(15)
                        async with session.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers) as resp:
                            if resp.status == 200:
                                res = await resp.json()
                                if res['data']['attributes']['status'] == 'completed':
                                    stats = res['data']['attributes']['stats']
                                    await self.cache_result(file_hash, stats['malicious'], stats['suspicious'], "FILE_FULL")
                                    return stats, "VT_DETONATION", file_hash
                except: pass
        return None, "ERROR", file_hash

    async def scan_url(self, url):
        cached = await self.get_cached(url)
        if cached:
            return {'malicious': cached[0], 'suspicious': cached[1]}, "CACHE_HIT"
        async with api_semaphore:
            headers = {"x-apikey": VT_API_KEY}
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}) as resp:
                        if resp.status != 200: return None, "ERROR"
                        analysis_id = (await resp.json())['data']['id']
                    for _ in range(10):
                        await asyncio.sleep(5)
                        async with session.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers) as resp:
                            if resp.status == 200:
                                res = await resp.json()
                                if res['data']['attributes']['status'] == 'completed':
                                    stats = res['data']['attributes']['stats']
                                    await self.cache_result(url, stats['malicious'], stats['suspicious'], "URL")
                                    return stats, "VT_LIVE_URL"
                except: pass
        return None, "ERROR"

bot = SecurityScanner()

@bot.command(name="stats")
@commands.has_permissions(administrator=True)
async def stats(ctx):
    async with bot.db.execute("SELECT COUNT(*), SUM(malicious) FROM scan_logs") as cursor:
        row = await cursor.fetchone()
        total_scans = row[0] or 0
        total_malicious = row[1] or 0
    embed = discord.Embed(title="SYSTEM_DATABASE_STATS", color=discord.Color.blue())
    embed.add_field(name="RESOURCES_CACHED", value=str(total_scans), inline=True)
    embed.add_field(name="THREATS_DETECTED", value=str(total_malicious), inline=True)
    await ctx.send(embed=embed)

@bot.command(name="analyze")
async def analyze(ctx, url: str = None):
    target_url = url
    target_file = ctx.message.attachments[0] if ctx.message.attachments else None
    if not target_url and not target_file:
        return await ctx.send("INPUT_REQUIRED: PROVIDE_URL_OR_FILE")
    msg = await ctx.send("ANALYZING_RESOURCE")
    if target_file:
        stats, src, _ = await bot.scan_file(target_file)
        name = target_file.filename
    else:
        stats, src = await bot.scan_url(target_url)
        name = target_url
    if stats:
        color = discord.Color.red() if stats['malicious'] > 0 else discord.Color.green()
        verdict = "THREAT_DETECTED" if stats['malicious'] > 0 else "CLEAR"
        res_embed = discord.Embed(title=f"MANUAL_ANALYSIS: {verdict}", color=color)
        res_embed.add_field(name="TARGET", value=name[:50], inline=False)
        res_embed.add_field(name="MALICIOUS_ENGINES", value=str(stats['malicious']), inline=True)
        res_embed.add_field(name="SCAN_METHOD", value=src, inline=True)
        await msg.edit(content=None, embed=res_embed)
    else:
        await msg.edit(content="SCAN_FAILED")

@bot.event
async def on_message(message):
    if message.author == bot.user: return
    urls = re.findall(URL_REGEX, message.content)
    files = message.attachments
    if not urls and not files:
        await bot.process_commands(message)
        return
    status_msgs = []
    for cid in LOG_CHANNELS:
        ch = bot.get_channel(cid)
        if ch: status_msgs.append(await ch.send(f"SCAN_PENDING: {message.id}"))
    results = []
    is_malicious = False
    for url in urls:
        stats, src = await bot.scan_url(url)
        if stats:
            results.append({"name": url, "m": stats['malicious'], "s": stats['suspicious'], "src": src, "hash": "N/A"})
            if stats['malicious'] > 0: is_malicious = True
    for f in files:
        stats, src, f_hash = await bot.scan_file(f)
        if stats:
            results.append({"name": f.filename, "m": stats['malicious'], "s": stats['suspicious'], "src": src, "hash": f_hash})
            if stats['malicious'] > 0: is_malicious = True
    if is_malicious:
        try: await message.delete()
        except: pass
        verdict, color = "THREAT_NEUTRALIZED", discord.Color.red()
    else:
        verdict, color = "CLEAR", discord.Color.green()
    embed = discord.Embed(title=f"SYSTEM_REPORT: {verdict}", color=color, timestamp=datetime.datetime.utcnow())
    embed.add_field(name="USER_ID", value=str(message.author.id), inline=True)
    embed.add_field(name="CHANNEL_ID", value=str(message.channel.id), inline=True)
    for r in results:
        field_val = f"MALICIOUS: {r['m']} | SUSPICIOUS: {r['s']}\nSRC: {r['src']}\nID: {r['hash'][:16]}"
        embed.add_field(name=f"TARGET: {r['name'][:50]}", value=field_val, inline=False)
    for m in status_msgs:
        await m.edit(content=None, embed=embed)
    await bot.process_commands(message)

if __name__ == "__main__":
    bot.run(TOKEN)

