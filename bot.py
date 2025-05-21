import discord
from discord.ext import commands, tasks
import requests
import json
import hashlib
import random
from datetime import datetime
import os
import socket
import dns.resolver
import re
import base64
from cryptography.fernet import Fernet

# Configuration
with open('config.json') as config_file:
    config = json.load(config_file)

TOKEN = config['discord_token']
VIRUSTOTAL_API_KEY = config['virustotal_api_key']
ABUSEIPDB_API_KEY = config['abuseipdb_api_key']
NEWS_API_KEY = config['news_api_key']

# Initialize bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Encryption setup
def generate_key():
    return Fernet.generate_key()

if not os.path.exists('secret.key'):
    with open('secret.key', 'wb') as key_file:
        key_file.write(generate_key())

with open('secret.key', 'rb') as key_file:
    key = key_file.read()
cipher_suite = Fernet(key)

# Helper functions
def check_password_strength(password):
    strength = 0
    suggestions = []
    
    # Length check
    if len(password) >= 12:
        strength += 1
    else:
        suggestions.append("Use at least 12 characters")
    
    # Complexity checks
    if re.search(r'[A-Z]', password):
        strength += 1
    else:
        suggestions.append("Include uppercase letters")
    
    if re.search(r'[a-z]', password):
        strength += 1
    else:
        suggestions.append("Include lowercase letters")
    
    if re.search(r'[0-9]', password):
        strength += 1
    else:
        suggestions.append("Include numbers")
    
    if re.search(r'[^A-Za-z0-9]', password):
        strength += 1
    else:
        suggestions.append("Include special characters")
    
    # Common password check
    common_passwords = ["password", "123456", "qwerty", "letmein"]
    if password.lower() in common_passwords:
        strength = 0
        suggestions.append("Avoid common passwords")
    
    # Strength rating
    if strength <= 2:
        rating = "Very Weak"
    elif strength == 3:
        rating = "Weak"
    elif strength == 4:
        rating = "Moderate"
    else:
        rating = "Strong"
    
    return rating, suggestions

def check_url_safety(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    # Check if URL is in VT database
    params = {'url': url}
    response = requests.post('https://www.virustotal.com/api/v3/urls', 
                            headers=headers, data=params)
    
    if response.status_code == 200:
        analysis_id = response.json()['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        # Get analysis results
        analysis_response = requests.get(analysis_url, headers=headers)
        if analysis_response.status_code == 200:
            results = analysis_response.json()['data']['attributes']['results']
            malicious = sum(1 for engine in results.values() if engine['category'] == 'malicious')
            total = len(results)
            
            return f"Scan results: {malicious}/{total} security vendors flagged this URL as malicious"
    
    return "Could not retrieve URL analysis. Please try again later."

def check_ip_reputation(ip):
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    
    response = requests.get('https://api.abuseipdb.com/api/v2/check', 
                          headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()['data']
        return (f"IP: {data['ipAddress']}\n"
                f"Abuse Confidence: {data['abuseConfidenceScore']}%\n"
                f"Total Reports: {data['totalReports']}\n"
                f"Last Reported: {data['lastReportedAt'] or 'Never'}")
    
    return "Could not retrieve IP reputation. Please try again later."

def get_security_news():
    params = {
        'q': 'cybersecurity',
        'apiKey': NEWS_API_KEY,
        'pageSize': 5,
        'sortBy': 'publishedAt'
    }
    
    response = requests.get('https://newsapi.org/v2/everything', params=params)
    
    if response.status_code == 200:
        articles = response.json()['articles']
        return [f"{article['title']}\n{article['url']}" for article in articles]
    
    return ["Could not fetch security news at this time."]

# Bot commands
@bot.command(name='password', help='Check the strength of a password')
async def password_check(ctx, *, password):
    rating, suggestions = check_password_strength(password)
    response = f"Password Strength: **{rating}**"
    
    if suggestions:
        response += "\n\n**Suggestions for improvement:**\n" + "\n".join(f"- {s}" for s in suggestions)
    
    await ctx.send(response)

@bot.command(name='scanurl', help='Check if a URL is safe')
async def scan_url(ctx, url):
    await ctx.send("Scanning URL... This may take a moment.")
    result = check_url_safety(url)
    await ctx.send(result)

@bot.command(name='iprep', help='Check the reputation of an IP address')
async def ip_reputation(ctx, ip):
    await ctx.send("Checking IP reputation...")
    result = check_ip_reputation(ip)
    await ctx.send(f"```{result}```")

@bot.command(name='news', help='Get the latest cybersecurity news')
async def security_news(ctx):
    news = get_security_news()
    for item in news:
        await ctx.send(item)

@bot.command(name='encrypt', help='Encrypt a message')
async def encrypt_message(ctx, *, message):
    encrypted = cipher_suite.encrypt(message.encode()).decode()
    await ctx.send(f"Encrypted message:\n```{encrypted}```")

@bot.command(name='decrypt', help='Decrypt a message')
async def decrypt_message(ctx, *, message):
    try:
        decrypted = cipher_suite.decrypt(message.encode()).decode()
        await ctx.send(f"Decrypted message:\n```{decrypted}```")
    except:
        await ctx.send("Decryption failed. The message may be corrupted or not encrypted with this bot.")

@bot.command(name='hash', help='Generate a hash of the input')
async def generate_hash(ctx, algorithm, *, text):
    algorithm = algorithm.lower()
    if algorithm not in ['md5', 'sha1', 'sha256', 'sha512']:
        await ctx.send("Invalid algorithm. Choose from: md5, sha1, sha256, sha512")
        return
    
    hash_func = getattr(hashlib, algorithm)
    hashed = hash_func(text.encode()).hexdigest()
    await ctx.send(f"{algorithm.upper()} hash:\n```{hashed}```")

@bot.command(name='dns', help='Perform DNS lookup')
async def dns_lookup(ctx, record_type, domain):
    record_type = record_type.upper()
    try:
        answers = dns.resolver.resolve(domain, record_type)
        result = "\n".join(str(r) for r in answers)
        await ctx.send(f"DNS {record_type} records for {domain}:\n```{result}```")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='quiz', help='Take a cybersecurity quiz')
async def cybersecurity_quiz(ctx):
    questions = [
        {
            "question": "What is the most common attack vector for malware?",
            "options": ["A) USB drives", "B) Email attachments", "C) Social media", "D) Physical access"],
            "answer": "B"
        },
        {
            "question": "Which of these is NOT a type of phishing attack?",
            "options": ["A) Spear phishing", "B) Whaling", "C) Smishing", "D) Blue phishing"],
            "answer": "D"
        },
        {
            "question": "What does MFA stand for in security?",
            "options": ["A) Multiple Factor Authentication", "B) Multi-Function Authentication", 
                       "C) Multi-Factor Authentication", "D) Mandatory Factor Authentication"],
            "answer": "C"
        }
    ]
    
    question = random.choice(questions)
    formatted = f"{question['question']}\n" + "\n".join(question['options'])
    await ctx.send(formatted)
    
    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel and m.content.upper() in ['A', 'B', 'C', 'D']
    
    try:
        msg = await bot.wait_for('message', check=check, timeout=15.0)
        if msg.content.upper() == question['answer']:
            await ctx.send("Correct! 🎉")
        else:
            await ctx.send(f"Wrong! The correct answer was {question['answer']}.")
    except:
        await ctx.send("Time's up!")

# Background tasks
@tasks.loop(hours=6)
async def update_security_alerts():
    channel = bot.get_channel(config['alerts_channel_id'])
    if channel:
        news = get_security_news()
        for item in news:
            await channel.send(f"🔔 **Security Alert Update** 🔔\n{item}")

@bot.event
async def on_ready():
    print(f'{bot.user.name} has connected to Discord!')
    update_security_alerts.start()

# Run the bot
if __name__ == '__main__':
    bot.run(TOKEN)