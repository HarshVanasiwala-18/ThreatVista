import aiohttp
import aiofiles
import asyncio
from bs4 import BeautifulSoup
import json
import regex as re

async def fetch_content(session, url):
    try:
        async with session.get(url, timeout=30) as response:
            if response.status == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' in content_type:
                    return await response.text(errors='ignore')
                elif 'application/pdf' in content_type or 'application/octet-stream' in content_type:
                    return await response.read()
                else:
                    print(f"Unsupported content type for {url}: {content_type}")
                    return None
            else:
                print(f"Failed to fetch content for {url} with status {response.status}")
                return None
    except asyncio.TimeoutError:
        print(f"Timeout while fetching content for {url}")
        return None
    except Exception as e:
        print(f"Exception while fetching content for {url}: {str(e)}")
        return None

async def scrape_malpedia(session, name, is_threat_actor=True):
    if not name:
        print("No name provided for scraping")
        return []

    name = name.replace(" ", "_")
    url = f"https://malpedia.caad.fkie.fraunhofer.de/actor/{name}" if is_threat_actor else f"https://malpedia.caad.fkie.fraunhofer.de/details/{name}"
    
    try:
        async with session.get(url) as response:
            if response.status == 200:
                content = await response.text()
                soup = BeautifulSoup(content, "html.parser")
                articles = []
                for row in soup.find_all("tr", class_="clickable-row clickable-row-newtab"):
                    title = row.find("span", class_="title mono-font")
                    article_url = row["data-href"]
                    date = row.find("span", class_="date mono-font")
                    organization = row.find("span", class_="organization mono-font")
                    author = row.find("span", class_="authors mono-font")
                    malware_family = row.find("a", attrs={"data-family_name": True})

                    cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', title.text if title else "")
                    unique_cve_ids = list(set(cve_ids)) if cve_ids else None

                    title_text = title.text if title else None
                    date_text = date.text if date else None
                    organization_text = organization.text if organization else None
                    author_text = author.text if author else None
                    malware_family_text = malware_family.text.strip() if malware_family else None

                    # Fetch the content of the article URL
                    article_content = await fetch_content(session, article_url)

                    entry = {
                        "Title": title_text,
                        "URL": article_url,
                        "Date": date_text,
                        "Organization": organization_text,
                        "Author": author_text,
                        "CVE IDs": unique_cve_ids,
                        "Content": article_content
                    }
                    if is_threat_actor:
                        entry["Threat Actor"] = malware_family_text
                    else:
                        entry["Malware Family"] = malware_family_text

                    articles.append(entry)
                
                return articles
            else:
                print(f"Failed to fetch data for {name} with status {response.status}")
                return []

    except Exception as e:
        print(f"Exception for {name}: {str(e)}")
        return []

async def scrape_all():
    all_articles = {}

    async with aiohttp.ClientSession() as session:
        # Load threat actors and malware families from JSON files
        async with aiofiles.open(r"scripts (data collection)\threat_actors.json", "r") as f:
            threat_data = json.loads(await f.read())
        
        async with aiofiles.open(r"scripts (data collection)\malware_families.json", "r") as f:
            malware_data = json.loads(await f.read())

        # Create a list of tasks for threat actors and malware families
        tasks = []
        
        for entry in threat_data:
            threat_actor = entry.get("Threat Actor")
            if threat_actor:
                print(f"Scraping articles for threat actor: {threat_actor}")
                tasks.append(scrape_malpedia(session, threat_actor, is_threat_actor=True))
            else:
                print("Skipping an entry with missing 'Threat Actor' field")
        
        for entry in malware_data:
            malware_family = entry.get("Name")
            if malware_family:
                print(f"Scraping articles for malware family: {malware_family}")
                tasks.append(scrape_malpedia(session, malware_family, is_threat_actor=False))
            else:
                print("Skipping an entry with missing 'Name' field")

        results = await asyncio.gather(*tasks)

        # Combine results into all_articles
        idx = 0
        for entry in threat_data:
            threat_actor = entry.get("Threat Actor")
            if threat_actor:
                all_articles[threat_actor] = results[idx]
                idx += 1

        for entry in malware_data:
            malware_family = entry.get("Name")
            if malware_family:
                all_articles[malware_family] = results[idx]
                idx += 1

    # Save all articles to a JSON file
    async with aiofiles.open("all_articles.json", "w", encoding='utf-8') as f:
        await f.write(json.dumps(all_articles, indent=4, ensure_ascii=False))

# Run the async scrape_all function
asyncio.run(scrape_all())