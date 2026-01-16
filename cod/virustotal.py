import asyncio
import base64
import aiohttp


class VT:
    def __init__(self, key):
        self.api = "https://www.virustotal.com/api/v3"
        self.key = key
        self.sess = None

    async def get_session(self):
        if self.sess is None or self.sess.closed:
            self.sess = aiohttp.ClientSession(headers={"x-apikey": self.key})
        return self.sess

    async def close(self):
        if self.sess:
            await self.sess.close()

    async def req(self, method, path, **kw):
        session = await self.get_session()
        url = f"{self.api}/{path}"
        async with session.request(method, url, **kw) as r:
            if r.status == 429:
                raise Exception("limit")
            return await r.json()

    async def wait(self, aid):
        if not aid:
            raise Exception("fail")

        for _ in range(52):
            r = await self.req("GET", f"analyses/{aid}")
            st = r.get("data", {}).get("attributes", {}).get("status")
            if st == "completed":
                return r
            await asyncio.sleep(3)

        raise asyncio.TimeoutError

    async def scan_url(self, url):
        r = await self.req("POST", "urls", data={"url": url})
        aid = r.get("data", {}).get("id")
        await self.wait(aid)

        uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return await self.req("GET", f"urls/{uid}")

    async def scan_file(self, data, name):
        form = aiohttp.FormData()
        form.add_field("file", data, filename=name)

        r = await self.req("POST", "files", data=form)
        aid = r.get("data", {}).get("id")
        return await self.wait(aid)


def verdict(r, is_url=False):

    a = r["data"].get("attributes", {})
    s = a.get("stats") or a.get("last_analysis_stats", {})

    if s.get("malicious", 0) > 0:
        return "⚠️ Опасно!"

    if s.get("suspicious", 0) > 0:
        return "❓ Подозрительно."

    if is_url:
        bad = {"phishing", "malware", "scam", "fraud"}
        for t in a.get("categories", {}).values():
            if t.lower() in bad:
                return "⚠️ Опасно!"

    return "✅ Безопасно."
