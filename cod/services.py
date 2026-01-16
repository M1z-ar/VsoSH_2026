import re
from pyrogram.enums import ChatType
from virustotal import VT, verdict
import settings

URL_RE = re.compile(r"https?://[^\s]+")
vt = VT(settings.VT_KEY)


async def scan_url(url, status):
    url = url.rstrip(".,;!?)\"'")
    await status.edit("⏳ Проверяю ссылку...")

    try:
        res = await vt.scan_url(url)
        v = verdict(res, is_url=True)
        await status.edit(f"🔗 **Ссылка:** {url}\n{v}")
    except Exception as e:
        if str(e) == "limit":
            await status.edit("⏳ Лимит API превышен, попробуйте позже.")
        else:
            settings.logger.exception("URL scan failed")
            await status.edit("❌ Ошибка при проверке.")


async def scan_file(c, m, status):
    size = 0
    name = "unknown"

    if m.photo:
        size = m.photo.file_size
        name = "image.jpg"
    elif m.document:
        size = m.document.file_size
        name = m.document.file_name or "document"
    elif m.video:
        size = m.video.file_size
        name = m.video.file_name or "video.mp4"
    elif m.audio:
        size = m.audio.file_size
        name = m.audio.file_name or "audio.mp3"

    if size > settings.MAX_SIZE:
        mb = size // (1024 * 1024)
        await status.edit(f"❌ Файл слишком большой ({mb} МБ). Максимум: 32 МБ.")
        return

    await status.edit("📥 Скачиваю файл...")

    try:
        mem_file = await c.download_media(m, in_memory=True)

        data = mem_file.getvalue()

        await status.edit("🔎 Отправляю на проверку...")

        res = await vt.scan_file(data, name)
        v = verdict(res)

        await status.edit(f"📄 **Файл:** {name}\n{v}")

    except Exception as e:
        if str(e) == "limit":
            await status.edit("⏳ Лимит API превышен, попробуйте позже.")
        else:
            settings.logger.exception("File scan failed")
            await status.edit("❌ Ошибка при проверке.")


async def handle_msg(c, m):
    text = m.text or m.caption or ""
    m_url = URL_RE.search(text)

    status = await m.reply("⏳ Анализ...")

    if m_url:
        await scan_url(m_url.group(0), status)
        return

    if m.document or m.video or m.photo or m.audio:
        await scan_file(c, m, status)
        return

    if m.chat.type == ChatType.PRIVATE:
        await status.edit("❗Пришлите файл или ссылку.")
    else:
        await status.edit("❗В сообщении нет ссылки или файла для проверки.")
