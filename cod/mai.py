import sys
import asyncio
from pyrogram import Client, filters
from pyrogram.enums import ChatType
import settings
from services import handle_msg

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

app = Client(
    "bot_session",
    api_id=settings.API_ID,
    api_hash=settings.API_HASH,
    bot_token=settings.BOT_TOKEN
)

@app.on_message(filters.command("start") & filters.private)
async def cmd_start(c, m):
    await m.reply(settings.MSG_START)

@app.on_message(filters.command("help") & filters.private)
async def cmd_help(c, m):
    await m.reply(settings.MSG_HELP)

@app.on_message(filters.command("addbot") & filters.private)
async def cmd_addbot(c, m):
    await m.reply(settings.MSG_ADDBOT)

@app.on_message(filters.command("mhelp"))
async def cmd_mhelp(c, m):
    if m.chat.type == ChatType.PRIVATE:
        await m.reply(settings.ERR_PRIVATE)
    else:
        await m.reply(settings.MSG_MHELP)

@app.on_message(filters.command("scan"))
async def cmd_scan(c, m):
    if m.chat.type == ChatType.PRIVATE:
        await m.reply(settings.ERR_GROUP)
        return

    if not m.reply_to_message:
        await m.reply("❗Ответьте на сообщение с файлом.")
        return

    await handle_msg(c, m.reply_to_message)

@app.on_message(filters.private)
async def on_pm(c, m):
    await handle_msg(c, m)

if __name__ == "__main__":
    app.run()
