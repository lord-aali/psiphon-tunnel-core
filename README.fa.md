# هسته سفارشی سایفون

> اگر این پروژه برای شما مفید بود، لطفاً در گیت‌هاب به آن یک ⭐ بدهید!

یک نسخه سفارشی از هسته تونل سایفون که با لیستی انتخاب شده از سرورها برای بهینه‌سازی عملکرد و اتصال، از پیش پیکربندی شده است.

[English version](./README.md)

## این پروژه چیست؟

این پروژه یک نسخه اصلاح‌شده از [هسته تونل سایفون](https://github.com/Psiphon-Inc/psiphon) متن‌باز را ارائه می‌دهد. تفاوت اصلی این است که این نسخه شامل یک لیست خاص و دست‌چین شده از نقاط ورودی (سرورها) از کشورهای مختلف است که می‌تواند منجر به اتصال پایدارتر و قابل اطمینان‌تر برای کاربران در مناطق خاص شود.

## چرا از این نسخه سفارشی استفاده کنیم؟

*   **لیست سرور بهینه‌سازی شده**: به جای تکیه بر کشف سرور پیش‌فرض، این نسخه به مجموعه‌ای از پیش تعریف شده از سرورهای با کیفیت بالا متصل می‌شود.
*   **سادگی**: نیازی به پیکربندی پیچیده نیست. فقط فایل اجرایی را اجرا کرده و کشور مورد نظر خود را از لیست پشتیبانی شده مشخص کنید.
*   **شفافیت**: لیست کامل کشورها و سرورهای پشتیبانی شده مستقیماً در کد منبع موجود است و به شما کنترل کامل می‌دهد.

## کشورهای پشتیبانی شده

اگر هنوز برنامه را اجرا نکرده‌اید آن را اجرا کنید تا پوشه data و محتویات آن ایجاد شود سپس با دستور زیر لیست کشورهای موجود را ببینید:

```bash
./psiphon -list
```

## نحوه استفاده

برای اجرای کلاینت، از خط فرمان استفاده کنید. می‌توانید کشوری را که می‌خواهید از طریق آن متصل شوید، مشخص کنید.

### مثال ساده

این دستور پراکسی سایفون را اجرا کرده و برای اتصالات SOCKS روی `127.0.0.1:10808` گوش می‌دهد. این اتصال از طریق یک سرور در ایالات متحده برقرار خواهد شد.

```bash
./psiphon -c US
```

### فلگ‌های خط فرمان

```
Usage: psiphon [-b addr:port] [-c country] [-p proxy] [-wo|-mo|-mp|-pm|-pw] [-masque-sni sni] [-masque-endpoint ip:port] [-warp-endpoint ip:port] [-scan-masque|-scan-warp] [-list]

  -b string
        آدرس اتصال SOCKS (پیش‌فرض "127.0.0.1:10808")
  -c string
        کد کشور (مثلاً US, DE, JP). برای دیدن مقادیر معتبر از -list استفاده کنید. (پیش‌فرض "US")
  -config string
        فایل پیکربندی سایفون. (در صورت وجود، سایر فلگ‌ها نادیده گرفته می‌شوند)
  -d string
        پوشه کاری (پیش‌فرض "./")
  -list
        نمایش کشورهای خروجی موجود از داده‌های محلی
  -p string
        URL پراکسی بالادستی SOCKS5 [فرمت: socks5://127.0.0.1:1080]
  -wo
        فقط Cloudflare WARP (WireGuard)
  -mo
        فقط Cloudflare MASQUE (HTTP/2)
  -mp
        Cloudflare MASQUE (HTTP/2) روی سایفون
  -pm
        سایفون روی Cloudflare MASQUE (HTTP/2)
  -pw
        سایفون روی Cloudflare WARP (WireGuard)
  -masque-sni string
        بازنویسی SNI مربوط به MASQUE (پیش‌فرض: consumer-masque.cloudflareclient.com)
  -masque-endpoint string
        بازنویسی نقطه اتصال MASQUE به صورت host:port (برای IPv6 به شکل [addr]:port؛ پیش‌فرض: 162.159.198.2:443)
  -warp-endpoint string
        بازنویسی نقطه اتصال WARP WireGuard به صورت host:port (برای IPv6 به شکل [addr]:port؛ پیش‌فرض: نقطه اتصال پروفایل)
  -scan-masque
        اسکن بازه‌های IPv4/IPv6 مربوط به MASQUE HTTP/2 برای یافتن نقطه اتصال سالم؛ خروجی در scan-masque.csv
  -scan-warp
        اسکن بازه‌های IPv4/IPv6 مربوط به WARP WireGuard برای یافتن نقطه اتصال سالم؛ خروجی در scan-warp.csv
```

هر دو `-masque-endpoint` و `-warp-endpoint` از IPv4 و IPv6 پشتیبانی می‌کنند. آدرس IPv6 باید داخل براکت باشد: `[2606:4700:102::1]:443`.

مثال‌ها:

```bash
./psiphon -list
./psiphon -c US
./psiphon -wo
./psiphon -mo
./psiphon -mp -c US
./psiphon -pm -c US
./psiphon -pw -c US
./psiphon -mo -masque-endpoint 162.159.198.2:443 -masque-sni consumer-masque.cloudflareclient.com
./psiphon -mo -masque-endpoint "[2606:4700:102::1]:443"
./psiphon -wo -warp-endpoint 162.159.192.1:2408
./psiphon -wo -warp-endpoint "[2606:4700:d0::1]:2408"
./psiphon -pw -c US -warp-endpoint 162.159.193.1:2408
./psiphon -pw -c US -warp-endpoint "[2606:4700:100::1]:2408"
./psiphon -scan-masque
./psiphon -scan-warp
```

فایل‌های هویت:
- WireGuard WARP: `data/warp/`
- MASQUE: `data/masque/`

## ساختن از سورس

اگر می‌خواهید پروژه را خودتان بسازید، باید Go را نصب کرده باشید.

```bash
# کلون کردن ریپازیتوری
git clone https://github.com/lord-aali/psiphon-tunnel-core.git
cd custom-psiphon-core

# ساخت پروژه
go build -buildvcs=false
```

## مشارکت

از مشارکت شما استقبال می‌شود! اگر پیشنهادی برای سرورهای جدید یا بهبود کد دارید، لطفاً یک issue باز کنید یا یک pull request ارسال نمایید.

## حمایت مالی

اگر می‌خواهید از این پروژه حمایت کنید، می‌توانید از طریق آدرس‌های ارز دیجیتال زیر کمک‌های خود را ارسال کنید:

*   **BTC**: `bc1quuj84xva5tn2rued5l2rk7hsk00w8cdyzp2qxt`
*   **TRX/USDT**: `TDtSRmzUy2dqDN3Toy2383c7YbjVmNDaX8`
*   **BNB**: `0x15fc1eb651e183924b7e8f3097c53f942a9f0d10`
*   **ETH**: `0x15fc1eb651e183924b7e8f3097c53f942a9f0d10`
