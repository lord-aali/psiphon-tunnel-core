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
Usage: psiphon [-b addr:port] [-c country] [-p proxy] [-wo|-mo|-mp|-pm|-pw] [-masque-h3] [-masque-smart] [-masque-fragment] [-masque-sni sni] [-masque-endpoint ip:port] [-warp-endpoint ip:port] [-scan-masque|-scan-warp] [-list]

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
        فقط Cloudflare MASQUE
  -mp
        Cloudflare MASQUE روی سایفون
  -pm
        سایفون روی Cloudflare MASQUE
  -pw
        سایفون روی Cloudflare WARP (WireGuard)
  -masque-h3
        استفاده از MASQUE روی HTTP/3 (QUIC) به‌جای HTTP/2 (پیش‌فرض نقطه اتصال 162.159.198.1:443)
  -masque-smart
        ترجیح HTTP/3، بازگشت به HTTP/2 (fragment فقط اگر SNI بدون آن فیلتر شود)، و اسکن خودکار نقطه اتصال اگر پیش‌فرض‌ها (و نقطه ذخیره‌شده) در دسترس نباشند
  -masque-fragment
        تکه‌تکه کردن TLS ClientHello در MASQUE HTTP/2 (فقط TCP؛ با -masque-h3 نادیده گرفته می‌شود)
  -masque-fragment-size string
        بازه اندازه تکه‌ها به بایت (پیش‌فرض "16-32")
  -masque-fragment-delay string
        بازه تأخیر تکه‌ها به میلی‌ثانیه (پیش‌فرض "2-10")
  -masque-sni string
        بازنویسی SNI مربوط به MASQUE (پیش‌فرض: consumer-masque.cloudflareclient.com)
  -masque-endpoint string
        بازنویسی نقطه اتصال MASQUE به صورت host:port (برای IPv6 به شکل [addr]:port؛ پیش‌فرض H2: 162.159.198.2:443، H3: 162.159.198.1:443)
  -warp-endpoint string
        بازنویسی نقطه اتصال WARP WireGuard به صورت host:port (برای IPv6 به شکل [addr]:port؛ پیش‌فرض: نقطه اتصال پروفایل)
  -scan-masque
        اسکن بازه‌های MASQUE به سبک Aether (seed، نمونه CIDR، پورت‌های جایگزین، تأیید data-plane)؛ با -masque-h3 برای HTTP/3؛ خروجی scan-masque.csv
  -scan-warp
        اسکن بازه‌های WARP WireGuard به سبک Aether (seed، نمونه CIDR، پورت‌های UDP چرخشی، handshake)؛ خروجی scan-warp.csv
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
./psiphon -mo -masque-h3
./psiphon -mo -masque-smart
./psiphon -mo -masque-h3 -masque-endpoint 162.159.198.1:443
./psiphon -mo -masque-fragment
./psiphon -mo -masque-endpoint "[2606:4700:102::1]:443"
./psiphon -scan-masque -masque-h3
./psiphon -wo -warp-endpoint 162.159.192.1:2408
./psiphon -wo -warp-endpoint "[2606:4700:d0::1]:2408"
./psiphon -pw -c US -warp-endpoint 162.159.193.1:2408
./psiphon -pw -c US -warp-endpoint "[2606:4700:100::1]:2408"
./psiphon -scan-masque
./psiphon -scan-warp
```

فایل‌های هویت:
- WireGuard WARP: `data/warp/`
- MASQUE: `data/masque/` (`config.json` شامل `endpoint_h2_v4`، `protocol` (`h3`/`h2`) و `fragment`)

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
