# Web SEO Analyzer

خزنده فنی SEO بدون API پولی برای اجرای زمان‌بندی‌شده در Cursor Automations.

## قابلیت‌ها

- Crawl محدود و محترمانه با رعایت `robots.txt`
- بررسی وضعیت HTTP، ریدایرکت زنجیره‌ای و لینک‌های داخلی قابل Crawl
- بررسی Title، Description، H1، Canonical، Noindex و محتوای کم‌حجم
- استخراج JSON-LD Schema
- خواندن Sitemap و شناسایی صفحات یتیم احتمالی
- تشخیص Title و Description تکراری
- پیشنهاد اولیه لینک داخلی بر اساس هم‌پوشانی موضوعی
- مقایسه یافته‌ها با آخرین اجرای ثبت‌شده
- بررسی صفحات عمومی رقبا در روز دوشنبه
- تولید گزارش فارسی در `seo-reports/YYYY-MM-DD.md` و `seo-reports/latest.md`

این ابزار رتبه گوگل، حجم جستجو، ترافیک، Authority، بک‌لینک یا Core Web Vitals
واقعی تولید نمی‌کند؛ این داده‌ها بدون منبع خارجی معتبر قابل استخراج نیستند.

## تنظیمات

فایل `seo-audit.config.json` را ویرایش کنید:

```json
{
  "site_url": "https://anadarman.com/",
  "competitor_urls": [
    "https://competitor-one.example/",
    "https://competitor-two.example/"
  ],
  "timezone": "Asia/Tehran",
  "max_pages_per_site": 30
}
```

مقادیر `competitor_urls` نمونه هستند؛ فقط URLهای واقعی را وارد کنید.

## اجرا

Python 3.9 یا جدیدتر لازم است و کتابخانه جانبی نیاز نیست:

```bash
python3 seo_audit.py
```

برای اجرای بررسی رقبا خارج از روز دوشنبه:

```bash
python3 seo_audit.py --include-competitors
```

اجرای تست‌ها:

```bash
python3 -m unittest discover -s tests -v
```

متن آماده Automation در [AUTOMATION_PROMPT.md](AUTOMATION_PROMPT.md) قرار دارد.

## محدودیت و ایمنی

- فقط URLهای عمومی `http` و `https` دریافت می‌شوند؛ مقصدهای private و localhost رد می‌شوند.
- سقف صفحات، اندازه پاسخ، timeout و فاصله درخواست‌ها قابل تنظیم‌اند.
- «صفحه یتیم احتمالی» فقط بر اساس Sitemap و Crawl محدود گزارش می‌شود.
- پیشنهاد لینک داخلی نیازمند بازبینی انسانی محل قرارگیری لینک است.
- گزارش برنامه جایگزین داده Search Console یا ابزار تخصصی بک‌لینک نیست.
