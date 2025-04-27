# 🌟 AuroraFile – PHP File Manager

**AuroraFile** is a lightweight, modern PHP file manager built for easy file management with style.  
It features a beautiful iOS-like glass UI, recursive malware scanning, quick actions, and dark mode toggle.

---

## ✨ Features
- ✅ Glass‑blur UI (Bootstrap 5.3)
- ✅ Quick actions: Upload, New File, New Folder, CHMOD, Malware Scan
- ✅ Recursive malware scanner with **backdoor detection**
- ✅ Dark‑mode toggle (persists automatically)
- ✅ MIT Licensed – free to use!

---

## 🚀 Getting Started

1. **Upload** `Aurora.php` to your server.
2. Open the file in your browser.
3. Start managing files like a boss. 😎

---

## 🛡️ Malware Scanner

AuroraFile scans recursively for suspicious PHP patterns:
- Dangerous functions: `eval()`, `exec()`, `assert()`, etc.
- Obfuscation techniques: `base64_decode()`, `gzinflate()`
- Webshell names: `b374k`, `c99shell`, `wso`
- Variable-variable attacks (`$$var`)
- Backdoor behaviors (`include($_GET['x'])`)

---

## 📂 Screenshot

![image](https://github.com/user-attachments/assets/1094987f-e84b-44d3-95ee-560128ac3ebd)

---

## ⚡ Tech Stack
- PHP 8+
- Bootstrap 5.3
- FontAwesome 6
- Vanilla JS (tiny bits)

---

## 📄 License

AuroraFile is open-sourced under the [MIT License](LICENSE).

---

## 💬 Feedback & Contributions

Contributions, issues, and feature requests are welcome!  
Feel free to open a [pull request](https://github.com/your-repo/aurorafile/pulls) or [issue](https://github.com/your-repo/aurorafile/issues).

---

**Built with ❤️ for developers.**
