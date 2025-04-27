# 🌟 Aurora FileManager – PHP File Manager

**Aurora FileManager** is a modern PHP file manager focused on performance and security.
It offers quick file operations, malware detection, permission management, and a responsive dark mode interface.


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
Feel free to open a [pull request](https://github.com/AuroraFileManager/AuroraFileManager.github.io/pulls) or [issue](https://github.com/AuroraFileManager/AuroraFileManager.github.io/issues).

---

**Built with ❤️ for developers.**
