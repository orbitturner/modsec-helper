# 🚀 **ModSecurity Installer - Public Helper**
An automated tool to **install, configure, and manage** [ModSecurity](https://modsecurity.org) on an **Nginx** server running on Linux.

✅ **For System Administrators** → **One-command** installation and configuration  
✅ **For Developers** → **Extensible and customizable** with automated **GitHub Actions**  

---

# 📌 **Table of Contents**
- [🛠️ For System Administrators (Usage)](#for-system-administrators-usage)
  - [Quick Installation](#quick-installation)
  - [Usage](#usage)
  - [Examples](#examples)
  - [Updating](#updating)
- [💻 For Developers (Contributing & Automation)](#for-developers-contributing--automation)
  - [Project Setup](#project-setup)
  - [Compiling the Binary](#compiling-the-binary)
  - [GitHub Actions Automation](#github-actions-automation)
- [🔄 Customization](#customization)
- [🔧 Troubleshooting](#troubleshooting)
- [📜 License](#license)

---

# 🛠️ **For System Administrators (Usage)**  

### 📥 **Quick Installation**
On a **Linux machine**, install and run the script instantly with:

```bash
curl -sL https://github.com/orbitturner/modsec-helper/releases/latest/download/install_modsec -o install_modsec && chmod +x install_modsec && ./install_modsec
```
or with `wget`:
```bash
wget -qO install_modsec https://github.com/orbitturner/modsec-helper/releases/latest/download/install_modsec && chmod +x install_modsec && ./install_modsec
```

---

### ⚙️ **Usage**
The script will:
1. **Check if Nginx** is installed and prompt for installation if missing.
2. **Check if ModSecurity** (`libnginx-mod-security2`) is installed and proceed with installation if necessary.
3. **Download and configure** the **OWASP Core Rule Set (CRS)** for ModSecurity.
4. Apply a **security configuration profile** (`basic`, `strict`, `paranoid`).
5. **Restart Nginx** with the new security settings.

---

### 📌 **Examples**
- **Run the script with default settings**:  
  ```bash
  ./install_modsec
  ```

- **Specify a security profile** (`strict`, `paranoid`):  
  ```bash
  ./install_modsec --profile strict
  ```

- **Disable specific security rules** (e.g., `1001`, `1002`):  
  ```bash
  ./install_modsec --profile strict --disable-rules 1001 1002
  ```

- **Enable a specific rule** (`2001`):  
  ```bash
  ./install_modsec --enable-rules 2001
  ```

---

### 🔄 **Updating**
To **update to the latest version**, run:

```bash
curl -sL https://github.com/orbitturner/modsec-helper/releases/latest/download/install_modsec -o install_modsec && chmod +x install_modsec
```
or
```bash
wget -qO install_modsec https://github.com/orbitturner/modsec-helper/releases/latest/download/install_modsec && chmod +x install_modsec
```

---

# 💻 **For Developers (Contributing & Automation)**  

## 🛠️ **Project Setup**
Clone the repository:
```bash
git clone https://github.com/orbitturner/modsec-helper.git
cd modsec-helper/Linux/modsec-installer
```

Create and activate a **Python virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📦 **Compiling the Binary**
The script is compiled into a **standalone Linux binary** using **PyInstaller**:

```bash
pyinstaller --onefile --distpath ./bin install_modsec.py
```
This generates a **standalone binary** (`./bin/install_modsec`), which can be copied to any Linux server.

---

## 🚀 **GitHub Actions Automation**
The build process is automated using **GitHub Actions**, which:
- **Compiles** the script with **PyInstaller**.
- **Automatically increments** the version (`vX.Y.Z`).
- **Creates a GitHub Release** and uploads the binary.
- **Enables installation via `curl` or `wget`**.

### **Triggering a Manual Release**
To manually trigger a **new build and release**:
1. **Push a commit to `main`**:
   ```bash
   git add .
   git commit -m "fix: improved logging"
   git push origin main
   ```
2. **GitHub Actions will automatically compile and publish the new version.** 🎉

---

# 🔄 **Customization**  
Modify **ModSecurity security profiles** in `install_modsec.py` by adjusting the `PROFILES` dictionary:

```python
PROFILES = {
    "basic": {
        "description": "Basic profile with OWASP CRS default rules.",
        "rules": [
            "SecRuleEngine On",
            "Include /etc/nginx/modsec/coreruleset/crs-setup.conf",
            "Include /etc/nginx/modsec/coreruleset/rules/*.conf"
        ]
    },
    "strict": {
        "description": "More defensive rules enabled (SQLi, XSS).",
        "rules": [
            "SecRule REQUEST_HEADERS:User-Agent \"(?i:sqlmap)\" \"id:1001,deny,log,msg:'SQLMap Scan Detected'\""
        ]
    }
}
```

---

# 🔧 **Troubleshooting**

📌 **`Permission denied` error on the binary?** → Grant execution permissions:
```bash
chmod +x install_modsec
```

📌 **Python `ModuleNotFoundError`?** → Ensure dependencies are installed:
```bash
pip install -r requirements.txt
```

📌 **GitHub CLI (`gh`) not installed?** → Install it for managing releases:
```bash
sudo apt install gh
gh auth login
```

---

# 📜 **License**
📜 Distributed under the [MIT License](./LICENSE).  
📢 **Open-source and free to use** – Contributions are welcome! 🚀  

---

# 🚀 **Ready to Use!**
- 📥 **Instant installation** via `curl` or `wget`
- 🔄 **Auto-updates**
- 🏗 **Easily customizable**
- 🔥 **Automated releases with GitHub Actions**

💡 **Have questions or suggestions?** [Open an issue](https://github.com/orbitturner/modsec-helper/issues) or submit a PR! 😃🚀