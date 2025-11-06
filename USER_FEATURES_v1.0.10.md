# secure-string-cipher v1.0.10 - User Features & UX Guide

**Release Date**: November 6, 2025  
**Installation**: `pip install secure-string-cipher` or `pipx install secure-string-cipher`

---

## 🎯 **Core Features (What You Can Do)**

### **1. Text Encryption/Decryption** 📝
**What it does**: Encrypt messages and get a base64 string you can copy/paste
- Encrypts any text message with AES-256-GCM
- Output is a base64-encoded string (easy to share via email, chat, etc.)
- Decrypt back to original text with the same password

**Usage**:
```bash
cipher-start
# Choose option 1 (Encrypt text)
# Enter your message
# Enter password (+ confirm)
# Get base64 output to copy
```

**UX Notes**:
- Password confirmation required (prevents typos)
- Optional clipboard integration (auto-copy encrypted result)
- Base64 output is single-line (easy to copy/paste)

---

### **2. File Encryption/Decryption** 📁
**What it does**: Encrypt entire files (documents, images, archives, etc.)
- Streams files in chunks (handles large files without memory issues)
- Creates `.enc` file alongside original
- Preserves original file (doesn't delete it)
- Decrypt `.enc` files back to original

**Usage**:
```bash
cipher-start
# Choose option 3 (Encrypt file)
# Enter file path: /path/to/document.pdf
# Enter password (+ confirm)
# Creates: document.pdf.enc
```

**UX Notes**:
- Works with ANY file type (PDF, DOCX, ZIP, images, videos)
- Large file support (10MB, 100MB, 1GB+ - no problem)
- Original file kept intact
- `.enc` extension added (e.g., `report.pdf` → `report.pdf.enc`)

---

### **3. Passphrase Generator** 🔑
**What it does**: Generate cryptographically secure random passphrases
- **Word-based**: `mountain-tiger-ocean-basket-rocket-palace` (memorizable)
- **Alphanumeric + Symbols**: `xK9$mP2@qL5#vR8&nB3!` (maximum security)
- **Mixed**: `tiger-ocean-basket-palace-9247` (balanced)
- Shows entropy bits (measures password strength)

**Usage**:
```bash
cipher-start
# Choose option 5 (Generate passphrase)
# Select strategy [1/2/3]
# Get passphrase + entropy rating
```

**UX Notes**:
- Instant generation (< 1 second)
- Entropy calculation shows password strength
- Can save to encrypted vault immediately
- No network required (100% offline)

---

### **4. Passphrase Vault** 🔐
**What it does**: Securely store passphrases in encrypted vault
- AES-256-GCM encrypted vault file
- Protected by master password
- Store, retrieve, list, update, delete passphrases
- Vault file has restricted permissions (user-only: 600)

**Usage**:
```bash
# After generating a passphrase, you can store it:
cipher-start
# Generate passphrase (option 5)
# Then option 6 to store in vault
# Enter label: "project-x-backup"
# Enter master password
```

**Vault Features**:
- **Store**: Save passphrases with custom labels
- **Retrieve**: Get stored passphrase by label
- **List**: View all stored labels
- **Update**: Change existing passphrase
- **Delete**: Remove from vault

**UX Notes**:
- Master password required for all vault operations
- Vault location: `~/.local/share/secure-string-cipher/passphrase_vault.json`
- Encrypted even at rest
- Labels are searchable (e.g., "work-vpn", "backup-2025")

---

## 🎨 **User Experience Features**

### **Interactive Menu System**
```
Available Operations:
  1. Encrypt text          - Encrypt a message (returns base64 string)
  2. Decrypt text          - Decrypt a base64 encrypted message
  3. Encrypt file          - Encrypt a file (creates .enc file)
  4. Decrypt file          - Decrypt an encrypted file
  5. Generate passphrase   - Create a secure random passphrase
  6. Exit                  - Quit the program

Select operation [1-6]:
```

**UX Highlights**:
- ✅ Clear descriptions for each option
- ✅ Color-coded output (success=green, info=cyan, error=red)
- ✅ Password strength feedback
- ✅ Progress indicators for file operations
- ✅ Helpful error messages

---

### **Security Features (Behind the Scenes)**

1. **AES-256-GCM Encryption**
   - Industry-standard symmetric encryption
   - Authenticated encryption (detects tampering)
   - 256-bit keys (strongest practical encryption)

2. **PBKDF2 Key Derivation**
   - 390,000 iterations (OWASP recommended 2023+)
   - Makes brute-force attacks computationally expensive
   - Random salt per encryption (prevents rainbow tables)

3. **File Security**
   - Vault permissions: 600 (owner read/write only)
   - No plaintext password storage
   - Secure memory wiping after use

4. **Path Security**
   - Filename sanitization (prevents path traversal)
   - Symlink detection (prevents symlink attacks)
   - Sensitive directory detection (won't run in /etc, ~/.ssh)
   - Root/sudo execution prevention

---

## 🐳 **Docker Usage**

**Quick Start**:
```bash
# Run interactively
docker run --rm -it ghcr.io/theredtower/secure-string-cipher:latest

# Encrypt files in current directory
docker run --rm -it \
  -v "$PWD:/data" \
  ghcr.io/theredtower/secure-string-cipher:latest

# With persistent vault
docker run --rm -it \
  -v "$PWD:/data" \
  -v cipher-vault:/home/cipheruser/.secure-cipher \
  ghcr.io/theredtower/secure-string-cipher:latest
```

**Docker Features**:
- ✅ 78MB image size (Alpine-based)
- ✅ Runs as non-root user (secure by default)
- ✅ 0 critical/high/medium vulnerabilities
- ✅ Python 3.14 support
- ✅ Multi-stage build (minimal attack surface)

---

## 📋 **Common Workflows**

### **Workflow 1: Secure Document Sharing**
```bash
1. cipher-start
2. Select option 3 (Encrypt file)
3. Enter file path: confidential-report.pdf
4. Enter password: MyStrongP@ssw0rd!
5. Share: confidential-report.pdf.enc + password (separately)
6. Recipient decrypts with option 4
```

### **Workflow 2: Generate & Store Password**
```bash
1. cipher-start
2. Select option 5 (Generate passphrase)
3. Choose strategy 1 (word-based)
4. Get: mountain-tiger-ocean-basket-rocket-palace
5. Option 6: Store in vault
6. Label: "work-vpn-2025"
7. Enter master password
8. Done! Password safely stored
```

### **Workflow 3: Retrieve Stored Password**
```bash
1. cipher-start
2. Navigate to vault menu
3. Select "Retrieve passphrase"
4. Enter label: "work-vpn-2025"
5. Enter master password
6. Get decrypted passphrase
```

---

## 🆕 **What Changed in Recent Versions**

### **v1.0.10 (Current)** - Infrastructure & Quality
- 🔒 Security scanning added (detect-secrets, pip-audit)
- 🧪 150 tests in organized structure
- ✨ All linting/type errors fixed
- 🐳 Python 3.14 support confirmed
- **No UX changes** - purely internal improvements

### **v1.0.9** - Secure File Operations
- ✅ Secure temporary file creation
- ✅ Atomic file writes (no partial files)
- ✅ Better file permission handling
- **UX Impact**: More reliable file encryption/decryption

### **v1.0.8** - Privilege Checking
- ✅ Prevents running as root/sudo
- ✅ Detects execution in sensitive directories (/etc, ~/.ssh)
- **UX Impact**: Better security warnings

### **v1.0.7** - Path Security
- ✅ Path validation (prevents directory traversal)
- ✅ Symlink attack detection
- **UX Impact**: More secure file handling

### **v1.0.6** - Filename Safety
- ✅ Filename sanitization (removes dangerous characters)
- ✅ Unicode attack prevention
- **UX Impact**: Safer file naming

### **v1.0.4** - Major Feature Release
- ✨ **NEW**: Passphrase generator (3 strategies)
- ✨ **NEW**: Encrypted vault for password storage
- ✨ **NEW**: Menu option 5 (Generate passphrase)
- 🐳 Docker image security overhaul (78MB, Alpine-based)
- **UX Impact**: Major new features added!

### **v1.0.2** - UX Improvements
- ✨ Descriptive menu with clear operation descriptions
- **UX Impact**: Much clearer what each option does

### **v1.0.1** - Command Rename
- ✨ Command changed: `secure-string-cipher` → `cipher-start`
- **UX Impact**: Easier to type, more memorable

---

## 🎯 **Testing Checklist for You**

### **Basic Operations**
- [ ] Text encryption (option 1)
- [ ] Text decryption (option 2)
- [ ] File encryption (option 3) - try PDF, DOCX, image
- [ ] File decryption (option 4)
- [ ] Generate passphrase - word-based (option 5, choice 1)
- [ ] Generate passphrase - alphanumeric (option 5, choice 2)
- [ ] Generate passphrase - mixed (option 5, choice 3)

### **Vault Operations**
- [ ] Store passphrase in vault
- [ ] Retrieve passphrase from vault
- [ ] List all stored passphrases
- [ ] Update existing passphrase
- [ ] Delete passphrase from vault

### **Edge Cases**
- [ ] Wrong password on decryption (should fail gracefully)
- [ ] Empty password (should reject)
- [ ] Non-matching password confirmation (should reject)
- [ ] Non-existent file (should show clear error)
- [ ] Large file encryption (100MB+)
- [ ] Unicode in filenames
- [ ] Spaces in filenames

### **Docker Testing**
- [ ] Run in Docker container
- [ ] Encrypt file from mounted volume
- [ ] Decrypt file in Docker
- [ ] Persistent vault with named volume

---

## 🔍 **What to Look For (Feedback Areas)**

### **UX/Usability**
1. Is the menu clear and intuitive?
2. Are prompts descriptive enough?
3. Do error messages help you understand what went wrong?
4. Is password confirmation annoying or helpful?
5. Are file paths easy to enter (relative vs absolute)?
6. Should clipboard integration be automatic or optional?

### **Features**
1. Missing features you expected?
2. Features you don't understand?
3. Would you prefer different passphrase strategies?
4. Is vault location intuitive?
5. Should there be a --help flag?

### **Performance**
1. How fast is text encryption? (should be instant)
2. How fast is file encryption? (depends on file size)
3. Any noticeable delays?
4. Large file handling smooth?

### **Security**
1. Do security warnings make sense?
2. Too many or too few prompts?
3. Is master password flow clear?
4. Concerned about any security aspects?

### **Docker**
1. Image pull/run smooth?
2. Volume mounting intuitive?
3. Vault persistence working?
4. Any permissions issues?

---

## 🚀 **Quick Start for Testing**

```bash
# Install
pipx install secure-string-cipher

# Basic test
cipher-start

# Try encrypting a message (option 1)
# Message: "Hello World"
# Password: test123

# Try generating passphrase (option 5)
# Choice: 1 (word-based)

# Try encrypting a file (option 3)
# File: some_document.txt
# Password: test123

# Try decrypting (option 4)
# File: some_document.txt.enc
# Password: test123
```

---

## 📞 **Feedback Template**

When you test, consider noting:

**What Worked Well**:
- 
- 

**Confusing/Unclear**:
- 
- 

**Feature Requests**:
- 
- 

**Bugs/Issues**:
- 
- 

**UX Suggestions**:
- 
- 

---

## 🎁 **Pro Tips**

1. **Use pipx instead of pip**: `pipx install secure-string-cipher` (isolated environment)
2. **Docker for untrusted files**: Run in container for extra security layer
3. **Vault master password**: Use passphrase generator to create your master password!
4. **Backup vault**: Copy `~/.local/share/secure-string-cipher/` to secure location
5. **Long passwords**: Word-based passphrases are easier to remember than random characters

---

**Version**: 1.0.10  
**Last Updated**: November 6, 2025  
**Questions?**: Open an issue on GitHub or provide feedback after testing!
