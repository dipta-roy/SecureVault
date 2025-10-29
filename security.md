# SecureVault Password Manager: Your Security Explained

## Welcome to SecureVault!
We built SecureVault with your privacy and security as our top priorities. This document is designed to give you a clear understanding of how SecureVault protects your valuable information, why we made certain design choices, and what you can do to maximize your security. Think of this as a transparent look under the hood, from the developers who created it for you.

## Our Commitment to Your Security
Your trust is paramount. SecureVault is engineered from the ground up to be a highly secure, local-only password manager. We've focused on robust encryption and secure data handling to keep your passwords safe on your device, without ever sending them over the internet.

## How We Protect Your Passwords (Key Security Features)
We've implemented several layers of protection to keep your data safe:

*   **Your Data Stays Local**: SecureVault never connects to the internet. Your passwords are encrypted and stored only on your device, meaning no cloud servers, no online accounts, and no external vulnerabilities.
*   **Military-Grade Encryption**: We use AES-256-GCM, a highly respected encryption standard, to scramble your passwords. This ensures that only you, with your master password, can access them. It also verifies that your data hasn't been tampered with.
*   **Super Strong Master Password Protection**: When you set your master password, we don't just store it. We use advanced techniques like Argon2id (or PBKDF2-HMAC-SHA256 as a backup) to turn your password into a super-strong encryption key. These methods are designed to make it incredibly difficult for anyone to guess your password, even with powerful computers.
*   **Secure Storage on Your Device**: Your encrypted vault file is stored in a special folder (`~/.securevault/`) with strict permissions. This means only your user account can read or write to it. We also save your data very carefully, making sure that even if your computer crashes, your vault won't get corrupted.
*   **Safe Biometric (Fingerprint/PIN) Access**: If your device supports it (like Windows Hello, Touch ID, or Linux fingerprint readers), you can use biometrics for quick unlocking. We integrate this responsibly, always asking for your permission first, and ensuring your master password is never directly stored by the biometric system.
*   **Careful Browser Imports**: If you want to import passwords from your web browser, we handle this with extreme caution. We always ask for your explicit consent, and on Windows, we use your operating system's built-in security features to safely access your browser's stored passwords.
*   **Smart User Interface Security**: Our app includes features like:
    *   **Password Strength Checker**: Helps you create strong master passwords.
    *   **Auto-Lock**: Locks your vault after a period of inactivity.
    *   **Clipboard Auto-Clear**: Automatically removes copied passwords from your clipboard after a short time.
    *   **Hidden Passwords**: Passwords are masked by default in the display.
    *   **Secure Password Generator**: Creates truly random and strong passwords for you.
*   **Activity Logs**: We keep a local log of important security actions (like login attempts or when you import/export data). This helps you keep track of what's happening with your vault.

## Important Security Considerations (What You Should Know)

### Where Your Vault is Stored
*   **What we do**: Your encrypted vault file (`vault.enc`) and related security files are stored in a standard, easy-to-find location on your computer: `~/.securevault/`.
*   **Why we do it**: This makes it simple for you to find your vault for backups or if you ever need to move it. While the location is known, we've put strict security permissions on these files so that only your user account can access them. We assume your computer's operating system is secure; if an attacker has full control over your computer, they might be able to bypass these protections. Making the location customizable would add complexity for most users and could make backups and restores more difficult.

### Exporting Your Passwords (CSV)
*   **What we do**: SecureVault allows you to export your passwords into a CSV file.
*   **Why we do it**: We know you might need to move your passwords to another manager or keep a human-readable backup. This feature gives you that flexibility.
*   **Important Note**: When you export to CSV, the file is *not* encrypted. We show you a very clear warning about this. Please treat these files with extreme caution, store them securely, and delete them once you no longer need them. This is a trade-off between convenience and security, and we rely on you to handle these files responsibly.

### Your Master Password is Key (No "Pepper")
*   **What we do**: Your master password, combined with a unique "salt" (a random value), creates the key that encrypts your vault. We don't use an additional "device-specific secret" (sometimes called a "pepper").
*   **Why we do it**: Adding a "pepper" would make it even harder for someone to decrypt your vault if they stole it and tried to open it on a different computer. However, securely managing such a secret across different operating systems (Windows, macOS, Linux) without relying on specialized hardware (which isn't always available or easy to use with Python) is very complex. We've chosen to prioritize making SecureVault work smoothly on many systems, relying on the extreme strength of your master password and our advanced key derivation methods to keep your vault safe.

### How We Handle Sensitive Data in Memory
*   **What we do**: When your vault is unlocked, your passwords and the encryption key are temporarily held in your computer's memory. When you lock your vault, we make our best effort to erase this sensitive data from memory.
*   **Why we do it**: Programming languages like Python, which SecureVault is built with, manage memory automatically. This makes it very difficult to *guarantee* that sensitive information is instantly and completely wiped from memory. While we take steps to clear this data, a highly sophisticated attacker with access to your computer's memory might theoretically be able to recover fragments. We focus on strong encryption and other security measures, assuming that your operating system is generally secure.

### Biometric (Fingerprint/PIN) Security
*   **What we do**: SecureVault integrates with your device's biometric features (like Windows Hello or Touch ID) for convenient unlocking.
*   **Why we do it**: We know that quick and easy access is important to you. This feature is designed to make using SecureVault more convenient. However, it's crucial to understand that this relies on your operating system's security. If your operating system's biometric system is compromised, your vault could be at risk. We always advise you to keep your device's security strong (e.g., using BitLocker, secure boot, and strong login credentials).

### How Your PIN is Protected
*   **What we do**: If you set up a PIN for quick access, we don't store your PIN directly. Instead, we use a strong method called PBKDF2-HMAC-SHA256 with 100,000 "iterations" (repeated calculations) to create a secure hash of your PIN.
*   **Why we do it**: This number of iterations makes it very difficult for someone to guess your PIN, even if they somehow got hold of the hash. We've chosen 100,000 iterations as a good balance between strong security and ensuring that unlocking with your PIN is still fast enough for a smooth user experience, even on older computers. Increasing this number further would make it even more secure but could noticeably slow down your login time.

### Your Activity Logs
*   **What we do**: SecureVault keeps a local `audit.log` file in your `~/.securevault/` folder. This log records important actions like when you log in, import data, or export passwords.
*   **Why we do it**: This log is there to help you monitor activity and troubleshoot any issues. It's stored in plain text, which makes it easy for you to read. While we could make it more complex by adding integrity checks, our main focus is on protecting your vault's contents. If your computer is compromised to the point where an attacker can modify these logs, they likely have deeper access that log protection wouldn't prevent.

### How Windows Hello Works (Behind the Scenes)
*   **What we do**: For Windows users, we've worked hard to integrate directly with Windows Hello for a smooth biometric experience.
*   **Why we do it**: To make this work seamlessly without requiring you to install extra software or complex components, we use a clever method that involves a small, temporary piece of code (written in C#) that helps SecureVault talk to Windows Hello. This is a bit complex under the hood, but it allows us to give you native Windows Hello support, which was a key goal for us. We believe this is the most practical way to offer this feature while keeping the application lightweight.

### Protection Against Advanced Attacks
*   **What we do**: SecureVault focuses on protecting your data from common threats like brute-force attacks and unauthorized access to your vault file. We don't specifically implement defenses against highly advanced "side-channel attacks" (like analyzing power consumption or timing differences).
*   **Why we do it**: These types of attacks are extremely difficult to defend against, especially in a programming language like Python. They usually require specialized equipment and very low-level programming, which would make SecureVault incredibly complex and slow. Our design assumes that your computer's environment is generally secure, and we prioritize protecting against the most common and practical threats you might face.

### Antivirus Warnings (False Positives)
*   **What we do**: You might occasionally see a warning from your antivirus software about SecureVault.
*   **Why we do it**: This can happen for a few reasons:
    *   **Browser Access**: When SecureVault imports passwords from your browser (with your permission!), it needs to access your browser's password database. This behavior can sometimes look suspicious to antivirus programs, even though it's legitimate.
    *   **Windows Hello**: Our clever way of integrating with Windows Hello (using temporary code) can also sometimes trigger warnings.
    *   **Standalone App**: We package SecureVault into a single, easy-to-run file using a tool called PyInstaller. Sometimes, antivirus software can be overly cautious with these types of packaged applications.
*   **Rest assured**: These are "false positives." SecureVault is open-source, meaning anyone can inspect its code to confirm it's safe. We've designed these features because they're important for the app's functionality and your convenience. If you encounter a warning, you can safely add SecureVault to your antivirus's allowed list.

## Understanding SecureVault's Design (Our Threat Model)
It's important to understand what SecureVault is designed to protect against, and what it isn't. We call this our "threat model":

*   **Protection Focus**: SecureVault's main job is to protect your encrypted password vault file from unauthorized access *on your own, secure device*.
*   **Local-Only Protection**: Since SecureVault never connects to the internet, it naturally protects you from online attacks. However, it doesn't protect against threats that might come from your network if your device itself is compromised.
*   **Your Device's Security Matters**: We assume that the computer you're running SecureVault on is generally secure. SecureVault cannot protect you from threats like:
    *   **Keyloggers**: Software that records your keystrokes (including your master password).
    *   **Memory Dumps**: Advanced attacks that try to read your computer's memory.
    *   **Compromised Operating System**: If your operating system itself is infected or controlled by an attacker.
*   **Your Consent is Key**: SecureVault will always ask for your explicit permission before performing sensitive actions like importing browser passwords or setting up biometrics. It is strictly for your personal use on devices you own and administer.
*   **File System Access**: While we set strong permissions on your vault files, an attacker with full administrative control over your computer could potentially bypass these.

## Future Improvements We're Considering
We're always looking for ways to make SecureVault even better and more secure. Here are some enhancements we're thinking about for future versions:

*   **Custom Vault Locations**: Giving you the option to choose exactly where your vault files are stored.
*   **Encrypted CSV Exports**: Adding a feature to encrypt your CSV exports with a password, for an extra layer of security.
*   **Hardware-Backed Security**: Exploring ways to use specialized hardware in your computer (like TPMs) to make your vault even more resistant to advanced attacks.
*   **Tamper-Proof Activity Logs**: Improving the activity logs so they can't be secretly changed.
*   **Customizable PIN Security**: Allowing you to adjust the security level for your PIN, balancing speed and protection.
*   **Even Smoother Windows Hello**: Continuously looking for the best and most robust ways to integrate with Windows Hello.