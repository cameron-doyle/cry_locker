# cry_locker
An open source file encryptor that uses password derived AES256 keys (via Argon2).
Capable of encrypting and decrypting individual files or entire folders.

<strong>To install:</strong>
1. Head to the <a href="https://github.com/TeaStudios/cry_locker/releases">releases</a> and download the latest version.
2. Extract the zip file into the desired installation path.
3. Run the setup.exe to configure your system.

The setup process adds the following <strong>registry keys</strong> that can be deleted if the program in no longer used:
<br>Computer\HKEY_CLASSES_ROOT\Folder\shell\crylocker.exe
<br>Computer\HKEY_CLASSES_ROOT\SOFTWARE\Classes\*\shell\crylocker.exe
<br>Computer\HKEY_CLASSES_ROOT\SOFTWARE\Classes\.cry_locker\shell\cry_locker.exe
