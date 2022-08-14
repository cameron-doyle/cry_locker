# cry_locker
An open source file encryptor that uses password derived AES256 keys (via Argon2).
Capable of encrypting and decrypting individual files or entire folders.

To install:
1. Head to the releases and download the latest version.
2. Extract the zip file into the desired installation path.
3. Run the setup.exe to configure your system.

The setup process adds the following registry keys that can be deleted if the program in no longer used:
Computer\HKEY_CLASSES_ROOT\Folder\shell\crylocker.exe
Computer\HKEY_CLASSES_ROOT\SOFTWARE\Classes\*\shell\crylocker.exe
Computer\HKEY_CLASSES_ROOT\SOFTWARE\Classes\.cry_locker\shell\cry_locker.exe
