# cry_locker
An open source file encryptor that uses password derived AES256 keys (via Argon2).
Capable of encrypting and decrypting individual files or entire folders.

# To install:
1. Head to the <a href="https://github.com/TeaStudios/cry_locker/releases">releases</a> and download the latest version.
2. Extract the zip file into the desired installation path.
3. Run the setup.exe to configure your system.

# Use:
NOTE: We have gone to great effort to protect your data, the program will not overwrite existing files/folder when decrypting and will not automatically delete data after encrypting.
To encrypt, right click on a file/folder and select the "Encrypt" option, follow the onscreen prompts to encrypt.
To decrypt, open the locker file and follow the onscreen prompts.

# To uninstall
WARNING: DO NOT mess with the registry or the environment variables unless you know exactly what you are doing.
1. Delete the installation folder.
2. Search "env" in the start menu.
3. Open "Edit the system environment variables".
4. go to "environment Variables"->Path(System variables)->Edit.
5. Find the path to the installation folder and delete it.
6. Search "reg" in the start menu.
7. Open "Registry Editor".
8. Delete the registry keys associated with the program (see keys below)

# Registry Keys:
<br>Computer\HKEY_CLASSES_ROOT\Folder\shell\crylocker.exe
<br>Computer\HKEY_CLASSES_ROOT\SOFTWARE\Classes\*\shell\crylocker.exe
<br>Computer\HKEY_CLASSES_ROOT\SOFTWARE\Classes\.cry_locker\shell\cry_locker.exe
