using System.Text;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Reflection;

namespace cry_locker
{
    class CryLocker
    {
        /// <summary>
        /// Debugging flag used to disable encryption and enable file start and end headers to validate locker files.
        /// </summary>
        private static bool debug = false;

        /// <summary>
        /// Used to store the current icon status for loading.
        /// Used by GetLoading()
        /// </summary>
        private static string _icon = "|";

        private static Process? explorer;
        public const string extention = "cry_locker";
        static void Main(string[] args)
        {
            string loc = $"{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}";
            loc = new DirectoryInfo(loc).FullName;

            string? cmd = "";
            string? path = "";

            //Test hardcoding
            args = new string[1];
            //args[0] = @"C:\Users\Camer\Documents\VSProjects\cry_releases\New folder\.doc.fake.cry_locker";
            args[0] = @"C:\Users\Camer\Documents\VSProjects\cry_releases\New folder\.doc.fake.txt";

            if (args.Length == 1)
			{
				switch (EvalAction(args[0]))
				{
                    case EvalType.decrypt:
                        cmd = "decrypt";
                        path = args[0];
                        break;
                    case EvalType.encrypt_dir:
                        cmd = "encrypt";
                        path = args[0];
                        break;
                    case EvalType.encrypt_file:
                        cmd = "encrypt";
                        path = args[0];
                        break;
                }
            }
            else if(args.Length >= 2)
			{
                cmd = GetCmd(args[0]);
                path = args[1];
            }

			switch (cmd)
            {
                case "encrypt":
                    Encrypt(path);
                    break;

                case "decrypt":
                    Decrypt(path);
                    //clear = true;
                    break;

                case "help":
                    Console.WriteLine("" +
                        "-e/encrypt encrypts selected folder.\n" +
                        "-d/decrypt decrypts locker.\n" +
                        "examples:\n-e sensitive_clients.txt\n-e important_folder" +
                        "");
                    break;

                default:
                    Console.WriteLine($"Syntax invalid! use -h to see a list of commands");
                    break;


            }
        }

        private enum EvalType
		{
            decrypt,
            encrypt_file,
            encrypt_dir
		}

        private static EvalType? EvalAction(string path)
		{
            //Figure out if dir and file
            if (File.Exists(path) || Directory.Exists(path))
            {
                FileAttributes attr = File.GetAttributes(path);
                if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    if (Directory.Exists(path))
                        return EvalType.encrypt_dir;
                }
                else
                {
                    var f = new FileInfo(path);
                    if (f.Exists && f.Extension == $".{extention}")
                    {
                        return EvalType.decrypt;
                    }
                    else if (f.Exists)
                    {
                        return EvalType.encrypt_file;
                    }
                }
            }
            return null;
        }
        private static string? GetCmd(string? input)
        {
            try
            {
                string? t = input?.Trim();
                t = t?.Split(' ')[0].ToLower();

                switch (t)
				{
                    case "-e":
                        t = "encrypt";
                        break;
                    case "-d":
                        t = "decrypt";
                        break;
                    case "encrypt": break;
                    case "decrypt": break;
                    case "-h":
                        t = "help";
                        break;
                    case "help": break;
                    default:return null;
				}
                return t;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// Converts bytes to PB, TB, GB, MB, KB, B, all Rounded to 2 places.
        /// Can be used with dataSizePostFix() to get the postfix (i.e. GB)
        /// </summary>
        /// <param name="size">The value in bytes</param>
        /// <returns></returns>
        public static long DataSizeConverter(long bytes)
        {
            //{Math.Round(DM.Root.size > 1073741824 ? DM.Root.size / 1073741824 : DM.Root.size / 1048576, 2)} {(DM.Root.size > 1073741824 ? gb : mb)} in {Math.Round(DirManager.encryptionTime, 2)} seconds! ({Math.Round(((DM.Root.size / DirManager.encryptionTime) > 1073741824 ? DM.Root.size / 1073741824 : DM.Root.size / 1048576) / DirManager.encryptionTime)} {((DM.Root.size / DirManager.encryptionTime) > 1073741824 ? gb : mb)}/s)");
            if(bytes >= 1125899906842624)
            {
                //PB
                return bytes / 1125899906842624;
            }
            else if(bytes >= 1099511627776)
            {
                //TB
                return bytes / 1099511627776;
            }
            else if (bytes >= 1073741824)
            {
                //GB
                return bytes / 1073741824;
            }
            else if (bytes >= 1048576)
            {
                //MB
                return bytes / 1048576;
            }
            else if(bytes >= 1024)
            {
                //KB
                return bytes / 1024;
            }
            else
            {
                //Bytes
                return bytes;
            }
        }

        /// <summary>
        /// Returns the conversion post fix for a given bytes (to be used with dataSizeConverter())
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string DataSizePostFix(long bytes)
        {
            if (bytes >= 1125899906842624)
            {
                //PB
                return "PB";
            }
            else if (bytes >= 1099511627776)
            {
                //TB
                return "TB";
            }
            else if (bytes >= 1073741824)
            {
                //GB
                return "GB";
            }
            else if (bytes >= 1048576)
            {
                //MB
                return "MB";
            }
            else if (bytes >= 1024)
            {
                //KB
                return "KB";
            }
            else
            {
                //Bytes
                return "B";
            }
        }
        
        private static string GetLoading()
        {
            switch (_icon)
            {
                case "|":
                    _icon = "/";
                    break;
                case "/":
                    _icon = "-";
                    break;
                case "-":
                    _icon = @"\";
                    break;
                case @"\":
                    _icon = "|";
                    break;
                default:
                    return _icon;
            }
            return _icon;
        }

		private static void OpenFolder(string path)
		{
			string explorerPath = @"C:\Windows\explorer.exe";
			try
			{
				explorer = Process.Start(explorerPath, $"/root, {path}");
			}
			catch (Exception e)
			{
				Console.WriteLine(e);
				throw;
			}
		}

        /// <summary>
        /// Number of bytes (length of array)
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>byte[]</returns>
        private static byte[] GenerateRandomBytes(int bytes = 32)
		{
            return RandomNumberGenerator.GetBytes(bytes);
        }

        private static void Encrypt(string path)
        {
            bool isFolder = false;
            //DirectoryInfo? dir = null;
            //FileInfo? file = null;

            var type = EvalAction(path);

            if (type == EvalType.encrypt_dir || type == EvalType.encrypt_file)
            {
                if (type == EvalType.encrypt_dir)
                    isFolder = true;

				//Ask for password
				#region Password

                string? password = "abc";
				/*bool badPassword = true;
				Console.CursorVisible = true;
				while (badPassword)
				{
					Console.Write("Password:");
					string p1 = "";

					ConsoleKey k;
					do
					{
						var keyInfo = Console.ReadKey(true);
						k = keyInfo.Key;

						if (k == ConsoleKey.Backspace && p1.Length > 0)
						{
							Console.Write("\b \b");
							p1 = p1[0..^1];
						}
						else if (!char.IsControl(keyInfo.KeyChar))
						{
							Console.Write("*");
							p1 += keyInfo.KeyChar;
						}
					} while (k != ConsoleKey.Enter);

					p1 = p1.Trim();
					// Password Format 1 lower, upper, number, and symbol. Min 10 max 256
					if (p1 != null && Regex.IsMatch(p1, @"^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[^A-Za-z0-9])([^\s]){10,256}$"))
					{
						ConsoleClearLine();
						Console.Write("Confirm Password:");
						string? p2 = "";

						ConsoleKey k2;
						do
						{
							var keyInfo2 = Console.ReadKey(true);
							k2 = keyInfo2.Key;

							if (k2 == ConsoleKey.Backspace && p2.Length > 0)
							{
								Console.Write("\b \b");
								p2 = p2[0..^1];
							}
							else if (!char.IsControl(keyInfo2.KeyChar))
							{
								Console.Write("*");
								p2 += keyInfo2.KeyChar;
							}
						} while (k2 != ConsoleKey.Enter);

						p2 = p2?.Trim();
						if (p1 != null && p2 != null && p1 == p2)
						{
							password = p1;
							badPassword = false;
						}
						else
						{
							ConsoleClearLine();
							Console.WriteLine("Passwords don't match, try again!\n");
						}
					}
					else
					{
						ConsoleClearLine();
						Console.WriteLine("Passwords must contain 1 lower, upper, number and symbol with a minimum length of 10 (max 256)");
					}
				}*/
				#endregion

				ConsoleClearLine();
                Console.CursorVisible = true;
                Console.WriteLine("Loading...");

                //Setup locker and Direcotry Manager
                DirManager? DM = null;
                Locker? locker = new();

                string? ex = null;
                if (!isFolder)
                    ex = new FileInfo(path).Name;
                LockerConfig lc = new(isFolder, GenerateRandomBytes(), ex);
                locker.SetConfig(lc);
                if (isFolder)
                {
                    var dir = new DirectoryInfo(path);
                    locker.GenerateLocker(dir.FullName);
                    DM = new(dir);
                }
                else
                {
                    var file = new FileInfo(path);
                    locker.GenerateLocker(file.FullName);
                    DM = new(file);
                }

                locker.GenerateKey(password);

                //Clear password from RAM
                password = null;
                GC.Collect();

                ConsoleClearLine(1);
                //Begin encryption
                while (!DM.IsLoaded())
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write($"{GetLoading()} Discovering file(s)...");
                    Thread.Sleep(250);
                }

                new Thread(() => DM.Encrypt(locker, debug)).Start();

                //Wait for encryption
                ConsoleClearLine();
                while (!DM.IsEncrypted)
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    var fi = new FileInfo(locker.GetLockerFile().FullName);

                    //Prevent divide by zero crash
                    long t_length = 1;
                    if (fi.Length >= 1)
                        t_length = fi.Length;

                    long t_total = 1000;
                    if (DM.TotalBytes >= 1)
                        t_total = DM.TotalBytes;

                    //Display progress
                    Console.Write($"{GetLoading()} Encrypting: {Math.Round((((decimal)t_length / (decimal)t_total)) * 100, 2)}%");
                    Thread.Sleep(250);
                }

                

                //Check hashing

                var failed = DM.Failed;
                var total = DM.GetFileCount();
                var size = DM.TotalBytes;
                var encryptionTime = DM.EncryptionTime;
                
                bool isArchive = locker.IsArchive();
				if (total == failed.Count)
				{
					locker.DeleteLocker();
				}

                //Check for failed items
                if (failed.Count > 0)
                {
                    ConsoleClearLine();
                    if (!isArchive)
					{
                        Console.WriteLine($"Encryption failed!");
                        Console.WriteLine(failed[0].Exception.Message);
                    }
					else
					{
                        string ms = "ms";
                        string s = "s";
                        foreach (var f in failed)
                        {
                            Console.WriteLine($"{f.File.Path}{f.File.Name}");
                            Console.WriteLine($"{f.Exception.Message}\n");
                        }
                        if(total == failed.Count)
						{
                            Console.WriteLine($"Failed to encrypt all file(s)!");
                        }
						else
						{
                            Console.WriteLine($"Attempted to encrypt {total} file(s), {DataSizeConverter(size)} {DataSizePostFix(size)} in {Math.Round(encryptionTime >= 1000 ? encryptionTime / 1000 : encryptionTime)}{(encryptionTime >= 1000 ? s : ms)}! ({DataSizeConverter((long)(size / (encryptionTime / 1000)))} {DataSizePostFix((long)(size / (encryptionTime / 1000)))}/s), however {failed.Count} failed!");
                        }
                    }
                    Console.WriteLine("\nPress any key to continue...");
                    Console.ReadKey();
                }
                else
                {
                    ConsoleClearLine();
                    string ms = "ms";
                    string s = "s";
                    Console.WriteLine($"Encrypted {DataSizeConverter(size)} {DataSizePostFix(size)} in {Math.Round(encryptionTime >= 1000 ? encryptionTime / 1000 : encryptionTime)}{(encryptionTime >= 1000 ? s : ms)}! ({DataSizeConverter((long)(size / (encryptionTime / 1000)))} {DataSizePostFix((long)(size / (encryptionTime / 1000)))}/s)");
                    PromptToDelete(locker, DM);
                }
            }
			else
			{
				Console.WriteLine($"\"{path}\" does not exit. Please try again.");
				Console.WriteLine("Press any key to continue...");
				Console.ReadKey();
                ConsoleClearLine();

            }
		}

        public static void PromptToDelete(Locker locker, DirManager DM)
		{
            string type = (locker.IsArchive()) ? "folder" : "file";
            bool inputRecognised = false;
			while (!inputRecognised)
			{
                Console.Write($"Would you like to delete the original {type} (Y/N): ");

                string input = "";
                bool doContinue = true;
			    while (doContinue)
			    {
                    var key = Console.ReadKey();
                    if (key.Key != ConsoleKey.Enter)
                        input += key.KeyChar;
                    else doContinue = false;
                }
                ConsoleClearLine();
                input = input.ToLower();
			    switch (input)
			    {
                    case "y":
						//Delete
						if (locker.IsArchive())
						{
                            DM.RootDir.Self.Delete(true);
						}
						else
						{
                            DM.TargetFile.Delete();
						}
                        inputRecognised = true;
                        break;
                    case "n":
                        inputRecognised = true;
                        break;
				    default:
                        Console.WriteLine($"{input} is not recognised, please try again!");
					    break;
			    }
            }
        }

        public static long DirSize(DirectoryInfo d)
        {
            long size = 0;
            // Add file sizes.
            FileInfo[] fis = d.GetFiles();
            foreach (FileInfo fi in fis)
            {
                size += fi.Length;
            }
            // Add subdirectory sizes.
            DirectoryInfo[] dis = d.GetDirectories();
            foreach (DirectoryInfo di in dis)
            {
                size += DirSize(di);
            }
            return size;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="cleanPreviousLine"></param>
        public static void ConsoleClearLine(int linesBefore = 0)
        {
            int currentLineCursor = Console.CursorTop;
            Console.SetCursorPosition(0, Console.CursorTop - linesBefore);
            Console.Write(new string(' ', Console.WindowWidth));
            Console.SetCursorPosition(0, currentLineCursor - linesBefore);
        }

        private static void Decrypt(string path)
		{
			if (EvalAction(path) == EvalType.decrypt)
            {
                FileInfo file = new(path);

				//Ask for password
				#region password
				Console.Write("Password:");
                string password = "abc";

				/*ConsoleKey k;
				do
				{
					var keyInfo = Console.ReadKey(true);
					k = keyInfo.Key;

					if (k == ConsoleKey.Backspace && password.Length > 0)
					{
						Console.Write("\b \b");
						password = password[0..^1];
					}
					else if (!char.IsControl(keyInfo.KeyChar))
					{
						Console.Write("*");
						password += keyInfo.KeyChar;
					}
				} while (k != ConsoleKey.Enter);

				password = password.Trim();*/
                #endregion

                ConsoleClearLine();
                Console.WriteLine("Loading Locker...");

                DirManager.IsDecrypted = false;

                //Setup locker
                Locker locker = new(file);

                //locker.LoadConfig();
                locker.GenerateKey(password);
                if (locker.IsArchive())
                {
                    if (locker.LoadManifest(debug) == null)
                    {
                        ConsoleClearLine();
                        Console.WriteLine("Failed to load locker! Please check your password and try again!");
                        Console.WriteLine("Press any key to continue...");
                        Console.ReadKey();
                        ConsoleClearLine();
                        return;
                    }
                }

                string name = Regex.Replace(file.FullName, $"[.]{extention}$", "", RegexOptions.IgnoreCase);
                int index = 0;
                while (File.Exists(name) || Directory.Exists(name))
                {
                    index++;
                    if (index <= 1)
                        name = Regex.Replace(file.FullName, $"[.]{extention}$", "_decrypted", RegexOptions.IgnoreCase);
                    else name = Regex.Replace(file.FullName, $"[.]{extention}$", $"_decrypted({index})", RegexOptions.IgnoreCase);
                }

                //Setup output dir and start decrypt
                DirectoryInfo? outputDir = null;
                if (locker.IsArchive())
                    outputDir = Directory.CreateDirectory(name);

                new Thread(() => DirManager.DecryptFiles(locker, name, debug)).Start();

                ConsoleClearLine();

                Console.CursorVisible = false;
                while (!DirManager.IsDecrypted)
                {
                    Thread.Sleep(250);
                    Console.SetCursorPosition(0, Console.CursorTop);
                    if (locker.IsArchive())
                    {
                        var current = DirSize(new DirectoryInfo(name));
                        Console.Write($"{GetLoading()} Decrypting:{Math.Round(((decimal)current / (decimal)DirManager.TotalSize) * 100, 2)}%");
                    }
					else
					{
                        if (DirManager.DecryptingPath != "" && DirManager.DecryptingPath != null)
                        {
                            FileInfo decryption_file = new FileInfo(DirManager.DecryptingPath);
                            //$"{GetLoading()} Encrypting: {Math.Round(((decimal)fi.Length / (decimal)DM._totalBytes) * 100, 2)}%"
                            Console.Write($"{GetLoading()} Decrypting:{Math.Round(((decimal)decryption_file.Length / (decimal)DirManager.TotalSize) * 100, 2)}%");
                        }
                    }
                    
                    if (DirManager.DecryptFailed && DirManager.DecryptFailReason != null)
                    {
                        ConsoleClearLine();
                        Console.WriteLine("Decryption failed with reason:");
                        Console.WriteLine(DirManager.DecryptFailReason);
                        Console.WriteLine("Press any key to continue...");
                        if (outputDir != null)
                            outputDir.Delete(true);
                        Console.ReadKey();
                        ConsoleClearLine();
                        break;
                    }
                }
                Console.CursorVisible = true;

                if (outputDir != null && !DirManager.DecryptFailed)
                    OpenFolder(outputDir.FullName);
            }
            else
            {
                Console.WriteLine($"File \"{path}\" doesn't exit or is not a locker, please try again.");
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();
                ConsoleClearLine();
            }
        }
        
    }
}
