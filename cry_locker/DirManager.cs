using System.Collections;
using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.Json;
using System.ComponentModel;
using System.Text.RegularExpressions;
using crylocker;
using Konscious.Security.Cryptography;
using System.Security.Permissions;

/// <summary>
/// Represents and manages a directory structure including sub dirs.
/// Handles their encryption/decryption.
/// </summary>
public class DirManager
{
	#region Members
	/// <summary>
	/// The root directory (folder encryption)
	/// </summary>
	public Dir? RootDir { get; private set; }

	/// <summary>
	/// The "Target" file to be encrypted (single file encryption)
	/// </summary>
	public FileInfo? TargetFile { get; private set; }

	/// <summary>
	/// Used to flag if the encryption is complete or not.
	/// </summary>
	public bool IsEncrypted { get; private set; }

	/// <summary>
	/// The total number of bytes to be encrypted. Defaults to 1000 for display reasons.
	/// </summary>
	public long TotalBytes = 1000;

	/// <summary>
	/// The total number of milliseconds that elapsed during encryption.
	/// </summary>
	public double EncryptionTime { get; private set; }

	/// <summary>
	/// A list of files that failed to encrypt.
	/// </summary>
	public List<FailedItem> Failed = new List<FailedItem>();
	#endregion

	#region Boring methods
	/// <summary>
	/// Constructor for DirManager
	/// </summary>
	/// <param name="rootDir">The root directory to be encrypted (folder encryption)</param>
	public DirManager(DirectoryInfo rootDir, bool threaded = false)
	{
		if (threaded)
		{
			new Thread(() =>
			{
				RootDir = new Dir(this, rootDir);
			}).Start();
		}
		else RootDir = new Dir(this, rootDir);
	}
	/// <summary>
	/// Constructor for DirManager
	/// </summary>
	/// <param name="targetFile">The file to be encrypted (single file encryption)</param>
	public DirManager(FileInfo targetFile)
	{
		TargetFile = targetFile;
	}

	/// <summary>
	/// Probes all files and subfolders of the _rootDir to see if everything is ready.
	/// Returns true if _rootDir is null (single file encryption)
	/// </summary>
	/// <returns>true/false</returns>
	public bool IsLoaded()
	{
		if ((RootDir == null && TargetFile == null) || (RootDir != null && !RootDir.IsLoaded()))
		{
			//if Both rootDir and Target and null (Means rootdir is still loading)
			//Or rootdir is loaded (Single thread) and IsLoaded returns false;
			return false;
		}
		else
		{
			return true;
		}
		//return (RootDir == null) ? true: RootDir.IsLoaded();
	}

	/// <summary>
	/// Returns all files in the DirManager (even if single file encryption is being performed)
	/// </summary>
	/// <returns>List of files (represented in ourfile entities)</returns>
	private List<OurFile> GetFiles()
	{
		if(TargetFile != null)
		{
			var temp = new List<OurFile>();
			temp.Add(new OurFile(TargetFile, this));
			return temp;
		}else if(RootDir != null)
		{
			return RootDir.GetFiles();
		}
		else
		{
			throw new Exception("Both TargetFile and RootDir are null");
		}
	}

	/// <summary>
	/// Returns the number of files stored in DirManager
	/// </summary>
	/// <returns>a number</returns>
	public int GetFileCount()
	{
		return GetFiles().Count;
	}
	#endregion

	/// <summary>
	/// Encrypts all file(s) stored in DirManager.
	/// Also triggers the manifest to be written (or not to be).
	/// </summary>
	/// <param name="locker">stored information about the locker (output archive) and key </param>
	/// <param name="debug">Debug flag that disables encryption</param>
	public void Encrypt(Locker locker, bool debug = false)
	{
		List<OurFile> files = GetFiles();

		//Setup vars used to indicate progress to the user.
		if (!locker.IsArchive() && TargetFile != null)
		{
			//Prevent divide by zero crash
			if (TargetFile.Length >= 1)
				TotalBytes = TargetFile.Length;
		}
		else
		{
			//Calculate total bytes in all files in dirManager
			TotalBytes = 1; //Divide by zero fix
			foreach (var file in files)
			{
				TotalBytes += file.Info.Length;
			}
			TotalBytes -= 1; //Correction for the first byte
		}

		//Clear and reinitualize Failed item list.
		Failed = new List<FailedItem>();

		//Overflow check
		if (files.Count > int.MaxValue)
		{
			var e = new Exception($"Maximum number of files exceeded! Max files {int.MaxValue}");
			Failed.Add(new FailedItem(files[0],e));
			throw e;
		}

		//Time encryption
		Stopwatch sw = new();
		sw.Start();

		//Encrypt each file in DirManager
		foreach (OurFile f in files)
		{
			f.Encrypt(locker, this, debug);
		}

		//Stop timer and post results
		sw.Stop();
		EncryptionTime = sw.Elapsed.TotalMilliseconds;

		IsEncrypted = true; //Flag the UI that encryption is done

		if (locker.IsArchive())
		{
			//If archive (folder encryption) save manifest
			locker.SetManifest(GenerateManifest());
			locker.WriteManifest(debug);
		}
	}

	public static int Decrypted;
	public static int ToDecrypt;
	public static bool IsDecrypted;
	public static bool DecryptFailed;
	public static long TotalSize;
	public static string? DecryptingPath;
	public static string? DecryptFailReason;
	public static void DecryptFiles(Locker locker, string name, bool debug = false)
	{
		IsDecrypted = false;
		Decrypted = 0;
		DecryptFailed = false;
		DecryptFailReason = "";
		TotalSize = 1000;
		DecryptingPath = "";

		if (locker.IsArchive())
		{
			Manifest man = locker.GetManifest();
			ToDecrypt = man.GetItems().Count;


			var outputDir = Directory.CreateDirectory(name);

			foreach (var item in man)
			{
				try
				{
					using FileStream fRead = File.OpenRead(locker.GetPath());
					using BufferedStream bRead = new(fRead);
					TotalSize = fRead.Length;
					var dir = Directory.CreateDirectory($"{outputDir.FullName}/{item.Path}");

					using FileStream fWrite = File.Create($"{dir.FullName}/{item.Name}");
					using BufferedStream bWrite = new(fWrite);

					//bRead.Seek(man.GetStartingByte(item.FileIndex), SeekOrigin.Begin);
					bRead.Seek(item.StartingByte, SeekOrigin.Begin);

					int bl = 0;
					long overflows = 0;

					int maxBufferSize = (256 * 1024); //256 KB (max is 2GB)

					if (item.ByteLength > maxBufferSize)
					{
						overflows = item.ByteLength / maxBufferSize;
						bl = (int)(item.ByteLength - (overflows * maxBufferSize));
					}
					else bl = (int)item.ByteLength;

					CryptoStream? cs = null;
					StreamWriter? sw = null;
					if (debug)
					{
						sw = new(bWrite);
					}
					else
					{
						cs = new(bWrite, locker.GetDecryptor(), CryptoStreamMode.Write); //Padding is invalid and cannot be removed...
					}

					
					for (int i = 0; i <= overflows; i++)
					{
						int toWrite = bl;

						if (i < overflows)
							toWrite = maxBufferSize;

						byte[] buffer = new byte[toWrite];
						bRead.Read(buffer, 0, buffer.Length);
						if (cs != null)
							cs.Write(buffer, 0, buffer.Length);
						else if(sw != null)
						{
							sw.Write(Encoding.Default.GetString(buffer));
						}
						else
						{
							throw new Exception("Both CS and SW are null");
						}
					}
					if (sw != null)
						sw.Close();
					if (cs != null)
						cs.Close();
				}
				catch (Exception e)
				{
					DecryptFailReason = e.Message;
					if (e.Message == "Padding is invalid and cannot be removed.")
					{
						DecryptFailReason = "This error sometimes occurs if the hard drive is full...";
					}
						
					DecryptFailed = true;
					break;
				}

				Decrypted++;
			}
		}
		else
		{
			//FindLocker config ending token, then decrypt untill end of file
			try
			{
				using FileStream fRead = File.OpenRead(locker.GetPath());
				using BufferedStream bRead = new(fRead);
				TotalSize = fRead.Length;
				using BinaryReader br = new BinaryReader(bRead);
				string pattern = "]";
				byte[] bytes = new byte[pattern.Length];
				for (long i = 0; i >= 0; i++)
				{
					//Shift bytes
					//bytes = ShiftRight(bytes);

					bRead.Seek(i, SeekOrigin.Begin);
					bytes[0] = br.ReadByte();

					//Check for header pattern
					string s = Encoding.Default.GetString(bytes);
					if (s.StartsWith(pattern))
					{
						bRead.Seek(i + pattern.Length, SeekOrigin.Begin);

						using var cs = new CryptoStream(bRead, locker.GetDecryptor(), CryptoStreamMode.Read);

						//Bug, when multple periods in name, the wrong file name gets used
						//(?<!^)\.[^.]+$
						//string fname = locker.GetFileName();
						string? temp_name = locker.GetConfig().FileName;
						if(temp_name == null)
							temp_name = locker.GetFileName();

						int index = 0;
						string file_name = temp_name;
						string ext = Regex.Match(file_name, @"(?<!^)\.[^.]+$").ToString();
						while (File.Exists($"{locker.GetDirectoryPath()}/{file_name}") || Directory.Exists($"{locker.GetDirectoryPath()}/{file_name}"))
						{
							index++;

							file_name = Regex.Replace(temp_name, @"(?<!^)\.[^.]+$", $"({index}){ext}", RegexOptions.IgnoreCase);
						}
						string path = $"{locker.GetDirectoryPath()}/{file_name}";
						using FileStream fWrite = File.Create(path);
						DecryptingPath = path;
						using BufferedStream bWrite = new(fWrite);
						cs.CopyTo(bWrite);
						break;
					}
				}
			}
			catch (Exception e)
			{
				DecryptFailReason = e.Message;
				if (e.Message == "Padding is invalid and cannot be removed.")
					DecryptFailReason = "Password is incorrect, please try again!";
				DecryptFailed = true;
			}
		}
		IsDecrypted = true;
		GC.Collect();

	}

	/// <summary>
	/// Generates a Manfest file.
	/// </summary>
	/// <returns>Manifest</returns>
	private Manifest GenerateManifest()
	{
		List<OurFile> files = GetFiles();

		//Remove files that failed to encrypt
		foreach (var item in Failed)
		{
			files.Remove(item.File);
		}

		//Add all encrypted files to the manifest
		Manifest m = new();
		foreach (OurFile f in files)
		{
			m.Add(new ManifestItem(f.Path, f.Name, f.StartingByte, f.Length));
		}

		return m;
	}
}

/// <summary>
/// Entity class representing a directory as a member of DirManager.
/// </summary>
public class Dir
{
	/// <summary>
	/// The DirManager responsible for the Directory.
	/// </summary>
	public DirManager Manager { get; private set; }
	/// <summary>
	/// The reference to it's own directory in the file system
	/// </summary>
	public DirectoryInfo Self { get; private set; }
	/// <summary>
	/// Size of all files and sub directories in bytes.
	/// </summary>
	public long Size { get; private set; }

	/// <summary>
	/// Parent Directory in the structure, null if this is the root
	/// </summary>
	private Dir? Parent; //If null, it signified it's the root

	/// <summary>
	/// List of Sub Directory in the structure
	/// </summary>
	private List<Dir> SubDirs = new();

	/// <summary>
	/// List of Files in the Directory
	/// </summary>
	private List<OurFile> Files = new();

	/// <summary>
	/// Indicates if the sub structures have been complete explored
	/// </summary>
	private bool Loaded = false;

	/// <summary>
	/// Constructor that seaches the sub structure and does various calculations like Dir size
	/// </summary>
	/// <param name="manager">Reference to DirManager</param>
	/// <param name="dir">Filesystem reference</param>
	/// <param name="parent">Parent Directory, null if root</param>
	public Dir(DirManager manager, DirectoryInfo dir, Dir? parent = null)
	{
		Manager = manager;
		Parent = parent;
		Self = dir;
		Size = 0;

		FileAttributes attr = Self.Attributes;
		if (attr.HasFlag(FileAttributes.Offline) || attr.HasFlag(FileAttributes.Device) || attr.HasFlag(FileAttributes.System))
		{
			throw new Exception("Permission denied when trying to read Directory.");
		}

		//Foreach sub Directory found by file system, create a new Dir instance and save into SubDirs list
		foreach (var d in Self.GetDirectories())
		{
			try
			{
				Dir subD = new(manager, d, this);
				SubDirs.Add(subD);
				Size += subD.Size; //Calculate dir byte size
			}
			catch (Exception e)
			{
				//If access violation occurs
				Manager.Failed.Add(new FailedItem(d, e));
			}
		}

		foreach (FileInfo f in dir.GetFiles())
		{
			try
			{
				Size += f.Length;
				OurFile nf = new(f, this);
				Files.Add(nf);
			}
			catch (Exception e)
			{
				//If access violation occurs
				Manager.Failed.Add(new FailedItem(new OurFile(f, this), e));
			}

		}
		Loaded = true;
	}

	/// <summary>
	/// Probes all files and subfolders of the dir to see if everything is ready
	/// </summary>
	/// <returns>true/false</returns>
	public bool IsLoaded()
	{
		return Loaded;
	}

	/// <summary>
	/// Gets all the files in the folder and sub folders
	/// </summary>
	/// <returns>List of file entities</returns>
	public List<OurFile> GetFiles()
	{
		List<OurFile> temp = new();

		//Get files in all sub folders
		foreach (Dir d in SubDirs)
		{
			foreach (OurFile f in d.GetFiles())
			{
				temp.Add(f);
			}
		}

		//Get files in self
		foreach (OurFile f in Files)
		{
			temp.Add(f);
		}

		return temp;
	}

	/// <summary>
	/// Gets the path relative to the root directory
	/// </summary>
	/// <returns></returns>
	public string GetLocalPath()
	{
		//Check if root
		if (Parent != null)
		{
			return $"{Parent.GetLocalPath()}{Self.Name}/"; //Get relative path
		}
		else
		{
			//Is root
			return "/";
		}
	}
}

public class OurFile
{
	#region Members
	/// <summary>
	/// Reference to the file in the filesystem
	/// </summary>
	public FileInfo Info { get; private set; }

	/// <summary>
	/// The parent Directory (Dir)
	/// </summary>
	public Dir? Parent { get; private set; }

	/// <summary>
	/// Length of the file in bytes
	/// </summary>
	public long Length { get; private set; }

	/// <summary>
	/// The starting bytes index in the locker (archive file)
	/// </summary>
	public long StartingByte { get; private set; }

	/// <summary>
	/// The local path from the RootDir to the file. Used to recreate the folder structure when decrypting.
	/// </summary>
	public string Path { get; private set; }

	/// <summary>
	/// The name and extension of the file used when decrypting.
	/// </summary>
	public string Name { get; private set; }
	#endregion

	public OurFile(FileInfo file, Dir parent)
	{
		Info = file;
		Name = file.Name;
		Parent = parent;
		Path = parent.GetLocalPath();
	}

	public OurFile(FileInfo file, DirManager manager)
	{
		Info = file;
		Name = file.Name;
		Path = "";
	}

	public string GetRelativePath()
	{
		if(Parent == null)
		{
			return $"{Info.Name}";
		}
		return $"{Parent.GetLocalPath()}\\{Info.Name}";
	}

	/// <summary>
	/// Encrypts the file content and writes to end of locker.
	/// </summary>
	/// <param name="locker">locker (file) to write to</param>
	/// <param name="manager">used as a callback if encryption fails</param>
	/// <param name="debug">disables encryption and adds file headers</param>
	/// <returns></returns>
	public bool Encrypt(Locker locker, DirManager manager, bool debug = false)
	{
		try
		{
			//Check if the file is empty
			if (Info.Length <= 0)
			{
				throw new Exception("File empty");
			}

			//Note starting byte by checking the locker length
			//Could override this by getting the previous files starting byte and length, which would future proof for adding a file to a locker
			StartingByte = new FileInfo(locker.GetLockerFile().FullName).Length;

			//Open target file
			using (FileStream fileRead = Info.OpenRead())
			{
				long startingLength = locker.GetWriteStream().Length; //Get length of locker file (used to calc a encrpted byte length)
					
				using BufferedStream bRead = new(fileRead);
				locker.GetWriteStream().Seek(0, SeekOrigin.End); //Seek to end of locker file

				//If debug, disable encryption and enable headers
				if (debug)
				{
					//Write debug file header
					StreamWriter sw = new StreamWriter(locker.GetWriteStream());
					sw.Write($"[file_start]");
					sw.Flush(); //Flush to ensure the data is writen before moving on.

					locker.GetWriteStream().Seek(0, SeekOrigin.End); //Pretty sure this does shit all
					bRead.CopyTo(locker.GetWriteStream());
					bRead.Flush();

					locker.GetWriteStream().Seek(0, SeekOrigin.End); //Pretty sure this does shit all
					sw.Write($"[file_end]");
					sw.Close();
				}
				else
				{
					using CryptoStream cs = new(bRead, locker.GetEncryptor(), CryptoStreamMode.Read); //Encrypt from buffer
					cs.CopyTo(locker.GetWriteStream()); //Copy from cs to write stream.
				}

				//Calculate the length of bytes for the encrypted data. This will be used to differentiate the files from each other in the locker.
				Length = (long)(locker.GetWriteStream().Length - startingLength);
			}
			
			
		}
		catch (Exception e)
		{
			manager.Failed.Add(new FailedItem(this, e));
			GC.Collect();
			return false;
		}
		GC.Collect();
		return true;
	}

}


/// <summary>
/// The file manifest used to keep track of information related to files inside the archive and where their starting and ending bytes are located within.
/// </summary>
public class Manifest : IEnumerable<ManifestItem>
{
	#region Implmentation of ienumerable
	public IEnumerator<ManifestItem> GetEnumerator()
	{
		return Items.GetEnumerator();
	}

	IEnumerator IEnumerable.GetEnumerator()
	{
		return GetEnumerator();
	}
	#endregion

	private List<ManifestItem> Items = new();

	public Manifest() { /*Thought there was a better way of writing an empty Constructor...*/ }
	public Manifest(List<ManifestItem> list)
	{
		list.Sort(); //Sorts ManifestItems by startingbyte
		Items = list;
	}

	/// <summary>
	/// Gets manifest items
	/// </summary>
	/// <returns></returns>
	public List<ManifestItem> GetItems()
	{
		return Items;
	}

	/// <summary>
	/// Writes the manifest to the locker (archive)
	/// </summary>
	/// <param name="locker">the archive to write to</param>
	/// <param name="debug">Disables encryption</param>
	public void WriteToLocker(Locker locker, bool debug = false)
	{
		try
		{
			locker.GetWriteStream().Seek(0, SeekOrigin.End);
			StreamWriter sw = new StreamWriter(locker.GetWriteStream());
			sw.Write("[manifest]");
			sw.Flush(); //Need to flush before seeking to make sure the header is writen

			locker.GetWriteStream().Seek(0, SeekOrigin.End);
			if (debug)
			{
				StreamWriter csWriter = new StreamWriter(locker.GetWriteStream());

				csWriter.Write(Serialize());
				csWriter.Close();
			}
			else
			{
				CryptoStream cs = new CryptoStream(locker.GetWriteStream(), locker.GetEncryptor(), CryptoStreamMode.Write);

				StreamWriter csWriter = new StreamWriter(cs);
				csWriter.Write(Serialize());

				csWriter.Close();
				cs.Close();
			}
			
			locker.CloseWriteStream();
		}
		catch (Exception e)
		{
			locker.DeleteLocker();
			Console.WriteLine("Failed to save locker, reason:");
			Console.WriteLine(e.Message);
			throw;
		}

	}

	public static Manifest? LoadManifest(Locker locker, bool debug = false)
	{
		try
		{
			var file = locker.GetLockerFile();
			if (!file.Exists)
				throw new Exception($"\"{file.FullName}\" does not exist!");

			using (FileStream fs = File.OpenRead(file.FullName))
			{
				using BufferedStream buff = new BufferedStream(fs);
				using BinaryReader br = new BinaryReader(buff);

				string pattern = "[manifest]";
				byte[] bytes = new byte[pattern.Length];
				for (long i = fs.Length - 1; i >= 0; i--)
				{
					//Shift bytes
					bytes = ShiftRight(bytes);

					buff.Seek(i, SeekOrigin.Begin);
					bytes[0] = br.ReadByte();

					//Check for header pattern
					string s = Encoding.Default.GetString(bytes);
					if (s.StartsWith(pattern))
					{
						buff.Seek(i + pattern.Length, SeekOrigin.Begin);

						StreamReader? sr = null;
						if (debug)
						{
							sr = new(buff);
							string json_string = sr.ReadToEnd();

							return Deserialize(json_string);
						}
						else
						{
							var cs = new CryptoStream(buff, locker.GetDecryptor(), CryptoStreamMode.Read);

							sr = new(cs);
							string json_string = sr.ReadToEnd();

							return Deserialize(json_string);
						}
						
						
					}
				}
			}
			throw new Exception("Failed to find manifest in archive");
		}
		catch (Exception)
		{
			return null;
		}
		
	}
/*
	/// <summary>
	/// Shifts bytes
	/// </summary>
	/// <param name="input">Byte array to shift</param>
	/// <returns>Shifted array</returns>
	private static byte[] ShiftLeft(byte[] input)
	{
		byte[] shifted = new byte[input.Length];
		for (int i = 0; i < input.Length; i++)
		{
			shifted[i] = input[(i + 1) % input.Length];
		}
		return shifted;
	}*/

	/// <summary>
	/// Shifts bytes
	/// </summary>
	/// <param name="input">Byte array to shift</param>
	/// <returns>Shifted array</returns>
	private static byte[] ShiftRight(byte[] input)
	{
		byte[] shifted = new byte[input.Length];
		for (int i = 0; i < input.Length; i++)
		{
			shifted[(i + 1) % input.Length] = input[i];
		}
		return shifted;
	}

	/// <summary>
	/// Adds a manifest item (file) to the manifest
	/// </summary>
	/// <param name="item">file</param>
	public void Add(ManifestItem item)
	{
		Items.Add(item);
	}

	/// <summary>
	/// Removes a manifest file from the manifest
	/// </summary>
	/// <param name="item"></param>
	public void Remove(ManifestItem item)
	{
		Items.Remove(item);
	}
/*
	/// <summary>
	/// Verifies a file exists in the manifest and is located in the same path.
	/// </summary>
	/// <param name="item"></param>
	/// <returns></returns>
	private bool Exists(ManifestItem item)
	{
		foreach (ManifestItem i in Items)
		{
			if (i.Name == item.Name &&
				i.Path == item.Path)
				return true;
		}
		return false;
	}
	private bool Exists(string name, string localPath)
	{
		foreach (ManifestItem i in Items)
		{
			if (i.Name == name &&
				i.Path == localPath)
				return true;
		}
		return false;
	}*/

	public string Serialize()
	{
		return JsonSerializer.Serialize(Items);
	}

	/// <summary>
	/// Returns a JSON string
	/// </summary>
	/// <returns></returns>
	public override string ToString()
	{
		return Serialize();
	}

	public static Manifest Deserialize(string input)
	{
		List<ManifestItem>? newItems = JsonSerializer.Deserialize<List<ManifestItem>>(input);
		if (newItems == null)
			throw new NullReferenceException("Deserialize list is null!");
		return new Manifest(newItems);
	}
}

public class ManifestItem : IComparable
{   
	/// <summary>
	/// Local path of the file, used to reconstruct the folder structure when decrypting.
	/// </summary>
	public string Path { get; set; }

	/// <summary>
	/// Name of the file
	/// </summary>
	public string Name { get; set; }

	/// <summary>
	/// Starting Byte of the file data located in the archive
	/// </summary>
	public long StartingByte { get; set; }

	/// <summary>
	/// The total amount of bytes to be read from the starting byte
	/// </summary>
	public long ByteLength { get; set; }

	/// <summary>
	/// 
	/// </summary>
	/// <param name="path">Local path of the file from the RootDir</param>
	/// <param name="name">Name of the file</param>
	/// <param name="startingByte">The first bytes index within the archive</param>
	/// <param name="byteLength">how many bytes are stored in the archive</param>
	public ManifestItem(string path, string name, long startingByte, long byteLength)
	{
		Path = path;
		Name = name;
		StartingByte = startingByte;
		ByteLength = byteLength;
	}

	public int CompareTo(object? obj)
	{
		var t = (ManifestItem?)obj;
		if (100 > 200);

		return StartingByte.CompareTo(t?.StartingByte);
	}
}

/// <summary>
/// Contains information critical to the locker (archive), like encryption key, path, name, configuration, manifest, ect.
/// </summary>
public class Locker
{
	#region Members
	/// <summary>
	/// the fileStream for writing to the locker
	/// </summary>
	private static FileStream? LockerStream;

	/// <summary>
	/// The BufferedSteam for lockerStream.
	/// </summary>
	private static BufferedStream? LockerBuffer;

	/// <summary>
	/// The locker file reference on the filesystem
	/// </summary>
	private FileInfo? LockerFile;

	/// <summary>
	/// The locker configuration, contains things like if the locker is an archive or a single file.
	/// </summary>
	private LockerConfig? LockerConfig;

	/// <summary>
	/// The locker file manifest
	/// </summary>
	private Manifest? LockerManifest;

	/// <summary>
	/// The AES256 symetric key
	/// </summary>
	private Aes? Key;

	/// <summary>
	/// Indicated if the AES256 key has finished generating
	/// </summary>
	private bool _isKeyGenerated = false;
	#endregion

	public Locker(FileInfo? lockerFile = null)
	{
		LockerFile = lockerFile;
	}

	/// <summary>
	/// Returns the archive writing stream.
	/// </summary>
	/// <returns>BufferedStream</returns>
	public ref BufferedStream GetWriteStream()
	{
		if(LockerStream == null || (!LockerStream.CanWrite && !LockerStream.CanRead && !LockerStream.CanSeek))
		{
			LockerStream = File.OpenWrite(GetPath());
			LockerBuffer = new BufferedStream(LockerStream);
		}

		if (LockerBuffer == null)
			throw new Exception("Failed to get write stream!");
		LockerBuffer.Seek(0, SeekOrigin.End);
		return ref LockerBuffer;
	}

	public void CloseWriteStream()
	{
		if ((LockerStream != null && LockerBuffer != null) && (LockerStream.CanWrite || LockerStream.CanSeek || LockerStream.CanRead))
		{
			LockerBuffer.Flush();
			LockerStream.Flush();
			LockerBuffer.Close();
		}
	}

	/// <summary>
	/// Gets the lockers configuration
	/// </summary>
	/// <returns>Locker Configuration</returns>
	public LockerConfig GetConfig()
	{
		if (LockerConfig == null)
			return LoadConfig(this);
		else return LockerConfig;
	}

	public void SetConfig(LockerConfig config)
	{
		LockerConfig = config;
	}

	public bool IsKeyGenerated()
	{
		return _isKeyGenerated;
	}

	public Manifest GetManifest()
	{
		if (LockerManifest == null)
			throw new Exception("LockerManifest is null");
		return LockerManifest;
	}

	public void SetManifest(Manifest man)
	{
		LockerManifest = man;
	}

	public FileInfo GetLockerFile()
	{
		if (LockerFile == null)
			throw new Exception("LockerFile is null");
		return LockerFile;
	}

	/// <summary>
	/// Deletes the locker file, should only be used on critical errors.
	/// </summary>
	public void DeleteLocker()
	{
		GetLockerFile().Delete();
	}

	public string GetFileName()
	{
		string? temp_name = null;
		if (LockerConfig != null)
			temp_name = GetConfig().FileName;

		if (temp_name == null)
			throw new Exception("OGFileName is null");
		return temp_name;
	}

	/// <summary>
	/// Indicates wether the locker is an archive (dir encryption) or a single file
	/// </summary>
	/// <returns>true/false</returns>
	public bool IsArchive()
	{
		return GetConfig().IsArchive;
	}

	public ICryptoTransform GetEncryptor()
	{
		if (Key == null)
			throw new Exception("Key is null (GetEncryptor)");
		return Key.CreateEncryptor();
	}

	public ICryptoTransform GetDecryptor()
	{
		if (Key == null)
			throw new Exception("Key is null (getDecryptor)");
		return Key.CreateDecryptor();
	}

	public Aes GetKey()
	{
		if(Key != null)
		{
			return Key;
		}
		else
		{
			throw new Exception("Key is null (GetKey)");
		}
	}

	/// <summary>
	/// Generates an AES256 symetric key from a password.
	/// Uses Argon2 to crate the key and iv.
	/// </summary>
	/// <param name="password">string to derive key from</param>
	public void GenerateKey(string password)
	{
		//Get argon2 params from config
		var tempConf = GetConfig();

		//Convert password string to byte array
		byte[]? pBytes = Encoding.ASCII.GetBytes(password);
		Argon2id? argon = new(pBytes);

		argon.DegreeOfParallelism = tempConf.DegreeOfParallelism;
		argon.MemorySize = tempConf.MemorySize;
		argon.Iterations = tempConf.Iterations;
		argon.Salt = tempConf.Salt;

		var key = argon.GetBytes(32); //256 bit key
		var iv = argon.GetBytes(16); //128 bit IV

		//Empty ram after hashes are generated
		argon = null;
		pBytes = null;
		password = "";
		GC.Collect();

		//Generate key
		var AES = Aes.Create();
		AES.Key = key;
		AES.IV = iv;
		AES.Mode = CipherMode.CBC;
		AES.Padding = PaddingMode.PKCS7;

		Key = AES;
		_isKeyGenerated = true;
	}

	public void GenerateLocker(string fileName)
	{
		if(LockerConfig == null)
		{
			throw new NullReferenceException("LockerConfig cannot be null when Generating a locker");
		}
		//(?<!^)\.[^.]+$
		string name = $"{Regex.Replace(fileName, @"(?<!^)\.[^.]+$", "", RegexOptions.IgnoreCase)}.{CryLocker.extention}";
		int index = 0;
		while (File.Exists(name) || Directory.Exists(name))
		{
			index++;
			name = $"{Regex.Replace(fileName, @"(?<!^)\.[^.]+$", "", RegexOptions.IgnoreCase)}({index}).{CryLocker.extention}";
		}

		try
		{
			string obj = LockerConfig.Serialize(GetKey());
			using (var fs = File.Create(name))
			{
				using(StreamWriter sw = new StreamWriter(fs))
				{
					sw.Write($"[Config:{obj}]");
				}
			}
		}
		catch (Exception e)
		{
			Console.WriteLine("Failed to write locker file, this is likely due to a lack of permissions.");
			throw e;
		}
		LockerFile = new FileInfo(name);
	}

	/// <summary>
	/// Gets the full path of the locker
	/// </summary>
	/// <returns>fullpath to locker file</returns>
	/// <exception cref="NullReferenceException"></exception>
	public string GetPath()
	{
		if (!GetLockerFile().Exists)
		{
			throw new NullReferenceException("LockerFile has not been generated!");
		}
		return GetLockerFile().FullName;
	}

	public string GetDirectoryPath()
	{
		var temp_name = GetLockerFile().DirectoryName;
		if (temp_name != null)
		{
			return temp_name;
		}
		else throw new NullReferenceException("Directory Name is null");

		
	}

	/// <summary>
	/// Completes the encryption process by saving the manifest to the end of the file.
	/// </summary>
	public void WriteManifest(bool debug = false)
	{
		GetManifest().WriteToLocker(this, debug);
	}

	/// <summary>
	/// Loads manifest from locker
	/// </summary>
	/// <param name="debug"></param>
	/// <returns></returns>
	/// <exception cref="Exception"></exception>
	public Manifest? LoadManifest(bool debug = false)
	{
		if (!IsArchive())
			throw new Exception("Manifest cannot be loaded on a non archive!");
		LockerManifest = Manifest.LoadManifest(this, debug);
		return LockerManifest;
	}

	/// <summary>
	/// Loads config from locker
	/// </summary>
	/// <returns></returns>
	/// <exception cref="NullReferenceException">LockerFile != null</exception>
	/// <exception cref="Exception">Config header couldn't be found or the end token is missing</exception>
	private LockerConfig LoadConfig(Locker locker)
	{
		if (LockerFile == null)
		{
			throw new NullReferenceException("LockerFile cannot be null when loading config");
		}

		try
		{
			using (FileStream fs = File.OpenRead(LockerFile.FullName))
			{
				using BinaryReader br = new BinaryReader(fs);

				//Define header pattern
				string pattern = "[Config:";

				//Read from index 0 (Config is assumed to start at index 0)
				byte[] bytes = br.ReadBytes(pattern.Length);

				//Check for header pattern
				string s = Encoding.Default.GetString(bytes);
				if (s.StartsWith(pattern))
				{
					//Compile results until ending token (]) is found
					string result = "";
					for (int i = pattern.Length; i < /*fs.Length*/2048; i++) //2048 is hard coded because the config length doesn't scale with the encrypted files. This should prevent scanning for a missing end token to go through possibly petabytes of data.
					{
						fs.Seek(i, SeekOrigin.Begin);
						char b = br.ReadChar();
						if (b == 93) // 93 = 5d (] in hex)
						{
							LockerConfig = LockerConfig.Deserialize(result, this);
							return LockerConfig;
						}
						else result += b; //Add to results and continue scanning (this prevents end token being mixed into the config data)
					}
				}
			}
		}
		catch (Exception e)
		{
			throw e;
		}
		throw new Exception("Config header damaged!");
	}
}

/// <summary>
/// Stores information about the password hash, original file name (for single file encryption), 
/// </summary>
public class LockerConfig
{
	#region Members
	/// <summary>
	/// Indicates wether the locker is an archive (directory encryption) or a single file (without a manifest)
	/// </summary>
	public bool IsArchive { get; private set; }

	/// <summary>
	/// The Argon2 hash salt
	/// </summary>
	public byte[] Salt { get; private set; }

	/// <summary>
	/// The Original file name (single file encryption only)
	/// </summary>

	private string? fileName;
	public string? FileName {
		get { 
			if(!IsDecrypted)
			{
				if (Manager == null)
					throw new Exception("Manager is null! call Deserialize first!");
				fileName = DecryptData(fileName, Manager.GetKey());
			}
			return fileName;
		} 

		private set {
			fileName = value;
		} 
	}

	/// <summary>
	/// 
	/// </summary>
	public int DegreeOfParallelism { get; private set; }
	public int MemorySize { get; private set; }
	public int Iterations { get; private set; }

	private bool IsDecrypted = true;

	private Locker? Manager = null;
	#endregion

	public LockerConfig(bool isArchive, byte[] salt, string? fileName = null, int degreeOfParallelism = 16, int memorySize = 2097152 /*KB*/, int iterations = 3)
	{
		IsArchive = isArchive;
		FileName = fileName;
		Salt = salt;
		DegreeOfParallelism = degreeOfParallelism;
		MemorySize = memorySize;
		Iterations = iterations;
	}

	public string? EncryptData(string? input, Aes key)
	{
		if (input == null)
			return null;

		try
		{
			var plainBytes = Encoding.UTF8.GetBytes(input);
			using MemoryStream ms = new();
			using CryptoStream cs = new(ms, key.CreateEncryptor(), CryptoStreamMode.Write);
			cs.Write(plainBytes, 0, plainBytes.Length);
			cs.FlushFinalBlock();

			var output = Convert.ToHexString(ms.ToArray()).ToLower();

			return output;
		}
		catch (Exception e)
		{
			throw e;
		}

	}

	public string? DecryptData(string? input, Aes key)
	{
		if (input == null)
			return null;

		try
		{
			var encryptedBytes = Convert.FromHexString(input);
			using MemoryStream ms = new();
			using CryptoStream cs = new(ms, key.CreateDecryptor(), CryptoStreamMode.Write);
			cs.Write(encryptedBytes, 0, encryptedBytes.Length);
			cs.FlushFinalBlock();

			var output = System.Text.Encoding.Default.GetString(ms.ToArray());

			return output;
		}
		catch (Exception e)
		{
			throw e;
		}

	}

	//Serlizes the lockerConfig (and encrypts filename for single file encryption)
	public string Serialize(Aes key)
	{
		string js = JsonSerializer.Serialize(
			new LockerConfig(
			IsArchive,
			Salt,
			EncryptData(FileName, key),
			DegreeOfParallelism,
			MemorySize,
			Iterations));

		byte[] bytes = Encoding.Default.GetBytes(js);
		string hex = Convert.ToHexString(bytes).ToLower();
		return hex;
	}


	public static LockerConfig Deserialize(string input, Locker manager)
	{
		var decoded = Convert.FromHexString(input);
		var conf = JsonSerializer.Deserialize<LockerConfig>(decoded);
		if(conf == null)
		{
			throw new NullReferenceException("Failed to deserialize LockerConfig");
		}
		conf.IsDecrypted = false; //Marks the FileName as encrypted
		conf.Manager = manager; //Passes the manager for filename decryption
		return conf;
	}
}

/// <summary>
/// Entity class that stores information on files that failed to encrypt, and the exception that caused it.
/// </summary>
public class FailedItem
{
	public OurFile? File { get; private set; }
	public DirectoryInfo? Dir { get; private set; }
	public Exception Exception { get; private set; }
	public string Type { get; private set; }
	public FailedItem(OurFile file, Exception exception)
	{
		File = file;
		Type = "file";
		Exception = exception;
	}
	public FailedItem(DirectoryInfo dir, Exception exception)
	{
		Dir = dir;
		Type = "directory";
		Exception = exception;
	}
}