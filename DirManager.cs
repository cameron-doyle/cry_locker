using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Threading;
using System.Diagnostics;
using cry_locker;
using System.Text.Json;

public class DirManager
{
	public Dir _root { get; private set; }
	private bool _isEncrypted;
	private static FileInfo? LockerFile;
	private static DirectoryInfo? DecryptFolder;
	private static AesCryptoServiceProvider? Key;


	public DirManager(DirectoryInfo root)
	{
		DecryptFolder = null;
		Key = null;
		LockerFile = null;
		_root = new Dir(this, root);
	}
/*	public DirManager(string path)
	{
		if (Directory.Exists(path))
		{
			_root = new Dir(this, new DirectoryInfo(path));
		}
		else
		{
			throw new Exception($"Directory \"{path}\" does not exist!");
		}
	}*/

	public bool IsLoaded()
	{
		return _root.IsLoaded();
	}

	public bool IsHashed()
	{
		return _root.IsHashed();
	}

	public bool IsEncrypted()
	{
		return _isEncrypted;
	}

	public List<OurFile> GetFiles()
	{
		return _root.GetFiles();
	}

	public static AesCryptoServiceProvider GetKey()
	{
		if (Key == null)
			throw new NullReferenceException("Key was never set!");
		return Key;
	}

	public static void SetKey(AesCryptoServiceProvider key)
	{
		Key = key;
	}

	public static FileInfo GetLockerFile()
	{
		if (LockerFile == null)
			throw new NullReferenceException("_lockerFile was never set!");
		return LockerFile;
	}
	public static void SetLockerFile(FileInfo locker)
	{
		if (!locker.Exists)
			throw new Exception($"{locker.FullName} does not exist!");
		LockerFile = locker;
	}
	public static DirectoryInfo GetDecryptFolder()
	{
		if (DecryptFolder == null)
			throw new NullReferenceException("_decryptFolder was never set!");
		return DecryptFolder;
	}
	public static void SetDecryptFolder(DirectoryInfo folder)
	{
		if (!folder.Exists)
			throw new Exception($"{folder.FullName} does not exist!");
		DecryptFolder = folder;
	}


	public int _encryptCount = 0;
	public double _encryptionTime { get; private set; }
	public List<FailedItem> _failed = new List<FailedItem>();
	public void EncryptFiles()
	{
		//Reset vars
		_encryptCount = 0;
		_failed = new List<FailedItem>();

		List<OurFile> files = _root.GetFiles();

		if(files.Count > int.MaxValue)
		{
			_failed.Add(new FailedItem(files[0], new Exception($"Maximum number of files exceeded! Max files {int.MaxValue}")));
			_isEncrypted = true;
			return;
		}

		//Time encryption
		Stopwatch sw = new();
		sw.Start();

		int i = 0;
		foreach (OurFile f in files)
		{
			if (f._info.Length <= long.MaxValue)
			{
				f._fileIndex = i;
				f.Encrypt();
				i++;
			}
			else
			{
				_failed.Add(new FailedItem(f, new Exception($"Maximum file size exceed, 8EB (Exabytes) max!")));
			}
		}

		sw.Stop();
		_encryptionTime = sw.Elapsed.TotalMilliseconds;

		_isEncrypted = true;

		while (!IsHashed())
		{
			//Hashing isn't complete
			Thread.Sleep(1);
		}

		//Generate manifest (requires hashes) and write
		Manifest man = GenerateManifest();
		man.WriteToDisk();
	}

	public static int Decrypted;
	public static int ToDecrypt;
	public static bool IsDecrypted;
	public static bool DecryptFailed;
	public static string DecryptFailReason;
	public static void DecryptFiles()
	{
		IsDecrypted = false;
		Decrypted = 0;
		DecryptFailed = false;
		DecryptFailReason = "";

		var locker = GetLockerFile();
		var outputFolder = GetDecryptFolder();
		var key = GetKey();

		if (!locker.Exists)
			throw new Exception($"\"{locker.FullName}\" does not exist!");
		if (!outputFolder.Exists)
			throw new Exception($"\"{outputFolder.FullName}\" does not exist!");

		Manifest manifest = Manifest.LoadFromDisk(key, locker);
		
		ToDecrypt = manifest.GetItems().Count;

		//Decrypt files
		//TODO make manifest ienumerable

		foreach (var item in manifest)
		{
			using FileStream fRead = File.OpenRead(locker.FullName);
			using BufferedStream bRead = new(fRead);

			var dir = Directory.CreateDirectory($"{outputFolder.FullName}/{item.Path}");

			using FileStream fWrite = File.Create($"{dir.FullName}/{item.Name}");
			using BufferedStream bWrite = new(fWrite);

			bRead.Seek(manifest.GetStartingByte(item.FileIndex), SeekOrigin.Begin);

			int bl = 0;
			int overflows = 0;

			int maxBufferSize = (256 * 1024); //KB (max is 2GB)

			if (item.ByteLength > maxBufferSize)
			{
				overflows = (int)item.ByteLength / maxBufferSize;
				bl = (int)item.ByteLength - (overflows * maxBufferSize);
			}
			else bl = (int)item.ByteLength;

			using CryptoStream cs = new(bWrite, key.CreateDecryptor(), CryptoStreamMode.Write);
			for (int i = 0; i <= overflows; i++)
			{
				int toWrite = bl;

				if (i < overflows)
					toWrite = maxBufferSize;

				byte[] buffer = new byte[toWrite];
				bRead.Read(buffer, 0, buffer.Length);
				cs.Write(buffer, 0, buffer.Length);
			}
			Decrypted++;
		}
		IsDecrypted = true;
		GC.Collect();

	}

	/// <summary>
	/// Generates a Manfest file and if saveLocation is set, saves to file inside of locker
	/// </summary>
	/// <returns>Manifest</returns>
	private Manifest GenerateManifest()
	{
		List<OurFile> files = GetFiles();
		Manifest m = new Manifest(this);
		foreach (OurFile f in files)
		{
			if (!f._isComputed)
			{
				throw new Exception("All file hashes must be computed before generating manifest!");
			}
			m.Add(new ManifestItem(f._uuid, f._path, f._hash, f._name, f._byteLength, f._fileIndex));
		}

		return m;
	}
}

public class Dir
{
	public DirManager _manager { get; private set; }
	public DirectoryInfo _self { get; private set; }
	public double _size { get; private set; }

	private Dir? _parent; //If null, it signified it's the root
	private List<Dir> _subDirs = new();
	private List<OurFile> _files = new();
	private bool _filesLoaded = false;
	private bool _subDirsLoaded = false;

	public Dir(DirManager manager, DirectoryInfo dir, Dir? parent = null)
	{
		_manager = manager;
		_parent = parent;
		_self = dir;
		_size = 0;

		foreach (DirectoryInfo d in dir.GetDirectories())
		{
			Dir subD = new(manager, d, this);
			_subDirs.Add(subD);
			_size += subD._size;
		}
		_subDirsLoaded = true;

		foreach (FileInfo f in dir.GetFiles())
		{
			_size += f.Length;
			OurFile nf = new(f, this);
			_files.Add(nf);
		}

		_filesLoaded = true;
	}

	public bool IsLoaded()
	{
		if (_filesLoaded && _subDirsLoaded)
			return true;
		return false;
	}

	public bool IsHashed()
	{
		foreach (OurFile f in GetFiles())
		{
			if (!f._isComputed)
				return false;
		}
		return true;
	}

	public List<OurFile> GetFiles()
	{
		List<OurFile> temp = new();
		foreach (Dir d in _subDirs)
		{
			foreach (OurFile f in d.GetFiles())
			{
				temp.Add(f);
			}
		}

		foreach (OurFile f in _files)
		{
			temp.Add(f);
		}

		return temp;
	}

	public string GetLocalPath()
	{
		if (_parent != null)
		{
			return $"{_parent.GetLocalPath()}{_self.Name}/";
		}
		else
		{
			//Is root
			return $"/";
		}
	}
}

public class OurFile
{
	public FileInfo _info { get; private set; }
	//private byte[] fileContent;
	private Dir _parent;
	public string? _hash { get; private set; }
	//public static long rootByte { get; private set; }
	public uint _byteLength { get; private set; }
	/// <summary>
	/// fileIndex is the index or order that the file was written into the locker (for example, the second file will be index 1).
	/// This information is vital for calculating where the starting byte is for a particular file
	/// </summary>
	public int _fileIndex { get; set; }
	public string _path { get; private set; }
	public string _name { get; private set; }
	public string? _uuid { get; private set; }
	public bool _isComputed { get; private set; }

	public OurFile(FileInfo file, Dir parent, string? uuid = null)
	{
		_info = file;
		_name = file.Name;
		_parent = parent;
		_path = parent.GetLocalPath();
		if (uuid == null)
			uuid = Guid.NewGuid().ToString();
		_uuid = uuid;
		ThreadPool.QueueUserWorkItem(Hash);
	}

	public string getRelativePath()
	{
		return $"{_parent.GetLocalPath()}\\{_info.Name}";
	}

	private void Hash(Object stateInfo)
	{
		using (FileStream fs = _info.OpenRead())
		{
			using BufferedStream b = new(fs);

			var hash_algo = MD5.Create();
			_hash = BitConverter.ToString(hash_algo.ComputeHash(b)).Replace("-", "").ToLower();
		}

		_isComputed = true;
	}

	public void Encrypt()
	{
		var locker = DirManager.GetLockerFile().FullName;
		var encryptor = DirManager.GetKey().CreateEncryptor();
		var manager = _parent._manager;
		
		try
		{
			using (FileStream fileRead = _info.OpenRead())
			{
				long startingLength;
				using (FileStream fileWrite = File.OpenWrite(locker))
				{
					startingLength = fileWrite.Length;
					
					using BufferedStream bRead = new(fileRead);
					using BufferedStream bWrite = new(fileWrite);
					using CryptoStream cs = new(bWrite, encryptor, CryptoStreamMode.Write);

					bWrite.Seek(0, SeekOrigin.End);
					bRead.CopyTo(cs);
				}
				_byteLength = (uint)(new FileInfo(locker).Length - startingLength);
			}
			manager._encryptCount++;
		}
		catch (Exception e)
		{
			manager._failed.Add(new FailedItem(this, e));
		}
		GC.Collect();
	}

}



public class Manifest : IEnumerable<ManifestItem>
{
	private List<ManifestItem> _items = new();
	#region Implmentation of ienumerable
	public IEnumerator<ManifestItem> GetEnumerator()
	{
		return _items.GetEnumerator();
	}

	IEnumerator IEnumerable.GetEnumerator()
	{
		return GetEnumerator();
	}
	#endregion
	private readonly DirManager? _manager;
	public Manifest(DirManager manager)
	{
		_manager = manager;
	}
	public Manifest(List<ManifestItem> list)
	{
		list.Sort(); //Sorts ManifestItems by fileIndex
		_items = list;
	}

	public ManifestItem GetItemByIndex(int index)
	{
		return _items[index];
	}

	public ManifestItem? GetItemByUUID(string uuid)
	{
		foreach (var item in _items)
		{
			if (item.UUID == uuid)
			{
				return item;
			}
		}
		return null;
	}

	public ManifestItem GetItemByName(string name)
	{
		foreach (var item in _items)
		{
			if (item.Name == name)
			{
				return item;
			}
		}
		return null;
	}

	public List<ManifestItem> GetItems()
	{
		return _items;
	}

	public void WriteToDisk()
	{
		var encryptor = DirManager.GetKey().CreateEncryptor();
		var locker = DirManager.GetLockerFile().FullName;

		using (FileStream fs = File.OpenWrite(locker))
		{
			fs.Seek(0, SeekOrigin.End);
			StreamWriter sw = new StreamWriter(fs);
			sw.Write("[manifest]");
			sw.Flush(); //Need to flush before seeking to make sure the header is writen
			fs.Seek(0, SeekOrigin.End);

			using (CryptoStream cs = new CryptoStream(fs, encryptor, CryptoStreamMode.Write))
			{
				using (StreamWriter csWriter = new StreamWriter(cs))
				{
					csWriter.Write(Serialize());
				}
			}

		}
	}

	public static Manifest? LoadFromDisk(AesCryptoServiceProvider key, FileInfo locker)
	{
		if (!locker.Exists)
			throw new Exception($"\"{locker.FullName}\" does not exist!");

		using (FileStream fs = File.OpenRead(locker.FullName))
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

					using var cs = new CryptoStream(buff, key.CreateDecryptor(), CryptoStreamMode.Read);

					StreamReader sr = new(cs);
					string json_string = sr.ReadToEnd();

					return Deserialize(json_string);
				}
			}
		}
		return null;
	}

	private static byte[] ShiftLeft(byte[] input)
	{
		byte[] shifted = new byte[input.Length];
		for (int i = 0; i < input.Length; i++)
		{
			shifted[i] = input[(i + 1) % input.Length];
		}
		return shifted;
	}

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
	/// Gets the starting byte for a given file
	/// </summary>
	/// <returns></returns>
	public long GetStartingByte(int index)
	{
		long byteLocation = 0;
		for (int i = 0; i < index; i++)
		{
			byteLocation += _items[i].ByteLength;
		}
		return byteLocation;
	}

	public void Add(ManifestItem item)
	{
		_items.Add(item);
	}
	public void Remove(ManifestItem item)
	{
		_items.Remove(item);
	}

	/// <summary>
	/// Verifies a file exists in the manifest and is located in the same path.
	/// </summary>
	/// <param name="item"></param>
	/// <returns></returns>
	private bool Exists(ManifestItem item)
	{
		foreach (ManifestItem i in _items)
		{
			if (i.Name == item.Name &&
				i.Path == item.Path)
				return true;
		}
		return false;
	}
	private bool Exists(string name, string localPath)
	{
		foreach (ManifestItem i in _items)
		{
			if (i.Name == name &&
				i.Path == localPath)
				return true;
		}
		return false;
	}

	public string Serialize()
	{
		return JsonSerializer.Serialize(_items);
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
	//Different case used for JSON formatting
	public string UUID { get; set; }
	public string Path { get; set; }
	public string Hash { get; set; }
	public string Name { get; set; }
	public long ByteLength { get; set; }
	public int FileIndex { get; set; }

	public ManifestItem(string uuid, string path, string hash, string name, long byteLength, int fileIndex)
	{
		UUID = uuid;
		Path = path;
		Hash = hash;
		Name = name;
		ByteLength = byteLength;
		FileIndex = fileIndex;
	}

	public int CompareTo(object? obj)
	{
		/*System.ArgumentException: 'Object must be of type Int32.'*/
		var t = (ManifestItem)obj;
		/*if(t == null)
		{
			throw new Exception("Manifest item cannot be compared to null");
		}*/
		return FileIndex.CompareTo(t.FileIndex);
	}
}

public class FailedItem
{
	public OurFile _file { get; private set; }
	public Exception _exception { get; private set; }
	public FailedItem(OurFile file, Exception exception)
	{
		_file = file;
		_exception = exception;
	}
}