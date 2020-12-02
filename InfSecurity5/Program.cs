using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MerkleHellmanCryptosystem;
using Newtonsoft.Json;
using System.Security.Cryptography;
using RSAModule;

namespace InfSecurity5
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                if (args.Length > 0)
                {
                    var command = args[0].ToLower();
                    if (command == "gen-encr-keys" && args.Length >= 2)
                    {
                        GenerateEncryptionKeys(args[1]);
                    }
                    else if (command == "gen-sign-keys" && args.Length >= 2)
                    {
                        GenerateSignKeys(args[1]);
                    }
                    else if (command == "encrypt" && args.Length >= 4)
                    {
                        EncryptFile(args[1], args[2], args[3]);
                    }
                    else if (command == "decrypt" && args.Length >= 4)
                    {
                        DecryptFile(args[1], args[2], args[3]);
                    }
                    else
                    {
                        Console.WriteLine("Wrong command or number of arguments.");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        static void GenerateEncryptionKeys(string filename)
        {
            var crypto = new MerkleHellmanEncryption();
            var key = crypto.GenerateKey(24);

            var privateKeyFilename = AddToFilename(filename, "_private");
            SerializeToFile(key.SecretKey, privateKeyFilename);
            Console.WriteLine("File " + privateKeyFilename + " created.");

            var publicKeyFilename = AddToFilename(filename, "_public");
            SerializeToFile(key.PublicKey, publicKeyFilename);
            Console.WriteLine("File " + publicKeyFilename + " created.");
        }

        static void GenerateSignKeys(string filename)
        {
            var crypto = new RSAModule.RSAModule();
            crypto.GenerateKeys(out string privateKey, out string publicKey);

            var privateKeyFilename = AddToFilename(filename, "_public");
            WriteTextFile(privateKey, privateKeyFilename);
            Console.WriteLine("File " + privateKeyFilename + " created.");

            var publicKeyFilename = AddToFilename(filename, "_private");
            WriteTextFile(publicKey, publicKeyFilename);
            Console.WriteLine("File " + publicKeyFilename + " created.");
        }

        static void EncryptFile(string filename, string encryptionKeyFilename, string signKeyFilename)
        {
            var originalBytes = ReadFile(filename);
            var crypto = new MerkleHellmanEncryption();
            var merkleHellmanPublicKey = DeserializeFromFile<PublicKey>(encryptionKeyFilename);
            Console.WriteLine("Encrypting...");
            byte[] originalBytesEncrypted = crypto.EncryptBytes(originalBytes, merkleHellmanPublicKey);

            Console.WriteLine("Signing...");
            byte[] originalBytesEncryptedHash = new MD4.MD4().GetHash(originalBytesEncrypted);

            var rsa = new RSAModule.RSAModule();
            var rsaPublicKey = ReadTextFile(signKeyFilename);
            byte[] originalBytesEncryptedHashEncrypted = rsa.Encrypt(originalBytesEncryptedHash, rsaPublicKey);

            byte[] encryptedSignedBytes = ConcatArrays(originalBytesEncrypted, originalBytesEncryptedHashEncrypted);

            var enryptedFilename = AddToFilename(filename, "_encrypted");
            WriteFile(encryptedSignedBytes, enryptedFilename);
            Console.WriteLine("File " + enryptedFilename + " created.");
        }

        static void DecryptFile(string filename, string decryptionKeyFilename, string signKeyFilename)
        {
            var encryptedSignedBytes = ReadFile(filename);
            var rsa = new RSAModule.RSAModule();
            byte[] encryptedHash = new byte[rsa.KeySize];
            Array.Copy(encryptedSignedBytes, encryptedSignedBytes.Length - rsa.KeySize, encryptedHash, 0, rsa.KeySize);

            byte[] encryptedBodyBytes = new byte[encryptedSignedBytes.Length - rsa.KeySize];
            Array.Copy(encryptedSignedBytes, encryptedBodyBytes, encryptedBodyBytes.Length);

            var rsaPrivateKey = ReadTextFile(signKeyFilename);
            Console.WriteLine("Checking sign...");
            byte[] decryptedHash = rsa.Decrypt(encryptedHash, rsaPrivateKey);

            byte[] encryptedBodyBytesHash = new MD4.MD4().GetHash(encryptedBodyBytes);

            if (BitConverter.ToString(encryptedBodyBytesHash) == BitConverter.ToString(decryptedHash))
            {
                Console.WriteLine("Sign is correct.");
                var crypto = new MerkleHellmanEncryption();
                var merkleHellmanSecretKey = DeserializeFromFile<SecretKey>(decryptionKeyFilename);
                Console.WriteLine("Decrypting...");
                byte[] decryptedBodyBytes = crypto.DecryptBytes(encryptedBodyBytes, merkleHellmanSecretKey);

                var decryptedFilename = AddToFilename(filename, "_decrypted");
                WriteFile(decryptedBodyBytes, decryptedFilename);
                Console.WriteLine("File " + decryptedFilename + " created.");
            }
            else
            {
                Console.WriteLine("Sign is corrupted. Can't decrypt file.");
            }
        }

        static void Test2()
        {
            var filePath = "D:\\my_files\\inf_secur_5_demo\\test_text.txt";
            var merkleHellmanKeyPath = "D:\\my_files\\inf_secur_5_demo\\key.json";
            var rsaPrivateKeyPath = "D:\\my_files\\inf_secur_5_demo\\rsa_private_key.xml";
            var rsaPublicKeyPath = "D:\\my_files\\inf_secur_5_demo\\rsa_public_key.xml";
            var filePathEncrypted = "D:\\my_files\\inf_secur_5_demo\\test_text_encrypted.txt";
            var filePathDecrypted = "D:\\my_files\\inf_secur_5_demo\\test_text_decrypted.txt";


            var originalBytes = ReadFile(filePath);
            var crypto = new MerkleHellmanEncryption();

            Console.WriteLine("Generating key...");
            var merkleHellmanKey = crypto.GenerateKey(24);
            SerializeToFile(merkleHellmanKey, merkleHellmanKeyPath);
            merkleHellmanKey = DeserializeFromFile<MerkleHellmanKey>(merkleHellmanKeyPath);

            Console.WriteLine("Encrypting...");
            byte[] originalBytesEncrypted = crypto.EncryptBytes(originalBytes, merkleHellmanKey.PublicKey);

            Console.WriteLine("Hashing...");
            byte[] originalBytesEncryptedHash = new MD4.MD4().GetHash(originalBytesEncrypted);

            var rsa = new RSAModule.RSAModule();
            rsa.GenerateKeys(out string rsaPrivateKey, out string rsaPublicKey);

            WriteTextFile(rsaPrivateKey, rsaPrivateKeyPath);
            WriteTextFile(rsaPublicKey, rsaPublicKeyPath);

            rsaPrivateKey = ReadTextFile(rsaPrivateKeyPath);
            rsaPublicKey = ReadTextFile(rsaPublicKeyPath);

            Console.WriteLine("Hash encrypting...");
            byte[] originalBytesEncryptedHashEncrypted = rsa.Encrypt(originalBytesEncryptedHash, rsaPublicKey);

            byte[] encryptedSignedBytes = ConcatArrays(originalBytesEncrypted, originalBytesEncryptedHashEncrypted);

            WriteFile(encryptedSignedBytes, filePathEncrypted);


            var encryptedSignedBytesReaded = ReadFile(filePathEncrypted);

            if (BytesAreSame(encryptedSignedBytesReaded, encryptedSignedBytes))
            { 
                Console.WriteLine("CHECK #1 OK!");
            }
            else
            {
                Console.WriteLine("CHECK #1 FAILED!");
            }

            byte[] originalBytesEncryptedHashEncryptedReaded = new byte[rsa.KeySize];
            Array.Copy(encryptedSignedBytesReaded, encryptedSignedBytesReaded.Length - rsa.KeySize, originalBytesEncryptedHashEncryptedReaded, 0, rsa.KeySize);

            if (BytesAreSame(originalBytesEncryptedHashEncryptedReaded, originalBytesEncryptedHashEncrypted))
            {
                Console.WriteLine("CHECK #2 OK!");
            }
            else
            {
                Console.WriteLine("CHECK #2 FAILED!");
            }

            byte[] originalBytesEncryptedReaded = new byte[encryptedSignedBytesReaded.Length - rsa.KeySize];
            Array.Copy(encryptedSignedBytesReaded, originalBytesEncryptedReaded, originalBytesEncryptedReaded.Length);

            if (BytesAreSame(originalBytesEncryptedReaded, originalBytesEncrypted))
            {
                Console.WriteLine("CHECK #3 OK!");
            }
            else
            {
                Console.WriteLine("CHECK #3 FAILED!");
            }

            byte[] originalBytesDecryptedHash = rsa.Decrypt(originalBytesEncryptedHashEncryptedReaded, rsaPrivateKey);

            byte[] decryptedBytesHash = new MD4.MD4().GetHash(originalBytesEncryptedReaded);

            if (BitConverter.ToString(decryptedBytesHash) == BitConverter.ToString(originalBytesDecryptedHash))
            {
                Console.WriteLine("HASH IS VALID!");

                Console.WriteLine("Decrypting...");
                byte[] originalBytesDecrypted = crypto.DecryptBytes(originalBytesEncryptedReaded, merkleHellmanKey.SecretKey);
                WriteFile(originalBytesDecrypted, filePathDecrypted);
            }
            else
            {
                Console.WriteLine("HASH IS NOT VALID!");
            }
            Console.WriteLine("Done!");
            Console.ReadLine();

        }

        static void Test()
        {
            var filePath = "D:\\my_files\\inf_secur_5_demo\\test_text.txt";
            var bytes = ReadFile(filePath);
            var crypto = new MerkleHellmanEncryption();

            Console.WriteLine("Generating key...");
            var key = crypto.GenerateKey(24);
            SerializeToFile(key, "D:\\my_files\\inf_secur_5_demo\\key.json");
            key = DeserializeFromFile<MerkleHellmanKey>("D:\\my_files\\inf_secur_5_demo\\key.json");

            Console.WriteLine("Encrypting...");
            byte[] encryptedBytes = crypto.EncryptBytes(bytes, key.PublicKey);

            Console.WriteLine("Hashing...");
            byte[] MD4Hash = new MD4.MD4().GetHash(encryptedBytes);

            var rsa = new RSAModule.RSAModule();
            //var rsaKeys = rsa.GenerateKeys();
            //SerializeToFile(rsaKeys, "D:\\my_files\\inf_secur_5_demo\\rsaKeys.json");
            //rsaKeys = DeserializeFromFile<RSAKeys>("D:\\my_files\\inf_secur_5_demo\\rsaKeys.json");

            rsa.GenerateKeys(out string privateKey, out string publicKey);
            WriteTextFile(privateKey, "D:\\my_files\\inf_secur_5_demo\\rsa_private_key.xml");
            WriteTextFile(publicKey, "D:\\my_files\\inf_secur_5_demo\\rsa_public_key.xml");

            privateKey = ReadTextFile("D:\\my_files\\inf_secur_5_demo\\rsa_private_key.xml");
            publicKey = ReadTextFile("D:\\my_files\\inf_secur_5_demo\\rsa_public_key.xml");

            Console.WriteLine("Hash encrypting...");
            byte[] encryptedHash = rsa.Encrypt(MD4Hash, publicKey);

            Console.WriteLine("Appending encrypted hash...");
            Array.Resize(ref encryptedBytes, encryptedBytes.Length + encryptedHash.Length);
            encryptedHash.CopyTo(encryptedBytes, encryptedBytes.Length - encryptedHash.Length);

            WriteFile(encryptedBytes, AddToFilename(filePath, "_encrypted"));

            // Decrytping
            var filePath2 = AddToFilename(filePath, "_encrypted");
            var bytes2 = ReadFile(filePath2);

            byte[] encryptedHash2 = new byte[rsa.KeySize];
            Array.Copy(bytes2, bytes2.Length - rsa.KeySize, encryptedHash2, 0, rsa.KeySize);

            var res = BytesAreSame(encryptedHash, encryptedHash2);

            byte[] encryptedBody = new byte[bytes2.Length - rsa.KeySize];
            Array.Copy(bytes2, encryptedBody, encryptedBody.Length);

            //rsaKeys = DeserializeFromFile<RSAKeys>("D:\\my_files\\inf_secur_5_demo\\rsaKeys.json");
            byte[] decryptedHash = rsa.Decrypt(encryptedHash2, privateKey);
            byte[] actualHash = new MD4.MD4().GetHash(encryptedBody);
            if (BitConverter.ToString(decryptedHash) == BitConverter.ToString(actualHash))
            {
                Console.WriteLine("HASH IS VALID!");

                Console.WriteLine("Decrypting...");
                byte[] decryptedBytes = crypto.DecryptBytes(encryptedBody, key.SecretKey);
                WriteFile(decryptedBytes, AddToFilename(filePath2, "_decrypted"));
            }
            else
            {
                Console.WriteLine("HASH IS NOT VALID!");
            }
            Console.ReadLine();
        }

        static byte[] ReadFile(string fileName)
        {
            using (var fileStream = File.Open(fileName, FileMode.Open))
            {
                using (var reader = new BinaryReader(fileStream))
                {
                    return reader.ReadBytes((int)fileStream.Length);
                }
            }
        }

        static void WriteFile(byte[] bytes, string fileName)
        {
            File.WriteAllBytes(fileName, bytes);
        }

        static string AddToFilename(string filename, string appendix)
        {
            return filename.Insert(filename.LastIndexOf('.'), appendix);
        }

        static void SerializeToFile<T>(T key, string filename)
        {
            var jsonString = JsonConvert.SerializeObject(key);
            File.WriteAllText(filename, jsonString);
        }

        static T DeserializeFromFile<T>(string filename)
        {
            var jsonString = File.ReadAllText(filename);
            return JsonConvert.DeserializeObject<T>(jsonString);
        }

        static void WriteTextFile(string text, string filename)
        {
            File.WriteAllText(filename, text);
        }

        static string ReadTextFile(string filename)
        {
            return File.ReadAllText(filename);
        }

        static bool BytesAreSame(byte[] bytes1, byte[] bytes2)
        {
            if (bytes1.Length == bytes2.Length)
            {
                for (int i = 0; i < bytes1.Length; ++i)
                {
                    if (bytes1[i] != bytes2[i])
                    {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        static byte[] ConcatArrays(byte[] array1, byte[] array2)
        {
            byte[] result = new byte[array1.Length + array2.Length];
            array1.CopyTo(result, 0);
            array2.CopyTo(result, array1.Length);
            return result;
        }
    }
}
