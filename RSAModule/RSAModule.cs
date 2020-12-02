using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSAModule
{
    public class RSAKeys
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
    }

    public class RSAModule
    {
        static readonly int keyBitSize = 1024;

        private string KeyToString(RSAParameters key)
        {
            var stringWriter = new System.IO.StringWriter();
            var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xmlSerializer.Serialize(stringWriter, key);
            return stringWriter.ToString();
        }

        public int KeySize
        {
            get => keyBitSize / 8;
        }

        public RSAKeys GenerateKeys()
        {
            var cryptoServiceProvider = new RSACryptoServiceProvider(keyBitSize);
            var privateKey = cryptoServiceProvider.ToXmlString(true); 
            var publicKey = cryptoServiceProvider.ToXmlString(false);
            return new RSAKeys
            {
                PublicKey = publicKey,
                PrivateKey = privateKey
            };
        }

        public void GenerateKeys(out string privateKey, out string publicKey)
        {
            var cryptoServiceProvider = new RSACryptoServiceProvider(keyBitSize);
            privateKey = cryptoServiceProvider.ToXmlString(true);
            publicKey = cryptoServiceProvider.ToXmlString(false);
        }

        public byte[] Encrypt(byte[] bytesToEncrypt, string privateKeyString)
        {
            using (var rsa = new RSACryptoServiceProvider(keyBitSize))
            {
                rsa.FromXmlString(privateKeyString);
                var encryptedData = rsa.Encrypt(bytesToEncrypt, false);
                return encryptedData;
            }
        }

        public byte[] Decrypt(byte[] bytesToDecrypt, string publicKeyString)
        {
            using (var rsa = new RSACryptoServiceProvider(keyBitSize))
            {
                rsa.FromXmlString(publicKeyString);
                var decryptedBytes = rsa.Decrypt(bytesToDecrypt, false);
                return decryptedBytes;
            }
        }
    }
}
