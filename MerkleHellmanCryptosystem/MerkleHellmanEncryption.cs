using Open.Numeric.Primes;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MerkleHellmanCryptosystem
{
    public class MerkleHellmanEncryption
    {
        private const ulong maxRandomULong = 100;
        private readonly RNGCryptoServiceProvider cryptoServiceProvider = new RNGCryptoServiceProvider();

        private ulong RandomULong(ulong min = ulong.MinValue, ulong max = ulong.MaxValue)
        {
            ulong scale = ulong.MaxValue;
            while (scale == ulong.MaxValue)
            {
                byte[] four_bytes = new byte[8];
                cryptoServiceProvider.GetBytes(four_bytes);
                scale = BitConverter.ToUInt64(four_bytes, 0);
            }
            return (ulong)(min + (max - min) * (scale / (double)ulong.MaxValue));
        }

        public MerkleHellmanKey GenerateKey(int sequenceLength)
        {
            ulong[] secretSequence = new ulong[sequenceLength];
            ulong sum = 0;
            for (int i = 0; i < sequenceLength; ++i)
            {
                if (i > 0)
                {
                    secretSequence[i] = sum + RandomULong(1, maxRandomULong);
                }
                else
                {
                    secretSequence[i] = RandomULong(1, maxRandomULong);
                }
                sum += secretSequence[i];
            }

            ulong q = Prime.Numbers.StartingAt(sum + 1).First();
            ulong r = RandomULong(1, q);

            ulong[] publicKey = new ulong[sequenceLength];
            for (int i = 0; i < sequenceLength; ++i)
            {
                publicKey[i] = secretSequence[i] * r % q;
            }

            return new MerkleHellmanKey
            {
                PublicKey = new PublicKey
                {
                    PublicSequence = publicKey
                },
                SecretKey = new SecretKey
                {
                    SecretSequence = secretSequence,
                    Q = q,
                    R = r
                }
            };
        }

        private ulong EncryptBitArray(BitArray bits, PublicKey key)
        {
            ulong result = 0;
            for (int i = 0; i < bits.Length; ++i)
            {
                if (bits[i])
                {
                    result += key.PublicSequence[i];
                }
            }
            return result;
        }

        private ulong FindInverse(ulong number, ulong mod)
        {
            return (ulong)BigInteger.ModPow(number, mod - 2, mod);
        }

        private ulong GetMaxLessThen(ulong[] array, ulong ceil)
        {
            return array.Where(elem => elem <= ceil).Max();
        }

        private BitArray DecryptEncryptedValue(ulong encryptedValue, SecretKey key)
        {
            var selectedIndexes = new List<int>();
            ulong decrypted = encryptedValue * FindInverse(key.R, key.Q) % key.Q;
            ulong keyElem = GetMaxLessThen(key.SecretSequence, decrypted);
            selectedIndexes.Add(key.SecretSequence.ToList().IndexOf(keyElem));
            ulong diff = decrypted - keyElem;
            while (diff > 0)
            {
                keyElem = GetMaxLessThen(key.SecretSequence, diff);
                selectedIndexes.Add(key.SecretSequence.ToList().IndexOf(keyElem));
                diff -= keyElem;
            }

            var result = new BitArray(key.SecretSequence.Length);
            foreach (var index in selectedIndexes)
            {
                result[index] = true;
            }
            return result;
        }

        private byte[] BitArrayToBytes(BitArray bitArray)
        {
            byte[] bytes = new byte[bitArray.Length / 8];
            for (int i = 0; i < bytes.Length; ++i)
            {
                byte sum = 0;
                for (int k = 0; k < 8; ++k)
                {
                    sum += (byte)(bitArray[8 * i + k] ? Math.Pow(2, k) : 0);
                }
                bytes[i] = sum;
            }
            return bytes;
        }

        private byte[] AddExtraBytes(byte[] bytes, int blockSize)
        {
            if (bytes.Length % blockSize != 0)
            {
                int nExtraBytes = blockSize - (bytes.Length % blockSize);
                int normalizedLength = bytes.Length + nExtraBytes;
                byte[] normalizedBytes = new byte[normalizedLength];
                bytes.CopyTo(normalizedBytes, 0);
                for (int i = 0; i < nExtraBytes; ++i)
                {
                    normalizedBytes[bytes.Length + i] = (byte)nExtraBytes;
                }
                return normalizedBytes;
            }
            return bytes;
        }

        private int GetExtraBytes(byte[] bytes)
        {
            int possibleExtraBytes = bytes[bytes.Length - 1];
            for (int i = 0; i < possibleExtraBytes; ++i)
            {
                if (bytes[bytes.Length - i - 1] != possibleExtraBytes)
                {
                    return 0;
                }
            }
            return possibleExtraBytes;
        }

        private byte[] RemoveExtraBytes(byte[] bytes)
        {
            int extraBytes = GetExtraBytes(bytes);
            Array.Resize(ref bytes, bytes.Length - extraBytes);
            return bytes;
        }

        public ulong Encrypt(BitArray inputBits, PublicKey key)
        {
            return EncryptBitArray(inputBits, key);
        }

        public BitArray Decrypt(ulong encrypted, SecretKey key)
        {
            return DecryptEncryptedValue(encrypted, key);
        }

        public byte[] EncryptBytes(byte[] bytes, PublicKey key)
        {
            int bytesPerBlock = key.PublicSequence.Length / 8;
            byte[] normalizedBytes = AddExtraBytes(bytes, bytesPerBlock);
            int nBlocks = normalizedBytes.Length / bytesPerBlock;
            var byteList = new List<byte>(normalizedBytes);
            byte[] encryptedBytes = new byte[nBlocks * sizeof(ulong)];
            for (int i = 0; i < nBlocks; i++)
            {
                var byteBlock = byteList.GetRange(i * bytesPerBlock, bytesPerBlock);
                var bitArray = new BitArray(byteBlock.ToArray());
                ulong encryptedValue = Encrypt(bitArray, key);
                BitConverter.GetBytes(encryptedValue).CopyTo(encryptedBytes, i * sizeof(ulong));
            }
            return encryptedBytes;
        }

        public byte[] DecryptBytes(byte[] bytes, SecretKey key)
        {
            int nBlocks = bytes.Length / sizeof(ulong);
            int bytesPerBlock = key.SecretSequence.Length / 8;
            byte[] decryptedBytes = new byte[nBlocks * key.SecretSequence.Length / 8];
            for (int i = 0; i < nBlocks; ++i)
            {
                ulong encryptedValue = BitConverter.ToUInt64(bytes, i * sizeof(ulong));
                var decryptedBits = Decrypt(encryptedValue, key);
                BitArrayToBytes(decryptedBits).CopyTo(decryptedBytes, i * bytesPerBlock);
            }
            byte[] originalBytes = RemoveExtraBytes(decryptedBytes);
            return originalBytes;
        }
    }
}
