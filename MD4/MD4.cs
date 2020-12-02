using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MD4
{
    public class MD4
    {
        private uint Rol(uint x, uint y)
        {
            return x << (int)y | x >> 32 - (int)y;
        }

        public byte[] GetHash(byte[] bytes)
        {
            List<byte> bytesList = new List<byte>(bytes);
            uint bitCount = (uint)(bytesList.Count) * 8;
            bytesList.Add(128);
            while (bytesList.Count % 64 != 56) bytesList.Add(0);
            var uints = new List<uint>();
            for (int i = 0; i + 3 < bytesList.Count; i += 4)
            {
                uints.Add(bytesList[i] | (uint)bytesList[i + 1] << 8 | (uint)bytesList[i + 2] << 16 | (uint)bytesList[i + 3] << 24);
            }
            uints.Add(bitCount);
            uints.Add(0);

            uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
            for (int q = 0; q + 15 < uints.Count; q += 16)
            {
                var chunk = uints.GetRange(q, 16);
                uint aa = a, bb = b, cc = c, dd = d;
                void round(Func<uint, uint, uint, uint> f, uint[] y)
                {
                    foreach (uint i in new[] { y[0], y[1], y[2], y[3] })
                    {
                        a = Rol(a + f(b, c, d) + chunk[(int)(i + y[4])] + y[12], y[8]);
                        d = Rol(d + f(a, b, c) + chunk[(int)(i + y[5])] + y[12], y[9]);
                        c = Rol(c + f(d, a, b) + chunk[(int)(i + y[6])] + y[12], y[10]);
                        b = Rol(b + f(c, d, a) + chunk[(int)(i + y[7])] + y[12], y[11]);
                    }
                }
                round((x, y, z) => (x & y) | (~x & z), new uint[] { 0, 4, 8, 12, 0, 1, 2, 3, 3, 7, 11, 19, 0 });
                round((x, y, z) => (x & y) | (x & z) | (y & z), new uint[] { 0, 1, 2, 3, 0, 4, 8, 12, 3, 5, 9, 13, 0x5a827999 });
                round((x, y, z) => x ^ y ^ z, new uint[] { 0, 2, 1, 3, 0, 8, 4, 12, 3, 9, 11, 15, 0x6ed9eba1 });
                a += aa; b += bb; c += cc; d += dd;
            }

            byte[] outBytes = new[] { a, b, c, d }.SelectMany(BitConverter.GetBytes).ToArray();
            return outBytes;
        }
    }
}
