using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MerkleHellmanCryptosystem
{
    public class MerkleHellmanKey
    {
        public PublicKey PublicKey { get; set; }
        public SecretKey SecretKey { get; set; }
    }

    public class PublicKey
    {
        public ulong[] PublicSequence { get; set; }
    }

    public class SecretKey
    {
        public ulong[] SecretSequence { get; set; }
        public ulong Q { get; set; }
        public ulong R { get; set; }
    }
}
