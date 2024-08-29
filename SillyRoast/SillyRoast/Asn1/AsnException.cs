// Taken from https://github.com/GhostPack/Rubeus/blob/master/Rubeus/Asn1/AsnException.cs

using System;
using System.IO;

namespace Asn1
{

    public class AsnException : IOException
    {

        public AsnException(string message)
            : base(message)
        {
        }

        public AsnException(string message, Exception nested)
            : base(message, nested)
        {
        }
    }

}
