using System;
using System.Numerics;
namespace RSA
{
    public class RSAProvider : IRSAProvider
    {
        public BigInteger Encrypt(string data, KeyInfo publicKey)
        {
            var number = BigInteger.Parse(data);
            var enc = BigInteger.ModPow(number, publicKey.Number, publicKey.Mod);
            return enc;
        }
        public string Decrypt(BigInteger data, KeyInfo privateKey)
        {
            var dec = BigInteger.ModPow(data, privateKey.Number, privateKey.Mod);
            return dec.ToString();
        }
    }
}
