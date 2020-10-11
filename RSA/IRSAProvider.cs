using System.Numerics;

namespace RSA
{
    public interface IRSAProvider
    {
        BigInteger Encrypt(string data, KeyInfo publicKey);

        string Decrypt(BigInteger data, KeyInfo privateKey);
    }
}
