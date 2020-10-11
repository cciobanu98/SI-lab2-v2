using System;

namespace RSA
{
    class Program
    {
        static void Main(string[] args)
        {
            var keyGenerator = new RSAKeyGenerator(128);
            var publicKey = keyGenerator.PublicKey();
            var privateKey = keyGenerator.PrivateKey();

            var rsaPrivider = new RSAProvider();

            Console.Write("Text: ");
            var msg = Console.ReadLine();
            var enc = rsaPrivider.Encrypt(msg, publicKey);
            Console.WriteLine($"Encrypted message: {enc}");
            var dec = rsaPrivider.Decrypt(enc, privateKey);
            Console.WriteLine($"Decypred meessage: {dec}");

        }
    }
}
