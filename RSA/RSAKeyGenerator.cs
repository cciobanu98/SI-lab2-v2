using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RSA
{
    public class RSAKeyGenerator : IRSAKeyGenerator
    {
        private BigInteger result;
        private BigInteger p, q, mod, f;
        private BigInteger e = 65537;
        public RSAKeyGenerator(int size)
        {
            p = randomGenerator(size);
            q = randomGenerator(size);
            if (IsPrime(p, 10) == true && IsPrime(q, 10) == true)
            {
                mod = p * q;
            }
            else
            {
                p = GetNearestPrime(p);
                q = GetNearestPrime(q);
                mod = p * q;
            }
            f = EulerFunction(p, q);
        }

        private bool IsPrime(BigInteger source, int certainty)
        {
            if (source == 2 || source == 3)
                return true;
            if (source < 2 || source % 2 == 0)
                return false;

            BigInteger d = source - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[source.ToByteArray().LongLength];
            BigInteger a;

            for (int i = 0; i < certainty; i++)
            {
                do
                {
                    rng.GetBytes(bytes);
                    a = new BigInteger(bytes);
                }
                while (a < 2 || a >= source - 2);

                BigInteger x = BigInteger.ModPow(a, d, source);
                if (x == 1 || x == source - 1)
                    continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, source);
                    if (x == 1)
                        return false;
                    if (x == source - 1)
                        break;
                }

                if (x != source - 1)
                    return false;
            }

            return true;
        }

        private BigInteger randomGenerator(int size)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] randomNumber = new byte[size];
            rng.GetBytes(randomNumber);
            var number = new BigInteger(randomNumber);
            number = BigInteger.Abs(number);
            return number;
        }

        private BigInteger GetNearestPrime(BigInteger bigInteger)
        {
            while (IsPrime(bigInteger, 10) == false)
            {
                bigInteger++;
            }
            return bigInteger;
        }

        private BigInteger EulerFunction(BigInteger p, BigInteger q)
        {
            BigInteger m = p - 1;
            BigInteger n = q - 1;
            return m * n;
        }

        private BigInteger Pow(BigInteger value, BigInteger exponent)
        {
            BigInteger originalValue = value;
            while (exponent-- > 1)
                value = BigInteger.Multiply(value, originalValue);
            return value;
        }

        public BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            if (m == 1) return 0;
            BigInteger m0 = m;
            (BigInteger x, BigInteger y) = (1, 0);

            while (a > 1)
            {
                BigInteger q = a / m;
                (a, m) = (m, a % m);
                (x, y) = (y, x - q * y);
            }
            return x < 0 ? x + m0 : x;
        }
        public KeyInfo PrivateKey()
        {
            var inverse = ModInverse(e, f);
            return new KeyInfo() { Mod = mod, Number = inverse };
        }

        public KeyInfo PublicKey()
        {
            return new KeyInfo() { Number = e, Mod = mod };
        }
    }
}
