namespace RSA
{
    public interface IRSAKeyGenerator
    {
        KeyInfo PrivateKey();

        KeyInfo PublicKey();
    }
}
