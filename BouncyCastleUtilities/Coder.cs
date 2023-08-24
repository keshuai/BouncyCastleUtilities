namespace BouncyCastleUtilities;

public abstract class Coder
{
    public abstract byte[] Code(byte[] input, int offset, int count);
    public byte[] Code(byte[] input) => this.Code(input, 0, input.Length);
}

public abstract class Signer
{
    public abstract byte[] Sign(byte[] input, int offset, int count);
    public byte[] Sign(byte[] input) => this.Sign(input, 0, input.Length);
}

public abstract class Verifier
{
    public abstract bool Verify(byte[] input, int offset, int count, byte[] signature);
    public bool Verify(byte[] input, byte[] signature) => this.Verify(input, 0, input.Length, signature);
}