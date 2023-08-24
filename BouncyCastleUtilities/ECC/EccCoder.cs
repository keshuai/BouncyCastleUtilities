using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BouncyCastleUtilities;


public class EccCoder : Coder
{
    private readonly SM2Engine _sm2Engine;
    
    public EccCoder(bool forEncryption, ICipherParameters key)
    {
        _sm2Engine = new SM2Engine();
        _sm2Engine.Init(forEncryption, key);
    }

    public override byte[] Code(byte[] input, int offset, int count)
    {
        return _sm2Engine.ProcessBlock(input, offset, count);
    }
}

public class EccEncoder : EccCoder
{
    public EccEncoder(ECPublicKeyParameters publicKey) : base(true, new ParametersWithRandom(publicKey))
    {
    }
}

public class EccDecoder : EccCoder
{
    public EccDecoder(ECPrivateKeyParameters privateKey) : base(false, privateKey)
    {
    }
}

public class EccSigner : Signer
{
    private readonly ISigner _signer;
    public EccSigner(ECPrivateKeyParameters privateKey)
    {
        _signer = SignerUtilities.GetSigner("ECDSA");
        _signer.Init(true, privateKey);
    }

    public override byte[] Sign(byte[] input, int offset, int count)
    {
        _signer.Reset();
        _signer.BlockUpdate(input, offset, count);
        return _signer.GenerateSignature();
    }
}

public class EccVerifier : Verifier
{
    private readonly ISigner _signer;
    public EccVerifier(ECPublicKeyParameters publicKey)
    {
        _signer = SignerUtilities.GetSigner("ECDSA");
        _signer.Init(false, publicKey);
    }

    public override bool Verify(byte[] input, int offset, int count, byte[] signature)
    {
        _signer.Reset();
        _signer.BlockUpdate(input, offset, count);
        return _signer.VerifySignature(signature);
    }
}