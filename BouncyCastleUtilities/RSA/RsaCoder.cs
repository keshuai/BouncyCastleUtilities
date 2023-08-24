using System.Runtime.CompilerServices;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BouncyCastleUtilities;

public abstract class RsaCoder : Coder
{
    protected readonly IBufferedCipher _cipher;

    protected readonly int _inputBlockSize;
    protected readonly int _outputBlockSize;
    
    public RsaCoder(bool forEncryption, RsaKeyParameters key)
    {
        _cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
        _cipher.Init(forEncryption, key);
        
        _inputBlockSize = _cipher.GetBlockSize();
        _outputBlockSize = _cipher.GetOutputSize(0);
    }

    public int GetInputBlockSize() => _inputBlockSize;
    public int GetOutputBlockSize() => _outputBlockSize;
    
    protected void CodeBlocksToBuffer(byte[] input, int offSet, int count, byte[] outputBuffer)
    {
        var inputBlockSize = _inputBlockSize;
        var outputBufferOffset = 0;

        while (count > 0)
        {
            var inputCount = Math.Min(inputBlockSize, count);
            
            var encodedBlock = _cipher.DoFinal(input, offSet, inputCount);
            Buffer.BlockCopy(encodedBlock, 0, outputBuffer, outputBufferOffset, encodedBlock.Length);
            
            offSet += inputCount;
            count -= inputCount;
            outputBufferOffset += encodedBlock.Length;
        }
    }

    protected int CalculateOutputSize(int inputSize)
    {
        var blockCount = inputSize / _inputBlockSize;
        if (inputSize % _inputBlockSize != 0)
        {
            ++blockCount;
        }

        return blockCount * _outputBlockSize;
    }
}

public class RsaEncoder : RsaCoder
{
    public RsaEncoder(RsaKeyParameters key) : base(true, key)
    {
    }
    
    public override byte[] Code(byte[] input, int offSet, int count)
    {
        _cipher.Reset();
        
        var outputSize = this.CalculateOutputSize(count);
        var outputBuffer = new byte[outputSize + 4]; // 将原始数据长度放在尾部，解密时可以处理尾0.
        
        this.CodeBlocksToBuffer(input, offSet, count, outputBuffer);
        WriteInt32(outputBuffer, outputSize, count);
        
        return outputBuffer;
    }
    
    private static void WriteInt32(byte[] buffer, int offset, int value)
    {
        var uintValue = (uint)value;
        buffer[offset] = (byte)(uintValue >> 24);
        buffer[offset + 1] = (byte)((uintValue & 0x0000FFFFFFFFFFFF) >> 16);
        buffer[offset + 2] = (byte)((uintValue & 0x00000000FFFFFFFF) >> 8);
        buffer[offset + 3] = (byte)((uintValue & 0x000000000000FFFF));
    }
}

public class RsaDecoder : RsaCoder
{
    public RsaDecoder(RsaKeyParameters key) : base(false, key)
    {
    }
    
    public override byte[] Code(byte[] input, int offSet, int count)
    {
        if (count < _inputBlockSize + 4)
        {
            throw new Exception($"input count < min: {count} < {_inputBlockSize + 4}");
        }

        _cipher.Reset();
        count -= 4;
        
        var outputSize = this.CalculateOutputSize(count);
        var sourceLength = ReadInt32(input, count);
        if (sourceLength < 0 || sourceLength > outputSize)
        {
            throw new Exception($"error source length: {sourceLength}, outputSize: {outputSize}");
        }
        
        var outputBuffer = new byte[outputSize];
        this.CodeBlocksToBuffer(input, offSet, count, outputBuffer);
        return TrimTailZeroWithSourceLength(outputBuffer, sourceLength);
    }

    private static byte[] TrimTailZeroWithSourceLength(byte[] buffer, int sourceLength)
    {
        if (sourceLength == buffer.Length)
        {
            return buffer;
        }

        var sourceBuffer = new byte[sourceLength];
        Buffer.BlockCopy(buffer, 0, sourceBuffer, 0, sourceLength);
        return sourceBuffer;
    }

    private static int ReadInt32(byte[] buffer, int offset)
    {
        var uintValue =
            (((uint)buffer[offset]    ) << 24) |
            (((uint)buffer[offset + 1]) << 16) |
            (((uint)buffer[offset + 2]) <<  8) |
            (((uint)buffer[offset + 3])      );
        return (int)uintValue;
    }
}

public class RsaSigner : Signer
{
    private readonly ISigner _signer;
    public RsaSigner(RsaPrivateCrtKeyParameters privateKey)
    {
        _signer = SignerUtilities.GetSigner("SHA256withRSA");
        _signer.Init(true, privateKey);
    }

    public override byte[] Sign(byte[] input, int offset, int count)
    {
        _signer.Reset();
        _signer.BlockUpdate(input, offset, count);
        return _signer.GenerateSignature();
    }
}

public class RsaVerifier : Verifier
{
    private readonly ISigner _signer;
    public RsaVerifier(RsaKeyParameters publicKey)
    {
        _signer = SignerUtilities.GetSigner("SHA256withRSA");
        _signer.Init(false, publicKey);
    }

    public override bool Verify(byte[] input, int offset, int count, byte[] signature)
    {
        _signer.Reset();
        _signer.BlockUpdate(input, offset, count);
        return _signer.VerifySignature(signature);
    }
}