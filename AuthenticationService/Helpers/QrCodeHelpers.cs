using QRCoder;
using System.Text.Encodings.Web;

namespace AuthenticationService.Helpers;

public static class QrCodeHelpers
{
    public static byte[] NewPng(string email, string key)
    {
        var uri = GenerateQRCodeUri(email, key);
        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(qrCodeData);
        
        return qrCode.GetGraphic(20);
    }

    private static string GenerateQRCodeUri(string email, string key)
    {
        var keyEncoded = UrlEncoder.Default.Encode(key);
        var emailEncoded = UrlEncoder.Default.Encode(email);
        return $"otpauth://totp/AuthenticationService:{emailEncoded}?secret={keyEncoded}&issuer=AuthenticationService&digits=6";
    }
}
