using QRCoder;
using System.Text.Encodings.Web;

namespace AuthenticationService.Helpers;

/// <summary>
/// Generates the QR code image a user scans into their authenticator app to enrol in MFA.
/// The encoded payload is a standard <c>otpauth://</c> TOTP URI.
/// </summary>
public static class QrCodeHelpers
{
    /// <summary>
    /// Returns a PNG of the TOTP enrolment QR code for the given account.
    /// </summary>
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
