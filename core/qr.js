import QRCode from 'qrcode';

/**
 * Render an otpauth:// URI as an inline SVG. Generated locally — the secret must never be
 * sent to a third-party QR service.
 */
export async function qrSvg(text) {
  return QRCode.toString(text, {
    type: 'svg',
    margin: 1,
    width: 220,
    errorCorrectionLevel: 'M',
    color: { dark: '#0f172a', light: '#ffffff' },
  });
}
