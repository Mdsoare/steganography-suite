/**
 * StegoSuite PRO - Web Worker para Processamento Forense
 */
'use strict';

const SIGNATURES = {
    PNG_HEADER: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    PNG_END: [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82],
    JPEG_HEADER: [0xFF, 0xD8, 0xFF],
    JPEG_END: [0xFF, 0xD9],
    GIF_HEADER: [0x47, 0x49, 0x46, 0x38],
    AVI_HEADER: [0x52, 0x49, 0x46, 0x46],

    PAYLOADS: [
        { bytes: [0x52, 0x61, 0x72, 0x21], ext: 'rar', label: 'Arquivo RAR' },
        { bytes: [0x50, 0x4B, 0x03, 0x04], ext: 'zip', label: 'Arquivo ZIP' },
        { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], ext: '7z', label: 'Arquivo 7-Zip' },
        { bytes: [0x25, 0x50, 0x44, 0x46], ext: 'pdf', label: 'Documento PDF' },
        { bytes: [0x4D, 0x5A], ext: 'exe', label: 'Executável Windows (PE)' },
        { bytes: [0x7F, 0x45, 0x4C, 0x46], ext: 'bin', label: 'Executável Linux (ELF)' },
        { bytes: [0x23, 0x21], ext: 'sh', label: 'Script Shell' }
    ]
};

function matchSignature(view, target, offset = 0) {
    if (offset + target.length > view.byteLength) return false;
    for (let i = 0; i < target.length; i++) {
        if (view.getUint8(offset + i) !== target[i]) return false;
    }
    return true;
}

function findMediaEOF(buffer, fileName = '') {
    if (!buffer || buffer.byteLength === 0) {
        return { eof: -1, format: 'Desconhecido' };
    }

    const view = new DataView(buffer);
    const length = view.byteLength;
    const ext = fileName ? fileName.split('.').pop().toLowerCase() : '';

    try {
        // 1. ISOBMFF / AVIF / HEIC / MP4
        if (length >= 8 && (matchSignature(view, [0x66, 0x74, 0x79, 0x70], 4) || ext === 'avif' || ext === 'heic' || ext === 'mp4')) {
            let offset = 0;
            let lastValidBoxEnd = -1;

            while (offset + 8 <= length) {
                let boxSize = view.getUint32(offset, false);
                let headerSize = 8;

                if (boxSize === 1) {
                    if (offset + 16 > length) break;
                    const bigSize = view.getBigUint64(offset + 8, false);
                    boxSize = Number(bigSize);
                    headerSize = 16;
                } else if (boxSize === 0) {
                    lastValidBoxEnd = length;
                    break;
                }

                if (boxSize < headerSize || offset + boxSize > length) {
                    break;
                }

                offset += boxSize;
                lastValidBoxEnd = offset;
            }

            if (lastValidBoxEnd > 0) {
                const detectedFormat = ext ? ext.toUpperCase() : 'ISOBMFF/AVIF';
                return { eof: lastValidBoxEnd, format: detectedFormat };
            }
        }

        // 2. PNG
        let pngStart = -1;
        for (let i = 0; i < Math.min(length - 8, 64); i++) {
            if (matchSignature(view, SIGNATURES.PNG_HEADER, i)) {
                pngStart = i;
                break;
            }
        }

        if (pngStart !== -1) {
            let offset = pngStart + 8;
            while (offset + 12 <= length) {
                const chunkSize = view.getUint32(offset, false);
                if (matchSignature(view, SIGNATURES.PNG_END, offset + 4)) {
                    return { eof: offset + 12, format: 'PNG' };
                }
                if (chunkSize > length) break;
                offset += 12 + chunkSize;
            }
        }

        // 3. JPEG
        if (matchSignature(view, SIGNATURES.JPEG_HEADER)) {
            let offset = 2;
            while (offset < length - 1) {
                if (view.getUint8(offset) !== 0xFF) {
                    offset++;
                    continue;
                }
                const marker = view.getUint8(offset + 1);

                if (marker === 0xDA) {
                    for (let i = length - 2; i >= offset; i--) {
                        if (view.getUint8(i) === 0xFF && view.getUint8(i + 1) === 0xD9) {
                            return { eof: i + 2, format: 'JPEG' };
                        }
                    }
                    break;
                }

                if (offset + 3 < length && marker !== 0xD8 && marker !== 0xD9) {
                    const segLength = view.getUint16(offset + 2, false);
                    offset += 2 + segLength;
                } else {
                    offset += 2;
                }
            }
        }

        // 4. RIFF (WEBP / WAV / AVI)
        if (matchSignature(view, SIGNATURES.AVI_HEADER)) {
            const riffSize = view.getUint32(4, true);
            const totalRiff = riffSize + 8;
            if (totalRiff <= length) {
                const subType = ext ? ext.toUpperCase() : 'RIFF Container';
                return { eof: totalRiff, format: subType };
            }
        }

        // 5. BMP
        if (length >= 6 && view.getUint8(0) === 0x42 && view.getUint8(1) === 0x4D) {
            const size = view.getUint32(2, true);
            if (size <= length && size > 0) return { eof: size, format: 'BMP' };
        }

    } catch {
        return { eof: -1, format: ext ? ext.toUpperCase() : 'Erro no Parsing' };
    }

    return { eof: -1, format: ext ? ext.toUpperCase() : 'Desconhecido' };
}

self.onmessage = function (e) {
    const { action, buffer, fileName } = e.data || {};

    if (action === 'ANALYZE_MEDIA' && buffer) {
        try {
            const view = new DataView(buffer);
            const { eof, format } = findMediaEOF(buffer, fileName);

            let hiddenType = 'Dados Genéricos';
            let payloadExt = 'bin';
            let extraBytes = 0;

            if (eof !== -1 && buffer.byteLength > eof) {
                extraBytes = buffer.byteLength - eof;
                for (const payload of SIGNATURES.PAYLOADS) {
                    if (matchSignature(view, payload.bytes, eof)) {
                        hiddenType = payload.label;
                        payloadExt = payload.ext;
                        break;
                    }
                }
            }

            self.postMessage({ 
                action: 'ANALYSIS_COMPLETE', 
                eof, 
                format, 
                extraBytes, 
                hiddenType, 
                payloadExt,
                buffer
            }, [buffer]);
        } catch {
            self.postMessage({ 
                action: 'ANALYSIS_COMPLETE', 
                eof: -1, 
                format: 'Erro de Leitura', 
                extraBytes: 0, 
                hiddenType: 'Nenhum', 
                payloadExt: 'bin' 
            });
        }
    }
};