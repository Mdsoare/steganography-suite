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
    RIFF_HEADER: [0x52, 0x49, 0x46, 0x46],

    PAYLOADS: [
        { bytes: [0x52, 0x61, 0x72, 0x21], ext: 'rar', label: 'Arquivo RAR' },
        { bytes: [0x50, 0x4B, 0x03, 0x04], ext: 'zip', label: 'Arquivo ZIP' },
        { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], ext: '7z', label: 'Arquivo 7-Zip' },
        { bytes: [0x25, 0x50, 0x44, 0x46], ext: 'pdf', label: 'Documento PDF' },
        { bytes: [0x4D, 0x5A], ext: 'exe', label: 'Executável Windows (PE)' },
        { bytes: [0xEF, 0xBB, 0xBF], ext: 'ps1', label: 'Script PowerShell (UTF-8 BOM)' },
        { bytes: [0xFF, 0xFE], ext: 'ps1', label: 'Script PowerShell (UTF-16 LE)' },
        { bytes: [0x3C, 0x23], ext: 'ps1', label: 'Script PowerShell (<# Bloco)' },
        { bytes: [0x7F, 0x45, 0x4C, 0x46], ext: 'bin', label: 'Executável Linux (ELF)' },
        { bytes: [0x23, 0x21], ext: 'sh', label: 'Script Shell (Shebang)' }
    ]
};

function identifyPayload(bytes, offset = 0) {
    const slice = bytes.subarray ? bytes.subarray(offset) : new Uint8Array(bytes.buffer || bytes, offset);
    if (!slice || slice.length === 0) return { ext: 'bin', label: 'Dados Genéricos' };

    for (const item of SIGNATURES.PAYLOADS) {
        if (matchSignature(slice, item.bytes, 0)) {
            return { ext: item.ext, label: item.label };
        }
    }

    const sampleSize = Math.min(slice.length, 512);
    let printableCount = 0;
    let asciiText = '';

    for (let i = 0; i < sampleSize; i++) {
        const b = slice[i];
        if ((b >= 0x20 && b <= 0x7E) || b === 0x09 || b === 0x0A || b === 0x0D) {
            printableCount++;
            asciiText += String.fromCharCode(b);
        }
    }

    if (sampleSize > 0 && (printableCount / sampleSize) > 0.90) {
        const lower = asciiText.toLowerCase();
        if (lower.includes('param') || lower.includes('write-host') || lower.includes('$') || 
            lower.includes('get-') || lower.includes('set-') || lower.includes('function') || lower.includes('#')) {
            return { ext: 'ps1', label: 'Script PowerShell' };
        }
        if (lower.includes('#!/bin') || lower.includes('echo ')) {
            return { ext: 'sh', label: 'Script Shell' };
        }
        return { ext: 'txt', label: 'Arquivo de Texto' };
    }

    return { ext: 'bin', label: 'Dados Genéricos' };
}

function matchSignature(array, target, offset = 0) {
    if (offset + target.length > array.length) return false;
    for (let i = 0; i < target.length; i++) {
        if (array[offset + i] !== target[i]) return false;
    }
    return true;
}

function findGIFEOF(bytes) {
    if (bytes.length < 13 || !matchSignature(bytes, SIGNATURES.GIF_HEADER)) return -1;

    let offset = 6;
    const packed = bytes[offset + 4];
    offset += 7;

    if (packed & 0x80) {
        const gctSize = 3 * Math.pow(2, (packed & 0x07) + 1);
        offset += gctSize;
    }

    while (offset < bytes.length) {
        const blockType = bytes[offset];

        if (blockType === 0x3B) {
            return offset + 1;
        }

        if (blockType === 0x21) {
            offset += 2;
            while (offset < bytes.length) {
                const subBlockSize = bytes[offset];
                offset += 1;
                if (subBlockSize === 0) break;
                offset += subBlockSize;
            }
        } else if (blockType === 0x2C) {
            if (offset + 10 > bytes.length) break;
            const imgPacked = bytes[offset + 9];
            offset += 10;

            if (imgPacked & 0x80) {
                const lctSize = 3 * Math.pow(2, (imgPacked & 0x07) + 1);
                offset += lctSize;
            }

            offset += 1;

            while (offset < bytes.length) {
                const subBlockSize = bytes[offset];
                offset += 1;
                if (subBlockSize === 0) break;
                offset += subBlockSize;
            }
        } else {
            break;
        }
    }
    return -1;
}

function findMediaEOF(bytes, fileName = '') {
    if (!bytes || bytes.length === 0) return { eof: -1, format: 'Desconhecido' };

    const ext = fileName ? fileName.split('.').pop().toLowerCase() : '';
    const length = bytes.length;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    try {
        // 1. ISOBMFF / AVIF / HEIC / MP4
        if (length >= 8 && (matchSignature(bytes, [0x66, 0x74, 0x79, 0x70], 4) || ext === 'avif' || ext === 'heic' || ext === 'mp4')) {
            let offset = 0;
            let lastValidBoxEnd = -1;

            while (offset + 8 <= length) {
                let boxSize = view.getUint32(offset, false);
                let headerSize = 8;

                if (boxSize === 1) {
                    if (offset + 16 > length) break;
                    boxSize = Number(view.getBigUint64(offset + 8, false));
                    headerSize = 16;
                } else if (boxSize === 0) {
                    lastValidBoxEnd = length;
                    break;
                }

                if (boxSize < headerSize || offset + boxSize > length) break;

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
            if (matchSignature(bytes, SIGNATURES.PNG_HEADER, i)) {
                pngStart = i;
                break;
            }
        }

        if (pngStart !== -1) {
            let offset = pngStart + 8;
            while (offset + 12 <= length) {
                const chunkSize = view.getUint32(offset, false);
                if (matchSignature(bytes, SIGNATURES.PNG_END, offset + 4)) {
                    return { eof: offset + 12, format: 'PNG' };
                }
                if (chunkSize > length) break;
                offset += 12 + chunkSize;
            }
        }

        // 3. JPEG
        if (matchSignature(bytes, SIGNATURES.JPEG_HEADER)) {
            let offset = 2;
            while (offset < length - 1) {
                if (bytes[offset] !== 0xFF) {
                    offset++;
                    continue;
                }
                const marker = bytes[offset + 1];

                if (marker === 0xDA) {
                    for (let i = length - 2; i >= offset; i--) {
                        if (bytes[i] === 0xFF && bytes[i + 1] === 0xD9) {
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
        if (matchSignature(bytes, SIGNATURES.RIFF_HEADER)) {
            const riffSize = view.getUint32(4, true);
            const totalRiff = riffSize + 8;
            if (totalRiff <= length && totalRiff > 0) {
                let subType = ext ? ext.toUpperCase() : 'RIFF Container';
                if (length >= 12) {
                    const fourCC = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]).trim();
                    if (fourCC) subType = fourCC.toUpperCase();
                }
                return { eof: totalRiff, format: subType };
            }
        }

        // 5. GIF
        if (matchSignature(bytes, SIGNATURES.GIF_HEADER)) {
            const gifEof = findGIFEOF(bytes);
            if (gifEof > 0 && gifEof <= length) {
                return { eof: gifEof, format: 'GIF' };
            }
        }

        // 6. BMP
        if (length >= 6 && bytes[0] === 0x42 && bytes[1] === 0x4D) {
            const size = view.getUint32(2, true);
            if (size <= length && size > 0) return { eof: size, format: 'BMP' };
        }

    } catch (e) {
        return { eof: -1, format: ext ? ext.toUpperCase() : 'Erro no Parsing' };
    }

    return { eof: -1, format: ext ? ext.toUpperCase() : 'Desconhecido' };
}

self.onmessage = function (e) {
    if (!e.data || typeof e.data !== 'object') return;
    
    const { action, buffer, fileName } = e.data;

    if (action === 'ANALYZE_MEDIA') {
        if (!buffer || !(buffer instanceof ArrayBuffer)) {
            self.postMessage({ 
                action: 'ANALYSIS_COMPLETE', 
                eof: -1, 
                format: 'Buffer inválido', 
                extraBytes: 0, 
                hiddenType: 'Nenhum', 
                payloadExt: 'bin' 
            });
            return;
        }

        try {
            const bytes = new Uint8Array(buffer);
            const { eof, format } = findMediaEOF(bytes, fileName);

            let hiddenType = 'Nenhum';
            let payloadExt = 'bin';
            let extraBytes = 0;

            if (eof !== -1 && bytes.length > eof) {
                extraBytes = bytes.length - eof;
                const info = identifyPayload(bytes, eof);
                hiddenType = info.label;
                payloadExt = info.ext;
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