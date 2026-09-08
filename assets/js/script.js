'use strict';

/**
 * StegoSuite PRO - Módulo Principal Refatorado
 */

// --- BASE DE DADOS DE ASSINATURAS (MAGIC BYTES) ---
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

// --- ESTADO GLOBAL DA APLICAÇÃO ---
const state = {
    detectFile: null,
    joinImgFile: null,
    joinSecretFile: null,
    extractFile: null,
    extractedData: { cleanImgBlob: null, payloadBlob: null, payloadExt: 'bin' },
    activePreviewUrl: null
};

// --- INICIALIZAÇÃO SEGURA DO WORKER ---
let forensicWorker = null;
let workerFailed = false;

try {
    const currentScript = document.currentScript || (function() {
        const scripts = document.getElementsByTagName('script');
        return scripts[scripts.length - 1];
    })();
    
    const rootUrl = new URL('../../worker.js', currentScript.src).href;
    forensicWorker = new Worker(rootUrl);
} catch (e) {
    console.warn("Web Worker bloqueado sincronicamente. Utilizando thread principal.", e);
    workerFailed = true;
}

// --- INICIALIZAÇÃO DA APLICAÇÃO ---
document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    setupDragAndDrop();
    setupEventListeners();
    if (forensicWorker) {
        setupWorkerListeners();
    }
});

// --- COMUNICAÇÃO COM O WORKER ---
function setupWorkerListeners() {
    forensicWorker.onmessage = function (e) {
        const { action, eof, format, extraBytes, hiddenType, payloadExt, buffer } = e.data || {};

        if (action === 'ANALYSIS_COMPLETE') {
            const bytes = buffer ? new Uint8Array(buffer) : null;
            renderDetectionResults(eof, format, extraBytes, hiddenType, payloadExt, bytes);
        }
    };

    forensicWorker.onerror = function (err) {
        console.warn("Erro no Worker detectado. Forçando fallback local.", err);
        workerFailed = true;
    };
}

// --- NAVEGAÇÃO POR ABAS ---
function setupTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');

            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const targetEl = document.getElementById(targetTab);
            if (targetEl) targetEl.classList.add('active');
        });
    });
}

/**
 * Identifica o tipo de payload via Magic Bytes ou Heurística de Texto
 */
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

// --- DRAG & DROP E FILE INPUTS ---
function setupDragAndDrop() {
    const dropZones = [
        { zone: document.getElementById('detectDropZone'), input: document.getElementById('detectFileInput'), handler: handleDetectFile },
        { zone: document.getElementById('joinImgDropZone'), input: document.getElementById('joinImgInput'), handler: handleJoinImgFile },
        { zone: document.getElementById('joinSecretDropZone'), input: document.getElementById('joinSecretInput'), handler: handleJoinSecretFile },
        { zone: document.getElementById('extractDropZone'), input: document.getElementById('extractFileInput'), handler: handleExtractFile }
    ];

    dropZones.forEach(({ zone, input, handler }) => {
        if (!zone || !input) return;

        ['dragenter', 'dragover'].forEach(eName => {
            zone.addEventListener(eName, (e) => { e.preventDefault(); zone.classList.add('dragover'); });
        });

        ['dragleave', 'drop'].forEach(eName => {
            zone.addEventListener(eName, (e) => { e.preventDefault(); zone.classList.remove('dragover'); });
        });

        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            if (e.dataTransfer.files.length > 0) {
                input.files = e.dataTransfer.files;
                handler(e.dataTransfer.files[0]);
            }
        });

        input.addEventListener('change', (e) => {
            if (e.target.files.length > 0) handler(e.target.files[0]);
        });
    });
}

function setupEventListeners() {
    const joinBtn = document.getElementById('joinBtn');
    if (joinBtn) joinBtn.addEventListener('click', executeJoin);

    const btnClean = document.getElementById('btnDownloadCleanImg');
    if (btnClean) btnClean.addEventListener('click', () => downloadBlob(state.extractedData.cleanImgBlob, 'media_limpa'));

    const btnPayload = document.getElementById('btnDownloadPayload');
    if (btnPayload) btnPayload.addEventListener('click', () => downloadBlob(state.extractedData.payloadBlob, `payload_extraido.${state.extractedData.payloadExt}`));

    const btnResetDetect = document.getElementById('btnResetDetect');
    if (btnResetDetect) btnResetDetect.addEventListener('click', resetDetectTab);

    const btnResetJoin = document.getElementById('btnResetJoin');
    if (btnResetJoin) btnResetJoin.addEventListener('click', resetJoinTab);

    const btnResetExtract = document.getElementById('btnResetExtract');
    if (btnResetExtract) btnResetExtract.addEventListener('click', resetExtractTab);
}

// --- MÓDULO 1: ANÁLISE E DETECÇÃO ---
function handleDetectFile(file) {
    if (!file) return;
    state.detectFile = file;

    const fileNameEl = document.getElementById('detectFileName');
    const fileSizeEl = document.getElementById('detectFileSize');
    if (fileNameEl) fileNameEl.textContent = file.name;
    if (fileSizeEl) fileSizeEl.textContent = formatBytes(file.size);

    updateMediaPreview(file);

    const reader = new FileReader();
    reader.onload = function (e) {
        const buffer = e.target.result;

        if (forensicWorker && !workerFailed) {
            try {
                const bufferToTransfer = buffer.slice(0);
                forensicWorker.postMessage({
                    action: 'ANALYZE_MEDIA',
                    buffer: bufferToTransfer,
                    fileName: file.name
                }, [bufferToTransfer]);
            } catch (err) {
                console.warn("Falha ao delegar buffer ao Worker. Executando processamento local.", err);
                runLocalAnalysis(buffer, file.name);
            }
        } else {
            runLocalAnalysis(buffer, file.name);
        }
    };
    reader.readAsArrayBuffer(file);
}

function runLocalAnalysis(buffer, fileName = '') {
    const bytes = new Uint8Array(buffer);
    const { eof, format } = findMediaEOF(bytes, fileName);
    const extraBytes = (eof !== -1 && bytes.length > eof) ? bytes.length - eof : 0;

    let hiddenType = 'Nenhum';
    let payloadExt = 'bin';

    if (extraBytes > 0) {
        const payloadInfo = identifyPayload(bytes, eof);
        hiddenType = payloadInfo.label;
        payloadExt = payloadInfo.ext;
    }

    renderDetectionResults(eof, format, extraBytes, hiddenType, payloadExt, bytes);
}

function renderDetectionResults(eof, format, extraBytes, hiddenType, payloadExt, bytes = null) {
    const resultSection = document.getElementById('detectResult');
    if (resultSection) {
        resultSection.classList.remove('hidden');
        resultSection.style.display = 'block';
    }

    const formatEl = document.getElementById('detectMetaFormat');
    const expectedEl = document.getElementById('detectMetaExpected');
    const extraEl = document.getElementById('detectMetaExtra');
    const typeEl = document.getElementById('detectMetaType');
    const hexViewer = document.getElementById('detectHexViewer');

    if (formatEl) formatEl.textContent = format;
    if (expectedEl) expectedEl.textContent = eof !== -1 ? formatBytes(eof) : 'N/A';
    if (extraEl) extraEl.textContent = formatBytes(extraBytes);
    if (typeEl) typeEl.textContent = extraBytes > 0 ? `${hiddenType} (.${payloadExt})` : 'Nenhum';

    if (extraBytes > 0) {
        setBanner('detectStatusBanner', 'suspicious', '⚠️ Dados Ocultos Encontrados!', `Detectados ${formatBytes(extraBytes)} de dados concatenados após o fim oficial do arquivo.`);
        
        if (bytes && hexViewer) {
            const maxBytes = Math.min(extraBytes, 256);
            const payloadBytes = bytes.slice(eof, eof + maxBytes);
            
            let hexString = '';
            let asciiString = '';
            
            for (let i = 0; i < payloadBytes.length; i++) {
                if (i % 16 === 0) {
                    if (i > 0) hexString += `  |${asciiString}|\n`;
                    asciiString = '';
                    const offset = (eof + i).toString(16).padStart(8, '0').toUpperCase();
                    hexString += `${offset}  `;
                }
                
                const byte = payloadBytes[i];
                hexString += byte.toString(16).padStart(2, '0').toUpperCase() + ' ';
                
                asciiString += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
            }
            
            const remainder = payloadBytes.length % 16;
            if (remainder !== 0) {
                const padding = (16 - remainder) * 3;
                hexString += ' '.repeat(padding) + `  |${asciiString}|`;
            } else if (payloadBytes.length > 0) {
                hexString += `  |${asciiString}|`;
            }
            
            if (extraBytes > 256) {
                hexString += '\n\n... [Dump truncado (restam ' + formatBytes(extraBytes - 256) + ')]';
            }
            
            hexViewer.textContent = hexString;
        } else if (hexViewer) {
            hexViewer.textContent = "Buffer inacessível para renderização hexadecimal.";
        }

    } else {
        setBanner('detectStatusBanner', 'clean', '✅ Mídia Limpa', 'Nenhuma anomalia de concatenação detectada.');
        if (hexViewer) hexViewer.textContent = "-";
    }
}

function updateMediaPreview(file) {
    if (state.activePreviewUrl) {
        URL.revokeObjectURL(state.activePreviewUrl);
    }
    state.activePreviewUrl = URL.createObjectURL(file);

    const container = document.getElementById('mediaPreviewContainer');
    if (container) {
        container.textContent = '';
        if (file.type.startsWith('image/')) {
            const img = document.createElement('img');
            img.src = state.activePreviewUrl;
            img.className = 'preview-thumb';
            img.alt = 'Preview';
            container.appendChild(img);
        } else {
            const icon = document.createElement('div');
            icon.textContent = '📁';
            icon.style.fontSize = '2rem';
            container.appendChild(icon);
        }
    }
}

// --- MÓDULO 2: JUNTAR (CONCATENAR) ---
function handleJoinImgFile(file) {
    state.joinImgFile = file;
    const nameEl = document.getElementById('joinImgName');
    if (nameEl) nameEl.textContent = `${file.name} (${formatBytes(file.size)})`;
    checkJoinReady();
}

function handleJoinSecretFile(file) {
    state.joinSecretFile = file;
    const nameEl = document.getElementById('joinSecretName');
    if (nameEl) nameEl.textContent = `${file.name} (${formatBytes(file.size)})`;
    checkJoinReady();
}

function checkJoinReady() {
    const btn = document.getElementById('joinBtn');
    if (btn) btn.disabled = !(state.joinImgFile && state.joinSecretFile);
}

async function executeJoin() {
    if (!state.joinImgFile || !state.joinSecretFile) return;

    const imgBuf = await state.joinImgFile.arrayBuffer();
    const secretBuf = await state.joinSecretFile.arrayBuffer();

    const combined = new Uint8Array(imgBuf.byteLength + secretBuf.byteLength);
    combined.set(new Uint8Array(imgBuf), 0);
    combined.set(new Uint8Array(secretBuf), imgBuf.byteLength);

    const blob = new Blob([combined], { type: state.joinImgFile.type || 'application/octet-stream' });
    downloadBlob(blob, `stego_${state.joinImgFile.name}`);

    const banner = document.getElementById('joinStatusBanner');
    if (banner) {
        banner.classList.remove('hidden');
        banner.style.display = 'block';
    }
}

// --- MÓDULO 3: EXTRAIR ---
function handleExtractFile(file) {
    state.extractFile = file;
    const reader = new FileReader();

    reader.onload = function (e) {
        const bytes = new Uint8Array(e.target.result);
        const { eof } = findMediaEOF(bytes, file.name);
        const extractResult = document.getElementById('extractResult');

        if (extractResult) {
            extractResult.classList.remove('hidden');
            extractResult.style.display = 'block';
        }

        const btnClean = document.getElementById('btnDownloadCleanImg');
        const btnPayload = document.getElementById('btnDownloadPayload');

        if (eof === -1 || eof >= bytes.length) {
            setBanner('extractStatusBanner', 'warning', 'Sem Dados Ocultos', 'Esta mídia não contém conteúdo extra para ser extraído.');
            if (btnClean) btnClean.style.display = 'none';
            if (btnPayload) btnPayload.style.display = 'none';
            return;
        }

        const cleanImgBytes = bytes.slice(0, eof);
        const payloadBytes = bytes.slice(eof);

        const payloadInfo = identifyPayload(payloadBytes, 0);

        state.extractedData.cleanImgBlob = new Blob([cleanImgBytes], { type: file.type || 'application/octet-stream' });
        state.extractedData.payloadBlob = new Blob([payloadBytes], { type: 'application/octet-stream' });
        state.extractedData.payloadExt = payloadInfo.ext;

        setBanner('extractStatusBanner', 'suspicious', 'Conteúdo Oculto Extraído!', `Foram extraídos ${formatBytes(payloadBytes.length)} de payload (${payloadInfo.label}).`);

        if (btnClean) btnClean.style.display = 'inline-block';
        if (btnPayload) btnPayload.style.display = 'inline-block';
    };

    reader.readAsArrayBuffer(file);
}

// --- RESETS E AUXILIARES ---
function resetDetectTab() {
    state.detectFile = null;
    const input = document.getElementById('detectFileInput');
    if (input) input.value = '';

    const container = document.getElementById('mediaPreviewContainer');
    if (container) container.textContent = '';

    if (state.activePreviewUrl) {
        URL.revokeObjectURL(state.activePreviewUrl);
        state.activePreviewUrl = null;
    }

    const res = document.getElementById('detectResult');
    if (res) {
        res.classList.add('hidden');
        res.style.display = 'none';
    }
}

function resetJoinTab() {
    state.joinImgFile = null;
    state.joinSecretFile = null;

    const input1 = document.getElementById('joinImgInput');
    const input2 = document.getElementById('joinSecretInput');
    if (input1) input1.value = '';
    if (input2) input2.value = '';

    const name1 = document.getElementById('joinImgName');
    const name2 = document.getElementById('joinSecretName');
    if (name1) name1.textContent = 'Nenhum arquivo selecionado';
    if (name2) name2.textContent = 'ZIP, RAR, PDF, TXT, etc.';

    const btn = document.getElementById('joinBtn');
    if (btn) btn.disabled = true;

    const banner = document.getElementById('joinStatusBanner');
    if (banner) {
        banner.classList.add('hidden');
        banner.style.display = 'none';
    }
}

function resetExtractTab() {
    state.extractFile = null;
    state.extractedData = { cleanImgBlob: null, payloadBlob: null, payloadExt: 'bin' };

    const input = document.getElementById('extractFileInput');
    if (input) input.value = '';

    const res = document.getElementById('extractResult');
    if (res) {
        res.classList.add('hidden');
        res.style.display = 'none';
    }
}

// --- PARSER FORENSE E IDENTIFICAÇÃO DE EOF ---
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

function findImageEOF(bytes, fileName = '') {
    return findMediaEOF(bytes, fileName);
}

function matchSignature(array, target, offset = 0) {
    if (offset + target.length > array.length) return false;
    for (let i = 0; i < target.length; i++) {
        if (array[offset + i] !== target[i]) return false;
    }
    return true;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function setBanner(id, type, title, desc) {
    const banner = document.getElementById(id);
    if (!banner) return;
    banner.className = `status-banner ${type}`;
    const h3 = banner.querySelector('h3');
    const p = banner.querySelector('p');
    if (h3) h3.textContent = title;
    if (p) p.textContent = desc;
}

function downloadBlob(blob, filename) {
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 100);
}