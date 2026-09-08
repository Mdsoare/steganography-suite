/**
 * StegoSuite PRO - Script Principal
 */
'use strict';

if (self !== top) {
    try {
        top.location = self.location;
    } catch {
        document.body.innerHTML = '<h1>Acesso não permitido em iframes.</h1>';
    }
}

const state = {
    detectFile: null,
    joinImgFile: null,
    joinSecretFile: null,
    extractFile: null,
    extractedData: { cleanImgBlob: null, payloadBlob: null, payloadExt: 'bin' },
    activePreviewUrl: null
};

const forensicWorker = new Worker('worker.js');

document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    setupDragAndDrop();
    setupEventListeners();
    setupWorkerListeners();
});

// --- COMUNICAÇÃO COM O WEB WORKER ---
function setupWorkerListeners() {
    forensicWorker.onerror = function (error) {
        console.error("Erro no Worker Forense:", error);
        setBanner('detectStatusBanner', 'warning', 'Erro de Processamento', 'Falha interna durante a execução da análise forense.');
    };

    forensicWorker.onmessage = function (e) {
        const { action, eof, format, extraBytes, hiddenType, payloadExt } = e.data || {};

        if (action === 'ANALYSIS_COMPLETE') {
            const resultSection = document.getElementById('detectResult');
            if (resultSection) {
                resultSection.classList.remove('hidden');
                resultSection.style.display = 'block';
            }

            // Atualiza os elementos da interface DOM sem destruir a estrutura HTML
            const metaFormatEl = document.getElementById('detectMetaFormat');
            const metaExpectedEl = document.getElementById('detectMetaExpected');
            const metaExtraEl = document.getElementById('detectMetaExtra');
            const metaTypeEl = document.getElementById('detectMetaType');

            if (metaFormatEl) metaFormatEl.textContent = format || 'Desconhecido';
            if (metaExpectedEl) metaExpectedEl.textContent = eof !== -1 ? formatBytes(eof) : 'N/A';
            if (metaExtraEl) metaExtraEl.textContent = formatBytes(extraBytes);
            if (metaTypeEl) metaTypeEl.textContent = extraBytes > 0 ? `${hiddenType} (.${payloadExt})` : 'Nenhum';

            // Atualiza o banner de status principal
            if (extraBytes > 0) {
                setBanner(
                    'detectStatusBanner',
                    'suspicious',
                    '⚠️ Anomalia / Payload Detectado!',
                    `Foram identificados ${formatBytes(extraBytes)} de dados anexados após o fim oficial do container (${format}).`
                );
            } else {
                setBanner(
                    'detectStatusBanner',
                    'clean',
                    '✅ Mídia Integra / Limpa',
                    `Nenhum dado oculto ou anomalia estrutural detectada na mídia (${format}).`
                );
            }
        }
    };
}

// --- DETECÇÃO & PROCESSAMENTO ---
function handleDetectFile(file) {
    if (!file) return;
    state.detectFile = file;
    
    // Atualiza metadados na interface (Nome e Tamanho)
    const fileNameEl = document.getElementById('detectFileName');
    const fileSizeEl = document.getElementById('detectFileSize');
    if (fileNameEl) fileNameEl.textContent = file.name;
    if (fileSizeEl) fileSizeEl.textContent = formatBytes(file.size);

    // Atualiza o preview visual da mídia
    revokeActivePreview();
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
        } else if (file.type.startsWith('video/')) {
            const video = document.createElement('video');
            video.src = state.activePreviewUrl;
            video.className = 'preview-thumb';
            video.controls = true;
            container.appendChild(video);
        } else {
            const icon = document.createElement('div');
            icon.textContent = '📁';
            icon.style.fontSize = '1.8rem';
            container.appendChild(icon);
        }
    }

    // Leitura e envio para o Worker usando Transferable Objects
    const reader = new FileReader();
    reader.onload = function (e) {
        const buffer = e.target.result;
        
        // Renderiza a Amostra Hex se o elemento existir na tela
        const hexViewer = document.getElementById('detectHexViewer');
        if (hexViewer) {
            const sampleView = new DataView(buffer);
            hexViewer.textContent = bytesToHexDump(sampleView, 0, Math.min(buffer.byteLength, 256));
        }

        // Dispara o Worker de forma performática via transferência de ownership
        forensicWorker.postMessage({
            action: 'ANALYZE_MEDIA',
            buffer: buffer,
            fileName: file.name
        }, [buffer]);
    };
    reader.readAsArrayBuffer(file);
}

// --- DRAG AND DROP & INPUTS ---
function setupDragAndDrop() {
    const dropZones = [
        { zone: document.getElementById('detectDropZone'), input: document.getElementById('detectFileInput'), handler: handleDetectFile },
        { zone: document.getElementById('joinImgDropZone'), input: document.getElementById('joinImgInput'), handler: handleJoinImgFile },
        { zone: document.getElementById('joinSecretDropZone'), input: document.getElementById('joinSecretInput'), handler: handleJoinSecretFile },
        { zone: document.getElementById('extractDropZone'), input: document.getElementById('extractFileInput'), handler: handleExtractFile }
    ];

    dropZones.forEach(({ zone, input, handler }) => {
        if (!zone || !input) return;

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            zone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            zone.addEventListener(eventName, () => zone.classList.add('dragover'), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            zone.addEventListener(eventName, () => zone.classList.remove('dragover'), false);
        });

        zone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                input.files = files;
                handler(files[0]);
            }
        }, false);

        input.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handler(e.target.files[0]);
            }
        });
    });
}

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function handleJoinImgFile(file) {
    state.joinImgFile = file;
    const el = document.getElementById('joinImgName');
    if (el) el.textContent = `${file.name} (${formatBytes(file.size)})`;
    checkJoinReady();
}

function handleJoinSecretFile(file) {
    state.joinSecretFile = file;
    const el = document.getElementById('joinSecretName');
    if (el) el.textContent = `${file.name} (${formatBytes(file.size)})`;
    checkJoinReady();
}

function checkJoinReady() {
    const btn = document.getElementById('joinBtn');
    if (btn) btn.disabled = !(state.joinImgFile && state.joinSecretFile);
}

// --- EXTRAÇÃO DE PAYLOAD ---
function handleExtractFile(file) {
    state.extractFile = file;
    
    const reader = new FileReader();
    reader.onload = function (e) {
        const buffer = e.target.result;
        const view = new DataView(buffer);
        
        const eofInfo = findEofUniversal(view, file.name);

        const resultSection = document.getElementById('extractResult');
        if (resultSection) {
            resultSection.classList.remove('hidden');
            resultSection.style.display = 'block';
        }

        if (eofInfo.eof === -1 || buffer.byteLength <= eofInfo.eof) {
            setBanner('extractStatusBanner', 'warning', 'Nenhum Payload Encontrado', 'A mídia selecionada não possui dados concatenados anexados.');
            const btnClean = document.getElementById('btnDownloadCleanImg');
            const btnPayload = document.getElementById('btnDownloadPayload');
            if (btnClean) btnClean.style.display = 'none';
            if (btnPayload) btnPayload.style.display = 'none';
            return;
        }

        const cleanBuffer = buffer.slice(0, eofInfo.eof);
        const payloadBuffer = buffer.slice(eofInfo.eof);

        // Identifica extensão do payload extraído
        const payloadView = new DataView(payloadBuffer);
        const detectedExt = detectPayloadExtension(payloadView);

        state.extractedData.cleanImgBlob = new Blob([cleanBuffer], { type: file.type || 'application/octet-stream' });
        state.extractedData.payloadBlob = new Blob([payloadBuffer], { type: 'application/octet-stream' });
        state.extractedData.payloadExt = detectedExt;

        setBanner('extractStatusBanner', 'suspicious', 'Payload Oculto Extraído!', `Foram isolados ${formatBytes(payloadBuffer.byteLength)} de payload (.${detectedExt}) da mídia original.`);
        
        const btnClean = document.getElementById('btnDownloadCleanImg');
        const btnPayload = document.getElementById('btnDownloadPayload');
        if (btnClean) btnClean.style.display = 'inline-block';
        if (btnPayload) btnPayload.style.display = 'inline-block';
    };
    reader.readAsArrayBuffer(file);
}

function detectPayloadExtension(view) {
    if (!view || view.byteLength < 2) return 'bin';

    let startOffset = 0;
    while (startOffset < Math.min(view.byteLength - 2, 16)) {
        const b = view.getUint8(startOffset);
        if (b !== 0x00 && b !== 0xFF) break;
        startOffset++;
    }

    const SIGNATURES = [
        { bytes: [0x4D, 0x5A], ext: 'exe' },
        { bytes: [0x50, 0x4B, 0x03, 0x04], ext: 'zip' },
        { bytes: [0x52, 0x61, 0x72, 0x21], ext: 'rar' },
        { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], ext: '7z' },
        { bytes: [0x25, 0x50, 0x44, 0x46], ext: 'pdf' },
        { bytes: [0x7F, 0x45, 0x4C, 0x46], ext: 'elf' },
        { bytes: [0xFF, 0xD8, 0xFF], ext: 'jpg' },
        { bytes: [0x89, 0x50, 0x4E, 0x47], ext: 'png' }
    ];

    for (const sig of SIGNATURES) {
        if (view.byteLength - startOffset >= sig.bytes.length) {
            let match = true;
            for (let i = 0; i < sig.bytes.length; i++) {
                if (view.getUint8(startOffset + i) !== sig.bytes[i]) {
                    match = false;
                    break;
                }
            }
            if (match) return sig.ext;
        }
    }

    let isText = true;
    const checkLength = Math.min(view.byteLength - startOffset, 256);
    for (let i = startOffset; i < startOffset + checkLength; i++) {
        const byte = view.getUint8(i);
        if ((byte < 0x09 || byte > 0x0D) && (byte < 0x20 || byte > 0x7E)) {
            isText = false;
            break;
        }
    }
    if (isText && checkLength > 0) return 'txt';

    return 'bin';
}

function setupEventListeners() {
    const joinBtn = document.getElementById('joinBtn');
    if (joinBtn) {
        joinBtn.addEventListener('click', () => {
            if (!state.joinImgFile || !state.joinSecretFile) return;

            const readerImg = new FileReader();
            readerImg.onload = function (e1) {
                const imgBuffer = e1.target.result;

                const readerSecret = new FileReader();
                readerSecret.onload = function (e2) {
                    const secretBuffer = e2.target.result;

                    const combined = new Uint8Array(imgBuffer.byteLength + secretBuffer.byteLength);
                    combined.set(new Uint8Array(imgBuffer), 0);
                    combined.set(new Uint8Array(secretBuffer), imgBuffer.byteLength);

                    const blob = new Blob([combined], { type: state.joinImgFile.type || 'application/octet-stream' });
                    downloadBlob(blob, `stego_${state.joinImgFile.name}`);

                    const banner = document.getElementById('joinStatusBanner');
                    if (banner) {
                        banner.classList.remove('hidden');
                        banner.style.display = 'block';
                    }
                };
                readerSecret.readAsArrayBuffer(state.joinSecretFile);
            };
            readerImg.readAsArrayBuffer(state.joinImgFile);
        });
    }

    const btnClean = document.getElementById('btnDownloadCleanImg');
    if (btnClean) {
        btnClean.addEventListener('click', () => {
            if (state.extractedData.cleanImgBlob && state.extractFile) {
                downloadBlob(state.extractedData.cleanImgBlob, `clean_${state.extractFile.name}`);
            }
        });
    }

    const btnPayload = document.getElementById('btnDownloadPayload');
    if (btnPayload) {
        btnPayload.addEventListener('click', () => {
            if (state.extractedData.payloadBlob) {
                const ext = state.extractedData.payloadExt || 'bin';
                downloadBlob(state.extractedData.payloadBlob, `extracted_payload.${ext}`);
            }
        });
    }

    const btnResetDetect = document.getElementById('btnResetDetect');
    if (btnResetDetect) {
        btnResetDetect.addEventListener('click', () => {
            state.detectFile = null;
            const input = document.getElementById('detectFileInput');
            if (input) input.value = '';
            const res = document.getElementById('detectResult');
            if (res) {
                res.classList.add('hidden');
                res.style.display = 'none';
            }
            revokeActivePreview();
        });
    }

    const btnResetJoin = document.getElementById('btnResetJoin');
    if (btnResetJoin) {
        btnResetJoin.addEventListener('click', () => {
            state.joinImgFile = null;
            state.joinSecretFile = null;
            const input1 = document.getElementById('joinImgInput');
            const input2 = document.getElementById('joinSecretInput');
            if (input1) input1.value = '';
            if (input2) input2.value = '';
            
            const name1 = document.getElementById('joinImgName');
            const name2 = document.getElementById('joinSecretName');
            if (name1) name1.textContent = 'Nenhum arquivo selecionado';
            if (name2) name2.textContent = 'ZIP, RAR, PDF, TXT, EXE, etc.';
            
            const btn = document.getElementById('joinBtn');
            if (btn) btn.disabled = true;
            
            const banner = document.getElementById('joinStatusBanner');
            if (banner) {
                banner.classList.add('hidden');
                banner.style.display = 'none';
            }
        });
    }

    const btnResetExtract = document.getElementById('btnResetExtract');
    if (btnResetExtract) {
        btnResetExtract.addEventListener('click', () => {
            state.extractFile = null;
            state.extractedData = { cleanImgBlob: null, payloadBlob: null, payloadExt: 'bin' };
            const input = document.getElementById('extractFileInput');
            if (input) input.value = '';
            const res = document.getElementById('extractResult');
            if (res) {
                res.classList.add('hidden');
                res.style.display = 'none';
            }
        });
    }
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 100);
}

function findEofUniversal(view, fileName = '') {
    const length = view.byteLength;
    const ext = fileName ? fileName.split('.').pop().toLowerCase() : '';

    if (length >= 8 && (
        (view.getUint8(4) === 0x66 && view.getUint8(5) === 0x74 && view.getUint8(6) === 0x79 && view.getUint8(7) === 0x70) ||
        ext === 'avif' || ext === 'heic' || ext === 'mp4'
    )) {
        let offset = 0;
        let lastBox = -1;

        while (offset + 8 <= length) {
            let boxSize = view.getUint32(offset, false);
            let headerSize = 8;

            if (boxSize === 1) {
                if (offset + 16 > length) break;
                const bigSize = view.getBigUint64(offset + 8, false);
                boxSize = Number(bigSize);
                headerSize = 16;
            } else if (boxSize === 0) {
                lastBox = length;
                break;
            }

            if (boxSize < headerSize || offset + boxSize > length) {
                break;
            }

            offset += boxSize;
            lastBox = offset;
        }

        if (lastBox > 0) return { eof: lastBox };
    }

    for (let i = 0; i < Math.min(length - 8, 64); i++) {
        if (view.getUint8(i) === 0x89 && view.getUint8(i + 1) === 0x50 && view.getUint8(i + 2) === 0x4E && view.getUint8(i + 3) === 0x47) {
            let offset = i + 8;
            while (offset + 12 <= length) {
                const chunkSize = view.getUint32(offset, false);
                if (view.getUint8(offset + 4) === 0x49 && view.getUint8(offset + 5) === 0x45 &&
                    view.getUint8(offset + 6) === 0x4E && view.getUint8(offset + 7) === 0x47) {
                    return { eof: offset + 12 };
                }
                if (chunkSize > length) break;
                offset += 12 + chunkSize;
            }
        }
    }

    if (length >= 2 && view.getUint8(0) === 0xFF && view.getUint8(1) === 0xD8) {
        for (let i = length - 2; i >= 2; i--) {
            if (view.getUint8(i) === 0xFF && view.getUint8(i + 1) === 0xD9) {
                return { eof: i + 2 };
            }
        }
    }

    if (length >= 8 && view.getUint8(0) === 0x52 && view.getUint8(1) === 0x49 && view.getUint8(2) === 0x46 && view.getUint8(3) === 0x43) {
        const riffSize = view.getUint32(4, true);
        if (riffSize + 8 <= length) return { eof: riffSize + 8 };
    }

    if (length >= 6 && view.getUint8(0) === 0x42 && view.getUint8(1) === 0x4D) {
        const size = view.getUint32(2, true);
        if (size <= length && size > 0) return { eof: size };
    }

    return { eof: -1 };
}

function bytesToHexDump(dataView, start, end) {
    let output = '';
    let hex = '';
    let ascii = '';

    for (let i = start; i < end && i < dataView.byteLength; i++) {
        const byte = dataView.getUint8(i);
        hex += byte.toString(16).padStart(2, '0').toUpperCase() + ' ';
        ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';

        if ((i - start + 1) % 16 === 0 || i === end - 1 || i === dataView.byteLength - 1) {
            const addr = i.toString(16).padStart(8, '0').toUpperCase();
            output += `${addr}  ${hex.padEnd(48, ' ')} |${ascii}|\n`;
            hex = '';
            ascii = '';
        }
    }
    return output;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function revokeActivePreview() {
    if (state.activePreviewUrl) {
        URL.revokeObjectURL(state.activePreviewUrl);
        state.activePreviewUrl = null;
    }
}

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

function setBanner(id, type, title, desc) {
    const banner = document.getElementById(id);
    if (!banner) return;
    banner.className = `status-banner ${type}`;
    const h3 = banner.querySelector('h3');
    const p = banner.querySelector('p');
    if (h3) h3.textContent = title;
    if (p) p.textContent = desc;
}