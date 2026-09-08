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

// Certifique-se de usar o caminho relativo correto até o worker.js
const forensicWorker = new Worker('worker.js');

forensicWorker.onerror = function (error) {
    console.error("Erro no Worker Forense:", error);
};

document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    setupDragAndDrop();
    setupEventListeners();
    setupWorkerListeners();
});

// --- COMUNICAÇÃO COM O WEB WORKER ---
function setupWorkerListeners() {
    forensicWorker.onmessage = function (e) {
        const { action, eof, format, extraBytes, hiddenType } = e.data || {};

        if (action === 'ANALYSIS_COMPLETE') {
            const resultSection = document.getElementById('detectResult');
            resultSection.classList.remove('hidden');

            document.getElementById('detectMetaFormat').textContent = format;

            if (eof === -1) {
                setBanner('detectStatusBanner', 'warning', 'Estrutura Não Reconhecida', 'Não foi possível determinar o limite do container da mídia.');
                document.getElementById('detectMetaExpected').textContent = '-';
                document.getElementById('detectMetaExtra').textContent = '0 Bytes';
                document.getElementById('detectMetaType').textContent = 'N/A';
                return;
            }

            document.getElementById('detectMetaExpected').textContent = formatBytes(eof);
            document.getElementById('detectMetaExtra').textContent = formatBytes(extraBytes);

            if (extraBytes > 0) {
                document.getElementById('detectMetaType').textContent = hiddenType;
                setBanner('detectStatusBanner', 'suspicious', '⚠️ Conteúdo Oculto Identificado!', `Anomalia detectada: ${formatBytes(extraBytes)} de dados após o EOF da mídia.`);
            } else {
                document.getElementById('detectMetaType').textContent = 'Nenhum';
                setBanner('detectStatusBanner', 'clean', '✅ Mídia Segura e Limpa', 'Nenhuma anomalia de concatenação identificada.');
            }
        }
    };
}

// --- DETECÇÃO & PROCESSAMENTO ---
function handleDetectFile(file) {
    if (!file) return;
    state.detectFile = file;
    document.getElementById('detectFileName').textContent = file.name;
    document.getElementById('detectFileSize').textContent = formatBytes(file.size);

    revokeActivePreview();
    state.activePreviewUrl = URL.createObjectURL(file);

    const container = document.getElementById('mediaPreviewContainer');
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

    const reader = new FileReader();
    reader.onload = function (e) {
        const buffer = e.target.result;
        
        const sampleView = new DataView(buffer);
        document.getElementById('detectHexViewer').textContent = bytesToHexDump(sampleView, 0, Math.min(buffer.byteLength, 256));

        forensicWorker.postMessage({
            action: 'ANALYZE_MEDIA',
            buffer: buffer,
            fileName: file.name
        });
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
    document.getElementById('joinImgName').textContent = `${file.name} (${formatBytes(file.size)})`;
    checkJoinReady();
}

function handleJoinSecretFile(file) {
    state.joinSecretFile = file;
    document.getElementById('joinSecretName').textContent = `${file.name} (${formatBytes(file.size)})`;
    checkJoinReady();
}

function checkJoinReady() {
    const btn = document.getElementById('joinBtn');
    btn.disabled = !(state.joinImgFile && state.joinSecretFile);
}

function handleExtractFile(file) {
    state.extractFile = file;
    
    const reader = new FileReader();
    reader.onload = function (e) {
        const buffer = e.target.result;
        const view = new DataView(buffer);
        const eofInfo = findEofLocally(view);

        const resultSection = document.getElementById('extractResult');
        resultSection.classList.remove('hidden');

        if (eofInfo.eof === -1 || buffer.byteLength <= eofInfo.eof) {
            setBanner('extractStatusBanner', 'warning', 'Nenhum Payload Encontrado', 'A mídia selecionada não possui dados concatenados anexados.');
            document.getElementById('btnDownloadCleanImg').style.display = 'none';
            document.getElementById('btnDownloadPayload').style.display = 'none';
            return;
        }

        const cleanBuffer = buffer.slice(0, eofInfo.eof);
        const payloadBuffer = buffer.slice(eofInfo.eof);

        state.extractedData.cleanImgBlob = new Blob([cleanBuffer], { type: file.type || 'application/octet-stream' });
        state.extractedData.payloadBlob = new Blob([payloadBuffer], { type: 'application/octet-stream' });

        setBanner('extractStatusBanner', 'suspicious', 'Payload Oculto Extraído!', `Foram isolados ${formatBytes(payloadBuffer.byteLength)} de payload da mídia original.`);
        document.getElementById('btnDownloadCleanImg').style.display = 'inline-block';
        document.getElementById('btnDownloadPayload').style.display = 'inline-block';
    };
    reader.readAsArrayBuffer(file);
}

function setupEventListeners() {
    document.getElementById('joinBtn').addEventListener('click', () => {
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

                document.getElementById('joinStatusBanner').classList.remove('hidden');
            };
            readerSecret.readAsArrayBuffer(state.joinSecretFile);
        };
        readerImg.readAsArrayBuffer(state.joinImgFile);
    });

    document.getElementById('btnDownloadCleanImg').addEventListener('click', () => {
        if (state.extractedData.cleanImgBlob && state.extractFile) {
            downloadBlob(state.extractedData.cleanImgBlob, `clean_${state.extractFile.name}`);
        }
    });

    document.getElementById('btnDownloadPayload').addEventListener('click', () => {
        if (state.extractedData.payloadBlob) {
            downloadBlob(state.extractedData.payloadBlob, `extracted_payload.bin`);
        }
    });

    document.getElementById('btnResetDetect').addEventListener('click', () => {
        state.detectFile = null;
        document.getElementById('detectFileInput').value = '';
        document.getElementById('detectResult').classList.add('hidden');
        revokeActivePreview();
    });

    document.getElementById('btnResetJoin').addEventListener('click', () => {
        state.joinImgFile = null;
        state.joinSecretFile = null;
        document.getElementById('joinImgInput').value = '';
        document.getElementById('joinSecretInput').value = '';
        document.getElementById('joinImgName').textContent = 'Nenhum arquivo selecionado';
        document.getElementById('joinSecretName').textContent = 'ZIP, RAR, PDF, TXT, EXE, etc.';
        document.getElementById('joinBtn').disabled = true;
        document.getElementById('joinStatusBanner').classList.add('hidden');
    });

    document.getElementById('btnResetExtract').addEventListener('click', () => {
        state.extractFile = null;
        state.extractedData = { cleanImgBlob: null, payloadBlob: null, payloadExt: 'bin' };
        document.getElementById('extractFileInput').value = '';
        document.getElementById('extractResult').classList.add('hidden');
    });
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

function findEofLocally(view) {
    const length = view.byteLength;

    if (length >= 8 && view.getUint8(0) === 0x89 && view.getUint8(1) === 0x50) {
        let offset = 8;
        while (offset + 8 <= length) {
            const chunkSize = view.getUint32(offset, false);
            if (view.getUint8(offset + 4) === 0x49 && view.getUint8(offset + 5) === 0x45 &&
                view.getUint8(offset + 6) === 0x4E && view.getUint8(offset + 7) === 0x44) {
                return { eof: offset + 12 };
            }
            offset += 12 + chunkSize;
        }
    } else if (length >= 2 && view.getUint8(0) === 0xFF && view.getUint8(1) === 0xD8) {
        for (let i = length - 2; i >= 2; i--) {
            if (view.getUint8(i) === 0xFF && view.getUint8(i + 1) === 0xD9) {
                return { eof: i + 2 };
            }
        }
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