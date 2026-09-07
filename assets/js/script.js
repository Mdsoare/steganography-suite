/**
 * StegoSuite PRO - Script Principal
 * Práticas: Strict Mode, Web Workers, DataView Parsing e Gestão Limpa de DOM.
 */

'use strict';

// Proteção básica de Frame Busting para GitHub Pages
if (self !== top) {
    try {
        top.location = self.location;
    } catch (e) {
        // Se o iframe estiver sandboxed sem allow-top-navigation, redefine a interface
        document.body.innerHTML = '<h1>Acesso não permitido em iframes.</h1>';
    }
}

// Instanciação do Worker para processamento assíncrono off-thread
const forensicWorker = new Worker('worker.js');

const state = {
    detectFile: null,
    joinImgFile: null,
    joinSecretFile: null,
    extractFile: null,
    extractedData: { cleanImgBlob: null, payloadBlob: null, payloadExt: 'bin' },
    activePreviewUrl: null
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
        const { action, eof, format, extraBytes, hiddenType } = e.data;

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
    state.detectFile = file;
    document.getElementById('detectFileName').textContent = file.name;
    document.getElementById('detectFileSize').textContent = formatBytes(file.size);

    revokeActivePreview();
    state.activePreviewUrl = URL.createObjectURL(file);

    const container = document.getElementById('mediaPreviewContainer');
    container.textContent = ''; // Limpeza limpa de DOM

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
        
        // Gera o Hex Viewer na UI (apenas os primeiros/últimos bytes para economizar renderização)
        const sampleView = new DataView(buffer);
        document.getElementById('detectHexViewer').textContent = bytesToHexDump(sampleView, 0, Math.min(buffer.byteLength, 256));

        // Envia o processamento pesado para a Thread Secundária
        forensicWorker.postMessage({
            action: 'ANALYZE_MEDIA',
            buffer: buffer,
            fileName: file.name
        }, [buffer]); // ArrayBuffer Transferível para consumo de memória 0-copy
    };
    reader.readAsArrayBuffer(file);
}

// --- AUXILIARES SEGUROS DE PARSING E DUMP ---
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

function setupDragAndDrop() {
    const dropZones = [
        { zone: document.getElementById('detectDropZone'), input: document.getElementById('detectFileInput'), handler: handleDetectFile }
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
    // Manter seus eventos de formulário/download originais
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