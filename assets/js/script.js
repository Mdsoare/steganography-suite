'use strict';

/**
 * StegoSuite - Módulo Principal (Vanilla JS Encapsulado)
 * Práticas: Strict Mode, Manipulação do DOM Segura (sem innerHTML perigoso), Gestão de Memória Local.
 */

// --- BASE DE DADOS DE ASSINATURAS (MAGIC BYTES) ---
const SIGNATURES = {
    // Formatos de Imagem (Marcadores de Cabeçalho e Fim)
    PNG_HEADER: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    PNG_END: [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82],

    JPEG_HEADER: [0xFF, 0xD8, 0xFF],
    JPEG_END: [0xFF, 0xD9],

    GIF_HEADER: [0x47, 0x49, 0x46, 0x38], // GIF87a ou GIF89a
    GIF_END: [0x3B], // GIF Trailer

    // Payloads Conhecidos
    RAR: { bytes: [0x52, 0x61, 0x72, 0x21], ext: 'rar', label: 'Arquivo RAR' },
    ZIP: { bytes: [0x50, 0x4B, 0x03, 0x04], ext: 'zip', label: 'Arquivo ZIP' },
    SEVEN_ZIP: { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], ext: '7z', label: 'Arquivo 7-Zip' },
    PDF: { bytes: [0x25, 0x50, 0x44, 0x46], ext: 'pdf', label: 'Documento PDF' }
};

// --- ESTADO GLOBAL DA APLICAÇÃO ---
const state = {
    detectFile: null,
    joinImgFile: null,
    joinSecretFile: null,
    extractFile: null,
    extractedData: { cleanImgBlob: null, payloadBlob: null, payloadExt: 'bin' }
};

// --- INICIALIZAÇÃO DA APLICAÇÃO ---
document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    setupDragAndDrop();
    setupEventListeners();
});

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
            document.getElementById(targetTab).classList.add('active');
        });
    });
}

// --- EVENTOS DRAG & DROP E FILE INPUTS ---
function setupDragAndDrop() {
    const dropZones = [
        { zone: document.getElementById('detectDropZone'), input: document.getElementById('detectFileInput'), handler: handleDetectFile },
        { zone: document.getElementById('joinImgDropZone'), input: document.getElementById('joinImgInput'), handler: handleJoinImgFile },
        { zone: document.getElementById('joinSecretDropZone'), input: document.getElementById('joinSecretInput'), handler: handleJoinSecretFile },
        { zone: document.getElementById('extractDropZone'), input: document.getElementById('extractFileInput'), handler: handleExtractFile }
    ];

    dropZones.forEach(({ zone, input, handler }) => {
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
    document.getElementById('joinBtn').addEventListener('click', executeJoin);
    document.getElementById('btnDownloadCleanImg').addEventListener('click', () => downloadBlob(state.extractedData.cleanImgBlob, 'imagem_limpa'));
    document.getElementById('btnDownloadPayload').addEventListener('click', () => downloadBlob(state.extractedData.payloadBlob, `payload_extraido.${state.extractedData.payloadExt}`));

    // Handlers de Limpeza / Reset
    document.getElementById('btnResetDetect').addEventListener('click', resetDetectTab);
    document.getElementById('btnResetJoin').addEventListener('click', resetJoinTab);
    document.getElementById('btnResetExtract').addEventListener('click', resetExtractTab);
}

// --- AUXILIARES E UTILITÁRIOS ---

function resetDetectTab() {
    state.detectFile = null;

    // Limpar preview da imagem e revogar objeto de URL
    const preview = document.getElementById('detectPreview');
    if (preview.src.startsWith('blob:')) {
        URL.revokeObjectURL(preview.src);
    }
    preview.src = '';

    // Limpar inputs de arquivo
    document.getElementById('detectFileInput').value = '';

    // Esconder seção de resultados
    document.getElementById('detectResult').classList.add('hidden');
}

function resetJoinTab() {
    state.joinImgFile = null;
    state.joinSecretFile = null;

    // Limpar inputs de arquivo e formulário
    document.getElementById('joinForm').reset();

    // Resetar textos
    document.getElementById('joinImgName').textContent = 'Nenhum arquivo selecionado';
    document.getElementById('joinSecretName').textContent = 'ZIP, RAR, PDF, TXT, etc.';

    // Desabilitar botão e ocultar banner de sucesso
    document.getElementById('joinBtn').disabled = true;
    document.getElementById('joinStatusBanner').classList.add('hidden');
}

function resetExtractTab() {
    state.extractFile = null;

    // Revogar Blobs armazenados em memória local
    if (state.extractedData.cleanImgBlob) state.extractedData.cleanImgBlob = null;
    if (state.extractedData.payloadBlob) state.extractedData.payloadBlob = null;

    // Limpar input de arquivo
    document.getElementById('extractFileInput').value = '';

    // Esconder seção de resultados
    document.getElementById('extractResult').classList.add('hidden');
}

// --- AJUSTE NO EXECUTE JOIN (Exibir mensagem e permitir limpar após injeção) ---
async function executeJoin() {
    if (!state.joinImgFile || !state.joinSecretFile) return;

    const imgBuf = await state.joinImgFile.arrayBuffer();
    const secretBuf = await state.joinSecretFile.arrayBuffer();

    const combined = new Uint8Array(imgBuf.byteLength + secretBuf.byteLength);
    combined.set(new Uint8Array(imgBuf), 0);
    combined.set(new Uint8Array(secretBuf), imgBuf.byteLength);

    const blob = new Blob([combined], { type: state.joinImgFile.type });
    downloadBlob(blob, `stego_${state.joinImgFile.name}`);

    // Exibir confirmação na interface
    document.getElementById('joinStatusBanner').classList.remove('hidden');
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

function bytesToHexDump(uint8Array, start, end) {
    let output = '';
    let hex = '';
    let ascii = '';

    for (let i = start; i < end && i < uint8Array.length; i++) {
        const byte = uint8Array[i];
        hex += byte.toString(16).padStart(2, '0').toUpperCase() + ' ';
        ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';

        if ((i - start + 1) % 16 === 0 || i === end - 1 || i === uint8Array.length - 1) {
            const addr = i.toString(16).padStart(8, '0').toUpperCase();
            output += `${addr}  ${hex.padEnd(48, ' ')} |${ascii}|\n`;
            hex = '';
            ascii = '';
        }
    }
    return output;
}

function findImageEOF(bytes) {
    // Retorna o índice de corte baseando-se no formato
    if (matchSignature(bytes, SIGNATURES.PNG_HEADER)) {
        for (let i = bytes.length - 8; i >= 0; i--) {
            if (matchSignature(bytes, SIGNATURES.PNG_END, i)) return { eof: i + 8, format: 'PNG' };
        }
    } else if (matchSignature(bytes, SIGNATURES.JPEG_HEADER)) {
        for (let i = bytes.length - 2; i >= 0; i--) {
            if (matchSignature(bytes, SIGNATURES.JPEG_END, i)) return { eof: i + 2, format: 'JPEG' };
        }
    } else if (matchSignature(bytes, SIGNATURES.GIF_HEADER)) {
        for (let i = bytes.length - 1; i >= 0; i--) {
            if (matchSignature(bytes, SIGNATURES.GIF_END, i)) return { eof: i + 1, format: 'GIF' };
        }
    } else if (bytes[0] === 0x42 && bytes[1] === 0x4D) { // BMP
        const size = bytes[2] | (bytes[3] << 8) | (bytes[4] << 16) | (bytes[5] << 24);
        if (size <= bytes.length) return { eof: size, format: 'BMP' };
    }
    return { eof: -1, format: 'Desconhecido' };
}

// --- MÓDULO 1: ANÁLISE E DETECÇÃO ---
function handleDetectFile(file) {
    state.detectFile = file;
    document.getElementById('detectFileName').textContent = file.name;
    document.getElementById('detectFileSize').textContent = formatBytes(file.size);

    const preview = document.getElementById('detectPreview');
    preview.src = URL.createObjectURL(file);

    const reader = new FileReader();
    reader.onload = function (e) {
        const bytes = new Uint8Array(e.target.result);
        const { eof, format } = findImageEOF(bytes);

        const resultSection = document.getElementById('detectResult');
        resultSection.classList.remove('hidden');

        document.getElementById('detectMetaFormat').textContent = format;

        if (eof === -1) {
            setBanner('detectStatusBanner', 'warning', 'Estrutura Inválida', 'Não foi possível encontrar o fim estrutural do arquivo.');
            return;
        }

        const extraBytes = bytes.length - eof;
        document.getElementById('detectMetaExpected').textContent = formatBytes(eof);
        document.getElementById('detectMetaExtra').textContent = formatBytes(extraBytes);

        const hexStart = Math.max(0, eof - 32);
        document.getElementById('detectHexViewer').textContent = bytesToHexDump(bytes, hexStart, Math.min(bytes.length, eof + 64));

        if (extraBytes > 0) {
            let hiddenType = 'Dados Genéricos';
            for (const key in SIGNATURES) {
                if (SIGNATURES[key].bytes && matchSignature(bytes, SIGNATURES[key].bytes, eof)) {
                    hiddenType = SIGNATURES[key].label;
                    break;
                }
            }
            document.getElementById('detectMetaType').textContent = hiddenType;
            setBanner('detectStatusBanner', 'suspicious', '⚠️ Dados Ocultos Encontrados!', `Detectados ${formatBytes(extraBytes)} de dados concatenados após o fim oficial da imagem.`);
        } else {
            document.getElementById('detectMetaType').textContent = 'Nenhum';
            setBanner('detectStatusBanner', 'clean', '✅ Imagem Limpa', 'Nenhuma anomalia de concatenação detectada.');
        }
    };
    reader.readAsArrayBuffer(file);
}

// --- MÓDULO 2: JUNTAR (CONCATENAR) ---
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
    document.getElementById('joinBtn').disabled = !(state.joinImgFile && state.joinSecretFile);
}

async function executeJoin() {
    if (!state.joinImgFile || !state.joinSecretFile) return;

    const imgBuf = await state.joinImgFile.arrayBuffer();
    const secretBuf = await state.joinSecretFile.arrayBuffer();

    const combined = new Uint8Array(imgBuf.byteLength + secretBuf.byteLength);
    combined.set(new Uint8Array(imgBuf), 0);
    combined.set(new Uint8Array(secretBuf), imgBuf.byteLength);

    const blob = new Blob([combined], { type: state.joinImgFile.type });
    downloadBlob(blob, `stego_${state.joinImgFile.name}`);
}

// --- MÓDULO 3: EXTRAIR ---
function handleExtractFile(file) {
    state.extractFile = file;
    const reader = new FileReader();

    reader.onload = function (e) {
        const bytes = new Uint8Array(e.target.result);
        const { eof, format } = findImageEOF(bytes);
        const extractResult = document.getElementById('extractResult');

        if (eof === -1 || eof >= bytes.length) {
            setBanner('extractStatusBanner', 'warning', 'Sem Dados Ocultos', 'Esta imagem não contém conteúdo extra para ser extraído.');
            extractResult.classList.remove('hidden');
            document.getElementById('btnDownloadCleanImg').disabled = true;
            document.getElementById('btnDownloadPayload').disabled = true;
            return;
        }

        // Separar buffers
        const cleanImgBytes = bytes.slice(0, eof);
        const payloadBytes = bytes.slice(eof);

        // Identificar Extensão
        let ext = 'bin';
        for (const key in SIGNATURES) {
            if (SIGNATURES[key].bytes && matchSignature(payloadBytes, SIGNATURES[key].bytes, 0)) {
                ext = SIGNATURES[key].ext;
                break;
            }
        }

        state.extractedData.cleanImgBlob = new Blob([cleanImgBytes], { type: file.type });
        state.extractedData.payloadBlob = new Blob([payloadBytes], { type: 'application/octet-stream' });
        state.extractedData.payloadExt = ext;

        setBanner('extractStatusBanner', 'suspicious', 'Conteúdo Oculto Extraído!', `Foram extraídos ${formatBytes(payloadBytes.length)} de payload concatenado.`);

        extractResult.classList.remove('hidden');
        document.getElementById('btnDownloadCleanImg').disabled = false;
        document.getElementById('btnDownloadPayload').disabled = false;
    };

    reader.readAsArrayBuffer(file);
}

// --- UTILITÁRIOS DA INTERFACE ---
function setBanner(id, type, title, desc) {
    const banner = document.getElementById(id);
    banner.className = `status-banner ${type}`;
    banner.querySelector('h3').textContent = title;
    banner.querySelector('p').textContent = desc;
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
    URL.revokeObjectURL(url); // Liberar memória imediatamente
}