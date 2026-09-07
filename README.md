# 🛡️ Steganography Suite

> **Suíte Client-Side de Análise Forense, Injeção e Extração de Esteganografia via Concatenação.**

![CI Pipeline](https://github.com/Mdsoare/steganography-suite/actions/workflows/ci.yml/badge.svg)
[![Security Rating](https://img.shields.io/badge/Security-DevSecOps%20Hardened-green?style=flat&logo=github)](https://github.com/Mdsoare/steganography-suite/security/code-scanning)
![Security: CSP Compliant](https://img.shields.io/badge/Security-CSP--Compliant-success.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

<!-- Badges de Linguagens, Ecossistema e DevSecOps -->
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![NPM](https://img.shields.io/badge/NPM-CB3837?style=for-the-badge&logo=npm&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![ESLint](https://img.shields.io/badge/ESLint-4B32C3?style=for-the-badge&logo=eslint&logoColor=white)
![Dependabot](https://img.shields.io/badge/Dependabot-025E8C?style=for-the-badge&logo=dependabot&logoColor=white)
![SAST & SCA](https://img.shields.io/badge/DevSecOps-SAST%20%26%20SCA-red?style=for-the-badge&logo=shield&logoColor=white)

---

**Steganography Suite** é uma ferramenta de segurança e análise forense digital desenvolvida para identificar, ocultar e extrair dados anexados após o marcador final ($EOF$) de imagens digitais.

Projetada com foco em privacidade e segurança máxima (Zero-Trust), a aplicação opera **100% no navegador (Client-Side)** utilizando Vanilla JS, sem dependências externas e com suporte a uma política rígida de segurança de conteúdo (Content Security Policy - CSP), garantindo que nenhum byte das suas imagens ou arquivos secretos seja enviado para servidores externos.

---

## 💡 O que é Esteganografia?

A **Esteganografia** (do grego _steganos_, "oculto", e _graphia_, "escrita") é a arte e a ciência de esconder dados dentro de outros arquivos de mídia comuns de forma imperceptível.

Diferente da **Criptografia** — que transforma uma mensagem em um texto indecifrável chamando a atenção de observadores —, a **Esteganografia** esconde a _existência_ da própria mensagem.

---

### 📌 Técnica Utilizada: Concatenação EOF (End of File) / Overlay Data

Os reprodutores e visualizadores de mídia interpretam um arquivo lendo os bytes a partir do cabeçalho (_Header_) até identificarem a estrutura binária que marca o fim do contêiner (_EOF - End of File_ ou o fim das _chunks/atoms_ estruturais).

A **Steganography Suite** analisa e explora essa característica ao injetar payloads (como arquivos `.zip`, `.rar`, `.pdf`, `.exe`) **após** o marcador final da mídia. Visualizadores convencionais exibem a imagem ou reproduzem o vídeo normalmente ignorando os bytes sobressalentes, enquanto nossa ferramenta é capaz de analisar a estrutura, identificar anomalias, isolar e extrair o conteúdo oculto com precisão forense.

---

## 🚀 Funcionalidades Principais

🔍 1. Análise Forense & Detecção (Off-Thread Engine):
    - **Varredura Assíncrona via Web Worker:** Processamento binário em thread secundária (`worker.js`), garantindo interface 100% responsiva mesmo em arquivos grandes (>100MB).
    - **Inspeção Ampla de Assinaturas (Magic Bytes):** Identificação e parsing estrutural de formatos **PNG, JPEG, GIF, BMP, RIFF (AVI/WAV) e MP4/ISOBMFF** (suporte a ponteiros 64-bit via `BigInt`/`DataView`).
    - **Detecção de Anomalias no EOF:** Cálculo dinâmico do tamanho estrutural esperado da mídia versus tamanho real do arquivo para identificação exata de concatenações atípicas.
    - **Identificação Automática do Payload:** Reconhecimento de assinaturas embutidas como **ZIP, RAR, 7z, PDF, Executáveis (PE/ELF)** logo após o EOF da mídia.
    - **Inspecionador Hexadecimal Embutido:** Exibição do _Hex Dump_ formatado (Endereço, Hex, ASCII) diretamente no ponto de transição e início do arquivo.

🛠️ 2. Juntar (Ocultar Payload):
    - **Injeção em Memória Local:** Concatenação de arquivos ocultos à imagem de capa diretamente via `Uint8Array` no navegador.
    - **Zero Dependências:** Operação 100% client-side, sem necessidade de comandos de terminal (como `copy /b` ou `cat`) ou servidores externos.

🔓 3. Extrair (Separador Automático):
    - **Isolamento de Objetos:** Localização precisa do marcador EOF do container original e divisão do arquivo em dois elementos totalmente isolados.
    - **Download Seguro:** Permite baixar separadamente a **Imagem Limpa** (com metadados/EOF restaurados e sem payload) e o **Payload Oculto** (com a extensão de arquivo identificada automaticamente).

🛡️ 4. Arquitetura de Segurança & Compliance:
    - **Proteção Anticlone e Clickjacking:** Mecanismo defensivo de _Frame Busting_ para mitigar o enquadramento em `iframe` em hospedagens estáticas (GitHub Pages).
    - **Content Security Policy (CSP):** Configurações rígidas de política de conteúdo autorizando unicamente scripts da própria origem e suporte seguro a `worker-src` e recursos Blob.
    - **Sanitização de Eventos:** Tratamento estrito de mensagens e validação de `origin` em conformidade com as regras de análise estática do CodeQL.

---

## 🔒 Arquitetura de Segurança e Boas Práticas

A aplicação foi desenvolvida sob o conceito de **Defesa em Profundidade (Defense in Depth)**, priorizando execução segura e isolada _client-side_:

- **Frontend & Core:** HTML5, CSS3 Puro (Dark Theme) e Vanilla JavaScript (ES6+) sem dependências externas de runtime.
- **Off-Thread Processing (Web Workers):** Isolamento de rotinas pesadas de parsing em thread secundária (`worker.js`), mantendo a UI totalmente responsiva sem bloquear a thread principal.
- **Content Security Policy (CSP) Rígida:** Proteção robusta contra ataques XSS (_Cross-Site Scripting_) e injeções de código, com controle estrito para `worker-src 'self' blob:` e restrição de recursos de terceiros.
- **Proteção Anticlone (Anti-Clickjacking):** Implementação defensiva de _Frame Busting_ para evitar o enquadramento não autorizado da ferramenta em `iframe` em plataformas estáticas (GitHub Pages).
- **Conformidade de Análise Estática (SAST):** Código auditado e higienizado com validação de `origin` em eventos de mensagens inter-processos (`postMessage`), em estrito cumprimento às diretrizes do GitHub CodeQL.
- **Privacidade & Execução Local:** Manipulação binária direta via `ArrayBuffer`, `DataView` (com parsing BigInt 64-bit) e `Uint8Array`. Zero tráfego de dados na rede — os arquivos nunca saem do seu navegador.
- **Gestão Consciente de Memória:** Desalocação ativa de ponteiros e liberação de buffers em memória utilizando `URL.revokeObjectURL()` imediatamente após o processamento dos downloads.
- **Automação & CI/CD:** Workflows automatizados via GitHub Actions e atualizações contínuas de segurança com GitHub Dependabot.
- **Segurança Estática & DSN (SAST/SCA):** Cobertura contínua com CodeQL, Horusec, Semgrep, ESLint (Flat Config), Stylelint, HTMLHint, TruffleHog, OSV-Scanner, Trivy Scan e `npm audit`.

---

## 🛠️ Como Executar

Por ser uma aplicação totalmente _Client-Side_, você não precisa instalar o Node.js, Python ou servidores web.

1. Clone este repositório

   ```bash
   git clone https://github.com/Mdsoare/steganography-suite.git
   ```

2. Abra a pasta do projeto.

   ```bash
   cd steganography-suite
   ```

3. Clique duas vezes no arquivo `index.html` para executá-lo em qualquer navegador moderno.

---

## ⚠️ Limitações Conhecidas (Importante)

Regra de Ouro da Esteganografia por Concatenação:
Redes Sociais e Aplicativos de Mensagem (WhatsApp, Instagram, X/Twitter, Discord) comprimem, reamostram e re-encodam imagens enviadas como mídia comum. Esse processo "lava" a imagem e destrói permanentemente os bytes anexados no final do arquivo.

Para que a mensagem esteganografada chegue intacta ao destinatário, a imagem modficada deve ser enviada sempre como Documento / Arquivo sem compressão.

---

## ⚖️ Alerta de Uso Responsável (Disclaimer)

Esta ferramenta foi desenvolvida exclusivamente para fins educacionais, acadêmicos e de conscientização sobre segurança da informação.

O uso desta ferramenta para ocultação, transporte ou evasão de dados maliciosos, vazamento não autorizado de informações (Data Exfiltration) ou qualquer atividade ilegal é estritamente proibido.

Os desenvolvedores não se responsabilizam pelo mau uso do software ou por quaisquer danos decorrentes da utilização indevida da ferramenta.

---

## 📜 Licença

Este projeto está sob a licença [MIT](LICENSE).

---

_Desenvolvido por **Marcelo Soares** | Especialista em Segurança da Informação e Computação Forense._
