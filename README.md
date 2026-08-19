# 🛡️ Steganography Suite

> **Suíte Client-Side de Análise Forense, Injeção e Extração de Esteganografia via Concatenação.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Security](https://img.shields.io/badge/Security-Client--Side%20Sandbox-green.svg)
![Dependencies](<https://img.shields.io/badge/dependencies-0%20(VanillaJS)-orange.svg>)

**Steganography Suite** é uma ferramenta de segurança e análise forense digital desenvolvida para identificar, ocultar e extrair dados anexados após o marcador final ($EOF$) de imagens digitais.

Projetada com foco em privacidade e segurança máxima (Zero-Trust), a aplicação opera **100% no navegador (Client-Side)** utilizando Vanilla JS, sem dependências externas e com suporte a uma política rígida de segurança de conteúdo (Content Security Policy - CSP), garantindo que nenhum byte das suas imagens ou arquivos secretos seja enviado para servidores externos.

---

## 💡 O que é Esteganografia?

A **Esteganografia** (do grego _steganos_, "oculto", e _graphia_, "escrita") é a arte e a ciência de esconder dados dentro de outros arquivos de mídia comuns de forma imperceptível.

Diferente da **Criptografia** — que transforma uma mensagem em um texto indecifrável chamando a atenção de observadores —, a **Esteganografia** esconde a _existência_ da própria mensagem.

### 📌 Técnica Utilizada: Concatenação EOF (End of File)

Os leitores e visualizadores de imagens interpretam o arquivo lendo os bytes do cabeçalho (_Header_) até encontrarem a estrutura binária que indica o fim do arquivo (_EOF - End of File_).

A **Steganography Suite** explora essa característica injetando arquivos adicionais (como arquivos `.zip`, `.pdf`, `.txt`) **após** o marcador final da imagem. Visualizadores normais exibem a imagem perfeitamente ignorando os bytes sobressalentes, enquanto nossa ferramenta é capaz de identificar, isolar e extrair o conteúdo oculto.

---

## 🚀 Funcionalidades Principais

- **🔍 1. Análise Forense & Detecção:**
  - Leitura dos _Magic Bytes_ (assinaturas hexadecimais) dos formatos PNG, JPEG, GIF e BMP.
  - Cálculo dinâmico do tamanho estrutural esperado da imagem vs. tamanho real do arquivo.
  - Alertas visuais de anomalias e exibição do tipo do payload oculto (ZIP, RAR, PDF, 7z).
  - Inspecionador embutido em Hexadecimal (_Hex Dump_) no ponto de transição EOF.

- **🛠️ 2. Juntar (Ocultar Payload):**
  - Concatena arquivos ocultos em imagens de capa diretamente na memória local via `Uint8Array`.
  - Zero dependências de terminal ou comandos como `copy /b` ou `cat`.

- **🔓 3. Extrair (Separador Automático):**
  - Localiza a assinatura $EOF$ precisa e divide o arquivo em dois objetos isolados.
  - Permite o download individual da **Imagem Limpa** (sem os dados extras) e do **Payload Oculto** (com a extensão identificada automaticamente).

---

## 🔒 Arquitetura de Segurança e Boas Práticas

A aplicação foi desenvolvida sob o conceito de **Defesa em Profundidade (Defense in Depth)**:

- **Content Security Policy (CSP) Rígida:** Proteção robusta contra ataques XSS (_Cross-Site Scripting_) e injeções de scripts externos.
- **Privacidade Absoluta:** Manipulação de buffers via `ArrayBuffer` e `Uint8Array` locais (`window.FileReader`). Nenhum dado trafega na rede.
- **Zero Trust em Dependências:** Desenvolvido em Vanilla JS puro para eliminar vulnerabilidades de cadeia de suprimentos (_Supply Chain Attacks_).
- **Gestão Consciente de Memória:** Limpeza ativa de ponteiros em memória utilizando `URL.revokeObjectURL()` após o processamento de downloads.

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

1. Clique duas vezes no arquivo `index.html` para executá-lo em qualquer navegador moderno.

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
