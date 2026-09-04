# 🔐 DocumentSentinel — Forensic RAG Agent

> A multi-format document forensics and RAG application for analyzing PDF, Word, and Excel files using metadata extraction, static security analysis, IOC detection, antivirus scanning, and AI-powered investigation.

---

## 🚀 Live Streamlit Application

### 👉 Open the Application

**[🔗 Launch DocumentSentinel on Streamlit](https://forensic-rag-agent-123.streamlit.app/)**

> ⚠️ Replace `PASTE-YOUR-STREAMLIT-LINK-HERE` with your actual Streamlit deployment URL.

---

## 📌 Project Overview

**DocumentSentinel** is a cybersecurity-focused document analysis application designed to help investigate potentially suspicious documents.

The application allows users to upload:

- 📄 PDF files
- 📝 Microsoft Word (`.docx`) files
- 📊 Microsoft Excel (`.xlsx`) files

The application extracts useful forensic information from the uploaded document and performs static security checks without executing the document.

It also uses **Retrieval-Augmented Generation (RAG)** to allow an AI model to analyze the extracted document content and answer investigation-related questions.

---

## 🎯 Main Features

### 📂 Multi-Format Document Support

DocumentSentinel supports:

- PDF
- DOCX
- XLSX

Users can upload a document directly through the Streamlit interface.

---

### 🔍 Forensic Analysis

The application can extract and analyze:

- File metadata
- Document properties
- Author information
- Creation and modification information
- File size
- SHA-256 hash
- Document structure
- Embedded objects
- Suspicious document features

---

### 🧪 Static Security Analysis

The application looks for potentially suspicious structures without executing the document.

For PDFs, it checks for indicators such as:

- JavaScript
- `/JS`
- `/OpenAction`
- `/AA`
- `/Launch`
- `/EmbeddedFile`
- `/RichMedia`
- `/AcroForm`
- `/SubmitForm`
- `/GoToR`
- `/URI`

For Office documents, it checks the underlying OOXML structure for potentially interesting objects such as:

- Embedded files
- VBA projects/macros
- External links
- Other suspicious structures

> ⚠️ These indicators do not automatically mean that a document is malicious. They are forensic indicators that require further investigation.

---

### 🌐 IOC Detection

DocumentSentinel searches extracted content for potential Indicators of Compromise (IOCs), including:

- URLs
- IPv4 addresses
- MD5 hashes
- SHA-256 hashes

This can help investigators identify potentially suspicious external resources or known file hashes.

---

### 🦠 ClamAV Integration

If ClamAV is available in the environment, the application can scan uploaded files using antivirus scanning.

The result can indicate whether ClamAV detected a known threat.

> ClamAV detection is an additional security layer and should not be treated as a guarantee that a document is safe.

---

### 🧬 VirusTotal Hash Lookup

Users can optionally provide a VirusTotal API key.

DocumentSentinel can submit the file's SHA-256 hash for reputation lookup.

This allows investigators to check whether the hash has previously been associated with malicious or suspicious files.

> The application uses hash lookup rather than uploading the document to VirusTotal.

---

## 🤖 Selectable Investigation Agents

The application provides different investigation modes so users can choose how they want to analyze a document.

### 🔍 Forensic Analyzer

Focuses on:

- Metadata
- File hashes
- Document structure
- Suspicious indicators
- IOCs

---

### 🤖 RAG Investigator

Uses Retrieval-Augmented Generation to analyze the extracted document content.

The system:

1. Extracts document text
2. Splits the text into smaller chunks
3. Creates embeddings
4. Stores the embeddings in FAISS
5. Retrieves relevant sections
6. Sends the relevant context to the AI model
7. Generates an investigation response

---

### 🦠 Security Analyzer

Focuses on:

- Suspicious structures
- URLs
- IP addresses
- Hashes
- Malware indicators
- Antivirus results
- VirusTotal reputation

---

### 🧩 Full Investigation

Combines the available analysis capabilities into a single investigation workflow.

This mode can combine:

- Forensic analysis
- Metadata analysis
- Hash analysis
- Static security analysis
- IOC detection
- ClamAV scanning
- VirusTotal lookup
- RAG-based AI investigation

---

# 🧠 How RAG Works

DocumentSentinel uses **Retrieval-Augmented Generation (RAG)** to improve document-based AI analysis.

The workflow is:

```text
             ┌─────────────────────┐
             │   Upload Document   │
             │ PDF / DOCX / XLSX   │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │  Extract Contents   │
             │ Text + Metadata     │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │ Static Analysis     │
             │ Hash / IOC / etc.   │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │ Text Chunking       │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │ OpenAI Embeddings   │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │      FAISS          │
             │ Vector Database     │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │ Retrieve Relevant   │
             │ Document Evidence   │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │     AI Analysis     │
             │     via OpenAI      │
             └─────────────────────┘
