# 🛡️ DocumentSentinel — Forensic RAG Agent

DocumentSentinel is a Streamlit-based document intelligence project for **PDF, DOCX, and XLSX** files.

It combines:

- 🔍 File and document metadata
- 🔐 SHA-256 hashing
- ⚠️ Suspicious PDF/Office package indicators
- 🎯 URL and IOC extraction
- 🦠 ClamAV antivirus scanning
- 🌐 Optional VirusTotal hash lookup
- 🤖 RAG-based document investigation with OpenAI + FAISS
- 📊 A Streamlit dashboard with selectable agent modes

## ⚠️ Important

This application does **not** prove that a document is malware-free. Metadata and heuristic checks can identify indicators that deserve investigation, while antivirus and reputation services provide additional evidence.

The application does not open uploaded files in Microsoft Office and does not execute embedded macros or code.

Supported formats:

- `.pdf`
- `.docx`
- `.xlsx`

Legacy `.doc` and `.xls` files are not currently supported.

## 🚀 Run locally

Create/activate your virtual environment, then:

```bash
pip install -r requirements.txt
streamlit run app.py
```

For the RAG features, provide your OpenAI API key in the application sidebar.

For VirusTotal lookup, provide a VirusTotal API key.

For ClamAV, install ClamAV and make sure `clamscan` is available on your PATH.

## ☁️ Streamlit Community Cloud

The repository contains `packages.txt` so Streamlit Community Cloud can install the Linux ClamAV dependency.

Deploy `app.py` as the entrypoint.

Do not commit API keys. Use Streamlit Secrets for deployment if you want to configure them server-side, or let users enter their own keys in the interface.

## 🧠 Agent modes

### Forensic Analyzer
Focuses on metadata, hashes, package structures, URLs and IOCs.

### RAG Investigator
Builds a searchable FAISS knowledge base from extracted document text and answers questions using retrieved context.

### Security Analyzer
Focuses on suspicious structures, antivirus scanning and optional VirusTotal hash reputation.

### Full Investigation
Combines forensic analysis, security analysis and RAG.

## 📁 Project structure

```text
DocumentSentinel/
├── app.py
├── requirements.txt
├── packages.txt
├── .gitignore
└── README.md
```

## 🔒 Security design

- Uploaded documents are analyzed as bytes.
- PDF/DOCX/XLSX content is parsed without opening it in Microsoft Office.
- Online URL mode is restricted to direct PDF URLs and includes basic SSRF protections.
- A 25 MB upload/download limit is enforced.
- Hash-based VirusTotal lookup is optional.
- ClamAV scanning is optional.

## 📌 Disclaimer

This project is intended for educational, defensive-security, digital-forensics and document-analysis use. A "clean" result does not guarantee that a document is completely safe.
