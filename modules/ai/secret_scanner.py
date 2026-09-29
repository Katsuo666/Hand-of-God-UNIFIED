# -*- coding: utf-8 -*-
"""
Análise estática de conteúdo HTTP (HTML/JS já obtido) em busca de segredos
expostos, palavras-chave sensíveis e fingerprint de tecnologia.

As assinaturas de formato de chave abaixo (prefixos como AKIA, ghp_,
sk_live_...) são publicadas pelos próprios provedores (AWS, GitHub, Stripe,
etc.) como parte do formato oficial das suas credenciais — não são
segredo de implementação de ninguém, e por isso aparecem, com pequenas
variações, em praticamente todo scanner de secrets open source (gitleaks,
trufflehog, detect-secrets...).
"""

import re
from typing import Any, Dict, List

# type_id -> (regex, severidade)
SECRET_SIGNATURES: Dict[str, Dict[str, str]] = {
    "aws_access_key": {"pattern": r"AKIA[0-9A-Z]{16}", "severity": "CRITICAL", "label": "AWS Access Key ID"},
    "aws_secret_key": {"pattern": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
                        "severity": "CRITICAL", "label": "AWS Secret Access Key"},
    "google_api_key": {"pattern": r"AIza[0-9A-Za-z\-_]{35}", "severity": "HIGH", "label": "Google API Key"},
    "stripe_live_key": {"pattern": r"sk_live_[0-9a-zA-Z]{16,}", "severity": "CRITICAL", "label": "Stripe Live Secret Key"},
    "stripe_publishable": {"pattern": r"pk_live_[0-9a-zA-Z]{16,}", "severity": "MEDIUM", "label": "Stripe Publishable Key"},
    "github_pat": {"pattern": r"gh[pousr]_[A-Za-z0-9]{30,}", "severity": "CRITICAL", "label": "GitHub Personal Access Token"},
    "slack_token": {"pattern": r"xox[baprs]-[0-9A-Za-z\-]{10,}", "severity": "HIGH", "label": "Slack Token"},
    "slack_webhook": {"pattern": r"hooks\.slack\.com/services/[A-Za-z0-9/]{20,}", "severity": "MEDIUM", "label": "Slack Webhook URL"},
    "jwt": {"pattern": r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*",
            "severity": "MEDIUM", "label": "JSON Web Token"},
    "generic_secret_assignment": {
        "pattern": r"(?i)\b(api[_-]?key|apikey|secret|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*['\"][a-zA-Z0-9_\-./]{16,}['\"]",
        "severity": "HIGH", "label": "Atribuição genérica de credencial",
    },
    "connection_string": {"pattern": r"\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis)://[^\s'\"<>]+",
                           "severity": "CRITICAL", "label": "Connection string com credenciais embutidas"},
    "pem_private_key": {"pattern": r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
                         "severity": "CRITICAL", "label": "Bloco de chave privada PEM"},
}

# Palavras isoladas que, mesmo sem casar um regex de formato específico,
# indicam que a página provavelmente não devia estar acessível publicamente.
CONTEXT_KEYWORDS: Dict[str, List[str]] = {
    "CRITICAL": ["begin private key", "begin rsa private key", "root_password", "db_password"],
    "HIGH": ["authorization: bearer", "x-api-key", "client_secret", "private_key"],
    "MEDIUM": ["password", "passwd", "credential", "session_token"],
}

# Fingerprint leve de stack front-end/back-end via marcadores presentes no HTML servido.
STACK_FINGERPRINTS: Dict[str, List[str]] = {
    "React": ["__reactfiber", "react-dom", "data-reactroot"],
    "Next.js": ["__next_data__", "/_next/static/"],
    "Vue.js": ["__vue__", "v-cloak", "vue.runtime"],
    "Angular": ["ng-version", "ng-app"],
    "jQuery": ["jquery.min.js", "jquery.js"],
    "WordPress": ["wp-content/", "wp-includes/", "wp-json"],
    "Laravel": ["laravel_session", "xsrf-token"],
    "Django": ["csrfmiddlewaretoken"],
    "Cloudflare": ["cf-ray", "__cf_bm"],
}


class SecretScanner:
    """Recebe HTML/JS já obtido (não faz requisições) e devolve um resumo
    de segredos, palavras-chave de contexto e stack detetados."""

    def scan(self, content: str, source_url: str = "") -> Dict[str, Any]:
        return {
            "url": source_url,
            "secrets": self.find_secrets(content, source_url),
            "context_flags": self.find_context_keywords(content, source_url),
            "stack": self.fingerprint_stack(content),
        }

    def find_secrets(self, content: str, source_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        already_reported = set()

        for signature_id, spec in SECRET_SIGNATURES.items():
            for match in re.finditer(spec["pattern"], content):
                snippet = match.group(0)
                dedupe_key = (signature_id, snippet[:30])
                if dedupe_key in already_reported:
                    continue
                already_reported.add(dedupe_key)
                findings.append({
                    "type": spec["label"],
                    "value": snippet[:80],
                    "url": source_url,
                    "severity": spec["severity"],
                    "source": "SecretScanner",
                })
        return findings

    def find_context_keywords(self, content: str, source_url: str) -> List[Dict[str, Any]]:
        lowered = content.lower()
        flags: List[Dict[str, Any]] = []
        for severity, keywords in CONTEXT_KEYWORDS.items():
            hit = next((kw for kw in keywords if kw in lowered), None)
            if hit:
                flags.append({
                    "url": source_url,
                    "issue": f'Termo sensível encontrado no conteúdo: "{hit}"',
                    "severity": severity,
                    "source": "SecretScanner",
                })
        return flags

    def fingerprint_stack(self, content: str) -> List[str]:
        lowered = content.lower()
        detected = {
            name for name, markers in STACK_FINGERPRINTS.items()
            if any(marker.lower() in lowered for marker in markers)
        }
        return sorted(detected)
