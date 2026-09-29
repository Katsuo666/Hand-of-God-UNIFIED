# -*- coding: utf-8 -*-
"""
Cliente HTTP centralizado com retry, timeout e validação
Fornece interface unificada para requisições HTTP seguras
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, List
import time
from .config import Config
from .logger import get_logger

logger = get_logger(__name__)


class HTTPClient:
    """Cliente HTTP com retry automático e tratamento de erros"""

    def __init__(
        self,
        timeout: int = Config.HTTP_TIMEOUT,
        max_retries: int = Config.HTTP_MAX_RETRIES,
        user_agent: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        """
        Inicializa o cliente HTTP

        Args:
            timeout: Timeout em segundos
            max_retries: Número de tentativas de retry
            user_agent: User-Agent customizado
            verify_ssl: Validar certificados SSL
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent or Config.HTTP_USER_AGENT
        self.verify_ssl = verify_ssl
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Cria uma sessão com retry automático"""
        session = requests.Session()

        # Configurar retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=1,
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Headers padrão
        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "pt-BR,pt;q=0.9",
        })

        return session

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Faz requisição GET

        Args:
            url: URL alvo
            params: Query parameters
            headers: Headers customizados
            **kwargs: Argumentos adicionais para requests

        Returns:
            Response object ou None em caso de erro
        """
        return self._request("GET", url, params=params, headers=headers, **kwargs)

    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Faz requisição POST

        Args:
            url: URL alvo
            data: Dados do formulário
            json: JSON para enviar
            headers: Headers customizados
            **kwargs: Argumentos adicionais

        Returns:
            Response object ou None em caso de erro
        """
        return self._request(
            "POST",
            url,
            data=data,
            json=json,
            headers=headers,
            **kwargs
        )

    def _request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Executa requisição com tratamento de erro

        Args:
            method: Método HTTP
            url: URL alvo
            **kwargs: Argumentos para session.request

        Returns:
            Response object ou None em caso de erro
        """
        try:
            # Merge headers
            headers = kwargs.pop("headers", None) or {}
            merged_headers = {**self.session.headers, **headers}
            raise_for_status = kwargs.pop("raise_for_status", True)

            kwargs["timeout"] = kwargs.get("timeout", self.timeout)
            kwargs["verify"] = self.verify_ssl

            response = self.session.request(
                method,
                url,
                headers=merged_headers,
                **kwargs
            )

            if raise_for_status:
                response.raise_for_status()
            return response

        except requests.exceptions.Timeout:
            logger.error(f"Timeout na requisição {method} {url}")
            return None
        except requests.exceptions.ConnectionError:
            logger.error(f"Erro de conexão {method} {url}")
            return None
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP Error {e.response.status_code} em {url}")
            return None
        except Exception as e:
            logger.error(f"Erro na requisição {method} {url}: {str(e)}")
            return None

    def get_json(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Requisição GET que retorna JSON

        Args:
            url: URL alvo
            params: Query parameters
            **kwargs: Argumentos adicionais

        Returns:
            Parsed JSON dict ou None
        """
        response = self.get(url, params=params, **kwargs)
        if response:
            try:
                return response.json()
            except ValueError:
                logger.error(f"Resposta não é JSON válido: {url}")
                return None
        return None

    def post_json(
        self,
        url: str,
        json: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Requisição POST que retorna JSON

        Args:
            url: URL alvo
            json: Dados JSON
            **kwargs: Argumentos adicionais

        Returns:
            Parsed JSON dict ou None
        """
        response = self.post(url, json=json, **kwargs)
        if response:
            try:
                return response.json()
            except ValueError:
                logger.error(f"Resposta não é JSON válido: {url}")
                return None
        return None

    def close(self) -> None:
        """Fecha a sessão"""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
