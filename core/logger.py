# -*- coding: utf-8 -*-
"""
Sistema centralizado de logging
Fornece logging estruturado e rastreável para todo o aplicativo
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional
from .config import Config


class ColoredFormatter(logging.Formatter):
    """Formatter que adiciona cores ao output de console"""

    COLORS = {
        logging.DEBUG: "\033[36m",      # Cyan
        logging.INFO: "\033[32m",       # Green
        logging.WARNING: "\033[33m",    # Yellow
        logging.ERROR: "\033[31m",      # Red
        logging.CRITICAL: "\033[41m",   # Red background
    }
    RESET = "\033[0m"

    def format(self, record):
        log_color = self.COLORS.get(record.levelno, self.RESET)
        record.levelname = f"{log_color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logger(
    name: str = "OlhoDeus",
    level: str = "INFO",
    log_file: Optional[Path] = None,
    console: bool = True,
) -> logging.Logger:
    """
    Configura e retorna um logger estruturado

    Args:
        name: Nome do logger
        level: Nível de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Caminho do arquivo de log (opcional)
        console: Se deve enviar output para console

    Returns:
        Logger configurado
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove handlers antigos
    logger.handlers = []

    # Formato padrão
    formatter = logging.Formatter(
        Config.LOG_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Handler para console
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ColoredFormatter(
            Config.LOG_FORMAT,
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(console_handler)

    # Handler para arquivo
    if log_file is None:
        log_file = Config.LOG_FILE

    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                str(log_file),
                maxBytes=10485760,  # 10MB
                backupCount=5,
                encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Não foi possível configurar arquivo de log: {e}")

    return logger


# Logger global
_global_logger: Optional[logging.Logger] = None


def get_logger(name: str = "OlhoDeus") -> logging.Logger:
    """
    Obtém um logger global ou cria um novo

    Args:
        name: Nome do logger

    Returns:
        Logger configurado
    """
    global _global_logger

    if _global_logger is None:
        _global_logger = setup_logger(
            name=name,
            level=Config.LOG_LEVEL,
            log_file=Config.LOG_FILE,
            console=True
        )

    return _global_logger


def set_log_level(level: str) -> None:
    """Define o nível de logging global"""
    logger = get_logger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    for handler in logger.handlers:
        handler.setLevel(getattr(logging, level.upper(), logging.INFO))


def log_exception(logger: logging.Logger, exc: Exception, context: str = "") -> None:
    """
    Loga uma exceção com contexto

    Args:
        logger: Logger a usar
        exc: Exceção
        context: Contexto adicional
    """
    if context:
        logger.error(f"{context}: {str(exc)}", exc_info=True)
    else:
        logger.error(f"Exceção: {str(exc)}", exc_info=True)
