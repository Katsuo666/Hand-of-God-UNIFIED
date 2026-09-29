# -*- coding: utf-8 -*-
"""Geração de relatórios: multi-formato (report.py) e dashboard NEXUS (nexus_reporter.py)."""

from .report import ReportGenerator
from .nexus_reporter import NexusReporter

__all__ = ['ReportGenerator', 'NexusReporter']

__version__ = '1.0.0'
