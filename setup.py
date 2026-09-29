# -*- coding: utf-8 -*-
"""Setup do Mão de Deus UNIFIED (arquitetura modular: core/, modules/, pipelines/, reports/)."""

from setuptools import setup, find_packages

setup(
    name="mao-de-deus-unified",
    version="1.0-unified",
    description="OSINT + Pentest modular — fusão de funções OSSINT e AI-Powered Pentest",
    packages=find_packages(include=[
        "core", "core.*",
        "modules", "modules.*",
        "pipelines", "pipelines.*",
        "reports", "reports.*",
    ]),
    py_modules=["cli"],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31,<3",
        "dnspython>=2.4,<3",
    ],
    entry_points={
        "console_scripts": [
            "olhodedeus=cli:main",
        ],
    },
)
