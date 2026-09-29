# -*- coding: utf-8 -*-
"""Testes de pipelines/: apenas o dispatch (sem rede)."""

import unittest

from pipelines import run_pipeline


class TestRunPipelineDispatch(unittest.TestCase):
    def test_pipeline_desconhecida_levanta_erro(self):
        with self.assertRaises(ValueError):
            run_pipeline('example.com', pipeline='99')


if __name__ == '__main__':
    unittest.main()
