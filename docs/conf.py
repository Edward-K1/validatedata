import os
import sys

sys.path.insert(0, os.path.abspath('..'))

project = 'validatedata'
copyright = '2021, Edward Kigozi'
author = 'Edward Kigozi'
release = '0.4.0'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx_copybutton',
]

templates_path = ['_templates']
exclude_patterns = ['_build']

html_theme = 'furo'
html_static_path = ['_static']

html_theme_options = {
    'sidebar_hide_name': False,
    'navigation_with_keys': True,
}

# copybutton — strip >>> prompts and shell $ signs
copybutton_prompt_text = r'>>> |\$ '
copybutton_prompt_is_regexp = True
