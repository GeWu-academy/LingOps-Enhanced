import importlib.util
from pathlib import Path
import unittest

TOOLS = Path(__file__).resolve().parents[1] / 'ext' / 'tools'
spec = importlib.util.spec_from_file_location('extract_files', TOOLS / 'extract_files.py')
extract_files = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract_files)


class ExtractFilesTests(unittest.TestCase):
    def test_file_marker_with_outer_fence_yields_executable_source(self):
        reply = '=== FILE: app.py ===\n```python\nprint("ready")\n```\n=== END FILE ==='
        files = extract_files.parse(reply)
        self.assertEqual(files, [('app.py', 'print("ready")\n')])
        compile(files[0][1], files[0][0], 'exec')

    def test_multiple_fenced_files_are_kept_separate(self):
        reply = ('### FILE: first.py\n```python\nvalue = 7\n```\n'
                 '### FILE: second.py\n```python\nvalue = 9\n```\n')
        self.assertEqual(extract_files.parse(reply),
                         [('first.py', 'value = 7\n'), ('second.py', 'value = 9\n')])

    def test_unwrapped_markdown_keeps_its_own_code_fences(self):
        reply = '=== FILE: README.md ===\n# Example\n```python\nprint(1)\n```\n=== END FILE ==='
        self.assertEqual(extract_files.parse(reply),
                         [('README.md', '# Example\n```python\nprint(1)\n```\n')])

    def test_long_outer_fence_preserves_shorter_inner_markdown_fence(self):
        reply = '=== FILE: README.md ===\n````markdown\n# Example\n```python\nprint(1)\n```\n````\n=== END FILE ==='
        self.assertEqual(extract_files.parse(reply),
                         [('README.md', '# Example\n```python\nprint(1)\n```\n')])

    def test_path_annotated_fence_still_works(self):
        self.assertEqual(extract_files.parse('```python:src/app.py\nvalue = 3\n```'),
                         [('app.py', 'value = 3\n')])

    def test_markdown_leading_code_blocks_are_content(self):
        for path in ['README.md', 'NOTES.MD', 'guide.markdown', 'page.mdx']:
            for opener in ['```python', '```', '````python']:
                for tail in ['', '\nInstallation instructions']:
                    with self.subTest(path=path, opener=opener, tail=tail):
                        fence = opener.split('python')[0]
                        body = opener + '\nprint(1)\n' + fence + tail
                        reply = f'=== FILE: {path} ===\n{body}\n=== END FILE ==='
                        self.assertEqual(extract_files.parse(reply), [(path, body + '\n')])

    def test_explicit_markdown_wrappers_are_unwrapped(self):
        for language in ['markdown', 'md', 'mdx']:
            with self.subTest(language=language):
                reply = f'=== FILE: README.md ===\n```{language}\n# Title\n```\n=== END FILE ==='
                self.assertEqual(extract_files.parse(reply), [('README.md', '# Title\n')])

    def test_unfenced_file_marker_still_works(self):
        self.assertEqual(extract_files.parse('=== FILE: a.py ===\nvalue = 1\n=== END FILE ==='),
                         [('a.py', 'value = 1\n')])


if __name__ == '__main__':
    unittest.main()
