import importlib.util
from pathlib import Path
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / 'ext' / 'tools'
spec = importlib.util.spec_from_file_location('make_patch', TOOLS / 'make_patch.py')
make_patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(make_patch)


class MakePatchTests(unittest.TestCase):
    def apply_patch(self, original, updated, allow_delete=False):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'src'
            fixed = Path(directory) / 'fixed'
            source.mkdir()
            fixed.mkdir()
            for root, files in [(source, original), (fixed, updated)]:
                for name, content in files.items():
                    (root / name).write_text(content)
            patch, changes = make_patch.build_patch(str(source), str(fixed), allow_delete)
            self.assertTrue(changes)
            checked, message = make_patch.self_check(str(source), patch)
            self.assertTrue(checked, message)
            applied, strip, message = make_patch.apply_to(str(source), patch)
            self.assertTrue(applied, message)
            self.assertEqual(strip, 1)
            self.assertEqual({f.name: f.read_text() for f in source.iterdir()}, updated)

    def test_add_empty_file_is_valid_and_creates_file(self):
        self.apply_patch({'keep.txt': 'keep\n'}, {'keep.txt': 'keep\n', 'empty.txt': ''})

    def test_delete_empty_file_is_valid_and_removes_file(self):
        self.apply_patch({'empty.txt': '', 'keep.txt': 'keep\n'}, {'keep.txt': 'keep\n'}, True)

    def test_truncate_existing_file_is_not_a_deletion(self):
        self.apply_patch({'empty.txt': 'old\n'}, {'empty.txt': ''})

    def test_nonempty_new_file_without_final_newline(self):
        self.apply_patch({}, {'value.txt': 'value'})


if __name__ == '__main__':
    unittest.main()
