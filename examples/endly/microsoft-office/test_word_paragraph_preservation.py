"""Synthetic verifier fixtures only; these are not Office GUI qualification."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("verifier", Path(__file__).with_name("verify-word-paragraph-edit.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def parts(body):
    return {
        "word/document.xml": f'<w:document xmlns:w="{W}"><w:body><w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Heading</w:t></w:r></w:p><w:p><w:r><w:t>{body}</w:t></w:r></w:p><w:sectPr><w:pgSz w:w="12240" w:h="15840"/></w:sectPr></w:body></w:document>'.encode(),
        "word/styles.xml": f'<w:styles xmlns:w="{W}"/>'.encode(),
        "word/settings.xml": f'<w:settings xmlns:w="{W}"><w:zoom w:percent="100"/><w:rsids><w:rsid w:val="1"/></w:rsids></w:settings>'.encode(),
        "word/media/image1.png": b"synthetic-image-bytes",
        "word/_rels/document.xml.rels": b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>',
    }


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.original = Path(self.temp.name) / "original.docx"
        self.edited = Path(self.temp.name) / "edited.docx"
        self.write(self.original, parts("Original"))

    def write(self, path, values):
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in values.items():
                archive.writestr(name, value)

    def test_edit_and_volatile_revision_preserve_protected_parts(self):
        edited = parts("Replacement")
        edited["word/settings.xml"] = edited["word/settings.xml"].replace(b'w:val="1"', b'w:val="2"')
        self.write(self.edited, edited)
        result = verifier.verify(self.original, self.edited, 2, "Replacement")
        self.assertTrue(result["documentStructureAndSectionSettingsPreserved"])
        self.assertTrue(result["protectedPackagePartsPreserved"])

    def test_protected_settings_parts_and_neighbors_cannot_change(self):
        for mutation in [
            lambda p: p.update({"word/document.xml": p["word/document.xml"].replace(b'12240', b'11900')}),
            lambda p: p.update({"word/document.xml": p["word/document.xml"].replace(b'Heading1', b'Normal')}),
            lambda p: p.update({"word/styles.xml": p["word/styles.xml"].replace(b'/>', b'><w:style/></w:styles>')}),
            lambda p: p.update({"word/settings.xml": p["word/settings.xml"].replace(b'100', b'80')}),
            lambda p: p.update({"word/media/image1.png": b"changed-image"}),
            lambda p: p.pop("word/_rels/document.xml.rels"),
            lambda p: p.update({"word/added-part.xml": b"new-part"}),
        ]:
            edited = parts("Replacement")
            mutation(edited)
            self.write(self.edited, edited)
            with self.assertRaises(ValueError):
                verifier.verify(self.original, self.edited, 2, "Replacement")

    def test_duplicate_noncanonical_and_entity_parts_refused(self):
        for bad_name in ["WORD/DOCUMENT.XML", "../private.xml", "word/../private.xml"]:
            edited = parts("Replacement")
            edited[bad_name] = b"invalid"
            self.write(self.edited, edited)
            with self.assertRaises(ValueError):
                verifier.verify(self.original, self.edited, 2, "Replacement")
        edited = parts("Replacement")
        edited["word/document.xml"] = b'<!DOCTYPE test [<!ENTITY x "value">]>' + edited["word/document.xml"]
        self.write(self.edited, edited)
        with self.assertRaises(ValueError):
            verifier.verify(self.original, self.edited, 2, "Replacement")


if __name__ == "__main__":
    unittest.main()
