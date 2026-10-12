"""Plan safety checks; no Office execution or artifact creation."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("plan_cells", Path(__file__).with_name("plan-cells.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def settings():
    return {"processId": 123, "processStartToken": "123456:789", "windowId": 456,
            "windowTitle": "Owned workbook", "caseId": "owned-case",
            "startRow": 3, "startColumn": "C", "rows": [["Region", "Revenue"], ["North", "1200"]]}


class PlanTests(unittest.TestCase):
    def test_exact_owned_cells_and_navigation_receipts(self):
        plan = module.build(settings())
        writes = [step for step in plan["steps"] if step["id"].startswith("text-")]
        self.assertEqual([step["effect"]["businessKey"]["cell"]["string"] for step in writes], ["C3", "C4", "D3", "D4"])
        for step in writes:
            self.assertEqual(step["precondition"]["inputs"]["expected"]["string"], "")
            self.assertEqual(step["postcondition"], step["effect"]["reconcile"])
        self.assertEqual(plan["steps"][-1]["postcondition"]["inputs"]["expected"]["string"], "D5")
        self.assertEqual(module.build(settings()), plan)

    def test_bounds_include_final_return_position(self):
        parameters = settings()
        parameters.update(startRow=1048575, startColumn="Z", rows=[["17"]])
        plan = module.build(parameters)
        self.assertEqual(plan["steps"][-1]["postcondition"]["inputs"]["expected"]["string"], "Z1048576")
        parameters["startRow"] = 1048576
        with self.assertRaises(ValueError):
            module.build(parameters)

    def test_rejects_coercion_malformed_identity_and_unbounded_input(self):
        invalid = [("processId", True), ("processId", "123"), ("processId", 2147483648),
                   ("windowId", 0), ("windowId", 4294967296), ("startRow", 3.5),
                   ("processStartToken", "stale"), ("caseId", "case\nnew"),
                   ("windowTitle", "\u2028"), ("startColumn", "AA"),
                   ("rows", [["a"], ["b", "c"]]), ("rows", [["a"]] * 101),
                   ("rows", [["a\tb"]]), ("rows", [["a\u2028b"]]),
                   ("rows", [["é" * 2049]]), ("rows", [[17]]), ("rows", [[]])]
        for field, value in invalid:
            with self.subTest(field=field, value=repr(value)[:50]):
                parameters = copy.deepcopy(settings())
                parameters[field] = value
                with self.assertRaises(ValueError):
                    module.build(parameters)
        parameters = settings()
        parameters["grantId"] = "not-a-plan-parameter"
        with self.assertRaises(ValueError):
            module.build(parameters)


if __name__ == "__main__":
    unittest.main()
