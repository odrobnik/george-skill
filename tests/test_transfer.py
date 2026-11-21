"""Offline regression tests: no browser, credentials, disk state, or bank requests.

Run with: python3 -B -m unittest discover -s tests -v
"""

import argparse
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch


spec = importlib.util.spec_from_file_location(
    "george", Path(__file__).resolve().parents[1] / "scripts" / "george.py")
george = importlib.util.module_from_spec(spec)
# Use the script's help import path so these tests do not require Playwright.
previous_umask = os.umask(0o077)
try:
    with patch.object(sys, "argv", ["george.py", "--help"]):
        spec.loader.exec_module(george)
finally:
    os.umask(previous_umask)


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.args = argparse.Namespace(
            from_account="sender", to_iban="DE89370400440532013000", to_name="Jane Doe",
            to_contact=None, amount="12.34", text="Invoice", date=None, instant=False,
            sign=True, yes=True, timeout=2, visible=False, ignore_payee_check=False)
        self.context = MagicMock()
        self.page = self.context.new_page.return_value
        self.clock = 0
        self.page.wait_for_timeout.side_effect = self.wait
        self.sender = {"id": "sender", "name": "Sender", "iban": "AT611904300234573201"}
        self.order = {
            "id": "order-123", "state": "OPEN", "signInfo": {"signId": "sign-123", "state": "OPEN"},
            "amount": {"value": 1234, "precision": 2, "currency": "EUR"}}
        self.created = (201, self.order)
        self.sign = (200, {"poll": {"url": "https://poll.example/sign", "interval": 1000}})
        self.polled = (200, {"state": "PENDING"})
        self.final = (200, {"signInfo": {"state": "OPEN"}})
        self.calls = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        playwright = self.stack.enter_context(patch.object(george, "sync_playwright"))
        playwright.return_value.__enter__.return_value.chromium.launch_persistent_context.return_value = self.context
        for name, value in (
            ("_resolve_user_id", "test-user"), ("_get_profile_dir", Path("unused-profile")),
            ("login", True), ("dismiss_modals", None), ("capture_bearer_auth_header", "test-token"),
            ("fetch_my_accounts", []), ("normalize_accounts_from_api", [self.sender]),
        ):
            self.stack.enter_context(patch.object(george, name, return_value=value))
        self.stack.enter_context(patch.object(george, "USER_ID_OVERRIDE", None))
        self.stack.enter_context(patch.object(george.time, "time", side_effect=lambda: self.clock))
        self.stack.enter_context(patch.object(george.sys.stdin, "isatty", return_value=True))
        self.api = self.stack.enter_context(patch.object(george, "_george_api", side_effect=self.request))

    def wait(self, milliseconds):
        self.clock += milliseconds / 1000

    def request(self, page, method, url, auth, body=None):
        self.calls.append((method, url, deepcopy(body)))
        self.assertIs(page, self.page)
        self.assertEqual(auth, "test-token")
        if url == george.PAYEE_VERIFICATION_URL:
            return 200, {"verifications": [{"result": "MATCH"}]}
        if url.endswith("/bookingdate"):
            return 200, {"bookingDate": george.date.today().isoformat()}
        if method == "POST" and url.endswith(("/sepa", "/domestic")):
            result = self.created
        elif "/sign/" in url:
            result = self.sign if method == "POST" else (200, {})
        elif url == "https://poll.example/sign":
            result = self.polled
        elif url.endswith("/order-123"):
            result = self.final
        else:
            self.fail(f"Unexpected request: {method} {url}")
        if isinstance(result, BaseException):
            raise result
        return deepcopy(result)

    def run_transfer(self, code, result=None, order_id="order-123"):
        self.clock = 0
        self.calls.clear()
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(george.cmd_transfer(self.args), code)
        text = output.getvalue()
        if result:
            self.assertEqual(text.splitlines()[-1],
                             f"[transfer] RESULT: {result} order_id={order_id} exit={code}")
        if result in ("unknown", "not_signed"):
            self.assertIn("Do not rerun", text)
        self.assertNotIn("test-token", text)
        return text

    def assert_no_order(self):
        self.assertFalse(any(method == "POST" and url.endswith(("/sepa", "/domestic"))
                             for method, url, _ in self.calls))

    def test_only_explicit_final_success_is_signed(self):
        for state in ("DONE", "COMPLETED", "SIGNED", "signed"):
            with self.subTest(state=state):
                self.final = (200, {"signInfo": {"state": state}})
                self.run_transfer(0, "signed")

    def test_final_refusals_are_not_signed(self):
        for state in ("REJECTED", "CANCELLED", "EXPIRED", "FAILED"):
            with self.subTest(state=state):
                self.final = (200, {"signInfo": {"state": state}})
                self.run_transfer(3, "not_signed")

    def test_missing_waiting_and_unfamiliar_states_are_unknown(self):
        for info in (None, {}, "bad-layout", {"state": None}, {"state": "OPEN"},
                     {"state": "PENDING"}, {"state": "PROCESSING"}, {"state": "NEW_STATE"},
                     {"state": ["SIGNED"]}):
            with self.subTest(sign_info=info):
                self.final = (200, {"signInfo": info})
                self.run_transfer(4, "unknown")

    def test_poll_success_survives_stale_or_unavailable_order(self):
        for state in ("DONE", "COMPLETED", "SIGNED"):
            for final in ((200, {"signInfo": {"state": "OPEN"}}), (200, {}),
                          (503, {}), RuntimeError("browser lost")):
                with self.subTest(state=state, final=final):
                    self.polled = (200, {"status": state})
                    self.final = final
                    self.run_transfer(0, "signed")

    def test_poll_refusals_are_not_signed(self):
        for state in ("REJECTED", "CANCELLED", "EXPIRED", "FAILED"):
            with self.subTest(state=state):
                self.polled = (200, {"state": state})
                self.run_transfer(3, "not_signed")

    def test_failed_poll_http_response_is_not_success(self):
        self.polled = (500, {"state": "SIGNED"})
        self.run_transfer(4, "unknown")

    def test_nested_poll_state_is_read(self):
        self.polled = (200, {"signInfo": {"state": "DONE"}})
        self.run_transfer(0, "signed")

    def test_poll_continues_after_waiting_or_unfamiliar_state(self):
        for state in ("PENDING", "NEW_STATE"):
            with self.subTest(state=state):
                responses = iter(((200, {"state": state}), (200, {"state": "DONE"})))

                def request(page, method, url, auth, body=None):
                    if url == "https://poll.example/sign":
                        self.polled = next(responses)
                    return self.request(page, method, url, auth, body)

                self.api.side_effect = request
                self.run_transfer(0, "signed")
                self.assertEqual(sum(url == "https://poll.example/sign" for _, url, _ in self.calls), 2)

    def test_order_can_catch_up_after_successful_poll(self):
        self.polled = (200, {"state": "DONE"})
        responses = iter(((200, {"signInfo": {"state": "OPEN"}}),
                          (200, {"signInfo": {"state": "SIGNED"}})))

        def request(page, method, url, auth, body=None):
            if url.endswith("/order-123"):
                self.final = next(responses)
            return self.request(page, method, url, auth, body)

        self.api.side_effect = request
        self.run_transfer(0, "signed")
        self.assertEqual(sum(url.endswith("/order-123") for _, url, _ in self.calls), 2)

    def test_sign_post_terminal_state_is_preserved(self):
        for state, code, result in (("SIGNED", 0, "signed"), ("REJECTED", 3, "not_signed")):
            with self.subTest(state=state):
                self.sign = (200, {"signInfo": {"state": state}})
                self.run_transfer(code, result)

    def test_conflicting_terminal_states_are_unknown(self):
        self.polled = (200, {"state": "DONE"})
        self.final = (200, {"signInfo": {"state": "REJECTED"}})
        self.run_transfer(4, "unknown")

    def test_declining_confirmation_never_creates_order(self):
        self.args.yes = False
        with patch("builtins.input", return_value="n"):
            self.run_transfer(1)
        self.assert_no_order()

    def test_confirmation_precedes_creation(self):
        self.args.yes = False

        def confirm(prompt):
            self.assert_no_order()
            return "y"

        self.final = (200, {"signInfo": {"state": "SIGNED"}})
        with patch("builtins.input", side_effect=confirm):
            self.run_transfer(0, "signed")

    def test_invalid_timeouts_fail_before_login(self):
        for timeout in (0, -1):
            with self.subTest(timeout=timeout):
                self.args.timeout = timeout
                self.run_transfer(1)
                self.api.assert_not_called()
                george.login.assert_not_called()

    def test_no_terminal_requires_yes_before_login(self):
        self.args.yes = False
        with patch.object(george.sys.stdin, "isatty", return_value=False):
            self.run_transfer(1)
        self.api.assert_not_called()

    def test_unsigned_creation_does_not_start_signature(self):
        self.args.sign = False
        self.run_transfer(0, "created")
        self.assertFalse(any("/sign/" in url for _, url, _ in self.calls))

    def test_no_sign_id_leaves_existing_unsigned_order(self):
        for info in (None, {}, "bad-layout"):
            with self.subTest(sign_info=info):
                self.order["signInfo"] = info
                self.run_transfer(3, "not_signed")
                self.assertFalse(any("/sign/" in url for _, url, _ in self.calls))

    def test_signature_request_errors_do_not_exit_one(self):
        for response in ((0, None), (408, {}), (500, {}), (200, None),
                         RuntimeError("browser lost"), KeyboardInterrupt()):
            with self.subTest(response=response):
                self.sign = response
                self.run_transfer(4, "unknown")

    def test_explicit_sign_http_rejection_leaves_unsigned_order(self):
        self.sign = (403, {})
        self.run_transfer(3, "not_signed")

    def test_read_and_wait_failures_after_sign_are_unknown(self):
        for response in ((503, {}), RuntimeError("browser lost"), KeyboardInterrupt()):
            with self.subTest(response=response):
                self.final = response
                self.run_transfer(4, "unknown")
        self.page.wait_for_timeout.side_effect = RuntimeError("browser lost")
        self.run_transfer(4, "unknown")

    def test_malformed_poll_interval_is_unknown(self):
        self.sign = (200, {"poll": {"url": "https://poll.example/sign", "interval": "invalid"}})
        self.run_transfer(4, "unknown")

    def test_error_before_signature_preserves_created_order(self):
        with patch.object(george, "_print_transfer_summary", side_effect=ValueError("bad-layout")):
            self.run_transfer(3, "not_signed")

    def test_ambiguous_creation_is_never_retryable(self):
        for response in ((0, None), (408, {}), (503, {}), (201, {}),
                         RuntimeError("browser lost"), KeyboardInterrupt()):
            with self.subTest(response=response):
                self.created = response
                self.run_transfer(4, "unknown", order_id="unknown")

    def test_creation_rejection_is_failure_before_order(self):
        self.created = (422, {})
        self.run_transfer(1)

    def test_cleanup_failure_preserves_result(self):
        self.context.close.side_effect = RuntimeError("browser lost")
        self.run_transfer(4, "unknown")
        self.final = (200, {"signInfo": {"state": "SIGNED"}})
        self.run_transfer(0, "signed")


if __name__ == "__main__":
    unittest.main()
