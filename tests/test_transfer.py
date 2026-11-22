"""Offline regression tests: no browser, credentials, disk state, or bank requests.

Run with: python3 -B -m unittest discover -s tests -v
"""

import argparse
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
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
        self.stack.enter_context(patch.object(george.time, "monotonic", side_effect=lambda: self.clock))
        self.stack.enter_context(patch.object(george.sys.stdin, "isatty", return_value=True))
        self.api = self.stack.enter_context(patch.object(george, "_george_api", side_effect=self.request))

    def wait(self, milliseconds):
        self.clock += milliseconds / 1000

    def request(self, page, method, url, auth, body=None, *, timeout_ms=None):
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
        self.sign = (200, {})
        for state in ("DONE", "COMPLETED", "SIGNED", "signed"):
            with self.subTest(state=state):
                self.final = (200, {"signInfo": {"state": state}})
                self.run_transfer(0, "signed")

    def test_final_refusals_are_not_signed(self):
        self.sign = (200, {})
        for state in ("REJECTED", "CANCELLED", "EXPIRED", "FAILED"):
            with self.subTest(state=state):
                self.final = (200, {"signInfo": {"state": state}})
                self.run_transfer(3, "not_signed")

    def test_missing_waiting_and_unfamiliar_states_are_unknown(self):
        self.sign = (200, {})
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
        self.args.timeout = 3
        for state in ("PENDING", "NEW_STATE"):
            with self.subTest(state=state):
                responses = iter(((200, {"state": state}), (200, {"state": "DONE"})))

                def request(page, method, url, auth, body=None, **kwargs):
                    if url == "https://poll.example/sign":
                        self.polled = next(responses)
                    return self.request(page, method, url, auth, body, **kwargs)

                self.api.side_effect = request
                self.run_transfer(0, "signed")
                self.assertEqual(sum(url == "https://poll.example/sign" for _, url, _ in self.calls), 2)

    def test_order_can_catch_up_after_successful_poll(self):
        self.args.timeout = 5
        self.polled = (200, {"state": "DONE"})
        responses = iter(((200, {"signInfo": {"state": "OPEN"}}),
                          (200, {"signInfo": {"state": "SIGNED"}})))

        def request(page, method, url, auth, body=None, **kwargs):
            if url.endswith("/order-123"):
                self.final = next(responses)
            return self.request(page, method, url, auth, body, **kwargs)

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
        self.sign = (200, {})

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

    def test_empty_contact_selector_fails_before_login(self):
        self.args.to_iban = None
        for selector in ("", "   ", "\t\n", "\u2003"):
            with self.subTest(selector=selector):
                self.args.to_contact = selector
                self.run_transfer(1)
                george.login.assert_not_called()
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
        self.sign = (200, {})
        for response in ((503, {}), RuntimeError("browser lost"), KeyboardInterrupt()):
            with self.subTest(response=response):
                self.final = response
                self.run_transfer(4, "unknown")
        self.page.wait_for_timeout.side_effect = RuntimeError("browser lost")
        self.run_transfer(4, "unknown")

    def test_malformed_poll_interval_is_unknown(self):
        self.sign = (200, {"poll": {"url": "https://poll.example/sign", "interval": "invalid"}})
        self.run_transfer(4, "unknown")

    def test_poll_stall_uses_remaining_budget_and_returns_unknown(self):
        def request(page, method, url, auth, body=None, **kwargs):
            if url == "https://poll.example/sign":
                self.assertEqual(kwargs["timeout_ms"], 1000)
                self.clock += kwargs["timeout_ms"] / 1000
                self.polled = (0, "The operation was aborted")
            return self.request(page, method, url, auth, body, **kwargs)

        self.api.side_effect = request
        self.run_transfer(4, "unknown")
        self.assertEqual(self.clock, self.args.timeout)
        self.assertFalse(any(url.endswith("/order-123") for _, url, _ in self.calls))

    def test_poll_interval_cannot_exceed_approval_budget(self):
        self.sign[1]["poll"]["interval"] = 60000
        self.run_transfer(4, "unknown")
        self.assertEqual(self.clock, self.args.timeout)
        self.assertFalse(any(url == "https://poll.example/sign" for _, url, _ in self.calls))

    def test_sign_post_stall_uses_approval_budget_and_returns_unknown(self):
        def request(page, method, url, auth, body=None, **kwargs):
            if method == "POST" and "/sign/" in url:
                self.assertEqual(kwargs["timeout_ms"], 2000)
                self.clock += kwargs["timeout_ms"] / 1000
                self.sign = (0, "The operation was aborted")
            return self.request(page, method, url, auth, body, **kwargs)

        self.api.side_effect = request
        self.run_transfer(4, "unknown")
        self.assertEqual(self.clock, self.args.timeout)

    def test_final_read_stall_cannot_extend_approval_budget(self):
        self.polled = (200, {"state": "SIGNED"})

        def request(page, method, url, auth, body=None, **kwargs):
            if url.endswith("/order-123"):
                self.assertEqual(kwargs["timeout_ms"], 1000)
                self.clock += kwargs["timeout_ms"] / 1000
                self.final = (0, "The operation was aborted")
            return self.request(page, method, url, auth, body, **kwargs)

        self.api.side_effect = request
        self.run_transfer(0, "signed")
        self.assertEqual(self.clock, self.args.timeout)

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
        self.sign = (200, {})
        self.run_transfer(4, "unknown")
        self.final = (200, {"signInfo": {"state": "SIGNED"}})
        self.run_transfer(0, "signed")


class ContactTests(unittest.TestCase):
    def setUp(self):
        self.entries = [{"name": "Jane Doe", "label": "", "iban": "DE89370400440532013000"}]

    def test_empty_selector_cannot_match_optional_empty_label(self):
        for selector in (None, "", "   ", "\t\n", "\u2003"):
            with self.subTest(selector=selector):
                with self.assertRaisesRegex(ValueError, "Contact selector must contain"):
                    george._find_contact(self.entries, selector)

    def test_nonempty_name_alias_and_iban_still_match(self):
        self.entries[0]["label"] = "Friend"
        for selector in ("  Jane Doe  ", "jane", "FRIEND", "DE89 3704 0044 0532 0130 00"):
            with self.subTest(selector=selector):
                self.assertEqual(george._find_contact(self.entries, selector), self.entries[0])


class AddressbookPaginationTests(unittest.TestCase):
    def setUp(self):
        self.first = {"name": "Jane Doe", "iban": "DE89370400440532013000"}
        self.last = {"name": "Jane Smith", "iban": "AT611904300234573201"}

    def fetch(self, responses):
        output = io.StringIO()
        with patch.object(george, "_george_api", side_effect=responses) as api, redirect_stdout(output):
            entries = george._fetch_addressbook(MagicMock(), "test-token", "[contacts]")
        return entries, api.call_count, output.getvalue()

    def test_nonfinal_pages_without_new_ibans_do_not_truncate_book(self):
        for count_key in ("totalPages", "pageCount"):
            for middle in ([{"name": "No bank details"}], [self.first], []):
                with self.subTest(count_key=count_key, middle=middle):
                    responses = [(200, {"contacts": contacts, count_key: 3})
                                 for contacts in ([self.first], middle, [self.last])]
                    entries, calls, _ = self.fetch(responses)
                    self.assertEqual([e["name"] for e in entries], ["Jane Doe", "Jane Smith"])
                    self.assertEqual(calls, 3)
                    with self.assertRaisesRegex(ValueError, "matches several contacts"):
                        george._find_contact(entries, "Jane")

    def test_without_metadata_stop_on_raw_empty_page_not_filtered_empty_page(self):
        for middle in ([{"name": "No bank details"}],
                       [{**self.first, "alias": "Duplicate account"}]):
            with self.subTest(middle=middle):
                entries, calls, _ = self.fetch([(200, contacts) for contacts in
                                               ([self.first], middle, [self.last], [])])
                self.assertEqual([e["name"] for e in entries], ["Jane Doe", "Jane Smith"])
                self.assertEqual(calls, 4)

    def test_page_count_persists_when_later_page_omits_it(self):
        entries, calls, _ = self.fetch([
            (200, {"contacts": [self.first], "totalPages": 3}),
            (200, {"contacts": []}), (200, {"contacts": [self.last]})])
        self.assertEqual(len(entries), 2)
        self.assertEqual(calls, 3)

    def test_repeated_raw_pages_without_metadata_fail_closed(self):
        entries, calls, output = self.fetch([
            (200, {"contacts": [self.first], "page": 0}),
            (200, {"contacts": [self.first], "page": 1})])
        self.assertIsNone(entries)
        self.assertEqual(calls, 2)
        self.assertIn("completeness is unknown", output)

    def test_plain_url_fallback_respects_page_count(self):
        entries, calls, _ = self.fetch([
            (400, {}), (200, {"contacts": [self.first], "totalPages": 2}),
            (200, {"contacts": [self.last], "totalPages": 2})])
        self.assertEqual(len(entries), 2)
        self.assertEqual(calls, 3)

    def test_page_limit_does_not_return_partial_book(self):
        entries, calls, output = self.fetch([
            (200, {"contacts": [self.first], "totalPages": 101})] * 100)
        self.assertIsNone(entries)
        self.assertEqual(calls, 100)
        self.assertIn("completeness is unknown", output)


class GeorgeAPITimeoutTests(unittest.TestCase):
    def test_expired_budget_never_sends_request(self):
        for timeout_ms in (0, -1):
            with self.subTest(timeout_ms=timeout_ms):
                page = MagicMock()
                status, _ = george._george_api(page, "POST", "unused", "token", timeout_ms=timeout_ms)
                self.assertEqual(status, 0)
                page.evaluate.assert_not_called()

    def test_default_and_custom_request_timeouts_are_finite(self):
        for timeout_ms, expected in ((None, 30000), (100, 100), (60000, 30000)):
            with self.subTest(timeout_ms=timeout_ms):
                page = MagicMock()
                page.evaluate.return_value = {"status": 200, "body": {}}
                kwargs = {} if timeout_ms is None else {"timeout_ms": timeout_ms}
                george._george_api(page, "GET", "unused", "token", **kwargs)
                self.assertEqual(page.evaluate.call_args.args[1][-1], expected)

    @unittest.skipUnless(shutil.which("node"), "Node is needed to execute the request JavaScript")
    def test_javascript_cancels_stalled_fetch_and_body_and_cleans_up_timers(self):
        for scenario in ("success", "fetch_stall", "body_stall", "error"):
            with self.subTest(scenario=scenario):
                page = MagicMock()
                page.evaluate.return_value = {"status": 200, "body": {}}
                george._george_api(page, "POST", "https://bank.invalid/test", "test-token",
                                   {"amount": 1234}, timeout_ms=25)
                source, args = page.evaluate.call_args.args
                completed = subprocess.run(
                    [shutil.which("node"), str(Path(__file__).with_name("check_api_timeout.js"))],
                    input=json.dumps({"source": source, "args": args, "scenario": scenario}),
                    text=True, capture_output=True, timeout=5)
                self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
