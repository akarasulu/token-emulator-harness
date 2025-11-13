"""Textual TUI for the token emulator harness."""
from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, ContentSwitcher, DataTable, Footer, Header, Input, ProgressBar, Static, Tab, Tabs

DEFAULT_BASE_URL = os.environ.get("HARNESS_BASE_URL", "http://127.0.0.1:8080")
_SERVER_STARTED = False


def ensure_server_running() -> None:
    """Launch the harness HTTP server in a background thread if needed."""
    global _SERVER_STARTED
    try:
        httpx.get(f"{DEFAULT_BASE_URL}/openapi.yaml", timeout=0.5)
        return
    except Exception:
        pass

    if _SERVER_STARTED:
        return

    def _run() -> None:
        from control_api.main import app as harness_app

        harness_app.serve(host="127.0.0.1", port=8080)

    _SERVER_STARTED = True
    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    time.sleep(1)


data_table_style = {
    "cursor_type": "row",
}


class HarnessClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(base_url=self.base_url, timeout=10)

    def issue_seed(self, token_type: str = "totp") -> Dict[str, Any]:
        return self._client.post("/otp/seed", json={"type": token_type}).json()

    def otp_code(self, seed_id: str) -> Dict[str, Any]:
        return self._client.get(f"/otp/code/{seed_id}").json()

    def list_keys(self) -> List[Dict[str, Any]]:
        return self._client.get("/pkcs11/keys").json()

    def create_key(self, label: str) -> Dict[str, Any]:
        return self._client.post("/pkcs11/keys", json={"label": label}).json()

    def smartcard_status(self) -> Dict[str, Any]:
        return self._client.get("/smartcard/status").json()

    def smartcard_refresh(self) -> Dict[str, Any]:
        return self._client.post("/smartcard/refresh").json()

    def smartcard_insert(self) -> Dict[str, Any]:
        return self._client.post("/smartcard/insert").json()

    def smartcard_remove(self) -> Dict[str, Any]:
        return self._client.post("/smartcard/remove").json()

    def mobile_pair(self, device_id: str) -> Dict[str, Any]:
        return self._client.post("/mobile/pair", json={"device_id": device_id}).json()

    def mobile_assert(self, device_id: str, challenge: str) -> Dict[str, Any]:
        payload = {"device_id": device_id, "challenge": challenge}
        return self._client.post("/mobile/assert", json=payload).json()

    def register_fido(self, user_id: str, rp_id: str) -> Dict[str, Any]:
        return self._client.post("/fido2/register", json={"user_id": user_id, "rp_id": rp_id}).json()

    def authenticate_fido(self, credential_id: str, challenge: str) -> Dict[str, Any]:
        payload = {"credential_id": credential_id, "challenge": challenge}
        return self._client.post("/fido2/authenticate", json=payload).json()

    def hsm_sign(self, payload: str) -> Dict[str, Any]:
        return self._client.post("/network_hsm/sign", json={"payload": payload}).json()

    def pgp_list(self) -> List[Dict[str, Any]]:
        return self._client.get("/pgp/keys").json()

    def pgp_generate(self, name: Optional[str], email: Optional[str]) -> Dict[str, Any]:
        payload = {"name": name, "email": email}
        return self._client.post("/pgp/keys", json=payload).json()

    def pgp_sign(self, fingerprint: str, message: str) -> Dict[str, Any]:
        payload = {"fingerprint": fingerprint, "message": message}
        return self._client.post("/pgp/sign", json=payload).json()

    def pgp_encrypt(self, fingerprint: str, message: str) -> Dict[str, Any]:
        payload = {"fingerprint": fingerprint, "message": message}
        return self._client.post("/pgp/encrypt", json=payload).json()

    def pgp_decrypt(self, fingerprint: str, ciphertext: str) -> Dict[str, Any]:
        payload = {"fingerprint": fingerprint, "ciphertext": ciphertext}
        return self._client.post("/pgp/decrypt", json=payload).json()


class ModuleView(Static):
    client: HarnessClient

    def on_mount(self) -> None:  # type: ignore[override]
        self.client = self.app.client  # type: ignore[attr-defined]

    async def call_api(self, func, *args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    def notify(self, message: str) -> None:
        self.app.notify(message)  # type: ignore[attr-defined]


class OTPView(ModuleView):
    def compose(self) -> ComposeResult:  # type: ignore[override]
        controls = Horizontal(
            Button("Issue Seed", id="issue"),
            Button("Get Code", id="code"),
            classes="controls",
        )
        self.table = DataTable(id="otp-table")
        self.table.zebra_stripes = True
        self.table.show_header = True
        (
            self.col_seed,
            self.col_type,
            self.col_secret,
            self.col_code,
            self.col_expire,
        ) = self.table.add_columns("Seed ID", "Type", "Secret", "Code", "Expires")
        # widen code column so 6 digits are visible
        try:
            column = self.table.columns[self.col_code]
            column.width = 10
            column.auto_width = False
        except Exception:
            pass
        yield controls
        yield self.table
        self.progress = ProgressBar(total=30, show_eta=False)
        self.detail = Static("Issue or select a seed to view details.", id="otp-detail")
        yield self.progress
        yield self.detail
        self.seed_rows: Dict[DataTable.RowKey, str] = {}
        self.seed_row_map: Dict[str, DataTable.RowKey] = {}
        self.seed_meta: Dict[str, Dict[str, Any]] = {}
        self.latest_codes: Dict[str, str] = {}
        self._period = 30
        self._updating = False
        self.active_seed_id: Optional[str] = None
        self.set_interval(1, self._tick)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "issue":
            seed = await self.call_api(self.client.issue_seed)
            row_key = self.table.add_row(
                seed["seed_id"], seed.get("token_type", "totp"), seed.get("secret", ""), "—", "30s"
            )
            self.seed_rows[row_key] = seed["seed_id"]
            self.seed_row_map[seed["seed_id"]] = row_key
            self.seed_meta[seed["seed_id"]] = {
                "secret": seed.get("secret", ""),
                "issued_at": seed.get("issued_at"),
            }
            self.active_seed_id = seed["seed_id"]
            self.notify("Issued new OTP seed")
            self._update_detail_text()
        elif event.button.id == "code":
            if not self.table.row_count:
                self.notify("No seeds available")
                return
            row = self.table.cursor_row or 0
            seed_id = self.table.get_row_at(row)[0]
            code = await self.call_api(self.client.otp_code, seed_id)
            row_key = self.seed_row_map.get(seed_id)
            if row_key:
                self.table.update_cell(row_key, self.col_code, code["code"])
            self.latest_codes[seed_id] = code["code"]
            self.notify(f"Code for {seed_id}: {code['code']}")
            self._update_detail_text()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        seed_id = self.seed_rows.get(event.row_key)
        if seed_id:
            self.active_seed_id = seed_id
            self._update_detail_text()

    def _tick(self) -> None:
        if not self.seed_rows:
            return
        remaining = self._period - (int(time.time()) % self._period)
        for row_key in self.seed_rows:
            self.table.update_cell(row_key, self.col_expire, f"{remaining:02d}s")
        self._update_detail_text(remaining)
        if not self._updating:
            asyncio.create_task(self._refresh_codes())

    async def _refresh_codes(self) -> None:
        self._updating = True
        try:
            for row_key, seed_id in self.seed_rows.items():
                code = await self.call_api(self.client.otp_code, seed_id)
                self.table.update_cell(row_key, self.col_code, code["code"])
                self.latest_codes[seed_id] = code["code"]
        finally:
            self._updating = False
            self._update_detail_text()

    def _update_detail_text(self, remaining: Optional[int] = None) -> None:
        if not self.active_seed_id:
            self.detail.update("Issue or select a seed to view details.")
            self.progress.update(total=self._period, progress=0)
            return
        seed_id = self.active_seed_id
        meta = self.seed_meta.get(seed_id, {})
        secret = meta.get("secret", "")
        code = self.latest_codes.get(seed_id, "—")
        if remaining is None:
            remaining = self._period - (int(time.time()) % self._period)
        remaining = max(0, min(self._period, remaining))
        self.progress.update(total=self._period, progress=self._period - remaining)
        self.detail.update(
            f"Seed: {seed_id}\n"
            f"Secret: {secret}\n"
            f"Code: {code}\n"
            f"Expires in: {remaining:02d}s"
        )


class PKCS11View(ModuleView):
    def compose(self) -> ComposeResult:  # type: ignore[override]
        controls = Horizontal(
            Button("Refresh", id="refresh"),
            Button("Generate", id="generate"),
        )
        self.table = DataTable(id="pkcs11-table")
        self.table.zebra_stripes = True
        self.table.show_header = True
        (
            self.col_key,
            self.col_label,
            self.col_created,
        ) = self.table.add_columns("Key ID", "Label", "Created")
        self.row_map: Dict[str, DataTable.RowKey] = {}
        yield controls
        yield self.table

    async def on_mount(self) -> None:  # type: ignore[override]
        super().on_mount()
        await self.refresh_keys()

    async def refresh_keys(self) -> None:
        keys = await self.call_api(self.client.list_keys)
        self.table.clear()
        self.row_map.clear()
        for key in keys:
            self._upsert_row(key)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh":
            await self.refresh_keys()
        elif event.button.id == "generate":
            label = f"key-{uuid.uuid4().hex[:6]}"
            key = await self.call_api(self.client.create_key, label)
            self._upsert_row(key)
            self.notify(f"Created key {label}")

    def _upsert_row(self, key: Dict[str, Any]) -> None:
        key_id = key["key_id"]
        label = key["label"]
        created = str(key["created_at"])
        row_key = self.row_map.get(key_id)
        if row_key:
            self.table.update_cell(row_key, self.col_label, label)
            self.table.update_cell(row_key, self.col_created, created)
        else:
            row_key = self.table.add_row(key_id, label, created)
            self.row_map[key_id] = row_key
            if self.table.cursor_row is None:
                self.table.cursor_type = "row"
                self.table.cursor_coordinate = (row_key, self.col_key)


class FidoView(ModuleView):
    def compose(self) -> ComposeResult:  # type: ignore[override]
        controls = Horizontal(
            Button("Register Sample", id="register"),
            Button("Authenticate", id="authenticate"),
        )
        self.info = Static("No credential registered", id="fido-info")
        yield controls
        yield self.info
        self.credential_id: Optional[str] = None

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "register":
            user_id = f"user-{uuid.uuid4().hex[:4]}"
            cred = await self.call_api(self.client.register_fido, user_id, "example.com")
            self.credential_id = cred["credential_id"]
            self.info.update(f"Registered credential: {self.credential_id}")
            self.notify("FIDO2 credential registered")
        elif event.button.id == "authenticate":
            if not self.credential_id:
                self.notify("Register a credential first")
                return
            result = await self.call_api(self.client.authenticate_fido, self.credential_id, "demo-challenge")
            self.notify(f"Assertion counter: {result['sign_count']}")


class SmartCardView(ModuleView):
    def compose(self) -> ComposeResult:  # type: ignore[override]
        self.insert_button = Button("Insert", id="insert")
        self.remove_button = Button("Remove", id="remove")
        self.refresh_button = Button("Refresh Cert", id="refresh")
        controls = Horizontal(
            self.insert_button,
            self.remove_button,
            self.refresh_button,
        )
        self.status = Static("Status unknown", id="smartcard-status")
        self.detail = Static("No certificate loaded.", id="smartcard-detail")
        panel = Vertical(self.status, self.detail, id="smartcard-panel")
        yield controls
        yield panel

    async def on_mount(self) -> None:  # type: ignore[override]
        super().on_mount()
        await self.refresh_status()

    async def refresh_status(self) -> None:
        status = await self.call_api(self.client.smartcard_status)
        state = "inserted" if status.get("inserted") else "removed"
        self.status.update(f"Smart-card is {state}")
        self.insert_button.disabled = state == "inserted"
        self.refresh_button.disabled = state != "inserted"
        self.remove_button.disabled = state != "inserted"
        certificate = status.get("certificate")
        if certificate:
            preview = certificate[:80] + "…" if len(certificate) > 80 else certificate
            self.detail.update(f"Certificate:\n{preview}")
        else:
            self.detail.update("No certificate present.")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "insert":
            await self.call_api(self.client.smartcard_insert)
            await self.refresh_status()
        elif event.button.id == "remove":
            await self.call_api(self.client.smartcard_remove)
            await self.refresh_status()
        elif event.button.id == "refresh":
            await self.call_api(self.client.smartcard_refresh)
            await self.refresh_status()


class MobileView(ModuleView):
    def compose(self) -> ComposeResult:  # type: ignore[override]
        self.device_input = Input(value="mobile1", placeholder="Device identifier (e.g., mobile1)")
        self.challenge_input = Input(
            value="hello",
            placeholder="Challenge payload",
        )
        controls = Horizontal(
            Button("Pair", id="pair"),
            Button("Assert", id="assert"),
        )
        self.status = Static("No device paired", id="mobile-status")
        panel = Vertical(
            Static("Device ID"),
            self.device_input,
            Static("Challenge"),
            self.challenge_input,
            controls,
            self.status,
            id="mobile-panel",
        )
        yield panel

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        device_id = self.device_input.value or "mobile1"
        if event.button.id == "pair":
            state = await self.call_api(self.client.mobile_pair, device_id)
            self.status.update(f"Device {state['device_id']} paired")
        elif event.button.id == "assert":
            challenge = self.challenge_input.value or "hello"
            result = await self.call_api(self.client.mobile_assert, device_id, challenge)
            self.status.update(
                f"Response for {device_id}: {result['response'][:32]}"
            )


class HSMView(ModuleView):
    def compose(self) -> ComposeResult:  # type: ignore[override]
        self.payload = Input(value="important", placeholder="Payload to sign")
        self.output = Static("Signature will appear here")
        yield Vertical(self.payload, Button("Sign", id="sign"), self.output)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "sign":
            return
        data = await self.call_api(self.client.hsm_sign, self.payload.value or "test")
        self.output.update(f"Signature: {data['signature'][:32]}…")


class PGPView(ModuleView):
    def compose(self) -> ComposeResult:  # type: ignore[override]
        self.name_input = Input(value="Harness User", placeholder="Name")
        self.email_input = Input(value="harness@example.com", placeholder="Email")
        controls = Horizontal(
            Button("Generate", id="generate"),
            Button("Sign", id="sign"),
            Button("Encrypt", id="encrypt"),
            Button("Decrypt", id="decrypt"),
            Button("Refresh", id="refresh"),
            classes="pgp-controls",
        )
        self.table = DataTable(id="pgp-table")
        self.table.zebra_stripes = True
        self.table.show_header = True
        self.table.add_columns("Fingerprint", "UIDs")
        self.output = Static("PGP output will appear here", id="pgp-output")
        yield Vertical(
            self.name_input,
            self.email_input,
            controls,
            Vertical(self.table, id="pgp-table-container"),
            self.output,
            id="pgp-panel",
        )

    async def on_mount(self) -> None:  # type: ignore[override]
        super().on_mount()
        await self.refresh_keys()

    async def refresh_keys(self) -> None:
        keys = await self.call_api(self.client.pgp_list)
        self.table.clear()
        for key in keys:
            uids = ", ".join(key.get("uids", []))
            self.table.add_row(key["fingerprint"], uids)

    def _selected_fingerprint(self) -> Optional[str]:
        if not self.table.row_count:
            return None
        row = self.table.cursor_row or 0
        return self.table.get_row_at(row)[0]

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh":
            await self.refresh_keys()
            return
        if event.button.id == "generate":
            key = await self.call_api(
                self.client.pgp_generate,
                self.name_input.value,
                self.email_input.value,
            )
            await self.refresh_keys()
            self.output.update(f"Generated key {key.get('fingerprint')}")
            return
        fingerprint = self._selected_fingerprint()
        if not fingerprint:
            self.notify("Select a key first")
            return
        if event.button.id == "sign":
            result = await self.call_api(self.client.pgp_sign, fingerprint, "hello world")
            self.output.update(result["signature"])
        elif event.button.id == "encrypt":
            result = await self.call_api(self.client.pgp_encrypt, fingerprint, "secret message")
            self.output.update(result["ciphertext"])
        elif event.button.id == "decrypt":
            if not self.output.renderable:
                self.notify("Encrypt something first")
                return
            ciphertext = str(self.output.renderable)
            if "BEGIN PGP MESSAGE" not in ciphertext:
                self.notify("Current output is not a PGP message")
                return
            result = await self.call_api(self.client.pgp_decrypt, fingerprint, ciphertext)
            self.output.update(result["plaintext"])


@dataclass
class ModuleSpec:
    label: str
    view: ModuleView


class HarnessTuiApp(App):
    CSS = """
    DataTable {
        height: 1fr;
        min-height: 12;
    }
    ContentSwitcher {
        height: auto;
    }
    #smartcard-panel {
        height: auto;
        min-height: 6;
        border: solid $accent;
        padding: 1 2;
    }
    #smartcard-status {
        padding-bottom: 1;
    }
    #mobile-panel {
        border: solid $accent;
        padding: 1 2;
        min-height: 8;
    }
    #pgp-panel {
        border: solid $accent;
        padding: 1 2;
        height: 1fr;
        min-height: 12;
    }
    .pgp-controls {
        padding-bottom: 1;
    }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        ensure_server_running()
        super().__init__()
        self.client = HarnessClient(DEFAULT_BASE_URL)

    def compose(self) -> ComposeResult:  # type: ignore[override]
        yield Header(show_clock=True)
        self.tabs = Tabs(
            Tab("OTP", id="otp"),
            Tab("PKCS#11", id="pkcs"),
            Tab("FIDO2", id="fido"),
            Tab("Smart-Card", id="smartcard"),
            Tab("Mobile", id="mobile"),
            Tab("HSM", id="hsm"),
            Tab("PGP", id="pgp"),
            id="module-tabs",
        )
        yield self.tabs
        self.switcher = ContentSwitcher(initial="otp")
        for view in (
            OTPView(id="otp"),
            PKCS11View(id="pkcs"),
            FidoView(id="fido"),
            SmartCardView(id="smartcard"),
            MobileView(id="mobile"),
            HSMView(id="hsm"),
            PGPView(id="pgp"),
        ):
            self.switcher.mount(view)
        yield self.switcher
        yield Footer()

    async def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        self.switcher.current = event.tab.id or "otp"


if __name__ == "__main__":
    HarnessTuiApp().run()
