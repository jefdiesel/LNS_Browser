# Names Wallet — UX Review & Redesign Plan (Next Version)

## Problem Observed (First-Time User Walkthrough)
1. **Main Wallet page buries what matters most:**
   - The **Bridge** panel (*Receive from Ethereum / Claim a bridge deposit / Bridge to Ethereum / Install LEZ Bridge*) and **Watch a public account** take up the entire above-the-fold screen.
   - The user's own **balances** and **Public / Private account addresses** (with a one-click **Copy** button) are not immediately visible at the top.
2. **Setup & CLI friction is too high for new users:**
   - Asking a user to locate a binary path (`names-lez04`), scroll past Zones to App Settings, or hit a missing-folder error (*"is the drive connected?"*) breaks first-run onboarding.
   - Creating a LEZ 0.4 wallet wrote the LEZ 0.3 URL (`testnet.lez.logos.co`) into `wallet_config.json`, causing silent sync/send failures.
   - Zones (*Change sequencer*, *Wallet folder*) look like primary settings and are easy to click by mistake.
3. **First-time receive on LEZ 0.4 is broken for normal users (`--to-pk`):**
   - Sending to a brand-new LEZ 0.4 public account fails with *"declared public but not admitted"* unless the sender supplies `--to-pk` (public key) instead of `--to` (account ID). Receive/Copy should either include the public key automatically or handle admission transparently.
4. **Storage setup should be invisible:**
   - Asking a user to type `http://127.0.0.1:8089/api/storage/v1` into LNS Browser Settings is dev-only friction. Basecamp should wire directly to its bundled `storage_module` with zero port configuration.
5. **Too many concepts thrown at once:**
   - Reserved name lists, public vs. private registration on 0.4 vs. 0.3, Zones, Bridge, Watch Wallet, and separate CLI tools all hit a new user before they can do the one basic thing: *see balance → register a name → publish/open a page*.
6. **Dead vaults & zero-balance clutter + duplicate Activity rows:**
   - The wallet lists 12 dead `0`-balance rows for old bridge deployments (`bridge v2` through `v7`, `wETH` & `dUSDC` repeated 6 times).
   - **Rule:** Never show `0`-balance token rows by default (hide behind an optional "Show zero balances" toggle), and remove all retired/dead bridge vault tokens (`v2`–`v6`) from the default token list.
   - Deduplicate Activity entries so a single LEZ 0.4 transfer doesn't appear twice (once for `bridge test network` and once for `zone Home`).
7. **Oversized, verbose banners (e.g. "No name yet" card):**
   - Multi-line explanatory cards with huge padding push real wallet data off-screen.
   - **Rule:** Replace the `"No name yet"` card with a compact, dismissible single-line strip (`No LNS name yet · [Pick a name] ×`) and tighten copy across every card — short labels, zero essays.

---

## Proposed Information Architecture

### 1. Wallet Page — Balances & Addresses First, Tabs for Everything Else
Top of the **Wallet** screen (always visible, above the fold):
- **Header strip:** Network pill (`LEZ 0.4` / `LEZ 0.3`) + Refresh + Hide/Show balances toggle.
- **Primary Balance Card:**
  - Total LEZ balance (large, clear) + breakdown of **Public** vs **Private** balance.
  - **Your Address (Copy)** right on the card (Public address with one-click Copy + QR/Receive button; Private receiving keys under Receive).
  - Primary action buttons: **Send**, **Receive**.

Below the balance card — **clean horizontal tabs** instead of stacked walls of panels:
1. **Assets** *(default)* — Native LEZ + wrapped tokens (`wETH`, `dUSDC`, etc.) with clean per-asset rows.
2. **Bridge** — *Receive from Ethereum*, *Claim a bridge deposit*, *Bridge to Ethereum*, and optional Bridge module install prompt (never clutters the main balance view).
3. **Watch** — *Watch a public account* (paste any read-only address to track balances without mixing it with your own wallet).
4. **Accounts** — Full list of public/private accounts, shield/deshield, and create/rename accounts.

### 2. Zero-Friction First-Run Onboarding
- **Bundle the matching `names` CLI** with the Basecamp package (or auto-download + verify signature on first launch) — never ask a regular user for a filesystem path to a binary.
- **Auto-create the wallet directory** if missing (never show *"is the drive connected?"* for a brand-new local wallet path).
- **One-click "Create Wallet"**: generates wallet → shows recovery phrase with "I saved it" confirmation → drops user straight onto the **Wallet** balance + address card.

### 3. Cleaner Settings Hierarchy
- **General Settings:** Network selector (`LEZ 0.4` / `LEZ 0.3`), Main Name, Backup / Recovery Phrase.
- **Advanced (collapsed by default):** Zones / custom sequencer URL, custom CLI binary path, wallet folder location.

---

## Implementation Plan (Next Version — Not Started Yet)
1. Refactor `names_ui` Wallet view (`Wallet` screen) into:
   - Top `BalanceAndAddressCard` (always visible, one-click Copy address).
   - `TabBar` switching between **Assets**, **Bridge**, **Watch**, and **Accounts**.
2. Move Zones + CLI path + wallet folder under a collapsed **Advanced** section in Settings.
3. Auto-create missing local wallet directories on first run and bundle/resolve the matching LEZ 0.4 CLI automatically.
4. Add QML UI tests verifying that a fresh user sees **Balance + Copy Address** above the fold on first open.
