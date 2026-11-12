"""
agent/core/agent.py

Core Agora agent loop — security hardened.

Security fixes applied:
  FIX-2: buyer_nonce generated per-intent and included in escrow commitment
  FIX-5: private key loaded from AgentKeystore, never from CLI args
  FIX-7: delivery verified via storage.verify_delivery() with size + hash checks
"""

import asyncio
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

from agent.logos.messaging import (
    LogosMessagingClient, MarketplaceMessaging,
    CapabilityManifest, CapabilityService, BuyIntent, Offer, DeliveryNotification,
)
from agent.logos.blockchain import LogosBlockchainClient, AgentIdentity
from agent.logos.storage import LogosStorageClient
from agent.daemon.llm import DaemonLLM, AgentReasoner
from agent.core.keystore import AgentKeystore, SecureKey, get_or_create_key  # FIX-5
from agent.core import signing


@dataclass
class AgentConfig:
    agent_name: str = "default"        # FIX-5: name used for keychain lookup, no raw key
    stake_nom: str = "1000"
    role: str = "seller"
    services: list = field(default_factory=list)
    messaging_url: str  = "http://localhost:8645"
    blockchain_url: str = "http://localhost:3001"
    storage_url: str    = "http://localhost:8080"
    capability_broadcast_interval_s: int = 60


class AgoraAgent:

    def __init__(self, config: AgentConfig):
        self.config = config
        self.identity: Optional[AgentIdentity] = None

        # FIX-5: Load key from secure keystore, never from config/CLI
        self._secure_key: Optional[SecureKey] = None
        self.pub_key_hex: str = ""

        self.messaging  = LogosMessagingClient(config.messaging_url)
        self.blockchain = LogosBlockchainClient(config.blockchain_url)
        self.storage    = LogosStorageClient(config.storage_url)
        self.llm        = DaemonLLM()
        self.reasoner   = AgentReasoner(self.llm, role=config.role)
        self.market: Optional[MarketplaceMessaging] = None
        self._running = False
        self._pending_offers: list[dict] = []

    def _sign(self, data: bytes) -> str:
        """Ed25519-sign data with the key held in memory. Verifiable against pub_key_hex."""
        if not self._secure_key:
            raise RuntimeError("Agent not started — key not loaded")
        return signing.sign(self._secure_key.bytes, data)

    def _priv_key_hex(self) -> str:
        """Return private key hex for blockchain calls — only called internally."""
        if not self._secure_key:
            raise RuntimeError("Key not loaded")
        return self._secure_key.hex

    async def start(self):
        print(f"\n{'='*60}")
        print(f"  Agora Agent Starting")
        print(f"  Name:  {self.config.agent_name}")
        print(f"  Role:  {self.config.role}")
        print(f"{'='*60}\n")

        # FIX-5: Load key securely from OS keychain or encrypted file
        self._secure_key = get_or_create_key(self.config.agent_name)
        self.pub_key_hex = signing.agent_id_from_private_key(self._secure_key.bytes)
        print(f"[Agent] Key loaded for {self.config.agent_name} — pubkey {self.pub_key_hex[:20]}…")

        await self.messaging.start()
        await self.blockchain.check_node()
        await self.storage.check_node()

        capability_hash = hashlib.sha256(
            json.dumps([s.id for s in self.config.services]).encode()
        ).hexdigest()

        self.identity = await self.blockchain.register_identity(
            agent_pub_key_hex=self.pub_key_hex,
            stake_nom=self.config.stake_nom,
            capability_hash=capability_hash,
        )
        print(f"[Agent] Identity registered: tx={self.identity.tx_hash[:20]}… mock={self.identity.mock}")

        self.market = MarketplaceMessaging(self.messaging, self.pub_key_hex, self._sign)

        if self.config.role in ("seller", "both"):
            self.market.on_intent(self._handle_intent)
        if self.config.role in ("buyer", "both"):
            self.market.on_offer(self._handle_offer)

        self._running = True
        tasks = [self.messaging.start_polling(2000)]
        if self.config.role in ("seller", "both"):
            tasks.append(self._broadcast_capabilities_loop())
        await asyncio.gather(*tasks)

    async def stop(self):
        self._running = False
        self.messaging.stop_polling()
        # FIX-5: Zero key material from memory on shutdown
        if self._secure_key:
            self._secure_key.zero()
            self._secure_key = None
        print("[Agent] Stopped — key zeroed from memory")

    async def _broadcast_capabilities_loop(self):
        while self._running:
            if self.identity and self.config.services:
                reputation = await self.blockchain.get_reputation(self.pub_key_hex)
                manifest = CapabilityManifest(
                    agent_id=self.pub_key_hex,
                    identity_tx_hash=self.identity.tx_hash,
                    stake=self.config.stake_nom,
                    reputation=reputation,
                    capabilities=self.config.services,
                )
                await self.market.broadcast_capabilities(manifest)
            await asyncio.sleep(self.config.capability_broadcast_interval_s)

    async def _handle_intent(self, msg: dict):
        if msg.get("type") != "buy_intent":
            return
        if msg.get("buyerId") == self.pub_key_hex:
            return

        buyer_id  = msg.get("buyerId", "")
        category  = msg.get("category", "")
        budget    = msg.get("budget", "0")

        print(f"[Seller] Intent from {buyer_id[:16]}…: {category}, budget={budget} NOM")

        matching = [s for s in self.config.services if s.category == category]
        if not matching:
            return

        service = matching[0]

        # FIX-1: evaluate_offer sanitises all intent data before passing to daemon-ai
        balance  = await self.blockchain.get_balance(self.pub_key_hex)
        decision = await self.reasoner.evaluate_offer(msg, balance, 0.9)

        if decision.get("action") == "reject":
            print(f"[Seller] Rejected intent: {decision.get('reason')}")
            return
        if decision.get("suspicious"):
            print(f"[Seller] Suspicious intent from {buyer_id[:16]}… — dropping")
            return

        session_id = secrets.token_hex(8)
        estimated_units = 2000
        total_price = str(float(service.price_per_unit) * estimated_units)
        output_commitment = hashlib.sha256(
            (session_id + "output_placeholder").encode()
        ).hexdigest()

        offer = Offer(
            session_id=session_id,
            seller_id=self.pub_key_hex,
            buyer_id=buyer_id,
            capability_id=service.id,
            price_per_unit=service.price_per_unit,
            estimated_units=estimated_units,
            total_price=total_price,
            delivery_timeout_ms=30000,
            delivery_hash_commitment="sha256:" + output_commitment,
        )
        ok = await self.market.send_offer(offer)
        if ok:
            print(f"[Seller] Offer sent to {buyer_id[:16]}…: {total_price} NOM")

    async def _handle_offer(self, msg: dict):
        if msg.get("type") != "offer":
            return
        if msg.get("buyerId") != self.pub_key_hex:
            return
        print(f"[Buyer] Offer from {msg.get('sellerId','')[:16]}…: {msg.get('totalPrice')} NOM")
        self._pending_offers.append(msg)

    async def execute_buy(
        self,
        category: str,
        task: str,
        budget: str,
        max_price_per_unit: str = "0.01",
        max_latency_ms: int = 10000,
        min_reputation: float = 0.7,
        timeout_s: int = 60,
    ) -> Optional[str]:
        if not self.market:
            raise RuntimeError("Agent not started")

        # FIX-2: generate buyer_nonce here — same nonce used in escrow commitment
        buyer_nonce = secrets.token_hex(16)
        print(f"\n[Buyer] Starting purchase: {category}, budget={budget} NOM, nonce={buyer_nonce[:8]}…")

        intent = BuyIntent(
            buyer_id=self.pub_key_hex,
            category=category,
            budget=budget,
            max_price_per_unit=max_price_per_unit,
            max_latency_ms=max_latency_ms,
            min_reputation=min_reputation,
            expire_ts=int(time.time() * 1000) + timeout_s * 1000,
            buyer_nonce=buyer_nonce,  # FIX-2
        )
        await self.market.broadcast_intent(intent)

        print(f"[Buyer] Waiting {timeout_s}s for offers…")
        self._pending_offers.clear()
        await asyncio.sleep(min(timeout_s, 15))

        if not self._pending_offers:
            print("[Buyer] No offers received")
            return None

        # FIX-1: find_best_offer sanitises all offer data before daemon-ai sees it
        best_offer = await self.reasoner.find_best_offer(
            self._pending_offers, budget,
            {"category": category, "maxPricePerUnit": max_price_per_unit},
        )
        if not best_offer:
            print("[Buyer] No suitable offer found")
            return None

        seller_id     = best_offer.get("sellerId", "")
        total_price   = best_offer.get("totalPrice", "0")
        session_id    = best_offer.get("sessionId", "")
        delivery_hash = best_offer.get("deliveryHashCommitment", "")

        print(f"[Buyer] Accepted offer from {seller_id[:16]}…: {total_price} NOM")
        await self.market.accept_offer(session_id)

        # FIX-2: Pass buyer_nonce to escrow contract — binds nonce to commitment
        escrow = await self.blockchain.create_escrow(
            buyer_priv_key_hex=self._priv_key_hex(),
            seller_id=seller_id,
            amount_nom=total_price,
            delivery_hash=delivery_hash,
            buyer_nonce=buyer_nonce,     # FIX-2
            timeout_ms=best_offer.get("escrowParams", {}).get("timeoutMs", 60000),
            slash_bps=best_offer.get("escrowParams", {}).get("slashBps", 500),
        )
        print(f"[Buyer] Escrow: {escrow.escrow_id[:24]}… mock={escrow.mock}")

        delivery_received = asyncio.Event()
        delivery_data = {}

        async def on_delivery(msg):
            if msg.get("sessionId") == session_id:
                delivery_data.update(msg)
                delivery_received.set()

        self.market.on_delivery(escrow.escrow_id, on_delivery)

        try:
            await asyncio.wait_for(delivery_received.wait(), timeout=timeout_s)
        except asyncio.TimeoutError:
            print("[Buyer] Delivery timed out — disputing")
            await self.blockchain.dispute_escrow(self._priv_key_hex(), escrow.escrow_id, "timeout")
            return None

        cid         = delivery_data.get("cid", "")
        output_hash = delivery_data.get("outputHash", "")
        agreed_size = int(best_offer.get("agreedDocSize", 0))

        print(f"[Buyer] Delivery CID={cid[:20]}… — verifying…")

        # FIX-7: Download with agreed size cap, then full verify_delivery check
        try:
            content = await self.storage.download(cid, agreed_size=agreed_size)
        except ValueError as e:
            print(f"[Buyer] Download rejected: {e} — disputing")
            await self.blockchain.dispute_escrow(self._priv_key_hex(), escrow.escrow_id, str(e))
            return None

        # FIX-7: Full delivery verification — hash + size
        valid, reason = self.storage.verify_delivery(content, output_hash, agreed_size=agreed_size)
        if not valid:
            print(f"[Buyer] Delivery invalid: {reason} — disputing")
            await self.blockchain.dispute_escrow(self._priv_key_hex(), escrow.escrow_id, reason)
            return None

        # FIX-2: Pass buyer_nonce when releasing escrow — contract verifies it
        released = await self.blockchain.release_escrow(
            buyer_priv_key_hex=self._priv_key_hex(),
            escrow_id=escrow.escrow_id,
            actual_output_hash=output_hash,
            buyer_nonce=buyer_nonce,     # FIX-2
        )
        if released:
            print(f"[Buyer] Payment released: {total_price} NOM → {seller_id[:16]}…")

        return content.decode("utf-8", errors="replace")
