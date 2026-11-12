"""
agent/core/autonomous.py

Autonomous daemon-ai agent — runs as a persistent seller + optional buyer on Agora.

This wraps AgoraAgent with:
  - DaemonWallet (own keypair, spending policy)
  - Background seller loop (listen for intents, evaluate, offer, execute, earn)
  - On-demand buyer flow (user or daemon initiates a buy through the wallet)
  - Full audit trail visible in the Basecamp UI
"""

import asyncio
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional, Callable

from agent.daemon.llm import DaemonLLM, AgentReasoner
from agent.logos.messaging import (
    LogosMessagingClient, MarketplaceMessaging,
    CapabilityManifest, CapabilityService, BuyIntent, Offer, DeliveryNotification,
)
from agent.logos.blockchain import LogosBlockchainClient, AgentIdentity
from agent.logos.storage import LogosStorageClient
from agent.core.daemon_wallet import DaemonWallet
from agent.core.owner_channel import OwnerChannel
from agent.skills.base import SkillRegistry, SkillContext
from agent.skills.storage_skills import register_storage_skills
from agent.skills.messaging_skills import register_messaging_skills
from agent.skills.blockchain_skills import register_blockchain_skills
from agent.skills.agent_skills import register_agent_skills
from agent.skills.meta_skills import register_meta_skills


@dataclass
class DaemonConfig:
    agent_name: str = "daemon-ai"
    stake_nom: str = "1000"
    services: list = field(default_factory=lambda: [
        CapabilityService(
            id="inference-v1", category="inference",
            price_per_unit="0.002", model="mamba-370m",
            context_window=32768, avg_latency_ms=850,
        ),
        CapabilityService(
            id="code-v1", category="code",
            price_per_unit="0.005", model="mamba-1.4b",
            avg_latency_ms=2000,
        ),
        CapabilityService(
            id="research-v1", category="research",
            price_per_unit="0.01", avg_latency_ms=15000,
        ),
    ])
    messaging_url: str = "http://localhost:8645"
    blockchain_url: str = "http://localhost:3001"
    storage_url: str = "http://localhost:8080"
    capability_broadcast_interval_s: int = 60
    auto_sell: bool = True       # Auto-respond to matching intents
    auto_buy: bool = False       # Don't auto-buy without explicit trigger


class AutonomousDaemon:
    """
    Fully autonomous daemon-ai agent.

    Owns its own wallet, makes its own decisions, earns its own NOM.
    The user controls the policy — daemon controls the execution.
    """

    def __init__(self, config: Optional[DaemonConfig] = None):
        self.config = config or DaemonConfig()
        self.wallet = DaemonWallet(self.config.agent_name)
        self.llm = DaemonLLM()
        self.reasoner = AgentReasoner(self.llm, role="seller")
        self.messaging = LogosMessagingClient(self.config.messaging_url)
        self.blockchain = LogosBlockchainClient(self.config.blockchain_url)
        self.storage = LogosStorageClient(self.config.storage_url)
        self.identity: Optional[AgentIdentity] = None
        self.market: Optional[MarketplaceMessaging] = None
        self.registry: Optional[SkillRegistry] = None
        self.owner_channel: Optional[OwnerChannel] = None
        self._running = False
        self._event_log: list[dict] = []
        self._on_event: Optional[Callable] = None

        # Stats
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.offers_sent = 0
        self.offers_accepted = 0
        self.intents_evaluated = 0

    def _sign(self, data: bytes) -> str:
        return self.wallet.sign(data)

    def _emit(self, event: str, level: str = "info", **data):
        entry = {"event": event, "level": level, "ts": time.time(), **data}
        self._event_log.append(entry)
        if self._on_event:
            self._on_event(entry)

    # ── Skill Registry ──────────────────────────────────────────

    def build_registry(self) -> SkillRegistry:
        """Build and populate the skill registry with all default skills."""
        registry = SkillRegistry()
        register_storage_skills(registry, self.storage)
        register_messaging_skills(registry, self.messaging)
        register_blockchain_skills(registry, self.wallet, self.blockchain)
        register_agent_skills(
            registry,
            agent_name=self.config.agent_name,
            agent_pub_key=self.wallet.pub_key_hex,
            messaging_address=self.wallet.pub_key_hex,
            messaging=self.messaging,
        )
        register_meta_skills(registry, self.wallet)
        self.registry = registry
        self._emit("skills_registered", msg=f"Skill SDK ready — {registry.count} skills registered")
        return registry

    def init_owner_channel(self, owner_pub_key: str) -> OwnerChannel:
        """Initialize the E2E encrypted owner channel."""
        self.owner_channel = OwnerChannel(
            messaging=self.messaging,
            wallet=self.wallet,
            agent_pub_key=self.wallet.pub_key_hex,
            owner_pub_key=owner_pub_key,
        )
        return self.owner_channel

    async def invoke_skill(self, name: str, params: dict, caller: str = "owner") -> dict:
        """Invoke a skill through the registry with proper context."""
        if not self.registry:
            self.build_registry()
        context = SkillContext(
            agent_pub_key=self.wallet.pub_key_hex,
            wallet_balance=self.wallet._balance_nom,
            caller=caller,
        )
        result = await self.registry.invoke(name, params, context)
        return result.to_dict()

    # ── Lifecycle ────────────────────────────────────────────────

    async def start(self):
        """Initialize wallet, register identity, start listening."""
        self._emit("daemon_starting", msg="Initializing daemon-ai autonomous agent...")

        # Initialize wallet (loads/creates keypair)
        pub_key = self.wallet.initialize()
        self._emit("wallet_ready", msg=f"Wallet ready: {pub_key[:20]}...",
                   pub_key=pub_key, balance=self.wallet._balance_nom)

        # Connect to Logos stack
        await self.messaging.start()
        await self.blockchain.check_node()
        await self.storage.check_node()

        # Register on-chain identity
        capability_hash = hashlib.sha256(
            json.dumps([s.id for s in self.config.services]).encode()
        ).hexdigest()

        self.identity = await self.blockchain.register_identity(
            agent_pub_key_hex=pub_key,
            stake_nom=self.config.stake_nom,
            capability_hash=capability_hash,
        )
        self._emit("identity_registered",
                   msg=f"Identity registered: {self.identity.tx_hash[:20]}...",
                   tx_hash=self.identity.tx_hash, mock=self.identity.mock)

        # Build skill registry
        self.build_registry()

        # Initialize owner channel (owner key = agent key for self-hosted mode)
        owner_key = os.environ.get("AGORA_OWNER_KEY", pub_key)
        self.init_owner_channel(owner_key)
        await self.owner_channel.initialize()
        await self.owner_channel.start()
        self._emit("owner_channel_ready",
                   msg=f"Owner channel established (topic: {self.owner_channel.topic_id[:12]}...)")

        # Set up marketplace messaging
        self.market = MarketplaceMessaging(self.messaging, pub_key, self._sign)

        # Subscribe to intents (seller mode)
        if self.config.auto_sell:
            self.market.on_intent(self._handle_intent)
            self._emit("seller_active",
                       msg=f"Seller active — {len(self.config.services)} services advertised",
                       level="success")

        self._running = True

        # Start background loops
        tasks = [self.messaging.start_polling(2000)]
        if self.config.auto_sell:
            tasks.append(self._broadcast_capabilities_loop())

        self._emit("daemon_ready", level="success",
                   msg="daemon-ai is online and autonomous")

        await asyncio.gather(*tasks)

    async def stop(self):
        self._running = False
        self.messaging.stop_polling()
        self.wallet.shutdown()
        self._emit("daemon_stopped", msg="daemon-ai stopped — key zeroed from memory")

    # ── Seller: Handle Incoming Intents ──────────────────────────

    async def _handle_intent(self, msg: dict):
        if msg.get("type") != "buy_intent":
            return
        if msg.get("buyerId") == self.wallet.pub_key_hex:
            return  # Don't respond to own intents

        # Check if wallet is frozen
        if self.wallet.policy.frozen:
            self._emit("intent_skipped", level="warning",
                       msg="Wallet frozen — skipping intent")
            return

        buyer_id = msg.get("buyerId", "")[:16]
        category = msg.get("category", "")
        budget = msg.get("budget", "0")
        task_desc = msg.get("task", "")

        self.intents_evaluated += 1
        self._emit("intent_received",
                   msg=f"Intent from {buyer_id}... | {category} | {budget} NOM",
                   buyer=buyer_id, category=category, budget=budget)

        # Check if we serve this category
        matching = [s for s in self.config.services if s.category == category]
        if not matching:
            self._emit("intent_no_match", level="info",
                       msg=f"No matching service for category: {category}")
            return

        service = matching[0]

        # Use daemon-ai to evaluate the intent
        self._emit("evaluating", msg=f"daemon-ai evaluating with {self.llm._backend or 'mock'}...")

        try:
            decision = await self.reasoner.evaluate_intent(msg)
        except Exception as e:
            self._emit("eval_error", level="error", msg=f"Evaluation failed: {e}")
            return

        action = decision.get("action", "reject")
        reason = decision.get("reason", "")
        suspicious = decision.get("suspicious", False)

        if suspicious:
            self._emit("suspicious_intent", level="warning",
                       msg=f"Suspicious intent from {buyer_id}... — dropping",
                       buyer=buyer_id)
            return

        if action == "reject":
            self._emit("intent_rejected", msg=f"Rejected: {reason}")
            return

        # Generate and send offer
        session_id = secrets.token_hex(8)
        estimated_units = 2000
        total_price = str(round(float(service.price_per_unit) * estimated_units, 4))
        output_commitment = hashlib.sha256(
            (session_id + "output_placeholder").encode()
        ).hexdigest()

        offer = Offer(
            session_id=session_id,
            seller_id=self.wallet.pub_key_hex,
            buyer_id=msg.get("buyerId", ""),
            capability_id=service.id,
            price_per_unit=service.price_per_unit,
            estimated_units=estimated_units,
            total_price=total_price,
            delivery_timeout_ms=30000,
            delivery_hash_commitment="sha256:" + output_commitment,
        )

        ok = await self.market.send_offer(offer)
        if ok:
            self.offers_sent += 1
            self._emit("offer_sent", level="success",
                       msg=f"Offer sent: {total_price} NOM | session: {session_id[:12]}...",
                       session_id=session_id, total_price=total_price)

            # If we have the task, execute it proactively
            if task_desc:
                await self._execute_and_deliver(task_desc, session_id, offer)

    async def _execute_and_deliver(self, task: str, session_id: str, offer: Offer):
        """Execute a task locally with daemon-ai and deliver the result."""
        self._emit("task_executing", msg="daemon-ai executing task locally...")

        try:
            result = await self.reasoner.execute_task(task)
            result_bytes = result.encode("utf-8")

            self.tasks_completed += 1
            output_tokens = len(result.split())
            self._emit("task_complete", level="success",
                       msg=f"Task complete | {output_tokens} tokens generated",
                       tokens=output_tokens)

            # Upload to Logos Storage
            storage_result = await self.storage.upload(
                result_bytes, mime_type="text/plain",
                filename=f"daemon-ai-{session_id[:8]}.txt",
            )
            self._emit("delivery_stored",
                       msg=f"Output pinned to Logos Storage | CID: {storage_result.cid[:20]}...",
                       cid=storage_result.cid)

            # Record earning
            earned = float(offer.total_price)
            self.wallet.earn(earned, offer.buyer_id[:20], session_id, "inference")
            self.offers_accepted += 1
            self._emit("payment_received", level="success",
                       msg=f"Earned +{earned:.4f} NOM | balance: {self.wallet._balance_nom:.4f} NOM",
                       earned=earned, balance=self.wallet._balance_nom)

        except Exception as e:
            self.tasks_failed += 1
            self._emit("task_failed", level="error", msg=f"Task execution failed: {e}")

    # ── Buyer: Execute a Purchase ────────────────────────────────

    async def buy(self, category: str, task: str, budget: float,
                  max_price_per_unit: float = 0.01) -> dict:
        """
        Autonomously buy a service from another agent on Agora.
        Checks spending policy before committing funds.
        """
        if not self.market:
            return {"error": "Daemon not started"}

        # Policy check
        allowed, reason = self.wallet.check_spend(
            budget, category,
            escrow_timeout_ms=60000,
            slash_bps=500,
        )
        if not allowed:
            self._emit("buy_denied", level="warning",
                       msg=f"Buy denied by policy: {reason}")
            return {"error": f"Policy denied: {reason}"}

        self._emit("buy_starting",
                   msg=f"Initiating buy: {category} | budget: {budget} NOM")

        buyer_nonce = secrets.token_hex(16)
        intent = BuyIntent(
            buyer_id=self.wallet.pub_key_hex,
            category=category,
            budget=str(budget),
            max_price_per_unit=str(max_price_per_unit),
            max_latency_ms=10000,
            min_reputation=self.wallet.policy.min_counterparty_reputation,
            expire_ts=int(time.time() * 1000) + 60000,
            buyer_nonce=buyer_nonce,
        )
        await self.market.broadcast_intent(intent)

        self._emit("intent_broadcast",
                   msg=f"Buy intent broadcast for {category}")

        # In a real flow, we'd wait for offers and evaluate them
        # For now, return the intent details
        return {
            "status": "intent_broadcast",
            "category": category,
            "budget": budget,
            "nonce": buyer_nonce[:8] + "...",
        }

    # ── Background Loops ─────────────────────────────────────────

    async def _broadcast_capabilities_loop(self):
        while self._running:
            if self.identity and self.config.services:
                reputation = await self.blockchain.get_reputation(self.wallet.pub_key_hex)
                manifest = CapabilityManifest(
                    agent_id=self.wallet.pub_key_hex,
                    identity_tx_hash=self.identity.tx_hash,
                    stake=self.config.stake_nom,
                    reputation=reputation,
                    capabilities=self.config.services,
                )
                await self.market.broadcast_capabilities(manifest)
            await asyncio.sleep(self.config.capability_broadcast_interval_s)

    # ── State ────────────────────────────────────────────────────

    def state(self) -> dict:
        wallet_state = self.wallet.state()
        return {
            "running": self._running,
            "wallet": wallet_state,
            "identity": {
                "pub_key": self.wallet.pub_key_hex,
                "tx_hash": self.identity.tx_hash if self.identity else None,
                "mock": self.identity.mock if self.identity else True,
            },
            "stats": {
                "tasks_completed": self.tasks_completed,
                "tasks_failed": self.tasks_failed,
                "offers_sent": self.offers_sent,
                "offers_accepted": self.offers_accepted,
                "intents_evaluated": self.intents_evaluated,
            },
            "services": [
                {"id": s.id, "category": s.category, "price": s.price_per_unit}
                for s in self.config.services
            ],
            "config": {
                "auto_sell": self.config.auto_sell,
                "auto_buy": self.config.auto_buy,
            },
            "backend": self.llm._backend or "detecting...",
        }

    def get_events(self, since_index: int = 0) -> dict:
        entries = self._event_log[since_index:]
        return {"entries": entries, "cursor": len(self._event_log)}
