# Selendra

Selendra is a fast, low-cost, **EVM-compatible zk rollup**. Transactions run on Selendra, their data is stored on **Avail**, and every state change is backed by **zero-knowledge proofs**.

## Features

| Feature | What it means |
|---|---|
| **1-second blocks** | A new block every second; transactions confirm almost instantly |
| **EVM compatible** | Deploy Solidity contracts; use MetaMask, Foundry, Hardhat, ethers and viem as on Ethereum |
| **Low cost** | Data is posted to Avail in large batches, and **nothing is posted when there are no transactions** |
| **Sponsored fees (fee payer)** | A dApp or any account can pay transaction fees for a list of accounts, so users can use the dApp with **zero SEL** |
| **Pay gas in many tokens** | SEL is the default; other approved tokens (e.g. stablecoins) can pay gas at live oracle prices |
| **zk-proven security** | Every state change is proven with SP1 zero-knowledge proofs; anyone can verify them |
| **Secure data availability** | Avail guarantees the data is published (KZG commitments + data availability sampling) |
| **Censorship resistant** | If the sequencer ignores a transaction, users can submit it directly to Avail and it is force-included |
| **Upgradable without hard forks** | Block time, batching rules and fees are on-chain settings that governance can change while the chain runs |
| **Two account types** | `sel1…` native accounts (ed25519) and `0x…` Ethereum accounts (MetaMask), with the same SEL balance system |

## SEL token

| | |
|---|---|
| Name | Selendra |
| Symbol | SEL |
| Decimals | 18 |
| Initial supply | 300,000,000 SEL |
| Used for | Gas fees, sequencer bonds, prover rewards, governance |
| Burn | 10% of every base fee is burned |

## How the chain works

```
 1. User signs tx        2. Sequencer executes      3. Batch posted to Avail
 (MetaMask or sel1)  ──► instantly, 1 s blocks  ──► (≥ 1000 txs or every 1 h)
                         "confirmed" in ~ms              │
                                                         ▼
 5. Proof posted     ◄── 4. Prover proves the  ◄── Full nodes re-execute and
    to Avail             new state with SP1          check the same result
```

**1. Send.** A user signs a transaction with MetaMask (`0x…`) or a native wallet (`sel1…`) and sends it to Selendra.

**2. Instant confirmation.** The sequencer executes it right away and includes it in the next **1-second block**. The user sees "confirmed" in milliseconds (a *soft confirmation*).

**3. Publish to Avail.** The sequencer collects blocks and posts them to Avail as one batch:
- when **1,000 or more transactions** are waiting, **or**
- **1 hour** after the oldest unposted transaction.

If there are no transactions, nothing is posted and no data fee is paid.

**4. Verify.** Every Selendra full node reads the batch from Avail, re-runs the transactions and checks it reaches the same result. Once the batch is on Avail, it is **final**: its order can't be changed.

**5. Prove.** A prover runs the same transactions inside the SP1 zkVM and produces a **zero-knowledge proof** that the new state is correct. The proof is posted to Avail, so anyone (light clients, bridges, exchanges) can verify Selendra's state in milliseconds without re-running the chain.

### If the sequencer misbehaves

- **Censoring:** users post their transaction directly to Avail. Selendra must include it after a fixed delay.
- **Going offline:** the chain keeps processing transactions posted directly to Avail.
- **Lying about results:** full nodes and zk proofs both reject any state that doesn't match the data on Avail.

## Fees

```
fee = gas used × (base fee + optional tip)
```

- The **base fee** rises when blocks are busy and falls when they're quiet (EIP-1559 style), changing smoothly second by second.
- **10%** of the base fee is burned; **90%** rewards provers. The **tip** goes to the sequencer.
- A simple transfer costs about **0.00002 SEL**.
- Fees can be paid in SEL or another approved token. The price comes from an oracle, with safety checks that fall back to SEL if a price is stale.

## Sponsored fees (fee payer)

A **payer** (usually a dApp) pays transaction fees for its users, so new users don't need to buy SEL before using the app.

```
1. Payer creates a sponsorship:
     accounts:  [alice, bob, carol]          ← list of accounts it pays for
     only for:  [dApp contract 0xABC…]       ← only these contracts/modules
     limits:    max 0.01 SEL per tx, 100 txs per account per day,
                total budget 1,000 SEL, expires 2027-06-30
     funded:    1,000 SEL deposited

2. Alice (0 SEL) sends a tx to 0xABC…
3. Chain checks: alice in list? target allowed? within limits? budget left?
     yes → fee taken from the payer's deposit   no → alice pays as normal
4. Unused gas is refunded to the payer
```

**What a payer can set:**

| Setting | Purpose |
|---|---|
| Account list | Which accounts are sponsored (add/remove any time); or "all accounts" for open promotions |
| Allowed targets | Only pay for calls to the dApp's own contracts/modules, so sponsored users can't spend the budget elsewhere |
| Per-tx limit | Max fee and max gas price per transaction |
| Per-account limit | Max transactions or fees per account per day |
| Total budget | Deposit in SEL (or another fee token); sponsorship stops when it runs out |
| Expiry | Date after which the sponsorship ends |
| Managers | Accounts allowed to update the list, limits and budget (e.g. the dApp's backend) |

**How a transaction chooses its payer:**
- **Native and EIP-712 transactions** name the payer in a `fee_payer` field. With EIP-712, MetaMask users just sign a message, so their wallet doesn't need any SEL.
- **Standard EVM transactions** are matched automatically: if the sender is on a sponsorship list for the contract being called, that sponsorship pays.
- Several dApps can sponsor the same user at once; each pays only for calls to its own contracts.

**Protection for payers:** strict per-account and total limits, allowed-target lists, and expiry. Failed transactions still cost gas, so limits also stop a sponsored account from draining the budget with failing calls. The payer can pause or withdraw the remaining deposit at any time.

## Governance

The chain's main settings are stored on-chain and can be changed by governance **without stopping the chain or forking it**:

- block time, and when batches are posted to Avail
- fee settings
- which tokens can pay gas
- the switch from operator mode to full zk-proof mode
- SEL supply (mint/burn)

Governance starts with an admin, moves to a multisig with a time delay, and later to SEL token holders.
