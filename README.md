# PoC: Solver controls deposit-address trigger prices, defeating the Lit price-impact check

Relay bug bounty report R-01. Run with Foundry (tested with forge 1.9.0):

```
forge test -vv
```

No setup, no network, no fork needed. All dependencies are vendored under `lib/`
(the settlement contracts are the unmodified sources from
`relayprotocol/relay-settlement` at commit `b2f3e0e`).

## What it proves (3/3 tests pass)

- **CONTROL** `test_control_onchainPricesRejectAttackMinimum`: with only routed
  currencies, `SignedPricingOracle` uses live on-chain $1/$1 prices and the Lit
  Action price-impact check (replicated verbatim from
  `packages/lit-deposit-address/src/attestation/index.ts`, `verifyOrderData`)
  REJECTS a 100 DAI minimum against a 1000 USDC deposit at 50 bps impact,
  while accepting the quoted 996 DAI.
- **ATTACK 1** `test_attack_forcedFallbackPassesAttackMinimum`: the same trigger
  with ONE extra unrouted currency forces the whole batch onto solver-signed
  prices (USDC=$0.05, DAI=$10, 1-year expiry). The trigger is recorded on-chain
  and the impact check now PASSES for the 100 DAI minimum. Nothing downstream
  can tell fallback prices from on-chain prices.
- **ATTACK 2** `test_attack_basicOracleNeedsNoSignature`: naming a
  `BasicPricingOracle` in `derivationFields.pricingOracle` binds arbitrary
  prices with NO signature at all; the impact check passes for the 100 DAI
  minimum.

## Setup notes

- `RelayPriceOracle` is the real contract, fed by a mock `IPriceFeedAdapter`
  returning canned $1 prices; the price-oracle precompile at `0x010002` is
  stubbed with `vm.etch` (the mock adapter ignores update data).
- The price-impact arithmetic is a line-for-line port of the Lit Action's
  `verifyOrderData` cross-multiplication.
- Local test only; nothing here touches mainnet.
