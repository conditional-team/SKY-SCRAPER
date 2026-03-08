// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title NFTLending
 * @dev Training Contract #57 - NFT Lending & Floor Price Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. Floor Price Oracle Manipulation (NFTLEND-FLOOR-01)
 * 2. Appraisal Manipulation (NFTLEND-APPRAISAL-01)
 * 3. Collection-Wide Liquidation Cascade (NFTLEND-CASCADE-01)
 * 4. Rarity Score Gaming (NFTLEND-RARITY-01)
 * 5. Wash Trading Floor Inflation (NFTLEND-WASHTRADE-01)
 * 6. Stale NFT Valuation (NFTLEND-STALE-01)
 * 7. Royalty Fee Drain on Liquidation (NFTLEND-ROYALTY-01)
 * 8. Peer-to-Peer Offer Snipe (NFTLEND-P2PSNIPE-01)
 * 9. NFT Transfer During Loan (NFTLEND-TRANSFER-01)
 * 10. Interest Rate Spike (NFTLEND-RATESPIKE-01)
 * 11. Collateral Substitution (NFTLEND-SUBSTITUTE-01)
 * 12. Underwater Loan Griefing (NFTLEND-UNDERWATER-01)
 * 13. Flash Loan NFT Borrow (NFTLEND-FLASHNFT-01)
 * 14. Collection Rug Propagation (NFTLEND-RUG-01)
 * 15. Metadata Update Devalue (NFTLEND-METADATA-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): NFTLEND-*, NFT, floor price, liquidation
 * - Engine 2 (deep-semantic): valuation logic, loan mechanics
 * - Engine 13 (mev-analyzer): snipe, flash loan, wash trade
 * - Engine 3 (state-desync): stale valuation, oracle lag
 */

interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

interface INFTOracle {
    function getFloorPrice(address collection) external view returns (uint256);
    function getTokenValuation(address collection, uint256 tokenId) external view returns (uint256);
}

contract NFTLendingProtocol {
    struct Loan {
        address borrower;
        address collection;
        uint256 tokenId;
        uint256 principal;
        uint256 interest;
        uint256 startTime;
        uint256 duration;
        uint256 ltv; // basis points
        bool active;
        bool liquidated;
    }

    struct P2POffer {
        address lender;
        address collection;
        uint256 maxPrincipal;
        uint256 interestRate;
        uint256 duration;
        uint256 maxLTV;
        bool active;
    }

    mapping(uint256 => Loan) public loans;
    uint256 public nextLoanId;
    mapping(uint256 => P2POffer) public offers;
    uint256 public nextOfferId;
    
    INFTOracle public oracle;
    mapping(address => bool) public acceptedCollections;
    mapping(address => uint256) public collectionFloorOverride;
    
    uint256 public liquidationThreshold = 8000; // 80% LTV triggers liquidation
    uint256 public protocolFee = 250; // 2.5%
    address public owner;
    
    // Pool lending
    mapping(address => uint256) public poolDeposits;
    uint256 public totalPoolDeposits;
    uint256 public totalLoaned;

    constructor(address _oracle) {
        oracle = INFTOracle(_oracle);
        owner = msg.sender;
    }

    // ========== VULN 1: Floor Price Oracle Manipulation (NFTLEND-FLOOR-01) ==========

    // BUG #1: floor price from single DEX, manipulable with thin liquidity
    function borrow(
        address collection,
        uint256 tokenId,
        uint256 requestedAmount
    ) external returns (uint256 loanId) {
        require(acceptedCollections[collection], "not accepted");
        
        // VULN: single oracle source for floor price
        // attacker buys cheapest NFTs at inflated price → oracle reports high floor
        // → borrows max against own NFT → defaults, keeping borrowed funds
        uint256 floorPrice = oracle.getFloorPrice(collection);
        uint256 maxBorrow = floorPrice * liquidationThreshold / 10000;
        require(requestedAmount <= maxBorrow, "exceeds LTV");
        
        IERC721(collection).transferFrom(msg.sender, address(this), tokenId);
        
        loanId = nextLoanId++;
        loans[loanId] = Loan({
            borrower: msg.sender,
            collection: collection,
            tokenId: tokenId,
            principal: requestedAmount,
            interest: 0,
            startTime: block.timestamp,
            duration: 30 days,
            ltv: requestedAmount * 10000 / floorPrice,
            active: true,
            liquidated: false
        });
        
        totalLoaned += requestedAmount;
        payable(msg.sender).transfer(requestedAmount);
    }

    // ========== VULN 2: Appraisal Manipulation (NFTLEND-APPRAISAL-01) ==========

    // BUG #2: individual token valuation uses trait-based formula
    // attacker transfers traits or metadata to inflate specific token
    function borrowWithAppraisal(
        address collection,
        uint256 tokenId,
        uint256 requestedAmount
    ) external returns (uint256 loanId) {
        // VULN: token-specific valuation relies on oracle that reads on-chain traits
        // if collection allows trait updates, attacker inflates then reverts
        uint256 tokenValue = oracle.getTokenValuation(collection, tokenId);
        uint256 maxBorrow = tokenValue * liquidationThreshold / 10000;
        require(requestedAmount <= maxBorrow, "exceeds LTV");
        
        IERC721(collection).transferFrom(msg.sender, address(this), tokenId);
        loanId = nextLoanId++;
        loans[loanId] = Loan({
            borrower: msg.sender,
            collection: collection,
            tokenId: tokenId,
            principal: requestedAmount,
            interest: 0,
            startTime: block.timestamp,
            duration: 30 days,
            ltv: requestedAmount * 10000 / tokenValue,
            active: true,
            liquidated: false
        });
        totalLoaned += requestedAmount;
        payable(msg.sender).transfer(requestedAmount);
    }

    // ========== VULN 3: Collection-Wide Liquidation Cascade (NFTLEND-CASCADE-01) ==========

    // BUG #3: one large liquidation drops floor → triggers more liquidations
    function liquidate(uint256 loanId) external {
        Loan storage loan = loans[loanId];
        require(loan.active, "not active");
        
        uint256 currentFloor = oracle.getFloorPrice(loan.collection);
        uint256 currentLTV = loan.principal * 10000 / currentFloor;
        require(currentLTV > liquidationThreshold, "safe");
        
        // VULN: liquidation auction dumps NFT on market → floor drops further
        // cascade: liquidate → floor drops → more loans underwater → more liquidations
        loan.liquidated = true;
        loan.active = false;
        
        // Transfer NFT to liquidator
        IERC721(loan.collection).transferFrom(address(this), msg.sender, loan.tokenId);
        
        // Liquidator pays discounted debt
        uint256 discount = loan.principal * 90 / 100;
        require(msg.value >= discount, "insufficient payment");
        totalLoaned -= loan.principal;
    }

    // ========== VULN 4: Rarity Score Gaming (NFTLEND-RARITY-01) ==========

    mapping(address => mapping(uint256 => uint256)) public rarityScores;

    // BUG #4: rarity score updated by external oracle without freshness check
    function updateRarityScore(address collection, uint256 tokenId, uint256 score) external {
        require(msg.sender == owner, "not owner");
        // VULN: score can be set to any value, inflating collateral value
        // no verification against actual trait distribution
        rarityScores[collection][tokenId] = score;
    }

    // ========== VULN 5: Wash Trading Floor Inflation (NFTLEND-WASHTRADE-01) ==========

    // BUG #5: protocol uses last sale price as floor reference
    // attacker wash trades own NFTs at inflated price
    mapping(address => uint256) public lastSalePrice;

    function recordSale(address collection, uint256 price) external {
        // VULN: no verification that sale was arms-length
        // attacker trades with self at 10x real value
        lastSalePrice[collection] = price;
    }

    // ========== VULN 6: Stale NFT Valuation (NFTLEND-STALE-01) ==========

    // BUG #6: valuation cached and not refreshed before liquidation check
    function checkHealth(uint256 loanId) external view returns (bool healthy) {
        Loan storage loan = loans[loanId];
        // VULN: uses potentially stale floor price
        // collection could have crashed since last oracle update
        uint256 floor = oracle.getFloorPrice(loan.collection);
        return loan.principal * 10000 / floor <= liquidationThreshold;
    }

    // ========== VULN 7: Royalty Fee Drain on Liquidation (NFTLEND-ROYALTY-01) ==========

    // BUG #7: liquidation triggers NFT transfer, which pays royalties
    // royalty % eats into liquidation proceeds, making liquidation unprofitable
    function liquidateWithRoyalty(uint256 loanId) external {
        Loan storage loan = loans[loanId];
        // VULN: 10% royalty on transfer makes liquidation break-even at best
        // no one liquidates → bad debt accumulates
        uint256 royaltyFee = loan.principal * 1000 / 10000; // 10%
        // Liquidation proceeds: debt - royalty - gas = potentially negative
        loan.active = false;
        loan.liquidated = true;
    }

    // ========== VULN 8: Peer-to-Peer Offer Snipe (NFTLEND-P2PSNIPE-01) ==========

    // BUG #8: lender creates offer visible on-chain
    // attacker sees good offer, borrows with known-worthless NFT before legitimate borrower
    function createOffer(
        address collection,
        uint256 maxPrincipal,
        uint256 interestRate,
        uint256 duration
    ) external returns (uint256 offerId) {
        // VULN: offer params are public, front-runnable
        offerId = nextOfferId++;
        offers[offerId] = P2POffer({
            lender: msg.sender,
            collection: collection,
            maxPrincipal: maxPrincipal,
            interestRate: interestRate,
            duration: duration,
            maxLTV: liquidationThreshold,
            active: true
        });
    }

    function acceptOffer(uint256 offerId, uint256 tokenId) external {
        P2POffer storage offer = offers[offerId];
        require(offer.active, "inactive");
        // VULN: first-come-first-served, cheapest NFT in collection wins
        // attacker uses floor-priced NFT with known issues
        offer.active = false;
    }

    // ========== VULN 9: NFT Transfer During Loan (NFTLEND-TRANSFER-01) ==========

    // BUG #9: some NFT contracts have admin transfer functions
    // collection owner can move NFT out of lending protocol
    // (no code fix needed—inherent risk of custodial lending)

    // ========== VULN 10: Interest Rate Spike (NFTLEND-RATESPIKE-01) ==========

    uint256 public baseRate = 500; // 5% base
    uint256 public utilizationMultiplier = 10;

    // BUG #10: utilization-based interest rate spikes during high demand
    function getCurrentRate() public view returns (uint256) {
        uint256 utilization = totalLoaned * 10000 / (totalPoolDeposits + 1);
        // VULN: at 90% utilization, rate becomes 90 * 10 = 900% APR
        // existing borrowers can't afford to repay, forced into default
        return baseRate + utilization * utilizationMultiplier;
    }

    // ========== VULN 11: Collateral Substitution (NFTLEND-SUBSTITUTE-01) ==========

    // BUG #11: borrower can swap collateral NFT for a cheaper one
    function substituteCollateral(uint256 loanId, uint256 newTokenId) external {
        Loan storage loan = loans[loanId];
        require(loan.borrower == msg.sender, "not borrower");
        // VULN: no re-valuation on substitution
        // borrower swaps high-value collateral for cheap one
        IERC721(loan.collection).transferFrom(address(this), msg.sender, loan.tokenId);
        IERC721(loan.collection).transferFrom(msg.sender, address(this), newTokenId);
        loan.tokenId = newTokenId;
        // Should re-check LTV with new token's value
    }

    // ========== VULN 12: Underwater Loan Griefing (NFTLEND-UNDERWATER-01) ==========

    // BUG #12: anyone can extend underwater loan to prevent protocol from seizing
    function extendLoan(uint256 loanId) external payable {
        Loan storage loan = loans[loanId];
        require(loan.active, "not active");
        // VULN: anyone can pay interest to keep bad loan alive
        // prevents liquidation of strategic positions
        loan.interest += msg.value;
        loan.duration += 30 days;
    }

    // ========== VULN 13: Flash Loan NFT Borrow (NFTLEND-FLASHNFT-01) ==========

    // BUG #13: flash-borrow NFT to use as collateral
    function flashBorrowNFT(
        address collection,
        uint256 tokenId,
        bytes calldata data
    ) external {
        address originalOwner = IERC721(collection).ownerOf(tokenId);
        IERC721(collection).transferFrom(originalOwner, msg.sender, tokenId);
        
        // VULN: borrower uses NFT as collateral during callback
        // then returns the NFT, keeping the loan proceeds
        (bool ok, ) = msg.sender.call(data);
        require(ok, "callback failed");
        
        // Verify NFT returned
        require(IERC721(collection).ownerOf(tokenId) == originalOwner, "not returned");
        // But loan still exists with no collateral
    }

    // ========== VULN 14: Collection Rug Propagation (NFTLEND-RUG-01) ==========

    // BUG #14: if collection team rugs, all loans backed by that collection = bad debt
    function markCollectionDeprecated(address collection) external {
        require(msg.sender == owner);
        // VULN: existing loans not force-liquidated
        // bad debt accumulates until someone manually liquidates each loan
        acceptedCollections[collection] = false;
    }

    // ========== VULN 15: Metadata Update Devalue (NFTLEND-METADATA-01) ==========

    // BUG #15: dynamic NFT metadata can change, devaluing collateral post-loan
    // collection updates artwork/traits → value drops → protocol can't liquidate profitably
    function checkMetadataHash(address collection, uint256 tokenId, bytes32 expectedHash) external view returns (bool) {
        // VULN: no on-chain mechanism to lock metadata during loan period
        // metadata can change at any time, no re-valuation triggered
        return true; // always passes—no actual content check
    }

    // ========== Admin & Pool ==========

    function depositToPool() external payable {
        poolDeposits[msg.sender] += msg.value;
        totalPoolDeposits += msg.value;
    }

    function addCollection(address collection) external {
        require(msg.sender == owner);
        acceptedCollections[collection] = true;
    }

    receive() external payable {}
}
