#!/usr/bin/python3
import logging
import sys
import datetime
import re
import certstream

dois = "crypto|nft|boredape|boredapes|boredapez|yachtclub|punk|doodles|phunks|phunkz|apez|y00ts|looksrare|opensea|coinbase|binance|gemini|rarible|bitcoin|polygon|matic|magiceden|x2y2|doge|ethereum|wallet|token|blockchain|cryptocurrency|mint|1inch|88mph|aave|abyss|adhive|aelf|aeternity|aion|airtoken|airdrop|airswap|airdrop|akasha|apecoin|anatomia|ankr|antpool|anyswap|apexone|appcoins|aragon|arcblock|arionum|artoken|arweave|atomicwallet|auctus|augur|aventus|axieinfinity|axpire|azbit|azuki|badgerdao|bakkt|balancer|banca|bancor|bankera|beetoken|bestchange|bestexchange|bibox|binance|bitclave|bitaeon|bitbay|bitbox|bitcoin|bitcoinarmory|bitcointalk|bitdegree|bitfinex|bitflyer|bithomp|bitjob|bitmain|bitmex|bitpie|bitpro|bitstamp|bittorrent|bittrex|blender|blockarray|blockchain|blocklancer|blockstack|blockv|bluzelle|boson|boredapeyachtclub|brickblock|buzcoin|calchain|calibra|callisto|cardano|cashaa|casper|celsius|centratech|chainlink|changebank|changelly|cindicator|classicetherwallet|cobinhood|coinbase|coinbene|coindash|coindesk|coingecko|coinomi|cointal|cointelegraph|collabland|coolmansuniverse|compound|coolcats|crowdsale|crypterium|cryptobridge|cryptokitties|cryptonator|cryptopunks|curve|dmarket|daedalus|daostack|datawallet|datum|decentraland|deepbrain|delta|dentacoin|descentx|dfinity|dice2win|digitex|digitexfutures|dimensions|district0x|dmarket|docai|dogechain|dragon|duneanalytics|dxexchange|electrifyasia|electrum|elite888|elitetreum|eloncity|empowr|encrybit|enigma|enjin|envion|eqwity|etoro|ethconnect|etherbunny|etherdelta|etherparty|etherzero|ethereum|ethereumcv|ethernity|ethereal|etheroll|etherparty|etherscan|etherzero|ethplode|ethtools|exchange|exodus|fantom|fetchai|fintrux|flashblocks|forkdelta|fortunejack|foundation|ftx|fulcrum|fundrequest|funfair|galaxy|gambling|gameflip|gatcoin|gatehub|gdax|gemini|generator|geth|gifto|giveaway|gizer|gladius|globitex|gonetwork|golem|gonetwork|greenwallet|guarda|guardian|harvestfinance|havven|hederahashgraph|helbiz|hellogold|hellobloom|hitbtc|humaniq|icostats|idex|idice|iexec|indorse|innovamine|instadapp|investment|investments|ipsx|jaxx|jibrel|kickico|keepkey|kentra|keyfund|keytron|kodak|kraken|kucoin|kutix|kyber|lodgix|liverez|leadcoin|ledger|lendium|litecoin|localbitcoins|localetherwallet|localethereum|lottofinance|makerdao|malware|matic|medicalchain|medium|mercatox|metamask|metaverse|metronome|mining|mithril|mixer|mobius|monero|monetha|moonbirds|mooniswap|moonlet|multiconcept|mycrypto|myetherwallet|mymonero|magiceden|nft|nebulas|nexo|nexus|nicehash|nucleus|numerai|ocoin|odyssey|olympusdao|onchainmonkey|onerooftop|omisego|optimism|opensea|oracles|orchid|paidnetwork|pancakeswap|paxful|paxos|paypie|paytomat|perlin|pokerbox|policypal|polkadot|polkastarter|pollux|poloniex|polymath|polyswarm|ponzi|populous|powerledger|pooltogether|privatix|props|protos|pumapay|pumpkin|pundi|pundix|qlink|qtum|quantstamp|quark|quarkchain|realmarkets|raiden|rarible|recovery|redpulse|refereum|remme|rightmesh|ripio|ripple|rivetzintl|sai2dai|samorai|seele|selfkey|sense|sentinel|sether|shapeshift|shivom|singularitynet|sirinlabs|smartlands|sparkster|spectre|spectrocoin|staking|starbas|stellar|substratum|sudoswap|surety|sushi|swapy|swerve|switcheo|syncfab|synthetix|telcoin|telegram|telos|tenx|tesla|texacon|tezbox|tezos|thegraph|themis|thunderscore|tokenpocket|tomochain|tomocoin|tornado|trezor|trinity|trust|trust-trading|trustwallet|tubig|twitter|tzero|ubex|ubiq|uniswap|unocoin|upfiring|uphold|utrust|vechain|viberate|wachain|wallbtc|wallet|wanchain|waves|web-wallet|webminer|webwallet|wepower|whitecoin|worldofbattles|worldofwoman|staking|onchain|moonbird|vitalik|uniswap|yobit|zapper|zcash|zedxe|zeex|zillet|zilliqa|zillow|zksync|xn|p4wn"

def print_callback(message, context):
    logging.debug("Message -> {}".format(message))

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        if len(all_domains) == 0:
            domain = "NULL"
        else:
            domain = all_domains[0]

        found = re.findall(dois,domain)
        if len(tt) > 0:
            sys.stdout.write(u"[{}] {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), f"trigger : {found} SITE ", ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
            sys.stdout.flush()

logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
