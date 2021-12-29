const bitcoin = require('bitcoinjs-lib');

module.exports = {
    mainnet : {
        xpriv1: 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
        xpriv2: 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
        xpub1: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
        xpub2: 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
        xpub3: 'xpub6E2Zaut1aNKyrKa3RNZ7WzucUgPNkpQoijZ5RQWbuty44oeEf1QiexBX4X7BC3do9apFkPULqjN8Yb6bxBCuKYR3usvGWc4HJiZo15AaDDi',
        network: bitcoin.networks.bitcoin,
    },
    testnet: {
        xpriv1: 'tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m',
        xpriv2: 'tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QC1vLT63TkjRssqJe4CvGNEC8DzW5AoPUw56D1Ayg6HY4oy8QZ9',
        xpub1: 'tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp',
        xpub2: 'tpubD8eQVK4Kdxg3gHrF62jGP7dKVCoYiEB8dFSpuTawkL5YxTus5j5pf83vaKnii4bc6v2NVEy81P2gYrJczYne3QNNwMTS53p5uzDyHvnw2jm',
        xpub3: 'tpubDEQC79hhHeHS87ktsZYCivEyooV2kCusGN9NmxZkFoiwp6JwjEFooPrMJZBxiYb2wVMAMxzDNqCBEmbDM349CysLyUfaC8iWtgACm43RQ18',
        network: bitcoin.networks.testnet,
    },
    path: '0/2',
    message : 'test message to sign',
    opcodes: {
        'OP_1': 1,
        'OP_2': 2,
        'OP_3': 3,
        'OP_4': 4,
        'OP_5': 5,
        'OP_6': 6,
        'OP_7': 7,
        'OP_8': 8,
        'OP_9': 9,
        'OP_20': 20,

    }
}

