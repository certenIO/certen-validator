{
    "recordType": "minorBlock",
    "index": 134530,
    "time": "2026-01-18T10:25:37.000Z",
    "source": "acc://dn.acme",
    "entries": {
        "recordType": "range",
        "records": [
            {
                "recordType": "chainEntry",
                "account": "acc://dn.acme/anchors",
                "name": "anchor(bvn1)-bpt",
                "type": "anchor",
                "index": 171833,
                "entry": "f2347a547699f4b4a4c27eb06081e49d6172ba95216c304b208700f850737d32"
            },
            {
                "recordType": "chainEntry",
                "account": "acc://dn.acme/anchors",
                "name": "anchor(bvn1)-root",
                "type": "anchor",
                "index": 171833,
                "entry": "261376826c041ccf6fbba744711c0714d4281384343bae45c28943cdbcad9496"
            },
            {
                "recordType": "chainEntry",
                "account": "acc://dn.acme/anchors",
                "name": "anchor(bvn3)-bpt",
                "type": "anchor",
                "index": 126942,
                "entry": "13f7816662ba052113e5ef96f8343c61526f1396bc4c48cfea4b9b19fe934562"
            },
            {
                "recordType": "chainEntry",
                "account": "acc://dn.acme/anchors",
                "name": "anchor(bvn3)-root",
                "type": "anchor",
                "index": 126942,
                "entry": "2b920f6c94fabf4dab5de259801bce94e12f889dcf4a492eadece5ba07593307"
            },
            {
                "recordType": "chainEntry",
                "account": "acc://dn.acme/anchors",
                "name": "anchor(directory)-bpt",
                "type": "anchor",
                "index": 134005,
                "entry": "1c666028dec4cfaaf20ab2b8172d96e8c28d0fe785a3bb8113291b247676d3a4"
            },
            {
                "recordType": "chainEntry",
                "account": "acc://dn.acme/anchors",
                "name": "anchor(directory)-root",
                "type": "anchor",
                "index": 134005,
                "entry": "a44bf548f07e7f0aeeff6f3348d375800d01296a0a123d0f3da7ca531722fe97"
            },
            {
                "recordType": "chainEntry",
                "account": "acc://dn.acme/anchors",
                "name": "anchor-sequence",
                "type": "transaction",
                "index": 134006,
                "entry": "3b4cdfb91186f243ac2e9eaa450d92d8e5dc31f1f2700f53041bf1e24f9b6f99",
                "value": {
                    "recordType": "message",
                    "id": "acc://3b4cdfb91186f243ac2e9eaa450d92d8e5dc31f1f2700f53041bf1e24f9b6f99@unknown",
                    "message": {
                        "type": "transaction",
                        "transaction": {
                            "header": {},
                            "body": {
                                "type": "directoryAnchor",
                                "source": "acc://dn.acme",
                                "minorBlockIndex": 134529,
                                "rootChainIndex": 1124856,
                                "rootChainAnchor": "cf5d62813fb1de54fa33159e467727e7575b39525e459a5dcd8e90d126950d49",
                                "stateTreeAnchor": "1538ccb730b6af5e9a66989cd9056cbb0e5e59fe307fb877be0443f5ae733822",
                                "receipts": [
                                    {
                                        "anchor": {
                                            "source": "acc://bvn-BVN1.acme",
                                            "minorBlockIndex": 171832,
                                            "rootChainIndex": 1401607,
                                            "rootChainAnchor": "1111678e2df2e1e014fbe19428abb73512c93eea24497eab670c77eb58c52cf3",
                                            "stateTreeAnchor": "b2fa5df7a837bc4a6edeff1759e4fa676d676108ff3410d0c88e68bdaa8a379d"
                                        },
                                        "rootChainReceipt": {
                                            "start": "1111678e2df2e1e014fbe19428abb73512c93eea24497eab670c77eb58c52cf3",
                                            "startIndex": 171831,
                                            "end": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d",
                                            "endIndex": 171832,
                                            "anchor": "cf5d62813fb1de54fa33159e467727e7575b39525e459a5dcd8e90d126950d49",
                                            "entries": [
                                                {
                                                    "hash": "a3ee0784384a61874f04fffcc238997aa78ec1aa2f95e6331669e0ce5d5a6b03"
                                                },
                                                {
                                                    "hash": "308fa76ff561d31f49e79c7ce43397798c10ef323588218d103b41d3a2306fd2"
                                                },
                                                {
                                                    "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d"
                                                },
                                                {
                                                    "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                },
                                                {
                                                    "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                },
                                                {
                                                    "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                },
                                                {
                                                    "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                },
                                                {
                                                    "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                },
                                                {
                                                    "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                },
                                                {
                                                    "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                },
                                                {
                                                    "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                },
                                                {
                                                    "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                },
                                                {
                                                    "hash": "76c8dfee08c6eb1b5b9163d8c661184fd7c0fd0a91d9968810c1a1936a4e4d32"
                                                },
                                                {
                                                    "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "21e3e5538a5ac1f507fd434a9e61a3e8493d8dc58a6ca16b794581d26fe674b4"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "448627c5e6a22394cc37c7e3570d5d4f7db6ff4c83d537a0101aab11984f1702"
                                                },
                                                {
                                                    "hash": "b7cc321c86a05b2036203f3dacc1437693c7e3e706da266c5fb72c93fb5e9a56"
                                                },
                                                {
                                                    "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                },
                                                {
                                                    "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                },
                                                {
                                                    "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                },
                                                {
                                                    "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                },
                                                {
                                                    "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                },
                                                {
                                                    "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                },
                                                {
                                                    "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                },
                                                {
                                                    "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                }
                                            ]
                                        }
                                    },
                                    {
                                        "anchor": {
                                            "source": "acc://bvn-BVN1.acme",
                                            "minorBlockIndex": 171833,
                                            "rootChainIndex": 1401616,
                                            "rootChainAnchor": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d",
                                            "stateTreeAnchor": "7d14b3d55421d39e2ca3ef29376e771dd2c1555ed849d60f0ba8328a2c3c53cf"
                                        },
                                        "rootChainReceipt": {
                                            "start": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d",
                                            "startIndex": 171832,
                                            "end": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d",
                                            "endIndex": 171832,
                                            "anchor": "cf5d62813fb1de54fa33159e467727e7575b39525e459a5dcd8e90d126950d49",
                                            "entries": [
                                                {
                                                    "hash": "dcf6fe6c2fd0dce3c1f4ebcebb22c1476b1d3239640785328db7359ac7045bd6"
                                                },
                                                {
                                                    "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                },
                                                {
                                                    "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                },
                                                {
                                                    "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                },
                                                {
                                                    "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                },
                                                {
                                                    "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                },
                                                {
                                                    "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                },
                                                {
                                                    "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                },
                                                {
                                                    "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                },
                                                {
                                                    "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                },
                                                {
                                                    "hash": "76c8dfee08c6eb1b5b9163d8c661184fd7c0fd0a91d9968810c1a1936a4e4d32"
                                                },
                                                {
                                                    "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "21e3e5538a5ac1f507fd434a9e61a3e8493d8dc58a6ca16b794581d26fe674b4"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "448627c5e6a22394cc37c7e3570d5d4f7db6ff4c83d537a0101aab11984f1702"
                                                },
                                                {
                                                    "hash": "b7cc321c86a05b2036203f3dacc1437693c7e3e706da266c5fb72c93fb5e9a56"
                                                },
                                                {
                                                    "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                },
                                                {
                                                    "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                },
                                                {
                                                    "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                },
                                                {
                                                    "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                },
                                                {
                                                    "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                },
                                                {
                                                    "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                },
                                                {
                                                    "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                },
                                                {
                                                    "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                }
                                            ]
                                        }
                                    },
                                    {
                                        "anchor": {
                                            "source": "acc://dn.acme",
                                            "minorBlockIndex": 134527,
                                            "rootChainIndex": 1124840,
                                            "rootChainAnchor": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                            "stateTreeAnchor": "b6097c12c42c4f86dc18da6e3dabf97e62af2589ecdad1c325077b50d7ecd647"
                                        },
                                        "rootChainReceipt": {
                                            "start": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                            "startIndex": 134004,
                                            "end": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                            "endIndex": 134004,
                                            "anchor": "cf5d62813fb1de54fa33159e467727e7575b39525e459a5dcd8e90d126950d49",
                                            "entries": [
                                                {
                                                    "hash": "a8b29c45c4d249478fceb2aecb2420873fe39afca91dc492dbe95820f20d62ad"
                                                },
                                                {
                                                    "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                },
                                                {
                                                    "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                },
                                                {
                                                    "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                },
                                                {
                                                    "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                },
                                                {
                                                    "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                },
                                                {
                                                    "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                },
                                                {
                                                    "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                },
                                                {
                                                    "hash": "46b3c617f44fa1554262a8fd6f07451773126203a2097220d71a27816ae453ce"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "00873a4930eef9cedf03a631af84f97049525c46ac01147906dc132374b8c039"
                                                },
                                                {
                                                    "hash": "eed1033f2c512f8c601b9cb6ef137a7582f9568154dfff35949222f751aa9a5d"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "448627c5e6a22394cc37c7e3570d5d4f7db6ff4c83d537a0101aab11984f1702"
                                                },
                                                {
                                                    "hash": "b7cc321c86a05b2036203f3dacc1437693c7e3e706da266c5fb72c93fb5e9a56"
                                                },
                                                {
                                                    "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                },
                                                {
                                                    "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                },
                                                {
                                                    "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                },
                                                {
                                                    "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                },
                                                {
                                                    "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                },
                                                {
                                                    "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                },
                                                {
                                                    "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                },
                                                {
                                                    "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                }
                                            ]
                                        }
                                    }
                                ],
                                "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                            }
                        }
                    },
                    "status": "remote",
                    "result": {
                        "type": "unknown"
                    },
                    "produced": {
                        "recordType": "range",
                        "start": 0,
                        "total": 0
                    },
                    "cause": {
                        "recordType": "range",
                        "start": 0,
                        "total": 0
                    },
                    "signatures": {
                        "recordType": "range",
                        "start": 0,
                        "total": 0
                    },
                    "sequence": {
                        "type": "sequenced"
                    }
                }
            },
            {
                "recordType": "chainEntry",
                "account": "acc://dn.acme/anchors",
                "name": "main",
                "type": "transaction",
                "index": 432939,
                "entry": "1b9ca58a0bbd5c38855afda522c335e96abf90fa2e2ed177fff1d2196285b813",
                "value": {
                    "recordType": "message",
                    "id": "acc://1b9ca58a0bbd5c38855afda522c335e96abf90fa2e2ed177fff1d2196285b813@dn.acme/anchors",
                    "message": {
                        "type": "transaction",
                        "transaction": {
                            "header": {
                                "principal": "acc://dn.acme/anchors"
                            },
                            "body": {
                                "type": "blockValidatorAnchor",
                                "source": "acc://bvn-BVN1.acme",
                                "minorBlockIndex": 171834,
                                "rootChainIndex": 1401625,
                                "rootChainAnchor": "261376826c041ccf6fbba744711c0714d4281384343bae45c28943cdbcad9496",
                                "stateTreeAnchor": "f2347a547699f4b4a4c27eb06081e49d6172ba95216c304b208700f850737d32"
                            }
                        }
                    },
                    "status": "delivered",
                    "result": {
                        "type": "unknown"
                    },
                    "received": 134530,
                    "produced": {
                        "recordType": "range",
                        "start": 0,
                        "total": 0
                    },
                    "cause": {
                        "recordType": "range",
                        "records": [
                            {
                                "recordType": "txID",
                                "value": "acc://98082889f5c97960fd5899744284b473675b0d29d478c5fb5a26c5f8a68a4dc0@dn.acme"
                            }
                        ],
                        "start": 0,
                        "total": 1
                    },
                    "signatures": {
                        "recordType": "range",
                        "records": [
                            {
                                "recordType": "signatureSet",
                                "account": {
                                    "type": "anchorLedger",
                                    "url": "acc://dn.acme/anchors",
                                    "minorBlockSequenceNumber": 134161,
                                    "majorBlockIndex": 9,
                                    "majorBlockTime": "2026-01-18T00:00:01.000Z",
                                    "sequence": [
                                        {
                                            "url": "acc://bvn-BVN1.acme",
                                            "received": 172029,
                                            "delivered": 172029
                                        },
                                        {
                                            "url": "acc://bvn-BVN2.acme",
                                            "received": 156,
                                            "delivered": 156
                                        },
                                        {
                                            "url": "acc://bvn-BVN3.acme",
                                            "received": 127082,
                                            "delivered": 127082
                                        },
                                        {
                                            "url": "acc://dn.acme",
                                            "received": 134158,
                                            "delivered": 134158
                                        }
                                    ]
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "message",
                                            "id": "acc://4fa6e752cfc2ab96828a11294bf8fd5482b8a66ebba098f0333cc365f1c82953@dn.acme/network",
                                            "message": {
                                                "type": "blockAnchor",
                                                "signature": {
                                                    "type": "ed25519",
                                                    "publicKey": "51fe2dbfe2a3005f2ab03a3177da7286870ea238d3d74f688043e2ea0b470640",
                                                    "signature": "6bd76ad576deebc8bd86633a3e7f5429bca62189296fb6a683e42e7e5d832077297c607a60262adbac48c8b163b1f29c7e227558e65acb4432aa30adbc667d0d",
                                                    "signer": "acc://dn.acme/network",
                                                    "timestamp": 1768731938572,
                                                    "transactionHash": "98082889f5c97960fd5899744284b473675b0d29d478c5fb5a26c5f8a68a4dc0"
                                                },
                                                "anchor": {
                                                    "type": "sequenced",
                                                    "message": {
                                                        "type": "transaction",
                                                        "transaction": {
                                                            "header": {
                                                                "principal": "acc://dn.acme/anchors"
                                                            },
                                                            "body": {
                                                                "type": "blockValidatorAnchor",
                                                                "source": "acc://bvn-BVN1.acme",
                                                                "minorBlockIndex": 171834,
                                                                "rootChainIndex": 1401625,
                                                                "rootChainAnchor": "261376826c041ccf6fbba744711c0714d4281384343bae45c28943cdbcad9496",
                                                                "stateTreeAnchor": "f2347a547699f4b4a4c27eb06081e49d6172ba95216c304b208700f850737d32"
                                                            }
                                                        }
                                                    },
                                                    "source": "acc://bvn-BVN1.acme",
                                                    "destination": "acc://dn.acme",
                                                    "number": 171834
                                                }
                                            }
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                }
                            }
                        ],
                        "start": 0,
                        "total": 1
                    },
                    "sequence": {
                        "type": "sequenced",
                        "message": {
                            "type": "transaction",
                            "transaction": {
                                "header": {
                                    "principal": "acc://dn.acme/anchors"
                                },
                                "body": {
                                    "type": "blockValidatorAnchor",
                                    "source": "acc://bvn-BVN1.acme",
                                    "minorBlockIndex": 171834,
                                    "rootChainIndex": 1401625,
                                    "rootChainAnchor": "261376826c041ccf6fbba744711c0714d4281384343bae45c28943cdbcad9496",
                                    "stateTreeAnchor": "f2347a547699f4b4a4c27eb06081e49d6172ba95216c304b208700f850737d32"
                                }
                            }
                        },
                        "source": "acc://bvn-BVN1.acme",
                        "destination": "acc://dn.acme",
                        "number": 171834
                    }
                }
            },
            {
                "recordType": "chainEntry",
                "account": "acc://dn.acme/anchors",
                "name": "signature",
                "type": "transaction",
                "index": 700950,
                "entry": "306907582c99e8fef21fb71938ed892ec9416d4e71cd087b6d1da3f8a6e81b08",
                "value": {
                    "recordType": "message",
                    "id": "acc://306907582c99e8fef21fb71938ed892ec9416d4e71cd087b6d1da3f8a6e81b08@dn.acme/network",
                    "message": {
                        "type": "blockAnchor",
                        "signature": {
                            "type": "ed25519",
                            "publicKey": "51fe2dbfe2a3005f2ab03a3177da7286870ea238d3d74f688043e2ea0b470640",
                            "signature": "4685b3ca211f82d7464184c3bebbffe6bbe22a361f90be2f47f24e634830c6b1d16ab36be98fd0a232240ae2bde7ce7b3c30aaab2835036fa29eb2718d7ab409",
                            "signer": "acc://dn.acme/network",
                            "timestamp": 1768731938921,
                            "transactionHash": "f1124fd4906be71f911a4903b7536f22c2889aeee4419d04f30e76161e6d98be"
                        },
                        "anchor": {
                            "type": "sequenced",
                            "message": {
                                "type": "transaction",
                                "transaction": {
                                    "header": {
                                        "principal": "acc://dn.acme/anchors"
                                    },
                                    "body": {
                                        "type": "directoryAnchor",
                                        "source": "acc://dn.acme",
                                        "minorBlockIndex": 134528,
                                        "rootChainIndex": 1124849,
                                        "rootChainAnchor": "a44bf548f07e7f0aeeff6f3348d375800d01296a0a123d0f3da7ca531722fe97",
                                        "stateTreeAnchor": "1c666028dec4cfaaf20ab2b8172d96e8c28d0fe785a3bb8113291b247676d3a4",
                                        "receipts": [
                                            {
                                                "anchor": {
                                                    "source": "acc://bvn-BVN3.acme",
                                                    "minorBlockIndex": 172228,
                                                    "rootChainIndex": 795677,
                                                    "rootChainAnchor": "cc0ed1da3f2234f9d8e5f43902fb75afa25cf48e216bbb09998afdaf2f582be3",
                                                    "stateTreeAnchor": "4dcddaf33e84c9bf54230ab3ce11be7a803ef1c1d07e51649bf595aa2fcb0729"
                                                },
                                                "rootChainReceipt": {
                                                    "start": "cc0ed1da3f2234f9d8e5f43902fb75afa25cf48e216bbb09998afdaf2f582be3",
                                                    "startIndex": 126940,
                                                    "end": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                                    "endIndex": 126941,
                                                    "anchor": "a44bf548f07e7f0aeeff6f3348d375800d01296a0a123d0f3da7ca531722fe97",
                                                    "entries": [
                                                        {
                                                            "right": true,
                                                            "hash": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7"
                                                        },
                                                        {
                                                            "hash": "9bd6d5e4abe7275af61702ebae99697020702bbd1d72535fa560842ff90fbe6a"
                                                        },
                                                        {
                                                            "hash": "c545b652f3c6c46a40eeaefef1c5e7ae410311aa11b63586391faabcf93b4a22"
                                                        },
                                                        {
                                                            "hash": "426a17720ddcbbe98982b03669954b71f4305394e823a06d50185f49b6e87dbe"
                                                        },
                                                        {
                                                            "hash": "c4136034fc8e84bf01150e48e6004d70d07f3029a798c02b4e88b2634608807c"
                                                        },
                                                        {
                                                            "hash": "337cf6886f0179f3d6a8a6aa550167695a7e45596f2675fd400de3d90a77777a"
                                                        },
                                                        {
                                                            "hash": "9e5e0cedbde8aaca69bd73b305a5157fa8929ee3facf706c86627c7064ec1767"
                                                        },
                                                        {
                                                            "hash": "4472fdbcfbcad5209f7e2a2a8c009e35dac0d03e53d48a484aeaeec3c6b5d993"
                                                        },
                                                        {
                                                            "hash": "cf69c7387abc3e14c39f96c624758a1dd335caca47147ac45457a47283d91ecb"
                                                        },
                                                        {
                                                            "hash": "106a563245495fbaa118cb2ca4274fea45821ec186070c928c9415da1b0621cf"
                                                        },
                                                        {
                                                            "hash": "85a44f2ca3ec5e3dcf59cbe468fae38269c4cb0c68d8aebc72a2b73a7fc4f354"
                                                        },
                                                        {
                                                            "hash": "d3f1f628a34dc36a35ee725601a468bf4d75179e65a36070d8d222e73a96a332"
                                                        },
                                                        {
                                                            "hash": "40bd99969dc9e74245243ce33675fa226fe141530c763f1c0a0c69fe0e340b78"
                                                        },
                                                        {
                                                            "hash": "b2ff0c192d92053f4f102174f192957eb4c6f5bc078e64b0990a53cdba92392a"
                                                        },
                                                        {
                                                            "right": true,
                                                            "hash": "fe24aa1185b59c050c7e1f9c046c69a65bf2b05900ac0145d5eed5cb06fca7a9"
                                                        },
                                                        {
                                                            "right": true,
                                                            "hash": "3ae91a3ef4198046f5aeb4b507e939a5987d234f98706f7e482027bfb1fb68b8"
                                                        },
                                                        {
                                                            "hash": "e1e9f8a0d8ab6cd192e8b175b2ce52064e9ac8061287b76e56cb74083b799cd4"
                                                        },
                                                        {
                                                            "hash": "4722bdb5b15724125e1e916f555cded4977d820abed3775c904d6395e6b9146a"
                                                        },
                                                        {
                                                            "right": true,
                                                            "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                                        },
                                                        {
                                                            "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                        },
                                                        {
                                                            "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                        },
                                                        {
                                                            "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                        },
                                                        {
                                                            "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                        },
                                                        {
                                                            "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                        },
                                                        {
                                                            "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                        },
                                                        {
                                                            "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                        },
                                                        {
                                                            "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                        }
                                                    ]
                                                }
                                            },
                                            {
                                                "anchor": {
                                                    "source": "acc://bvn-BVN1.acme",
                                                    "minorBlockIndex": 171831,
                                                    "rootChainIndex": 1401602,
                                                    "rootChainAnchor": "a3ee0784384a61874f04fffcc238997aa78ec1aa2f95e6331669e0ce5d5a6b03",
                                                    "stateTreeAnchor": "7faba59bd7c1029021869b3192d5f9d39be30939aaf4fbed6c998ad4e6295148"
                                                },
                                                "rootChainReceipt": {
                                                    "start": "a3ee0784384a61874f04fffcc238997aa78ec1aa2f95e6331669e0ce5d5a6b03",
                                                    "startIndex": 171830,
                                                    "end": "a3ee0784384a61874f04fffcc238997aa78ec1aa2f95e6331669e0ce5d5a6b03",
                                                    "endIndex": 171830,
                                                    "anchor": "a44bf548f07e7f0aeeff6f3348d375800d01296a0a123d0f3da7ca531722fe97",
                                                    "entries": [
                                                        {
                                                            "hash": "308fa76ff561d31f49e79c7ce43397798c10ef323588218d103b41d3a2306fd2"
                                                        },
                                                        {
                                                            "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                        },
                                                        {
                                                            "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                        },
                                                        {
                                                            "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                        },
                                                        {
                                                            "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                        },
                                                        {
                                                            "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                        },
                                                        {
                                                            "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                        },
                                                        {
                                                            "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                        },
                                                        {
                                                            "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                        },
                                                        {
                                                            "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                        },
                                                        {
                                                            "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                        },
                                                        {
                                                            "right": true,
                                                            "hash": "382834eb61ce6964bb2b8bacce286fe1a414394d046ea7c10cd243473d1ddd3d"
                                                        },
                                                        {
                                                            "hash": "efee7165f1748d7f8514d710d2946cc500db0fafeaccafe88d67844d4581e762"
                                                        },
                                                        {
                                                            "right": true,
                                                            "hash": "5e203b4e99e7b5ccd1b457d9844e658d27b287e308c9f034bdac3ad5bdfa0c7d"
                                                        },
                                                        {
                                                            "hash": "4722bdb5b15724125e1e916f555cded4977d820abed3775c904d6395e6b9146a"
                                                        },
                                                        {
                                                            "right": true,
                                                            "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                                        },
                                                        {
                                                            "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                        },
                                                        {
                                                            "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                        },
                                                        {
                                                            "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                        },
                                                        {
                                                            "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                        },
                                                        {
                                                            "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                        },
                                                        {
                                                            "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                        },
                                                        {
                                                            "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                        },
                                                        {
                                                            "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                        }
                                                    ]
                                                }
                                            },
                                            {
                                                "anchor": {
                                                    "source": "acc://dn.acme",
                                                    "minorBlockIndex": 134526,
                                                    "rootChainIndex": 1124831,
                                                    "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                    "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a"
                                                },
                                                "rootChainReceipt": {
                                                    "start": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                    "startIndex": 134003,
                                                    "end": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                    "endIndex": 134003,
                                                    "anchor": "a44bf548f07e7f0aeeff6f3348d375800d01296a0a123d0f3da7ca531722fe97",
                                                    "entries": [
                                                        {
                                                            "hash": "e312f39d2913ede4b010f20ac2186c5c7db5b26cacc9c0569e5ca6b8075c35a4"
                                                        },
                                                        {
                                                            "hash": "f4b9b8af5cc1d0dc05f1edc20680f60684521c2284947208cd59b6cad4e64527"
                                                        },
                                                        {
                                                            "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                        },
                                                        {
                                                            "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                        },
                                                        {
                                                            "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                        },
                                                        {
                                                            "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                        },
                                                        {
                                                            "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                        },
                                                        {
                                                            "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                        },
                                                        {
                                                            "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                        },
                                                        {
                                                            "right": true,
                                                            "hash": "b6e10d5e0e50dcfde50bea6cf32718c0238ee4aec0d3a60fa947cf27564035b3"
                                                        },
                                                        {
                                                            "hash": "0528b4ba0176ed5e73968e569da10a2a615d3c48e928aff5fa886b0f3fe42f05"
                                                        },
                                                        {
                                                            "hash": "e1e9f8a0d8ab6cd192e8b175b2ce52064e9ac8061287b76e56cb74083b799cd4"
                                                        },
                                                        {
                                                            "hash": "4722bdb5b15724125e1e916f555cded4977d820abed3775c904d6395e6b9146a"
                                                        },
                                                        {
                                                            "right": true,
                                                            "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                                        },
                                                        {
                                                            "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                        },
                                                        {
                                                            "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                        },
                                                        {
                                                            "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                        },
                                                        {
                                                            "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                        },
                                                        {
                                                            "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                        },
                                                        {
                                                            "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                        },
                                                        {
                                                            "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                        },
                                                        {
                                                            "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                        }
                                                    ]
                                                }
                                            },
                                            {
                                                "anchor": {
                                                    "source": "acc://bvn-BVN3.acme",
                                                    "minorBlockIndex": 172229,
                                                    "rootChainIndex": 795683,
                                                    "rootChainAnchor": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                                    "stateTreeAnchor": "3a7aeed93b2b5c1d04dbe556d112f1272c38f97499f9341e11c590addea40fc1"
                                                },
                                                "rootChainReceipt": {
                                                    "start": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                                    "startIndex": 126941,
                                                    "end": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                                    "endIndex": 126941,
                                                    "anchor": "a44bf548f07e7f0aeeff6f3348d375800d01296a0a123d0f3da7ca531722fe97",
                                                    "entries": [
                                                        {
                                                            "hash": "cc0ed1da3f2234f9d8e5f43902fb75afa25cf48e216bbb09998afdaf2f582be3"
                                                        },
                                                        {
                                                            "hash": "9bd6d5e4abe7275af61702ebae99697020702bbd1d72535fa560842ff90fbe6a"
                                                        },
                                                        {
                                                            "hash": "c545b652f3c6c46a40eeaefef1c5e7ae410311aa11b63586391faabcf93b4a22"
                                                        },
                                                        {
                                                            "hash": "426a17720ddcbbe98982b03669954b71f4305394e823a06d50185f49b6e87dbe"
                                                        },
                                                        {
                                                            "hash": "c4136034fc8e84bf01150e48e6004d70d07f3029a798c02b4e88b2634608807c"
                                                        },
                                                        {
                                                            "hash": "337cf6886f0179f3d6a8a6aa550167695a7e45596f2675fd400de3d90a77777a"
                                                        },
                                                        {
                                                            "hash": "9e5e0cedbde8aaca69bd73b305a5157fa8929ee3facf706c86627c7064ec1767"
                                                        },
                                                        {
                                                            "hash": "4472fdbcfbcad5209f7e2a2a8c009e35dac0d03e53d48a484aeaeec3c6b5d993"
                                                        },
                                                        {
                                                            "hash": "cf69c7387abc3e14c39f96c624758a1dd335caca47147ac45457a47283d91ecb"
                                                        },
                                                        {
                                                            "hash": "106a563245495fbaa118cb2ca4274fea45821ec186070c928c9415da1b0621cf"
                                                        },
                                                        {
                                                            "hash": "85a44f2ca3ec5e3dcf59cbe468fae38269c4cb0c68d8aebc72a2b73a7fc4f354"
                                                        },
                                                        {
                                                            "hash": "d3f1f628a34dc36a35ee725601a468bf4d75179e65a36070d8d222e73a96a332"
                                                        },
                                                        {
                                                            "hash": "40bd99969dc9e74245243ce33675fa226fe141530c763f1c0a0c69fe0e340b78"
                                                        },
                                                        {
                                                            "hash": "b2ff0c192d92053f4f102174f192957eb4c6f5bc078e64b0990a53cdba92392a"
                                                        },
                                                        {
                                                            "right": true,
                                                            "hash": "fe24aa1185b59c050c7e1f9c046c69a65bf2b05900ac0145d5eed5cb06fca7a9"
                                                        },
                                                        {
                                                            "right": true,
                                                            "hash": "3ae91a3ef4198046f5aeb4b507e939a5987d234f98706f7e482027bfb1fb68b8"
                                                        },
                                                        {
                                                            "hash": "e1e9f8a0d8ab6cd192e8b175b2ce52064e9ac8061287b76e56cb74083b799cd4"
                                                        },
                                                        {
                                                            "hash": "4722bdb5b15724125e1e916f555cded4977d820abed3775c904d6395e6b9146a"
                                                        },
                                                        {
                                                            "right": true,
                                                            "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                                        },
                                                        {
                                                            "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                        },
                                                        {
                                                            "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                        },
                                                        {
                                                            "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                        },
                                                        {
                                                            "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                        },
                                                        {
                                                            "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                        },
                                                        {
                                                            "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                        },
                                                        {
                                                            "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                        },
                                                        {
                                                            "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                        }
                                                    ]
                                                }
                                            }
                                        ],
                                        "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                    }
                                }
                            },
                            "source": "acc://dn.acme",
                            "destination": "acc://dn.acme",
                            "number": 134006
                        }
                    },
                    "status": "delivered",
                    "result": {
                        "type": "unknown"
                    },
                    "received": 134530,
                    "produced": {
                        "recordType": "range",
                        "records": [
                            {
                                "recordType": "txID",
                                "value": "acc://06653d8cf2638c082c5ee954d555fc1606df1e97aea1f881191dbb3d110e7720@dn.acme/network"
                            },
                            {
                                "recordType": "txID",
                                "value": "acc://f1124fd4906be71f911a4903b7536f22c2889aeee4419d04f30e76161e6d98be@dn.acme"
                            }
                        ],
                        "start": 0,
                        "total": 2
                    },
                    "cause": {
                        "recordType": "range",
                        "start": 0,
                        "total": 0
                    },
                    "signatures": {
                        "recordType": "range",
                        "start": 0,
                        "total": 0
                    },
                    "sequence": {
                        "type": "sequenced"
                    }
                }
            }
        ],
        "start": 0,
        "total": 9
    },
    "anchored": {
        "recordType": "range",
        "records": [
            {
                "recordType": "minorBlock",
                "index": 172231,
                "time": "2026-01-18T10:25:32.000Z",
                "source": "acc://bvn-BVN3.acme",
                "entries": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "chainEntry",
                            "account": "acc://bvn-BVN3.acme/anchors",
                            "name": "anchor(directory)-bpt",
                            "type": "anchor",
                            "index": 134003,
                            "entry": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a"
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://bvn-BVN3.acme/anchors",
                            "name": "anchor(directory)-root",
                            "type": "anchor",
                            "index": 134003,
                            "entry": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6"
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://bvn-BVN3.acme/anchors",
                            "name": "main",
                            "type": "transaction",
                            "index": 134004,
                            "entry": "b4bca7ad379a94c1f438b0c1f32a9b82ef7ef25c47539194bd9d8d9b6f11b920",
                            "value": {
                                "recordType": "message",
                                "id": "acc://b4bca7ad379a94c1f438b0c1f32a9b82ef7ef25c47539194bd9d8d9b6f11b920@bvn-BVN3.acme/anchors",
                                "message": {
                                    "type": "transaction",
                                    "transaction": {
                                        "header": {
                                            "principal": "acc://bvn-BVN3.acme/anchors"
                                        },
                                        "body": {
                                            "type": "directoryAnchor",
                                            "source": "acc://dn.acme",
                                            "minorBlockIndex": 134526,
                                            "rootChainIndex": 1124831,
                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                            "receipts": [
                                                {
                                                    "anchor": {
                                                        "source": "acc://bvn-BVN1.acme",
                                                        "minorBlockIndex": 171829,
                                                        "rootChainIndex": 1401584,
                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                    },
                                                    "rootChainReceipt": {
                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                        "startIndex": 171828,
                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                        "endIndex": 171828,
                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                        "entries": [
                                                            {
                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                            },
                                                            {
                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                            },
                                                            {
                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                            },
                                                            {
                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                            },
                                                            {
                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                            },
                                                            {
                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                            },
                                                            {
                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                            },
                                                            {
                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                            },
                                                            {
                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                            },
                                                            {
                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                            },
                                                            {
                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                            },
                                                            {
                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                            },
                                                            {
                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                            },
                                                            {
                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                            },
                                                            {
                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                            },
                                                            {
                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                            },
                                                            {
                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                            },
                                                            {
                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                            },
                                                            {
                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                            },
                                                            {
                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                            }
                                                        ]
                                                    }
                                                },
                                                {
                                                    "anchor": {
                                                        "source": "acc://dn.acme",
                                                        "minorBlockIndex": 134524,
                                                        "rootChainIndex": 1124817,
                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                    },
                                                    "rootChainReceipt": {
                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                        "startIndex": 134001,
                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                        "endIndex": 134001,
                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                        "entries": [
                                                            {
                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                            },
                                                            {
                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                            },
                                                            {
                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                            },
                                                            {
                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                            },
                                                            {
                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                            },
                                                            {
                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                            },
                                                            {
                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                            },
                                                            {
                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                            },
                                                            {
                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                            },
                                                            {
                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                            },
                                                            {
                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                            },
                                                            {
                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                            },
                                                            {
                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                            },
                                                            {
                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                            },
                                                            {
                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                            },
                                                            {
                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                            },
                                                            {
                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                            },
                                                            {
                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                            }
                                                        ]
                                                    }
                                                }
                                            ],
                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                        }
                                    }
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 172231,
                                "produced": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "cause": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264@bvn-BVN3.acme"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "signatureSet",
                                            "account": {
                                                "type": "anchorLedger",
                                                "url": "acc://bvn-BVN3.acme/anchors",
                                                "minorBlockSequenceNumber": 127085,
                                                "majorBlockTime": "0001-01-01T00:00:00.000Z",
                                                "sequence": [
                                                    {
                                                        "url": "acc://dn.acme",
                                                        "received": 134159,
                                                        "delivered": 134159
                                                    }
                                                ]
                                            },
                                            "signatures": {
                                                "recordType": "range",
                                                "records": [
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://edcb3d4c353a9a24681c35651347d44dfa256675306e8b039183fc4a335db85f@dn.acme/network",
                                                        "message": {
                                                            "type": "blockAnchor",
                                                            "signature": {
                                                                "type": "ed25519",
                                                                "publicKey": "cf5c0b621f887f3fc6f1a63b258d06420d7ca366e19b8b49328373eb1e5506de",
                                                                "signature": "fd0455ea595e9cb623833ae23f0d1dd91bac5e614111ea6f1fdea41f27c80b143a14a0ace1b716089ce0ac2ad364a88c857d347f1114cc05b4b3d0c23befc307",
                                                                "signer": "acc://dn.acme/network",
                                                                "timestamp": 1768731933052,
                                                                "transactionHash": "eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264"
                                                            },
                                                            "anchor": {
                                                                "type": "sequenced",
                                                                "message": {
                                                                    "type": "transaction",
                                                                    "transaction": {
                                                                        "header": {
                                                                            "principal": "acc://bvn-BVN3.acme/anchors"
                                                                        },
                                                                        "body": {
                                                                            "type": "directoryAnchor",
                                                                            "source": "acc://dn.acme",
                                                                            "minorBlockIndex": 134526,
                                                                            "rootChainIndex": 1124831,
                                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                                            "receipts": [
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://bvn-BVN1.acme",
                                                                                        "minorBlockIndex": 171829,
                                                                                        "rootChainIndex": 1401584,
                                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "startIndex": 171828,
                                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "endIndex": 171828,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                                            },
                                                                                            {
                                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                                            },
                                                                                            {
                                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                                            },
                                                                                            {
                                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                },
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://dn.acme",
                                                                                        "minorBlockIndex": 134524,
                                                                                        "rootChainIndex": 1124817,
                                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "startIndex": 134001,
                                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "endIndex": 134001,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                                            },
                                                                                            {
                                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                                            },
                                                                                            {
                                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                                            },
                                                                                            {
                                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                                            },
                                                                                            {
                                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                                            },
                                                                                            {
                                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                                            },
                                                                                            {
                                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                                            },
                                                                                            {
                                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                }
                                                                            ],
                                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                                        }
                                                                    }
                                                                },
                                                                "source": "acc://dn.acme",
                                                                "destination": "acc://bvn-BVN3.acme",
                                                                "number": 134004
                                                            }
                                                        }
                                                    },
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://6903b3d148bc8c66664fcc710a05ec4428fcc4ac909954cfa8cd9c08ee2b5e92@dn.acme/network",
                                                        "message": {
                                                            "type": "blockAnchor",
                                                            "signature": {
                                                                "type": "ed25519",
                                                                "publicKey": "51fe2dbfe2a3005f2ab03a3177da7286870ea238d3d74f688043e2ea0b470640",
                                                                "signature": "949a193eb5c4cd51585ba39ca7be14c5df623da0802731229d4a65399bdb0b9fa2aa1046141a4157df1206cf5af3b8bcb516c40693ce77ecf6bff7e3c587eb06",
                                                                "signer": "acc://dn.acme/network",
                                                                "timestamp": 1768731933052,
                                                                "transactionHash": "eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264"
                                                            },
                                                            "anchor": {
                                                                "type": "sequenced",
                                                                "message": {
                                                                    "type": "transaction",
                                                                    "transaction": {
                                                                        "header": {
                                                                            "principal": "acc://bvn-BVN3.acme/anchors"
                                                                        },
                                                                        "body": {
                                                                            "type": "directoryAnchor",
                                                                            "source": "acc://dn.acme",
                                                                            "minorBlockIndex": 134526,
                                                                            "rootChainIndex": 1124831,
                                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                                            "receipts": [
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://bvn-BVN1.acme",
                                                                                        "minorBlockIndex": 171829,
                                                                                        "rootChainIndex": 1401584,
                                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "startIndex": 171828,
                                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "endIndex": 171828,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                                            },
                                                                                            {
                                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                                            },
                                                                                            {
                                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                                            },
                                                                                            {
                                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                },
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://dn.acme",
                                                                                        "minorBlockIndex": 134524,
                                                                                        "rootChainIndex": 1124817,
                                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "startIndex": 134001,
                                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "endIndex": 134001,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                                            },
                                                                                            {
                                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                                            },
                                                                                            {
                                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                                            },
                                                                                            {
                                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                                            },
                                                                                            {
                                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                                            },
                                                                                            {
                                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                                            },
                                                                                            {
                                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                                            },
                                                                                            {
                                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                }
                                                                            ],
                                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                                        }
                                                                    }
                                                                },
                                                                "source": "acc://dn.acme",
                                                                "destination": "acc://bvn-BVN3.acme",
                                                                "number": 134004
                                                            }
                                                        }
                                                    },
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://2d26195853117e0bd9ab7a2e4a6238939ba98c3c7af38639535b22cea52dabcc@dn.acme/network",
                                                        "message": {
                                                            "type": "blockAnchor",
                                                            "signature": {
                                                                "type": "ed25519",
                                                                "publicKey": "ea744577476905ae36184a8023f8c8dcc24cfbd0e5b6d5792949bf8d02cdadaa",
                                                                "signature": "41e4c21cb1f6d449f5f56adcb1add10bb78d52fffbc7c07f71e729596b2d1438ed01861a7abe7c605e26da3464d9fbffa24b7693b185346abb365de1910acc02",
                                                                "signer": "acc://dn.acme/network",
                                                                "timestamp": 1768731933050,
                                                                "transactionHash": "eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264"
                                                            },
                                                            "anchor": {
                                                                "type": "sequenced",
                                                                "message": {
                                                                    "type": "transaction",
                                                                    "transaction": {
                                                                        "header": {
                                                                            "principal": "acc://bvn-BVN3.acme/anchors"
                                                                        },
                                                                        "body": {
                                                                            "type": "directoryAnchor",
                                                                            "source": "acc://dn.acme",
                                                                            "minorBlockIndex": 134526,
                                                                            "rootChainIndex": 1124831,
                                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                                            "receipts": [
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://bvn-BVN1.acme",
                                                                                        "minorBlockIndex": 171829,
                                                                                        "rootChainIndex": 1401584,
                                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "startIndex": 171828,
                                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "endIndex": 171828,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                                            },
                                                                                            {
                                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                                            },
                                                                                            {
                                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                                            },
                                                                                            {
                                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                },
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://dn.acme",
                                                                                        "minorBlockIndex": 134524,
                                                                                        "rootChainIndex": 1124817,
                                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "startIndex": 134001,
                                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "endIndex": 134001,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                                            },
                                                                                            {
                                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                                            },
                                                                                            {
                                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                                            },
                                                                                            {
                                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                                            },
                                                                                            {
                                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                                            },
                                                                                            {
                                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                                            },
                                                                                            {
                                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                                            },
                                                                                            {
                                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                }
                                                                            ],
                                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                                        }
                                                                    }
                                                                },
                                                                "source": "acc://dn.acme",
                                                                "destination": "acc://bvn-BVN3.acme",
                                                                "number": 134004
                                                            }
                                                        }
                                                    }
                                                ],
                                                "start": 0,
                                                "total": 3
                                            }
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                },
                                "sequence": {
                                    "type": "sequenced",
                                    "message": {
                                        "type": "transaction",
                                        "transaction": {
                                            "header": {
                                                "principal": "acc://bvn-BVN3.acme/anchors"
                                            },
                                            "body": {
                                                "type": "directoryAnchor",
                                                "source": "acc://dn.acme",
                                                "minorBlockIndex": 134526,
                                                "rootChainIndex": 1124831,
                                                "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                "receipts": [
                                                    {
                                                        "anchor": {
                                                            "source": "acc://bvn-BVN1.acme",
                                                            "minorBlockIndex": 171829,
                                                            "rootChainIndex": 1401584,
                                                            "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                            "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                        },
                                                        "rootChainReceipt": {
                                                            "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                            "startIndex": 171828,
                                                            "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                            "endIndex": 171828,
                                                            "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                            "entries": [
                                                                {
                                                                    "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                },
                                                                {
                                                                    "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                },
                                                                {
                                                                    "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                },
                                                                {
                                                                    "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                },
                                                                {
                                                                    "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                },
                                                                {
                                                                    "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                },
                                                                {
                                                                    "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                },
                                                                {
                                                                    "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                },
                                                                {
                                                                    "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                },
                                                                {
                                                                    "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                },
                                                                {
                                                                    "right": true,
                                                                    "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                },
                                                                {
                                                                    "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                },
                                                                {
                                                                    "right": true,
                                                                    "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                },
                                                                {
                                                                    "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                },
                                                                {
                                                                    "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                },
                                                                {
                                                                    "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                },
                                                                {
                                                                    "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                },
                                                                {
                                                                    "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                },
                                                                {
                                                                    "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                },
                                                                {
                                                                    "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                },
                                                                {
                                                                    "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                },
                                                                {
                                                                    "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                }
                                                            ]
                                                        }
                                                    },
                                                    {
                                                        "anchor": {
                                                            "source": "acc://dn.acme",
                                                            "minorBlockIndex": 134524,
                                                            "rootChainIndex": 1124817,
                                                            "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                            "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                        },
                                                        "rootChainReceipt": {
                                                            "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                            "startIndex": 134001,
                                                            "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                            "endIndex": 134001,
                                                            "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                            "entries": [
                                                                {
                                                                    "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                },
                                                                {
                                                                    "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                },
                                                                {
                                                                    "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                },
                                                                {
                                                                    "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                },
                                                                {
                                                                    "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                },
                                                                {
                                                                    "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                },
                                                                {
                                                                    "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                },
                                                                {
                                                                    "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                },
                                                                {
                                                                    "right": true,
                                                                    "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                },
                                                                {
                                                                    "right": true,
                                                                    "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                },
                                                                {
                                                                    "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                },
                                                                {
                                                                    "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                },
                                                                {
                                                                    "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                },
                                                                {
                                                                    "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                },
                                                                {
                                                                    "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                },
                                                                {
                                                                    "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                },
                                                                {
                                                                    "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                },
                                                                {
                                                                    "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                },
                                                                {
                                                                    "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                },
                                                                {
                                                                    "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                }
                                                            ]
                                                        }
                                                    }
                                                ],
                                                "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                            }
                                        }
                                    },
                                    "source": "acc://dn.acme",
                                    "destination": "acc://bvn-BVN3.acme",
                                    "number": 134004
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://bvn-BVN3.acme/anchors",
                            "name": "signature",
                            "type": "transaction",
                            "index": 402011,
                            "entry": "2d26195853117e0bd9ab7a2e4a6238939ba98c3c7af38639535b22cea52dabcc",
                            "value": {
                                "recordType": "message",
                                "id": "acc://2d26195853117e0bd9ab7a2e4a6238939ba98c3c7af38639535b22cea52dabcc@dn.acme/network",
                                "message": {
                                    "type": "blockAnchor",
                                    "signature": {
                                        "type": "ed25519",
                                        "publicKey": "ea744577476905ae36184a8023f8c8dcc24cfbd0e5b6d5792949bf8d02cdadaa",
                                        "signature": "41e4c21cb1f6d449f5f56adcb1add10bb78d52fffbc7c07f71e729596b2d1438ed01861a7abe7c605e26da3464d9fbffa24b7693b185346abb365de1910acc02",
                                        "signer": "acc://dn.acme/network",
                                        "timestamp": 1768731933050,
                                        "transactionHash": "eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264"
                                    },
                                    "anchor": {
                                        "type": "sequenced",
                                        "message": {
                                            "type": "transaction",
                                            "transaction": {
                                                "header": {
                                                    "principal": "acc://bvn-BVN3.acme/anchors"
                                                },
                                                "body": {
                                                    "type": "directoryAnchor",
                                                    "source": "acc://dn.acme",
                                                    "minorBlockIndex": 134526,
                                                    "rootChainIndex": 1124831,
                                                    "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                    "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                    "receipts": [
                                                        {
                                                            "anchor": {
                                                                "source": "acc://bvn-BVN1.acme",
                                                                "minorBlockIndex": 171829,
                                                                "rootChainIndex": 1401584,
                                                                "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                            },
                                                            "rootChainReceipt": {
                                                                "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                "startIndex": 171828,
                                                                "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                "endIndex": 171828,
                                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                "entries": [
                                                                    {
                                                                        "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                    },
                                                                    {
                                                                        "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                    },
                                                                    {
                                                                        "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                    },
                                                                    {
                                                                        "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                    },
                                                                    {
                                                                        "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                    },
                                                                    {
                                                                        "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                    },
                                                                    {
                                                                        "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                    },
                                                                    {
                                                                        "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                    },
                                                                    {
                                                                        "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                    },
                                                                    {
                                                                        "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                    },
                                                                    {
                                                                        "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                    },
                                                                    {
                                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                    },
                                                                    {
                                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                    },
                                                                    {
                                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                    },
                                                                    {
                                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                    },
                                                                    {
                                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                    },
                                                                    {
                                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                    },
                                                                    {
                                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                    },
                                                                    {
                                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                    },
                                                                    {
                                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                    }
                                                                ]
                                                            }
                                                        },
                                                        {
                                                            "anchor": {
                                                                "source": "acc://dn.acme",
                                                                "minorBlockIndex": 134524,
                                                                "rootChainIndex": 1124817,
                                                                "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                            },
                                                            "rootChainReceipt": {
                                                                "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                "startIndex": 134001,
                                                                "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                "endIndex": 134001,
                                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                "entries": [
                                                                    {
                                                                        "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                    },
                                                                    {
                                                                        "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                    },
                                                                    {
                                                                        "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                    },
                                                                    {
                                                                        "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                    },
                                                                    {
                                                                        "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                    },
                                                                    {
                                                                        "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                    },
                                                                    {
                                                                        "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                    },
                                                                    {
                                                                        "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                    },
                                                                    {
                                                                        "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                    },
                                                                    {
                                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                    },
                                                                    {
                                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                    },
                                                                    {
                                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                    },
                                                                    {
                                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                    },
                                                                    {
                                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                    },
                                                                    {
                                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                    },
                                                                    {
                                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                    },
                                                                    {
                                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                    },
                                                                    {
                                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                    }
                                                                ]
                                                            }
                                                        }
                                                    ],
                                                    "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                }
                                            }
                                        },
                                        "source": "acc://dn.acme",
                                        "destination": "acc://bvn-BVN3.acme",
                                        "number": 134004
                                    }
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 172231,
                                "produced": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://78535fdd99ee5da8ec82fd388718da3ea9660efb50cca0890b7a5fcaf89d5b7e@dn.acme/network"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264@bvn-BVN3.acme"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 2
                                },
                                "cause": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://certen-kermit-11.acme/book",
                            "name": "signature",
                            "type": "transaction",
                            "index": 13,
                            "entry": "85d1c899b2efcff50b14966e4b0f5d364021f46c7a45e13dd8741a7811a35f09",
                            "value": {
                                "recordType": "message",
                                "id": "acc://85d1c899b2efcff50b14966e4b0f5d364021f46c7a45e13dd8741a7811a35f09@certen-kermit-11.acme/book",
                                "message": {
                                    "type": "signatureRequest",
                                    "authority": "acc://certen-kermit-11.acme/book",
                                    "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                                    "cause": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 172231,
                                "produced": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                },
                                "cause": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://certen-kermit-11.acme/book/1",
                            "name": "signature",
                            "type": "transaction",
                            "index": 16,
                            "entry": "ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95",
                            "value": {
                                "recordType": "message",
                                "id": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1",
                                "message": {
                                    "type": "signature",
                                    "signature": {
                                        "type": "ed25519",
                                        "publicKey": "9d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7",
                                        "signature": "b2ec40a1915f0092f8c9e0f9097b21f67c397b9b52b95c0268ebfc0716018cfc0588490ea9858a20969157f8b74e17592091c03e73820656b7da07a3c8f8d908",
                                        "signer": "acc://certen-kermit-11.acme/book/1",
                                        "signerVersion": 2,
                                        "timestamp": 1768731929544000,
                                        "transactionHash": "835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a"
                                    },
                                    "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data"
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 172231,
                                "produced": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://cace5d35590ba975764bd0062be1ac52386c83b4871c0e3e45c2e9fee569d7d0@certen-kermit-11.acme/data"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://d0508ff9a08e920aff04c9dff1a1faf070828a4b8dd56e3ee35370c8ed5ddf86@certen-kermit-11.acme/data"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://cace5d35590ba975764bd0062be1ac52386c83b4871c0e3e45c2e9fee569d7d0@certen-kermit-11.acme/data"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://d0508ff9a08e920aff04c9dff1a1faf070828a4b8dd56e3ee35370c8ed5ddf86@certen-kermit-11.acme/data"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 6
                                },
                                "cause": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://certen-kermit-11.acme/data",
                            "name": "main",
                            "type": "transaction",
                            "index": 12,
                            "entry": "835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a",
                            "value": {
                                "recordType": "message",
                                "id": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                                "message": {
                                    "type": "transaction",
                                    "transaction": {
                                        "header": {
                                            "principal": "acc://certen-kermit-11.acme/data",
                                            "initiator": "bb0502cbecac0db1e91449a3b2aa1018623aed8a2c7456f235eb8ceb7ebff9f1",
                                            "memo": "CERTEN_INTENT",
                                            "metadata": "01025f00"
                                        },
                                        "body": {
                                            "type": "writeData",
                                            "entry": {
                                                "type": "doubleHash",
                                                "data": [
                                                    "7b226b696e64223a2243455254454e5f494e54454e54222c2276657273696f6e223a22312e30222c2270726f6f665f636c617373223a226f6e5f64656d616e64222c22696e74656e745f6964223a2266343663356538372d393966652d343337352d626465622d336639626330643032656663222c22637265617465645f6174223a22323032362d30312d31385431303a32353a32392e3534325a222c22696e74656e7454797065223a2263726f73735f636861696e5f7472616e73666572222c226465736372697074696f6e223a22455448207472616e73666572206f6e205365706f6c6961227d",
                                                    "7b2270726f746f636f6c223a2243455254454e222c2276657273696f6e223a22312e30222c226f7065726174696f6e47726f75704964223a2266343663356538372d393966652d343337352d626465622d336639626330643032656663222c226c656773223a5b7b226c65674964223a226c65672d31222c22636861696e223a22657468657265756d222c22636861696e4964223a31313135353131312c2266726f6d223a22307863363833316461363533373431616665626331346134396539633632393133313261306261336464222c22746f223a22307862653030343361626231306536646235366238633663356362336636333962663766653639323531222c22616d6f756e74576569223a2231222c22616e63686f72436f6e7472616374223a7b2261646472657373223a22307845623137654264333531443265303430613063423330323661334430344245633138326438623938222c2266756e6374696f6e53656c6563746f72223a22637265617465416e63686f7228627974657333322c627974657333322c627974657333322c627974657333322c75696e7432353629227d7d5d7d",
                                                    "7b226f7267616e697a6174696f6e416469223a226163633a2f2f63657274656e2d6b65726d69742d31312e61636d65222c22617574686f72697a6174696f6e223a7b2272657175697265645f6b65795f626f6f6b223a226163633a2f2f63657274656e2d6b65726d69742d31312e61636d652f626f6f6b222c227369676e61747572655f7468726573686f6c64223a317d7d",
                                                    "7b226e6f6e6365223a2263657274656e5f31373638373331393239353432222c22637265617465645f6174223a313736383733313932392c22657870697265735f6174223a313736383733353532397d"
                                                ]
                                            }
                                        }
                                    }
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "writeData",
                                    "entryHash": "9f453a09d6c4eca244e22427499a1a47ce1b207de9a7bb943c6ef9c89fcdd364",
                                    "accountUrl": "acc://certen-kermit-11.acme/data",
                                    "accountID": "d738a79366a931132e55183efa167128f225cb1a28852edf3cd467c7ea957ba1"
                                },
                                "received": 172231,
                                "produced": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "cause": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://85d1c899b2efcff50b14966e4b0f5d364021f46c7a45e13dd8741a7811a35f09@certen-kermit-11.acme/book"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 2
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "signatureSet",
                                            "account": {
                                                "type": "keyBook",
                                                "url": "acc://certen-kermit-11.acme/book",
                                                "authorities": [
                                                    {
                                                        "url": "acc://certen-kermit-11.acme/book"
                                                    }
                                                ],
                                                "pageCount": 1
                                            },
                                            "signatures": {
                                                "recordType": "range",
                                                "records": [
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://85d1c899b2efcff50b14966e4b0f5d364021f46c7a45e13dd8741a7811a35f09@certen-kermit-11.acme/book",
                                                        "message": {
                                                            "type": "signatureRequest",
                                                            "authority": "acc://certen-kermit-11.acme/book",
                                                            "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                                                            "cause": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                                                        },
                                                        "historical": true
                                                    }
                                                ],
                                                "start": 0,
                                                "total": 1
                                            }
                                        },
                                        {
                                            "recordType": "signatureSet",
                                            "account": {
                                                "type": "keyPage",
                                                "url": "acc://certen-kermit-11.acme/book/1",
                                                "creditBalance": 996590,
                                                "acceptThreshold": 1,
                                                "version": 2,
                                                "keys": [
                                                    {
                                                        "publicKeyHash": "4d07443e23bf3d244facb56f7fd4614d29b21f5530361ca1f77c40ac17f16192",
                                                        "lastUsedOn": 1768731929544000
                                                    }
                                                ]
                                            },
                                            "signatures": {
                                                "recordType": "range",
                                                "records": [
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1",
                                                        "message": {
                                                            "type": "signature",
                                                            "signature": {
                                                                "type": "ed25519",
                                                                "publicKey": "9d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7",
                                                                "signature": "b2ec40a1915f0092f8c9e0f9097b21f67c397b9b52b95c0268ebfc0716018cfc0588490ea9858a20969157f8b74e17592091c03e73820656b7da07a3c8f8d908",
                                                                "signer": "acc://certen-kermit-11.acme/book/1",
                                                                "signerVersion": 2,
                                                                "timestamp": 1768731929544000,
                                                                "transactionHash": "835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a"
                                                            },
                                                            "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data"
                                                        },
                                                        "historical": true
                                                    }
                                                ],
                                                "start": 0,
                                                "total": 1
                                            }
                                        },
                                        {
                                            "recordType": "signatureSet",
                                            "account": {
                                                "type": "dataAccount",
                                                "url": "acc://certen-kermit-11.acme/data"
                                            },
                                            "signatures": {
                                                "recordType": "range",
                                                "records": [
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data",
                                                        "message": {
                                                            "type": "signatureRequest",
                                                            "authority": "acc://certen-kermit-11.acme/data",
                                                            "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                                                            "cause": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1"
                                                        },
                                                        "historical": true
                                                    },
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://d0508ff9a08e920aff04c9dff1a1faf070828a4b8dd56e3ee35370c8ed5ddf86@certen-kermit-11.acme/data",
                                                        "message": {
                                                            "type": "creditPayment",
                                                            "paid": 40,
                                                            "payer": "acc://certen-kermit-11.acme/book/1",
                                                            "initiator": true,
                                                            "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                                                            "cause": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1"
                                                        },
                                                        "historical": true
                                                    },
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://cace5d35590ba975764bd0062be1ac52386c83b4871c0e3e45c2e9fee569d7d0@certen-kermit-11.acme/data",
                                                        "message": {
                                                            "type": "signature",
                                                            "signature": {
                                                                "type": "authority",
                                                                "origin": "acc://certen-kermit-11.acme/book/1",
                                                                "authority": "acc://certen-kermit-11.acme/book",
                                                                "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                                                                "cause": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1"
                                                            },
                                                            "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data"
                                                        },
                                                        "historical": true
                                                    }
                                                ],
                                                "start": 0,
                                                "total": 3
                                            }
                                        }
                                    ],
                                    "start": 0,
                                    "total": 3
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://certen-kermit-11.acme/data",
                            "name": "signature",
                            "type": "transaction",
                            "index": 35,
                            "entry": "cace5d35590ba975764bd0062be1ac52386c83b4871c0e3e45c2e9fee569d7d0",
                            "value": {
                                "recordType": "message",
                                "id": "acc://cace5d35590ba975764bd0062be1ac52386c83b4871c0e3e45c2e9fee569d7d0@certen-kermit-11.acme/data",
                                "message": {
                                    "type": "signature",
                                    "signature": {
                                        "type": "authority",
                                        "origin": "acc://certen-kermit-11.acme/book/1",
                                        "authority": "acc://certen-kermit-11.acme/book",
                                        "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                                        "cause": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1"
                                    },
                                    "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data"
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 172231,
                                "produced": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "cause": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME",
                            "name": "main",
                            "type": "transaction",
                            "index": 1165105,
                            "entry": "874ffd3376508f71d020a8c0c260743d037a5f7d35d21bce3bc7d781e571574c",
                            "value": {
                                "recordType": "message",
                                "id": "acc://874ffd3376508f71d020a8c0c260743d037a5f7d35d21bce3bc7d781e571574c@f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME",
                                "message": {
                                    "type": "transaction",
                                    "transaction": {
                                        "header": {
                                            "principal": "acc://f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME"
                                        },
                                        "body": {
                                            "type": "syntheticDepositTokens",
                                            "cause": "acc://963a2a28c5277f74f0ec55fc7cf2cb46abc35d9fe842be6186171d601f8eb640@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                            "source": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                            "initiator": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                            "feeRefund": 100,
                                            "index": 18,
                                            "token": "acc://ACME",
                                            "amount": "1000000000"
                                        }
                                    }
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 172231,
                                "produced": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "cause": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://bc0a7eb63ddd6dcbe3e69a29a31f907e3f59fd0693f19d7a3d62a71c7e99af43@bvn-BVN3.acme"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "sequence": {
                                    "type": "sequenced",
                                    "message": {
                                        "type": "transaction",
                                        "transaction": {
                                            "header": {
                                                "principal": "acc://f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME"
                                            },
                                            "body": {
                                                "type": "syntheticDepositTokens",
                                                "cause": "acc://963a2a28c5277f74f0ec55fc7cf2cb46abc35d9fe842be6186171d601f8eb640@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                                "source": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                                "initiator": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                                "feeRefund": 100,
                                                "index": 18,
                                                "token": "acc://ACME",
                                                "amount": "1000000000"
                                            }
                                        }
                                    },
                                    "source": "acc://bvn-BVN1.acme",
                                    "destination": "acc://bvn-BVN3.acme",
                                    "number": 1165113
                                }
                            }
                        }
                    ],
                    "start": 0,
                    "total": 9
                },
                "lastBlockTime": "2026-01-18T10:33:42.000Z"
            },
            {
                "recordType": "minorBlock",
                "index": 134528,
                "time": "2026-01-18T10:25:32.000Z",
                "source": "acc://dn.acme",
                "entries": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "chainEntry",
                            "account": "acc://dn.acme/anchors",
                            "name": "anchor(bvn1)-bpt",
                            "type": "anchor",
                            "index": 171830,
                            "entry": "7faba59bd7c1029021869b3192d5f9d39be30939aaf4fbed6c998ad4e6295148"
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://dn.acme/anchors",
                            "name": "anchor(bvn1)-root",
                            "type": "anchor",
                            "index": 171830,
                            "entry": "a3ee0784384a61874f04fffcc238997aa78ec1aa2f95e6331669e0ce5d5a6b03"
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://dn.acme/anchors",
                            "name": "anchor(bvn3)-bpt",
                            "type": "anchor",
                            "index": 126941,
                            "entry": "3a7aeed93b2b5c1d04dbe556d112f1272c38f97499f9341e11c590addea40fc1"
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://dn.acme/anchors",
                            "name": "anchor(bvn3)-root",
                            "type": "anchor",
                            "index": 126941,
                            "entry": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7"
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://dn.acme/anchors",
                            "name": "anchor(directory)-bpt",
                            "type": "anchor",
                            "index": 134003,
                            "entry": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a"
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://dn.acme/anchors",
                            "name": "anchor(directory)-root",
                            "type": "anchor",
                            "index": 134003,
                            "entry": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6"
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://dn.acme/anchors",
                            "name": "anchor-sequence",
                            "type": "transaction",
                            "index": 134004,
                            "entry": "ed16ed15e2c17663bf19579ab9b00c3e5fbd2234e10c1b4a58484b77d345747d",
                            "value": {
                                "recordType": "message",
                                "id": "acc://ed16ed15e2c17663bf19579ab9b00c3e5fbd2234e10c1b4a58484b77d345747d@unknown",
                                "message": {
                                    "type": "transaction",
                                    "transaction": {
                                        "header": {},
                                        "body": {
                                            "type": "directoryAnchor",
                                            "source": "acc://dn.acme",
                                            "minorBlockIndex": 134527,
                                            "rootChainIndex": 1124840,
                                            "rootChainAnchor": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                            "stateTreeAnchor": "b6097c12c42c4f86dc18da6e3dabf97e62af2589ecdad1c325077b50d7ecd647",
                                            "receipts": [
                                                {
                                                    "anchor": {
                                                        "source": "acc://bvn-BVN3.acme",
                                                        "minorBlockIndex": 172227,
                                                        "rootChainIndex": 795671,
                                                        "rootChainAnchor": "864f64bd3abd1a4f1a92315da01aceb6fd33de169d7970cc8401b08c58062398",
                                                        "stateTreeAnchor": "b6af44f71b89d9237b864658b61f51375e4c84eb57ba1d4d81b7550c47a483c0"
                                                    },
                                                    "rootChainReceipt": {
                                                        "start": "864f64bd3abd1a4f1a92315da01aceb6fd33de169d7970cc8401b08c58062398",
                                                        "startIndex": 126939,
                                                        "end": "864f64bd3abd1a4f1a92315da01aceb6fd33de169d7970cc8401b08c58062398",
                                                        "endIndex": 126939,
                                                        "anchor": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                                        "entries": [
                                                            {
                                                                "hash": "75b81aa5e876e772ece15d29439e3f3da63deaecfdbd13df853e12a0e6597530"
                                                            },
                                                            {
                                                                "hash": "c1aa0288bf49989a2204be18697d3be48ed9e2da198889f5fd1fd9f173e1db91"
                                                            },
                                                            {
                                                                "hash": "c545b652f3c6c46a40eeaefef1c5e7ae410311aa11b63586391faabcf93b4a22"
                                                            },
                                                            {
                                                                "hash": "426a17720ddcbbe98982b03669954b71f4305394e823a06d50185f49b6e87dbe"
                                                            },
                                                            {
                                                                "hash": "c4136034fc8e84bf01150e48e6004d70d07f3029a798c02b4e88b2634608807c"
                                                            },
                                                            {
                                                                "hash": "337cf6886f0179f3d6a8a6aa550167695a7e45596f2675fd400de3d90a77777a"
                                                            },
                                                            {
                                                                "hash": "9e5e0cedbde8aaca69bd73b305a5157fa8929ee3facf706c86627c7064ec1767"
                                                            },
                                                            {
                                                                "hash": "4472fdbcfbcad5209f7e2a2a8c009e35dac0d03e53d48a484aeaeec3c6b5d993"
                                                            },
                                                            {
                                                                "hash": "cf69c7387abc3e14c39f96c624758a1dd335caca47147ac45457a47283d91ecb"
                                                            },
                                                            {
                                                                "hash": "106a563245495fbaa118cb2ca4274fea45821ec186070c928c9415da1b0621cf"
                                                            },
                                                            {
                                                                "hash": "85a44f2ca3ec5e3dcf59cbe468fae38269c4cb0c68d8aebc72a2b73a7fc4f354"
                                                            },
                                                            {
                                                                "hash": "d3f1f628a34dc36a35ee725601a468bf4d75179e65a36070d8d222e73a96a332"
                                                            },
                                                            {
                                                                "hash": "40bd99969dc9e74245243ce33675fa226fe141530c763f1c0a0c69fe0e340b78"
                                                            },
                                                            {
                                                                "hash": "b2ff0c192d92053f4f102174f192957eb4c6f5bc078e64b0990a53cdba92392a"
                                                            },
                                                            {
                                                                "hash": "37c387421f8801616dd33a37ac2a411b740c7867ee1546ea7b2f1992d1e50f94"
                                                            },
                                                            {
                                                                "hash": "26f9b5466f391d2c82481a27cfdb97371683a6b968e693cab0281ecf23bc4bb3"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "b1394edafe5dd880fecaf6aad1f1827b4055cb880ba0104d662fd61fbbfe84e3"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "6e4f79a1eddfa5a02c4e2655fe543864f7e39654f5f9b2c9ab4f2cb1bd11a345"
                                                            },
                                                            {
                                                                "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                            },
                                                            {
                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                            },
                                                            {
                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                            },
                                                            {
                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                            },
                                                            {
                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                            },
                                                            {
                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                            },
                                                            {
                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                            },
                                                            {
                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                            }
                                                        ]
                                                    }
                                                },
                                                {
                                                    "anchor": {
                                                        "source": "acc://bvn-BVN1.acme",
                                                        "minorBlockIndex": 171830,
                                                        "rootChainIndex": 1401593,
                                                        "rootChainAnchor": "8504c0da129c77c66f0e48a373145d00ffd23aafd958b1ef9ccf92a6aefa8145",
                                                        "stateTreeAnchor": "67419a538d3dc4c6dc6fd32d3bc1ff31d4fb048bd6c730c09b2de816d8973ed9"
                                                    },
                                                    "rootChainReceipt": {
                                                        "start": "8504c0da129c77c66f0e48a373145d00ffd23aafd958b1ef9ccf92a6aefa8145",
                                                        "startIndex": 171829,
                                                        "end": "8504c0da129c77c66f0e48a373145d00ffd23aafd958b1ef9ccf92a6aefa8145",
                                                        "endIndex": 171829,
                                                        "anchor": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                                        "entries": [
                                                            {
                                                                "hash": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4"
                                                            },
                                                            {
                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                            },
                                                            {
                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                            },
                                                            {
                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                            },
                                                            {
                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                            },
                                                            {
                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                            },
                                                            {
                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                            },
                                                            {
                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                            },
                                                            {
                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                            },
                                                            {
                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                            },
                                                            {
                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                            },
                                                            {
                                                                "hash": "8b44a45b75459eb95eeda80da8f60510dd91938dcd385576e89fb52aab1a825d"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "e01c090a7133fb9f3a567e469953b4e50445c434f73ca13c19c50bb46ff2a7b0"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "b1394edafe5dd880fecaf6aad1f1827b4055cb880ba0104d662fd61fbbfe84e3"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "6e4f79a1eddfa5a02c4e2655fe543864f7e39654f5f9b2c9ab4f2cb1bd11a345"
                                                            },
                                                            {
                                                                "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                            },
                                                            {
                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                            },
                                                            {
                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                            },
                                                            {
                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                            },
                                                            {
                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                            },
                                                            {
                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                            },
                                                            {
                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                            },
                                                            {
                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                            }
                                                        ]
                                                    }
                                                },
                                                {
                                                    "anchor": {
                                                        "source": "acc://dn.acme",
                                                        "minorBlockIndex": 134525,
                                                        "rootChainIndex": 1124824,
                                                        "rootChainAnchor": "e312f39d2913ede4b010f20ac2186c5c7db5b26cacc9c0569e5ca6b8075c35a4",
                                                        "stateTreeAnchor": "8b57b8a89db4bbf8842aeffa19eccb00a82bef723ebd773b5e7b38e2009cddca"
                                                    },
                                                    "rootChainReceipt": {
                                                        "start": "e312f39d2913ede4b010f20ac2186c5c7db5b26cacc9c0569e5ca6b8075c35a4",
                                                        "startIndex": 134002,
                                                        "end": "e312f39d2913ede4b010f20ac2186c5c7db5b26cacc9c0569e5ca6b8075c35a4",
                                                        "endIndex": 134002,
                                                        "anchor": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                                        "entries": [
                                                            {
                                                                "hash": "f4b9b8af5cc1d0dc05f1edc20680f60684521c2284947208cd59b6cad4e64527"
                                                            },
                                                            {
                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                            },
                                                            {
                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                            },
                                                            {
                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                            },
                                                            {
                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                            },
                                                            {
                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                            },
                                                            {
                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                            },
                                                            {
                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                            },
                                                            {
                                                                "hash": "37be1964ce422eed97a6c33730c7d52741a76fe41b6d2649127c7472062dfa53"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "0ba6e906ccbd754f0530ef1297987e8761ccdf063832cb1d12ffae9d36d24d7c"
                                                            },
                                                            {
                                                                "hash": "e9f46e0d5b258869709c059afec81dc144106f7535d6f6e6af91996391cb3a90"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "6e4f79a1eddfa5a02c4e2655fe543864f7e39654f5f9b2c9ab4f2cb1bd11a345"
                                                            },
                                                            {
                                                                "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                            },
                                                            {
                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                            },
                                                            {
                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                            },
                                                            {
                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                            },
                                                            {
                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                            },
                                                            {
                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                            },
                                                            {
                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                            },
                                                            {
                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                            }
                                                        ]
                                                    }
                                                }
                                            ],
                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                        }
                                    }
                                },
                                "status": "remote",
                                "result": {
                                    "type": "unknown"
                                },
                                "produced": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "cause": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://dn.acme/anchors",
                            "name": "main",
                            "type": "transaction",
                            "index": 432933,
                            "entry": "c46a710be867bc4b6e750616e8f71fcd1ee040be9f0e16a88cc09b8cf60d997c",
                            "value": {
                                "recordType": "message",
                                "id": "acc://c46a710be867bc4b6e750616e8f71fcd1ee040be9f0e16a88cc09b8cf60d997c@dn.acme/anchors",
                                "message": {
                                    "type": "transaction",
                                    "transaction": {
                                        "header": {
                                            "principal": "acc://dn.acme/anchors"
                                        },
                                        "body": {
                                            "type": "blockValidatorAnchor",
                                            "source": "acc://bvn-BVN3.acme",
                                            "minorBlockIndex": 172229,
                                            "rootChainIndex": 795683,
                                            "rootChainAnchor": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                            "stateTreeAnchor": "3a7aeed93b2b5c1d04dbe556d112f1272c38f97499f9341e11c590addea40fc1"
                                        }
                                    }
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 134528,
                                "produced": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "cause": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://d8b7cdc21c39a6aca07a001ad5eac865bffb5af0751dfdcdd494cfce6bc831da@dn.acme"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "signatureSet",
                                            "account": {
                                                "type": "anchorLedger",
                                                "url": "acc://dn.acme/anchors",
                                                "minorBlockSequenceNumber": 134161,
                                                "majorBlockIndex": 9,
                                                "majorBlockTime": "2026-01-18T00:00:01.000Z",
                                                "sequence": [
                                                    {
                                                        "url": "acc://bvn-BVN1.acme",
                                                        "received": 172029,
                                                        "delivered": 172029
                                                    },
                                                    {
                                                        "url": "acc://bvn-BVN2.acme",
                                                        "received": 156,
                                                        "delivered": 156
                                                    },
                                                    {
                                                        "url": "acc://bvn-BVN3.acme",
                                                        "received": 127082,
                                                        "delivered": 127082
                                                    },
                                                    {
                                                        "url": "acc://dn.acme",
                                                        "received": 134158,
                                                        "delivered": 134158
                                                    }
                                                ]
                                            },
                                            "signatures": {
                                                "recordType": "range",
                                                "records": [
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://d6b3fdd6cc4c721c498a1a90ec801f885d72ce724996256187efd33d32f84315@dn.acme/network",
                                                        "message": {
                                                            "type": "blockAnchor",
                                                            "signature": {
                                                                "type": "ed25519",
                                                                "publicKey": "cf5c0b621f887f3fc6f1a63b258d06420d7ca366e19b8b49328373eb1e5506de",
                                                                "signature": "f41a00b755ccec0bf21db2a93e9ce602d0b141d8d9b3c8728d13c223ae070ef0e9ee939296bd127fa99388e943c8f8988ee5e56edb7b9f745d7799e1ae4a8207",
                                                                "signer": "acc://dn.acme/network",
                                                                "timestamp": 1768731933051,
                                                                "transactionHash": "d8b7cdc21c39a6aca07a001ad5eac865bffb5af0751dfdcdd494cfce6bc831da"
                                                            },
                                                            "anchor": {
                                                                "type": "sequenced",
                                                                "message": {
                                                                    "type": "transaction",
                                                                    "transaction": {
                                                                        "header": {
                                                                            "principal": "acc://dn.acme/anchors"
                                                                        },
                                                                        "body": {
                                                                            "type": "blockValidatorAnchor",
                                                                            "source": "acc://bvn-BVN3.acme",
                                                                            "minorBlockIndex": 172229,
                                                                            "rootChainIndex": 795683,
                                                                            "rootChainAnchor": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                                                            "stateTreeAnchor": "3a7aeed93b2b5c1d04dbe556d112f1272c38f97499f9341e11c590addea40fc1"
                                                                        }
                                                                    }
                                                                },
                                                                "source": "acc://bvn-BVN3.acme",
                                                                "destination": "acc://dn.acme",
                                                                "number": 126942
                                                            }
                                                        }
                                                    }
                                                ],
                                                "start": 0,
                                                "total": 1
                                            }
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                },
                                "sequence": {
                                    "type": "sequenced",
                                    "message": {
                                        "type": "transaction",
                                        "transaction": {
                                            "header": {
                                                "principal": "acc://dn.acme/anchors"
                                            },
                                            "body": {
                                                "type": "blockValidatorAnchor",
                                                "source": "acc://bvn-BVN3.acme",
                                                "minorBlockIndex": 172229,
                                                "rootChainIndex": 795683,
                                                "rootChainAnchor": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                                "stateTreeAnchor": "3a7aeed93b2b5c1d04dbe556d112f1272c38f97499f9341e11c590addea40fc1"
                                            }
                                        }
                                    },
                                    "source": "acc://bvn-BVN3.acme",
                                    "destination": "acc://dn.acme",
                                    "number": 126942
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://dn.acme/anchors",
                            "name": "signature",
                            "type": "transaction",
                            "index": 700940,
                            "entry": "ad0ff61d5fe03cdda0ee7f7dabf7c9f84c6cb058eb6883e89d5bef2632eb61ee",
                            "value": {
                                "recordType": "message",
                                "id": "acc://ad0ff61d5fe03cdda0ee7f7dabf7c9f84c6cb058eb6883e89d5bef2632eb61ee@dn.acme/network",
                                "message": {
                                    "type": "blockAnchor",
                                    "signature": {
                                        "type": "ed25519",
                                        "publicKey": "cf5c0b621f887f3fc6f1a63b258d06420d7ca366e19b8b49328373eb1e5506de",
                                        "signature": "4fd1b55f1ce8d2b4b35c8497e9d974253d7414a3a4de8d59ad4c67e06459d27d3b0f5fba18f6200e95a0dd63a97cbc24f9440871cd4d8b4c84bcd9f099549101",
                                        "signer": "acc://dn.acme/network",
                                        "timestamp": 1768731933052,
                                        "transactionHash": "9aec9740b2e8e3b596a0d1b3a1190e44561996d4e13dcc190f43656e8112131f"
                                    },
                                    "anchor": {
                                        "type": "sequenced",
                                        "message": {
                                            "type": "transaction",
                                            "transaction": {
                                                "header": {
                                                    "principal": "acc://dn.acme/anchors"
                                                },
                                                "body": {
                                                    "type": "directoryAnchor",
                                                    "source": "acc://dn.acme",
                                                    "minorBlockIndex": 134526,
                                                    "rootChainIndex": 1124831,
                                                    "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                    "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                    "receipts": [
                                                        {
                                                            "anchor": {
                                                                "source": "acc://bvn-BVN1.acme",
                                                                "minorBlockIndex": 171829,
                                                                "rootChainIndex": 1401584,
                                                                "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                            },
                                                            "rootChainReceipt": {
                                                                "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                "startIndex": 171828,
                                                                "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                "endIndex": 171828,
                                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                "entries": [
                                                                    {
                                                                        "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                    },
                                                                    {
                                                                        "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                    },
                                                                    {
                                                                        "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                    },
                                                                    {
                                                                        "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                    },
                                                                    {
                                                                        "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                    },
                                                                    {
                                                                        "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                    },
                                                                    {
                                                                        "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                    },
                                                                    {
                                                                        "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                    },
                                                                    {
                                                                        "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                    },
                                                                    {
                                                                        "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                    },
                                                                    {
                                                                        "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                    },
                                                                    {
                                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                    },
                                                                    {
                                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                    },
                                                                    {
                                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                    },
                                                                    {
                                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                    },
                                                                    {
                                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                    },
                                                                    {
                                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                    },
                                                                    {
                                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                    },
                                                                    {
                                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                    },
                                                                    {
                                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                    }
                                                                ]
                                                            }
                                                        },
                                                        {
                                                            "anchor": {
                                                                "source": "acc://dn.acme",
                                                                "minorBlockIndex": 134524,
                                                                "rootChainIndex": 1124817,
                                                                "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                            },
                                                            "rootChainReceipt": {
                                                                "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                "startIndex": 134001,
                                                                "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                "endIndex": 134001,
                                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                "entries": [
                                                                    {
                                                                        "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                    },
                                                                    {
                                                                        "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                    },
                                                                    {
                                                                        "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                    },
                                                                    {
                                                                        "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                    },
                                                                    {
                                                                        "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                    },
                                                                    {
                                                                        "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                    },
                                                                    {
                                                                        "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                    },
                                                                    {
                                                                        "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                    },
                                                                    {
                                                                        "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                    },
                                                                    {
                                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                    },
                                                                    {
                                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                    },
                                                                    {
                                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                    },
                                                                    {
                                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                    },
                                                                    {
                                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                    },
                                                                    {
                                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                    },
                                                                    {
                                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                    },
                                                                    {
                                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                    },
                                                                    {
                                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                    }
                                                                ]
                                                            }
                                                        }
                                                    ],
                                                    "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                }
                                            }
                                        },
                                        "source": "acc://dn.acme",
                                        "destination": "acc://dn.acme",
                                        "number": 134004
                                    }
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 134528,
                                "produced": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://9aec9740b2e8e3b596a0d1b3a1190e44561996d4e13dcc190f43656e8112131f@dn.acme"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://d3f108ce5d3e995e4983dccbd58f70768282bd142f446e007f01a13b7694df90@dn.acme/network"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 2
                                },
                                "cause": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        }
                    ],
                    "start": 0,
                    "total": 9
                },
                "anchored": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "minorBlock",
                            "index": 172228,
                            "source": "acc://bvn-BVN3.acme"
                        },
                        {
                            "recordType": "minorBlock",
                            "index": 171831,
                            "source": "acc://bvn-BVN1.acme"
                        },
                        {
                            "recordType": "minorBlock",
                            "index": 134526,
                            "source": "acc://dn.acme"
                        },
                        {
                            "recordType": "minorBlock",
                            "index": 172229,
                            "source": "acc://bvn-BVN3.acme"
                        }
                    ],
                    "start": 0,
                    "total": 4
                },
                "lastBlockTime": "2026-01-18T10:33:41.000Z"
            },
            {
                "recordType": "minorBlock",
                "index": 171834,
                "time": "2026-01-18T10:25:33.000Z",
                "source": "acc://bvn-BVN1.acme",
                "entries": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "chainEntry",
                            "account": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                            "name": "signature",
                            "type": "transaction",
                            "index": 1165283,
                            "entry": "e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9",
                            "value": {
                                "recordType": "message",
                                "id": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                "message": {
                                    "type": "signature",
                                    "signature": {
                                        "type": "ed25519",
                                        "publicKey": "a712ffe3deb1f07753329235c74c1404d82827290b7accb579189ecb251db694",
                                        "signature": "52c859328b121914e2db63a90246472d3e129aeab96d99c67489af2ba52b231c5ea57a57f9a0d8c56d6710f8634b81b184f127a5737b1cc3d9c9b38ac3e73e0b",
                                        "signer": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                        "signerVersion": 1,
                                        "timestamp": 1165284,
                                        "transactionHash": "d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d"
                                    },
                                    "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 171834,
                                "produced": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://906c6d3230631ed827d4bc82a01828ecdae36ea74681868590e595f5a8ca1a85@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://f30e957d0b794a4c4f0629ba89c06d861452ae5f4d108dadf408790e87ef3702@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://906c6d3230631ed827d4bc82a01828ecdae36ea74681868590e595f5a8ca1a85@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://f30e957d0b794a4c4f0629ba89c06d861452ae5f4d108dadf408790e87ef3702@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 4
                                },
                                "cause": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                            "name": "main",
                            "type": "transaction",
                            "index": 1165284,
                            "entry": "d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d",
                            "value": {
                                "recordType": "message",
                                "id": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                "message": {
                                    "type": "transaction",
                                    "transaction": {
                                        "header": {
                                            "principal": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                            "initiator": "4d7d9ee36124310914b6f92ed2650f23880cadc5ba56d18f9d14c8d42dedfdba"
                                        },
                                        "body": {
                                            "type": "sendTokens",
                                            "to": [
                                                {
                                                    "url": "acc://f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME",
                                                    "amount": "1000000000"
                                                }
                                            ]
                                        }
                                    }
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 171834,
                                "produced": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://f000524c952a6cd998daa2433259ecdeaacc2c8ae2ea227d86440232ca177f07@f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://f000524c952a6cd998daa2433259ecdeaacc2c8ae2ea227d86440232ca177f07@f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 2
                                },
                                "cause": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "signatureSet",
                                            "account": {
                                                "type": "liteIdentity",
                                                "url": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                                "creditBalance": 18446744073359528000,
                                                "lastUsedOn": 1166748
                                            },
                                            "signatures": {
                                                "recordType": "range",
                                                "records": [
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                                        "message": {
                                                            "type": "signature",
                                                            "signature": {
                                                                "type": "ed25519",
                                                                "publicKey": "a712ffe3deb1f07753329235c74c1404d82827290b7accb579189ecb251db694",
                                                                "signature": "52c859328b121914e2db63a90246472d3e129aeab96d99c67489af2ba52b231c5ea57a57f9a0d8c56d6710f8634b81b184f127a5737b1cc3d9c9b38ac3e73e0b",
                                                                "signer": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                                                "signerVersion": 1,
                                                                "timestamp": 1165284,
                                                                "transactionHash": "d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d"
                                                            },
                                                            "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                                                        },
                                                        "historical": true
                                                    }
                                                ],
                                                "start": 0,
                                                "total": 1
                                            }
                                        },
                                        {
                                            "recordType": "signatureSet",
                                            "account": {
                                                "type": "liteTokenAccount",
                                                "url": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                                "tokenUrl": "acc://ACME",
                                                "balance": "18833252000000000"
                                            },
                                            "signatures": {
                                                "recordType": "range",
                                                "records": [
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://906c6d3230631ed827d4bc82a01828ecdae36ea74681868590e595f5a8ca1a85@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                                        "message": {
                                                            "type": "creditPayment",
                                                            "paid": 300,
                                                            "payer": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                                            "initiator": true,
                                                            "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                                            "cause": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5"
                                                        },
                                                        "historical": true
                                                    },
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://f30e957d0b794a4c4f0629ba89c06d861452ae5f4d108dadf408790e87ef3702@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                                        "message": {
                                                            "type": "signature",
                                                            "signature": {
                                                                "type": "authority",
                                                                "origin": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                                                "authority": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                                                "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                                                "cause": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5"
                                                            },
                                                            "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                                                        },
                                                        "historical": true
                                                    }
                                                ],
                                                "start": 0,
                                                "total": 2
                                            }
                                        }
                                    ],
                                    "start": 0,
                                    "total": 2
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                            "name": "signature",
                            "type": "transaction",
                            "index": 2330567,
                            "entry": "f30e957d0b794a4c4f0629ba89c06d861452ae5f4d108dadf408790e87ef3702",
                            "value": {
                                "recordType": "message",
                                "id": "acc://f30e957d0b794a4c4f0629ba89c06d861452ae5f4d108dadf408790e87ef3702@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                "message": {
                                    "type": "signature",
                                    "signature": {
                                        "type": "authority",
                                        "origin": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                        "authority": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                        "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                        "cause": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5"
                                    },
                                    "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 171834,
                                "produced": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "cause": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://bvn-BVN1.acme/anchors",
                            "name": "anchor(directory)-bpt",
                            "type": "anchor",
                            "index": 134003,
                            "entry": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a"
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://bvn-BVN1.acme/anchors",
                            "name": "anchor(directory)-root",
                            "type": "anchor",
                            "index": 134003,
                            "entry": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6"
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://bvn-BVN1.acme/anchors",
                            "name": "anchor-sequence",
                            "type": "transaction",
                            "index": 171832,
                            "entry": "1f202816465b495152f90dfd4be98e5639cf3bfb0a24bd1ac099e8d359b1f978",
                            "value": {
                                "recordType": "message",
                                "id": "acc://1f202816465b495152f90dfd4be98e5639cf3bfb0a24bd1ac099e8d359b1f978@unknown",
                                "message": {
                                    "type": "transaction",
                                    "transaction": {
                                        "header": {},
                                        "body": {
                                            "type": "blockValidatorAnchor",
                                            "source": "acc://bvn-BVN1.acme",
                                            "minorBlockIndex": 171833,
                                            "rootChainIndex": 1401616,
                                            "rootChainAnchor": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d",
                                            "stateTreeAnchor": "7d14b3d55421d39e2ca3ef29376e771dd2c1555ed849d60f0ba8328a2c3c53cf"
                                        }
                                    }
                                },
                                "status": "remote",
                                "result": {
                                    "type": "unknown"
                                },
                                "produced": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "cause": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://bvn-BVN1.acme/anchors",
                            "name": "main",
                            "type": "transaction",
                            "index": 134004,
                            "entry": "2f7c8156456cd8d7188b9372c53bfc3dde55242c6eb048fdb2ea10c25f46a1da",
                            "value": {
                                "recordType": "message",
                                "id": "acc://2f7c8156456cd8d7188b9372c53bfc3dde55242c6eb048fdb2ea10c25f46a1da@bvn-BVN1.acme/anchors",
                                "message": {
                                    "type": "transaction",
                                    "transaction": {
                                        "header": {
                                            "principal": "acc://bvn-BVN1.acme/anchors"
                                        },
                                        "body": {
                                            "type": "directoryAnchor",
                                            "source": "acc://dn.acme",
                                            "minorBlockIndex": 134526,
                                            "rootChainIndex": 1124831,
                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                            "receipts": [
                                                {
                                                    "anchor": {
                                                        "source": "acc://bvn-BVN1.acme",
                                                        "minorBlockIndex": 171829,
                                                        "rootChainIndex": 1401584,
                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                    },
                                                    "rootChainReceipt": {
                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                        "startIndex": 171828,
                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                        "endIndex": 171828,
                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                        "entries": [
                                                            {
                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                            },
                                                            {
                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                            },
                                                            {
                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                            },
                                                            {
                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                            },
                                                            {
                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                            },
                                                            {
                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                            },
                                                            {
                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                            },
                                                            {
                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                            },
                                                            {
                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                            },
                                                            {
                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                            },
                                                            {
                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                            },
                                                            {
                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                            },
                                                            {
                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                            },
                                                            {
                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                            },
                                                            {
                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                            },
                                                            {
                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                            },
                                                            {
                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                            },
                                                            {
                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                            },
                                                            {
                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                            },
                                                            {
                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                            }
                                                        ]
                                                    }
                                                },
                                                {
                                                    "anchor": {
                                                        "source": "acc://dn.acme",
                                                        "minorBlockIndex": 134524,
                                                        "rootChainIndex": 1124817,
                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                    },
                                                    "rootChainReceipt": {
                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                        "startIndex": 134001,
                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                        "endIndex": 134001,
                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                        "entries": [
                                                            {
                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                            },
                                                            {
                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                            },
                                                            {
                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                            },
                                                            {
                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                            },
                                                            {
                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                            },
                                                            {
                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                            },
                                                            {
                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                            },
                                                            {
                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                            },
                                                            {
                                                                "right": true,
                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                            },
                                                            {
                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                            },
                                                            {
                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                            },
                                                            {
                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                            },
                                                            {
                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                            },
                                                            {
                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                            },
                                                            {
                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                            },
                                                            {
                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                            },
                                                            {
                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                            },
                                                            {
                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                            },
                                                            {
                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                            }
                                                        ]
                                                    }
                                                }
                                            ],
                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                        }
                                    }
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 171834,
                                "produced": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "cause": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab@bvn-BVN1.acme"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "signatureSet",
                                            "account": {
                                                "type": "anchorLedger",
                                                "url": "acc://bvn-BVN1.acme/anchors",
                                                "minorBlockSequenceNumber": 172032,
                                                "majorBlockTime": "0001-01-01T00:00:00.000Z",
                                                "sequence": [
                                                    {
                                                        "url": "acc://dn.acme",
                                                        "received": 134159,
                                                        "delivered": 134159
                                                    }
                                                ]
                                            },
                                            "signatures": {
                                                "recordType": "range",
                                                "records": [
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://919c708f3e90616502fc4d6783d4f8dc11c45fdd5e34aeb3108d0d748140f0a7@dn.acme/network",
                                                        "message": {
                                                            "type": "blockAnchor",
                                                            "signature": {
                                                                "type": "ed25519",
                                                                "publicKey": "cf5c0b621f887f3fc6f1a63b258d06420d7ca366e19b8b49328373eb1e5506de",
                                                                "signature": "c288ad717dc1a5b8fdff61367dae8c743f4b02129e1e5a22188bea01c3367c27288d0af4d2f7e92832abb5d9975c79c455ef2b9bee2b78c5947f25c1d6c9be09",
                                                                "signer": "acc://dn.acme/network",
                                                                "timestamp": 1768731933051,
                                                                "transactionHash": "341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab"
                                                            },
                                                            "anchor": {
                                                                "type": "sequenced",
                                                                "message": {
                                                                    "type": "transaction",
                                                                    "transaction": {
                                                                        "header": {
                                                                            "principal": "acc://bvn-BVN1.acme/anchors"
                                                                        },
                                                                        "body": {
                                                                            "type": "directoryAnchor",
                                                                            "source": "acc://dn.acme",
                                                                            "minorBlockIndex": 134526,
                                                                            "rootChainIndex": 1124831,
                                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                                            "receipts": [
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://bvn-BVN1.acme",
                                                                                        "minorBlockIndex": 171829,
                                                                                        "rootChainIndex": 1401584,
                                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "startIndex": 171828,
                                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "endIndex": 171828,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                                            },
                                                                                            {
                                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                                            },
                                                                                            {
                                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                                            },
                                                                                            {
                                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                },
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://dn.acme",
                                                                                        "minorBlockIndex": 134524,
                                                                                        "rootChainIndex": 1124817,
                                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "startIndex": 134001,
                                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "endIndex": 134001,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                                            },
                                                                                            {
                                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                                            },
                                                                                            {
                                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                                            },
                                                                                            {
                                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                                            },
                                                                                            {
                                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                                            },
                                                                                            {
                                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                                            },
                                                                                            {
                                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                                            },
                                                                                            {
                                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                }
                                                                            ],
                                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                                        }
                                                                    }
                                                                },
                                                                "source": "acc://dn.acme",
                                                                "destination": "acc://bvn-BVN1.acme",
                                                                "number": 134004
                                                            }
                                                        }
                                                    },
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://1a70d16fe83810eb7c8802b1e301dfdc497459b160c1d29ec3aa55ae39aa1e03@dn.acme/network",
                                                        "message": {
                                                            "type": "blockAnchor",
                                                            "signature": {
                                                                "type": "ed25519",
                                                                "publicKey": "51fe2dbfe2a3005f2ab03a3177da7286870ea238d3d74f688043e2ea0b470640",
                                                                "signature": "81573a375479341bfa12ce3c7452947849a2a773204a570351cbfd9588ac3be106b4dedacf352d59925e4f0a882c36e01322278709e25eaa6a2654ca4189bb0a",
                                                                "signer": "acc://dn.acme/network",
                                                                "timestamp": 1768731933051,
                                                                "transactionHash": "341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab"
                                                            },
                                                            "anchor": {
                                                                "type": "sequenced",
                                                                "message": {
                                                                    "type": "transaction",
                                                                    "transaction": {
                                                                        "header": {
                                                                            "principal": "acc://bvn-BVN1.acme/anchors"
                                                                        },
                                                                        "body": {
                                                                            "type": "directoryAnchor",
                                                                            "source": "acc://dn.acme",
                                                                            "minorBlockIndex": 134526,
                                                                            "rootChainIndex": 1124831,
                                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                                            "receipts": [
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://bvn-BVN1.acme",
                                                                                        "minorBlockIndex": 171829,
                                                                                        "rootChainIndex": 1401584,
                                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "startIndex": 171828,
                                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "endIndex": 171828,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                                            },
                                                                                            {
                                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                                            },
                                                                                            {
                                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                                            },
                                                                                            {
                                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                },
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://dn.acme",
                                                                                        "minorBlockIndex": 134524,
                                                                                        "rootChainIndex": 1124817,
                                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "startIndex": 134001,
                                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "endIndex": 134001,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                                            },
                                                                                            {
                                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                                            },
                                                                                            {
                                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                                            },
                                                                                            {
                                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                                            },
                                                                                            {
                                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                                            },
                                                                                            {
                                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                                            },
                                                                                            {
                                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                                            },
                                                                                            {
                                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                }
                                                                            ],
                                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                                        }
                                                                    }
                                                                },
                                                                "source": "acc://dn.acme",
                                                                "destination": "acc://bvn-BVN1.acme",
                                                                "number": 134004
                                                            }
                                                        }
                                                    },
                                                    {
                                                        "recordType": "message",
                                                        "id": "acc://f3731abf73ae48823b4f1d5096d43b079f8cd7019ed49c615b36d7323ee4b78b@dn.acme/network",
                                                        "message": {
                                                            "type": "blockAnchor",
                                                            "signature": {
                                                                "type": "ed25519",
                                                                "publicKey": "ea744577476905ae36184a8023f8c8dcc24cfbd0e5b6d5792949bf8d02cdadaa",
                                                                "signature": "3bebdc6c35ab0a5b23e2ea6e28f0a912b734dfb6d40c6c4c761926f82cbcc9f56463cf0bf8dcf3d675ba04cadcf9f5b2e13eab75b2a7e21e44cb0541e6d8dc01",
                                                                "signer": "acc://dn.acme/network",
                                                                "timestamp": 1768731933050,
                                                                "transactionHash": "341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab"
                                                            },
                                                            "anchor": {
                                                                "type": "sequenced",
                                                                "message": {
                                                                    "type": "transaction",
                                                                    "transaction": {
                                                                        "header": {
                                                                            "principal": "acc://bvn-BVN1.acme/anchors"
                                                                        },
                                                                        "body": {
                                                                            "type": "directoryAnchor",
                                                                            "source": "acc://dn.acme",
                                                                            "minorBlockIndex": 134526,
                                                                            "rootChainIndex": 1124831,
                                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                                            "receipts": [
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://bvn-BVN1.acme",
                                                                                        "minorBlockIndex": 171829,
                                                                                        "rootChainIndex": 1401584,
                                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "startIndex": 171828,
                                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                                        "endIndex": 171828,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                                            },
                                                                                            {
                                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                                            },
                                                                                            {
                                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                                            },
                                                                                            {
                                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                                            },
                                                                                            {
                                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                },
                                                                                {
                                                                                    "anchor": {
                                                                                        "source": "acc://dn.acme",
                                                                                        "minorBlockIndex": 134524,
                                                                                        "rootChainIndex": 1124817,
                                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                                    },
                                                                                    "rootChainReceipt": {
                                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "startIndex": 134001,
                                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                                        "endIndex": 134001,
                                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                                        "entries": [
                                                                                            {
                                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                                            },
                                                                                            {
                                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                                            },
                                                                                            {
                                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                                            },
                                                                                            {
                                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                                            },
                                                                                            {
                                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                                            },
                                                                                            {
                                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                                            },
                                                                                            {
                                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                                            },
                                                                                            {
                                                                                                "right": true,
                                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                                            },
                                                                                            {
                                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                                            },
                                                                                            {
                                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                                            },
                                                                                            {
                                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                                            },
                                                                                            {
                                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                                            },
                                                                                            {
                                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                                            },
                                                                                            {
                                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                                            },
                                                                                            {
                                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                                            },
                                                                                            {
                                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                                            },
                                                                                            {
                                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                }
                                                                            ],
                                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                                        }
                                                                    }
                                                                },
                                                                "source": "acc://dn.acme",
                                                                "destination": "acc://bvn-BVN1.acme",
                                                                "number": 134004
                                                            }
                                                        }
                                                    }
                                                ],
                                                "start": 0,
                                                "total": 3
                                            }
                                        }
                                    ],
                                    "start": 0,
                                    "total": 1
                                },
                                "sequence": {
                                    "type": "sequenced",
                                    "message": {
                                        "type": "transaction",
                                        "transaction": {
                                            "header": {
                                                "principal": "acc://bvn-BVN1.acme/anchors"
                                            },
                                            "body": {
                                                "type": "directoryAnchor",
                                                "source": "acc://dn.acme",
                                                "minorBlockIndex": 134526,
                                                "rootChainIndex": 1124831,
                                                "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                "receipts": [
                                                    {
                                                        "anchor": {
                                                            "source": "acc://bvn-BVN1.acme",
                                                            "minorBlockIndex": 171829,
                                                            "rootChainIndex": 1401584,
                                                            "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                            "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                        },
                                                        "rootChainReceipt": {
                                                            "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                            "startIndex": 171828,
                                                            "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                            "endIndex": 171828,
                                                            "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                            "entries": [
                                                                {
                                                                    "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                },
                                                                {
                                                                    "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                },
                                                                {
                                                                    "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                },
                                                                {
                                                                    "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                },
                                                                {
                                                                    "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                },
                                                                {
                                                                    "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                },
                                                                {
                                                                    "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                },
                                                                {
                                                                    "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                },
                                                                {
                                                                    "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                },
                                                                {
                                                                    "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                },
                                                                {
                                                                    "right": true,
                                                                    "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                },
                                                                {
                                                                    "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                },
                                                                {
                                                                    "right": true,
                                                                    "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                },
                                                                {
                                                                    "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                },
                                                                {
                                                                    "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                },
                                                                {
                                                                    "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                },
                                                                {
                                                                    "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                },
                                                                {
                                                                    "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                },
                                                                {
                                                                    "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                },
                                                                {
                                                                    "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                },
                                                                {
                                                                    "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                },
                                                                {
                                                                    "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                }
                                                            ]
                                                        }
                                                    },
                                                    {
                                                        "anchor": {
                                                            "source": "acc://dn.acme",
                                                            "minorBlockIndex": 134524,
                                                            "rootChainIndex": 1124817,
                                                            "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                            "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                        },
                                                        "rootChainReceipt": {
                                                            "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                            "startIndex": 134001,
                                                            "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                            "endIndex": 134001,
                                                            "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                            "entries": [
                                                                {
                                                                    "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                },
                                                                {
                                                                    "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                },
                                                                {
                                                                    "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                },
                                                                {
                                                                    "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                },
                                                                {
                                                                    "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                },
                                                                {
                                                                    "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                },
                                                                {
                                                                    "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                },
                                                                {
                                                                    "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                },
                                                                {
                                                                    "right": true,
                                                                    "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                },
                                                                {
                                                                    "right": true,
                                                                    "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                },
                                                                {
                                                                    "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                },
                                                                {
                                                                    "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                },
                                                                {
                                                                    "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                },
                                                                {
                                                                    "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                },
                                                                {
                                                                    "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                },
                                                                {
                                                                    "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                },
                                                                {
                                                                    "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                },
                                                                {
                                                                    "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                },
                                                                {
                                                                    "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                },
                                                                {
                                                                    "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                }
                                                            ]
                                                        }
                                                    }
                                                ],
                                                "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                            }
                                        }
                                    },
                                    "source": "acc://dn.acme",
                                    "destination": "acc://bvn-BVN1.acme",
                                    "number": 134004
                                }
                            }
                        },
                        {
                            "recordType": "chainEntry",
                            "account": "acc://bvn-BVN1.acme/anchors",
                            "name": "signature",
                            "type": "transaction",
                            "index": 402011,
                            "entry": "f3731abf73ae48823b4f1d5096d43b079f8cd7019ed49c615b36d7323ee4b78b",
                            "value": {
                                "recordType": "message",
                                "id": "acc://f3731abf73ae48823b4f1d5096d43b079f8cd7019ed49c615b36d7323ee4b78b@dn.acme/network",
                                "message": {
                                    "type": "blockAnchor",
                                    "signature": {
                                        "type": "ed25519",
                                        "publicKey": "ea744577476905ae36184a8023f8c8dcc24cfbd0e5b6d5792949bf8d02cdadaa",
                                        "signature": "3bebdc6c35ab0a5b23e2ea6e28f0a912b734dfb6d40c6c4c761926f82cbcc9f56463cf0bf8dcf3d675ba04cadcf9f5b2e13eab75b2a7e21e44cb0541e6d8dc01",
                                        "signer": "acc://dn.acme/network",
                                        "timestamp": 1768731933050,
                                        "transactionHash": "341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab"
                                    },
                                    "anchor": {
                                        "type": "sequenced",
                                        "message": {
                                            "type": "transaction",
                                            "transaction": {
                                                "header": {
                                                    "principal": "acc://bvn-BVN1.acme/anchors"
                                                },
                                                "body": {
                                                    "type": "directoryAnchor",
                                                    "source": "acc://dn.acme",
                                                    "minorBlockIndex": 134526,
                                                    "rootChainIndex": 1124831,
                                                    "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                    "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                    "receipts": [
                                                        {
                                                            "anchor": {
                                                                "source": "acc://bvn-BVN1.acme",
                                                                "minorBlockIndex": 171829,
                                                                "rootChainIndex": 1401584,
                                                                "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                            },
                                                            "rootChainReceipt": {
                                                                "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                "startIndex": 171828,
                                                                "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                "endIndex": 171828,
                                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                "entries": [
                                                                    {
                                                                        "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                    },
                                                                    {
                                                                        "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                    },
                                                                    {
                                                                        "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                    },
                                                                    {
                                                                        "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                    },
                                                                    {
                                                                        "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                    },
                                                                    {
                                                                        "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                    },
                                                                    {
                                                                        "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                    },
                                                                    {
                                                                        "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                    },
                                                                    {
                                                                        "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                    },
                                                                    {
                                                                        "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                    },
                                                                    {
                                                                        "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                    },
                                                                    {
                                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                    },
                                                                    {
                                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                    },
                                                                    {
                                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                    },
                                                                    {
                                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                    },
                                                                    {
                                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                    },
                                                                    {
                                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                    },
                                                                    {
                                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                    },
                                                                    {
                                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                    },
                                                                    {
                                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                    }
                                                                ]
                                                            }
                                                        },
                                                        {
                                                            "anchor": {
                                                                "source": "acc://dn.acme",
                                                                "minorBlockIndex": 134524,
                                                                "rootChainIndex": 1124817,
                                                                "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                            },
                                                            "rootChainReceipt": {
                                                                "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                "startIndex": 134001,
                                                                "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                "endIndex": 134001,
                                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                "entries": [
                                                                    {
                                                                        "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                    },
                                                                    {
                                                                        "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                    },
                                                                    {
                                                                        "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                    },
                                                                    {
                                                                        "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                    },
                                                                    {
                                                                        "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                    },
                                                                    {
                                                                        "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                    },
                                                                    {
                                                                        "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                    },
                                                                    {
                                                                        "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                    },
                                                                    {
                                                                        "right": true,
                                                                        "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                    },
                                                                    {
                                                                        "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                    },
                                                                    {
                                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                    },
                                                                    {
                                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                    },
                                                                    {
                                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                    },
                                                                    {
                                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                    },
                                                                    {
                                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                    },
                                                                    {
                                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                    },
                                                                    {
                                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                    },
                                                                    {
                                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                    },
                                                                    {
                                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                    }
                                                                ]
                                                            }
                                                        }
                                                    ],
                                                    "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                }
                                            }
                                        },
                                        "source": "acc://dn.acme",
                                        "destination": "acc://bvn-BVN1.acme",
                                        "number": 134004
                                    }
                                },
                                "status": "delivered",
                                "result": {
                                    "type": "unknown"
                                },
                                "received": 171834,
                                "produced": {
                                    "recordType": "range",
                                    "records": [
                                        {
                                            "recordType": "txID",
                                            "value": "acc://2b8355e0b72b89a8052f54574d82001b377ec46c47e526c5b84635b1c89dbf26@dn.acme/network"
                                        },
                                        {
                                            "recordType": "txID",
                                            "value": "acc://341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab@bvn-BVN1.acme"
                                        }
                                    ],
                                    "start": 0,
                                    "total": 2
                                },
                                "cause": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "signatures": {
                                    "recordType": "range",
                                    "start": 0,
                                    "total": 0
                                },
                                "sequence": {
                                    "type": "sequenced"
                                }
                            }
                        }
                    ],
                    "start": 0,
                    "total": 8
                },
                "lastBlockTime": "2026-01-18T10:33:42.000Z"
            }
        ],
        "start": 0,
        "total": 3
    },
    "lastBlockTime": "2026-01-18T10:33:41.000Z",
    "messages": [
        {
            "recordType": "chainEntry",
            "account": "acc://dn.acme/anchors",
            "name": "anchor-sequence",
            "type": "transaction",
            "index": 134006,
            "entry": "3b4cdfb91186f243ac2e9eaa450d92d8e5dc31f1f2700f53041bf1e24f9b6f99",
            "value": {
                "recordType": "message",
                "id": "acc://3b4cdfb91186f243ac2e9eaa450d92d8e5dc31f1f2700f53041bf1e24f9b6f99@unknown",
                "message": {
                    "type": "transaction",
                    "transaction": {
                        "header": {},
                        "body": {
                            "type": "directoryAnchor",
                            "source": "acc://dn.acme",
                            "minorBlockIndex": 134529,
                            "rootChainIndex": 1124856,
                            "rootChainAnchor": "cf5d62813fb1de54fa33159e467727e7575b39525e459a5dcd8e90d126950d49",
                            "stateTreeAnchor": "1538ccb730b6af5e9a66989cd9056cbb0e5e59fe307fb877be0443f5ae733822",
                            "receipts": [
                                {
                                    "anchor": {
                                        "source": "acc://bvn-BVN1.acme",
                                        "minorBlockIndex": 171832,
                                        "rootChainIndex": 1401607,
                                        "rootChainAnchor": "1111678e2df2e1e014fbe19428abb73512c93eea24497eab670c77eb58c52cf3",
                                        "stateTreeAnchor": "b2fa5df7a837bc4a6edeff1759e4fa676d676108ff3410d0c88e68bdaa8a379d"
                                    },
                                    "rootChainReceipt": {
                                        "start": "1111678e2df2e1e014fbe19428abb73512c93eea24497eab670c77eb58c52cf3",
                                        "startIndex": 171831,
                                        "end": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d",
                                        "endIndex": 171832,
                                        "anchor": "cf5d62813fb1de54fa33159e467727e7575b39525e459a5dcd8e90d126950d49",
                                        "entries": [
                                            {
                                                "hash": "a3ee0784384a61874f04fffcc238997aa78ec1aa2f95e6331669e0ce5d5a6b03"
                                            },
                                            {
                                                "hash": "308fa76ff561d31f49e79c7ce43397798c10ef323588218d103b41d3a2306fd2"
                                            },
                                            {
                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                            },
                                            {
                                                "right": true,
                                                "hash": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d"
                                            },
                                            {
                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                            },
                                            {
                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                            },
                                            {
                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                            },
                                            {
                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                            },
                                            {
                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                            },
                                            {
                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                            },
                                            {
                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                            },
                                            {
                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                            },
                                            {
                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                            },
                                            {
                                                "hash": "76c8dfee08c6eb1b5b9163d8c661184fd7c0fd0a91d9968810c1a1936a4e4d32"
                                            },
                                            {
                                                "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                            },
                                            {
                                                "right": true,
                                                "hash": "21e3e5538a5ac1f507fd434a9e61a3e8493d8dc58a6ca16b794581d26fe674b4"
                                            },
                                            {
                                                "right": true,
                                                "hash": "448627c5e6a22394cc37c7e3570d5d4f7db6ff4c83d537a0101aab11984f1702"
                                            },
                                            {
                                                "hash": "b7cc321c86a05b2036203f3dacc1437693c7e3e706da266c5fb72c93fb5e9a56"
                                            },
                                            {
                                                "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                            },
                                            {
                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                            },
                                            {
                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                            },
                                            {
                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                            },
                                            {
                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                            },
                                            {
                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                            },
                                            {
                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                            },
                                            {
                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                            }
                                        ]
                                    }
                                },
                                {
                                    "anchor": {
                                        "source": "acc://bvn-BVN1.acme",
                                        "minorBlockIndex": 171833,
                                        "rootChainIndex": 1401616,
                                        "rootChainAnchor": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d",
                                        "stateTreeAnchor": "7d14b3d55421d39e2ca3ef29376e771dd2c1555ed849d60f0ba8328a2c3c53cf"
                                    },
                                    "rootChainReceipt": {
                                        "start": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d",
                                        "startIndex": 171832,
                                        "end": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d",
                                        "endIndex": 171832,
                                        "anchor": "cf5d62813fb1de54fa33159e467727e7575b39525e459a5dcd8e90d126950d49",
                                        "entries": [
                                            {
                                                "hash": "dcf6fe6c2fd0dce3c1f4ebcebb22c1476b1d3239640785328db7359ac7045bd6"
                                            },
                                            {
                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                            },
                                            {
                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                            },
                                            {
                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                            },
                                            {
                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                            },
                                            {
                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                            },
                                            {
                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                            },
                                            {
                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                            },
                                            {
                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                            },
                                            {
                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                            },
                                            {
                                                "hash": "76c8dfee08c6eb1b5b9163d8c661184fd7c0fd0a91d9968810c1a1936a4e4d32"
                                            },
                                            {
                                                "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                            },
                                            {
                                                "right": true,
                                                "hash": "21e3e5538a5ac1f507fd434a9e61a3e8493d8dc58a6ca16b794581d26fe674b4"
                                            },
                                            {
                                                "right": true,
                                                "hash": "448627c5e6a22394cc37c7e3570d5d4f7db6ff4c83d537a0101aab11984f1702"
                                            },
                                            {
                                                "hash": "b7cc321c86a05b2036203f3dacc1437693c7e3e706da266c5fb72c93fb5e9a56"
                                            },
                                            {
                                                "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                            },
                                            {
                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                            },
                                            {
                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                            },
                                            {
                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                            },
                                            {
                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                            },
                                            {
                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                            },
                                            {
                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                            },
                                            {
                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                            }
                                        ]
                                    }
                                },
                                {
                                    "anchor": {
                                        "source": "acc://dn.acme",
                                        "minorBlockIndex": 134527,
                                        "rootChainIndex": 1124840,
                                        "rootChainAnchor": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                        "stateTreeAnchor": "b6097c12c42c4f86dc18da6e3dabf97e62af2589ecdad1c325077b50d7ecd647"
                                    },
                                    "rootChainReceipt": {
                                        "start": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                        "startIndex": 134004,
                                        "end": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                        "endIndex": 134004,
                                        "anchor": "cf5d62813fb1de54fa33159e467727e7575b39525e459a5dcd8e90d126950d49",
                                        "entries": [
                                            {
                                                "hash": "a8b29c45c4d249478fceb2aecb2420873fe39afca91dc492dbe95820f20d62ad"
                                            },
                                            {
                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                            },
                                            {
                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                            },
                                            {
                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                            },
                                            {
                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                            },
                                            {
                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                            },
                                            {
                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                            },
                                            {
                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                            },
                                            {
                                                "hash": "46b3c617f44fa1554262a8fd6f07451773126203a2097220d71a27816ae453ce"
                                            },
                                            {
                                                "right": true,
                                                "hash": "00873a4930eef9cedf03a631af84f97049525c46ac01147906dc132374b8c039"
                                            },
                                            {
                                                "hash": "eed1033f2c512f8c601b9cb6ef137a7582f9568154dfff35949222f751aa9a5d"
                                            },
                                            {
                                                "right": true,
                                                "hash": "448627c5e6a22394cc37c7e3570d5d4f7db6ff4c83d537a0101aab11984f1702"
                                            },
                                            {
                                                "hash": "b7cc321c86a05b2036203f3dacc1437693c7e3e706da266c5fb72c93fb5e9a56"
                                            },
                                            {
                                                "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                            },
                                            {
                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                            },
                                            {
                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                            },
                                            {
                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                            },
                                            {
                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                            },
                                            {
                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                            },
                                            {
                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                            },
                                            {
                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                        }
                    }
                },
                "status": "remote",
                "result": {
                    "type": "unknown"
                },
                "produced": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "cause": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://dn.acme/anchors",
            "name": "main",
            "type": "transaction",
            "index": 432939,
            "entry": "1b9ca58a0bbd5c38855afda522c335e96abf90fa2e2ed177fff1d2196285b813",
            "value": {
                "recordType": "message",
                "id": "acc://1b9ca58a0bbd5c38855afda522c335e96abf90fa2e2ed177fff1d2196285b813@dn.acme/anchors",
                "message": {
                    "type": "transaction",
                    "transaction": {
                        "header": {
                            "principal": "acc://dn.acme/anchors"
                        },
                        "body": {
                            "type": "blockValidatorAnchor",
                            "source": "acc://bvn-BVN1.acme",
                            "minorBlockIndex": 171834,
                            "rootChainIndex": 1401625,
                            "rootChainAnchor": "261376826c041ccf6fbba744711c0714d4281384343bae45c28943cdbcad9496",
                            "stateTreeAnchor": "f2347a547699f4b4a4c27eb06081e49d6172ba95216c304b208700f850737d32"
                        }
                    }
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 134530,
                "produced": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "cause": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://98082889f5c97960fd5899744284b473675b0d29d478c5fb5a26c5f8a68a4dc0@dn.acme"
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "signatures": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "signatureSet",
                            "account": {
                                "type": "anchorLedger",
                                "url": "acc://dn.acme/anchors",
                                "minorBlockSequenceNumber": 134161,
                                "majorBlockIndex": 9,
                                "majorBlockTime": "2026-01-18T00:00:01.000Z",
                                "sequence": [
                                    {
                                        "url": "acc://bvn-BVN1.acme",
                                        "received": 172029,
                                        "delivered": 172029
                                    },
                                    {
                                        "url": "acc://bvn-BVN2.acme",
                                        "received": 156,
                                        "delivered": 156
                                    },
                                    {
                                        "url": "acc://bvn-BVN3.acme",
                                        "received": 127082,
                                        "delivered": 127082
                                    },
                                    {
                                        "url": "acc://dn.acme",
                                        "received": 134158,
                                        "delivered": 134158
                                    }
                                ]
                            },
                            "signatures": {
                                "recordType": "range",
                                "records": [
                                    {
                                        "recordType": "message",
                                        "id": "acc://4fa6e752cfc2ab96828a11294bf8fd5482b8a66ebba098f0333cc365f1c82953@dn.acme/network",
                                        "message": {
                                            "type": "blockAnchor",
                                            "signature": {
                                                "type": "ed25519",
                                                "publicKey": "51fe2dbfe2a3005f2ab03a3177da7286870ea238d3d74f688043e2ea0b470640",
                                                "signature": "6bd76ad576deebc8bd86633a3e7f5429bca62189296fb6a683e42e7e5d832077297c607a60262adbac48c8b163b1f29c7e227558e65acb4432aa30adbc667d0d",
                                                "signer": "acc://dn.acme/network",
                                                "timestamp": 1768731938572,
                                                "transactionHash": "98082889f5c97960fd5899744284b473675b0d29d478c5fb5a26c5f8a68a4dc0"
                                            },
                                            "anchor": {
                                                "type": "sequenced",
                                                "message": {
                                                    "type": "transaction",
                                                    "transaction": {
                                                        "header": {
                                                            "principal": "acc://dn.acme/anchors"
                                                        },
                                                        "body": {
                                                            "type": "blockValidatorAnchor",
                                                            "source": "acc://bvn-BVN1.acme",
                                                            "minorBlockIndex": 171834,
                                                            "rootChainIndex": 1401625,
                                                            "rootChainAnchor": "261376826c041ccf6fbba744711c0714d4281384343bae45c28943cdbcad9496",
                                                            "stateTreeAnchor": "f2347a547699f4b4a4c27eb06081e49d6172ba95216c304b208700f850737d32"
                                                        }
                                                    }
                                                },
                                                "source": "acc://bvn-BVN1.acme",
                                                "destination": "acc://dn.acme",
                                                "number": 171834
                                            }
                                        }
                                    }
                                ],
                                "start": 0,
                                "total": 1
                            }
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "sequence": {
                    "type": "sequenced",
                    "message": {
                        "type": "transaction",
                        "transaction": {
                            "header": {
                                "principal": "acc://dn.acme/anchors"
                            },
                            "body": {
                                "type": "blockValidatorAnchor",
                                "source": "acc://bvn-BVN1.acme",
                                "minorBlockIndex": 171834,
                                "rootChainIndex": 1401625,
                                "rootChainAnchor": "261376826c041ccf6fbba744711c0714d4281384343bae45c28943cdbcad9496",
                                "stateTreeAnchor": "f2347a547699f4b4a4c27eb06081e49d6172ba95216c304b208700f850737d32"
                            }
                        }
                    },
                    "source": "acc://bvn-BVN1.acme",
                    "destination": "acc://dn.acme",
                    "number": 171834
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://dn.acme/anchors",
            "name": "signature",
            "type": "transaction",
            "index": 700950,
            "entry": "306907582c99e8fef21fb71938ed892ec9416d4e71cd087b6d1da3f8a6e81b08",
            "value": {
                "recordType": "message",
                "id": "acc://306907582c99e8fef21fb71938ed892ec9416d4e71cd087b6d1da3f8a6e81b08@dn.acme/network",
                "message": {
                    "type": "blockAnchor",
                    "signature": {
                        "type": "ed25519",
                        "publicKey": "51fe2dbfe2a3005f2ab03a3177da7286870ea238d3d74f688043e2ea0b470640",
                        "signature": "4685b3ca211f82d7464184c3bebbffe6bbe22a361f90be2f47f24e634830c6b1d16ab36be98fd0a232240ae2bde7ce7b3c30aaab2835036fa29eb2718d7ab409",
                        "signer": "acc://dn.acme/network",
                        "timestamp": 1768731938921,
                        "transactionHash": "f1124fd4906be71f911a4903b7536f22c2889aeee4419d04f30e76161e6d98be"
                    },
                    "anchor": {
                        "type": "sequenced",
                        "message": {
                            "type": "transaction",
                            "transaction": {
                                "header": {
                                    "principal": "acc://dn.acme/anchors"
                                },
                                "body": {
                                    "type": "directoryAnchor",
                                    "source": "acc://dn.acme",
                                    "minorBlockIndex": 134528,
                                    "rootChainIndex": 1124849,
                                    "rootChainAnchor": "a44bf548f07e7f0aeeff6f3348d375800d01296a0a123d0f3da7ca531722fe97",
                                    "stateTreeAnchor": "1c666028dec4cfaaf20ab2b8172d96e8c28d0fe785a3bb8113291b247676d3a4",
                                    "receipts": [
                                        {
                                            "anchor": {
                                                "source": "acc://bvn-BVN3.acme",
                                                "minorBlockIndex": 172228,
                                                "rootChainIndex": 795677,
                                                "rootChainAnchor": "cc0ed1da3f2234f9d8e5f43902fb75afa25cf48e216bbb09998afdaf2f582be3",
                                                "stateTreeAnchor": "4dcddaf33e84c9bf54230ab3ce11be7a803ef1c1d07e51649bf595aa2fcb0729"
                                            },
                                            "rootChainReceipt": {
                                                "start": "cc0ed1da3f2234f9d8e5f43902fb75afa25cf48e216bbb09998afdaf2f582be3",
                                                "startIndex": 126940,
                                                "end": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                                "endIndex": 126941,
                                                "anchor": "a44bf548f07e7f0aeeff6f3348d375800d01296a0a123d0f3da7ca531722fe97",
                                                "entries": [
                                                    {
                                                        "right": true,
                                                        "hash": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7"
                                                    },
                                                    {
                                                        "hash": "9bd6d5e4abe7275af61702ebae99697020702bbd1d72535fa560842ff90fbe6a"
                                                    },
                                                    {
                                                        "hash": "c545b652f3c6c46a40eeaefef1c5e7ae410311aa11b63586391faabcf93b4a22"
                                                    },
                                                    {
                                                        "hash": "426a17720ddcbbe98982b03669954b71f4305394e823a06d50185f49b6e87dbe"
                                                    },
                                                    {
                                                        "hash": "c4136034fc8e84bf01150e48e6004d70d07f3029a798c02b4e88b2634608807c"
                                                    },
                                                    {
                                                        "hash": "337cf6886f0179f3d6a8a6aa550167695a7e45596f2675fd400de3d90a77777a"
                                                    },
                                                    {
                                                        "hash": "9e5e0cedbde8aaca69bd73b305a5157fa8929ee3facf706c86627c7064ec1767"
                                                    },
                                                    {
                                                        "hash": "4472fdbcfbcad5209f7e2a2a8c009e35dac0d03e53d48a484aeaeec3c6b5d993"
                                                    },
                                                    {
                                                        "hash": "cf69c7387abc3e14c39f96c624758a1dd335caca47147ac45457a47283d91ecb"
                                                    },
                                                    {
                                                        "hash": "106a563245495fbaa118cb2ca4274fea45821ec186070c928c9415da1b0621cf"
                                                    },
                                                    {
                                                        "hash": "85a44f2ca3ec5e3dcf59cbe468fae38269c4cb0c68d8aebc72a2b73a7fc4f354"
                                                    },
                                                    {
                                                        "hash": "d3f1f628a34dc36a35ee725601a468bf4d75179e65a36070d8d222e73a96a332"
                                                    },
                                                    {
                                                        "hash": "40bd99969dc9e74245243ce33675fa226fe141530c763f1c0a0c69fe0e340b78"
                                                    },
                                                    {
                                                        "hash": "b2ff0c192d92053f4f102174f192957eb4c6f5bc078e64b0990a53cdba92392a"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "fe24aa1185b59c050c7e1f9c046c69a65bf2b05900ac0145d5eed5cb06fca7a9"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "3ae91a3ef4198046f5aeb4b507e939a5987d234f98706f7e482027bfb1fb68b8"
                                                    },
                                                    {
                                                        "hash": "e1e9f8a0d8ab6cd192e8b175b2ce52064e9ac8061287b76e56cb74083b799cd4"
                                                    },
                                                    {
                                                        "hash": "4722bdb5b15724125e1e916f555cded4977d820abed3775c904d6395e6b9146a"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                                    },
                                                    {
                                                        "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                    },
                                                    {
                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                    },
                                                    {
                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                    },
                                                    {
                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                    },
                                                    {
                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                    },
                                                    {
                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                    },
                                                    {
                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                    },
                                                    {
                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                    }
                                                ]
                                            }
                                        },
                                        {
                                            "anchor": {
                                                "source": "acc://bvn-BVN1.acme",
                                                "minorBlockIndex": 171831,
                                                "rootChainIndex": 1401602,
                                                "rootChainAnchor": "a3ee0784384a61874f04fffcc238997aa78ec1aa2f95e6331669e0ce5d5a6b03",
                                                "stateTreeAnchor": "7faba59bd7c1029021869b3192d5f9d39be30939aaf4fbed6c998ad4e6295148"
                                            },
                                            "rootChainReceipt": {
                                                "start": "a3ee0784384a61874f04fffcc238997aa78ec1aa2f95e6331669e0ce5d5a6b03",
                                                "startIndex": 171830,
                                                "end": "a3ee0784384a61874f04fffcc238997aa78ec1aa2f95e6331669e0ce5d5a6b03",
                                                "endIndex": 171830,
                                                "anchor": "a44bf548f07e7f0aeeff6f3348d375800d01296a0a123d0f3da7ca531722fe97",
                                                "entries": [
                                                    {
                                                        "hash": "308fa76ff561d31f49e79c7ce43397798c10ef323588218d103b41d3a2306fd2"
                                                    },
                                                    {
                                                        "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                    },
                                                    {
                                                        "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                    },
                                                    {
                                                        "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                    },
                                                    {
                                                        "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                    },
                                                    {
                                                        "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                    },
                                                    {
                                                        "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                    },
                                                    {
                                                        "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                    },
                                                    {
                                                        "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                    },
                                                    {
                                                        "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                    },
                                                    {
                                                        "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "382834eb61ce6964bb2b8bacce286fe1a414394d046ea7c10cd243473d1ddd3d"
                                                    },
                                                    {
                                                        "hash": "efee7165f1748d7f8514d710d2946cc500db0fafeaccafe88d67844d4581e762"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "5e203b4e99e7b5ccd1b457d9844e658d27b287e308c9f034bdac3ad5bdfa0c7d"
                                                    },
                                                    {
                                                        "hash": "4722bdb5b15724125e1e916f555cded4977d820abed3775c904d6395e6b9146a"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                                    },
                                                    {
                                                        "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                    },
                                                    {
                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                    },
                                                    {
                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                    },
                                                    {
                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                    },
                                                    {
                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                    },
                                                    {
                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                    },
                                                    {
                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                    },
                                                    {
                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                    }
                                                ]
                                            }
                                        },
                                        {
                                            "anchor": {
                                                "source": "acc://dn.acme",
                                                "minorBlockIndex": 134526,
                                                "rootChainIndex": 1124831,
                                                "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a"
                                            },
                                            "rootChainReceipt": {
                                                "start": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                "startIndex": 134003,
                                                "end": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                "endIndex": 134003,
                                                "anchor": "a44bf548f07e7f0aeeff6f3348d375800d01296a0a123d0f3da7ca531722fe97",
                                                "entries": [
                                                    {
                                                        "hash": "e312f39d2913ede4b010f20ac2186c5c7db5b26cacc9c0569e5ca6b8075c35a4"
                                                    },
                                                    {
                                                        "hash": "f4b9b8af5cc1d0dc05f1edc20680f60684521c2284947208cd59b6cad4e64527"
                                                    },
                                                    {
                                                        "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                    },
                                                    {
                                                        "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                    },
                                                    {
                                                        "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                    },
                                                    {
                                                        "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                    },
                                                    {
                                                        "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                    },
                                                    {
                                                        "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                    },
                                                    {
                                                        "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "b6e10d5e0e50dcfde50bea6cf32718c0238ee4aec0d3a60fa947cf27564035b3"
                                                    },
                                                    {
                                                        "hash": "0528b4ba0176ed5e73968e569da10a2a615d3c48e928aff5fa886b0f3fe42f05"
                                                    },
                                                    {
                                                        "hash": "e1e9f8a0d8ab6cd192e8b175b2ce52064e9ac8061287b76e56cb74083b799cd4"
                                                    },
                                                    {
                                                        "hash": "4722bdb5b15724125e1e916f555cded4977d820abed3775c904d6395e6b9146a"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                                    },
                                                    {
                                                        "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                    },
                                                    {
                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                    },
                                                    {
                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                    },
                                                    {
                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                    },
                                                    {
                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                    },
                                                    {
                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                    },
                                                    {
                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                    },
                                                    {
                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                    }
                                                ]
                                            }
                                        },
                                        {
                                            "anchor": {
                                                "source": "acc://bvn-BVN3.acme",
                                                "minorBlockIndex": 172229,
                                                "rootChainIndex": 795683,
                                                "rootChainAnchor": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                                "stateTreeAnchor": "3a7aeed93b2b5c1d04dbe556d112f1272c38f97499f9341e11c590addea40fc1"
                                            },
                                            "rootChainReceipt": {
                                                "start": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                                "startIndex": 126941,
                                                "end": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                                "endIndex": 126941,
                                                "anchor": "a44bf548f07e7f0aeeff6f3348d375800d01296a0a123d0f3da7ca531722fe97",
                                                "entries": [
                                                    {
                                                        "hash": "cc0ed1da3f2234f9d8e5f43902fb75afa25cf48e216bbb09998afdaf2f582be3"
                                                    },
                                                    {
                                                        "hash": "9bd6d5e4abe7275af61702ebae99697020702bbd1d72535fa560842ff90fbe6a"
                                                    },
                                                    {
                                                        "hash": "c545b652f3c6c46a40eeaefef1c5e7ae410311aa11b63586391faabcf93b4a22"
                                                    },
                                                    {
                                                        "hash": "426a17720ddcbbe98982b03669954b71f4305394e823a06d50185f49b6e87dbe"
                                                    },
                                                    {
                                                        "hash": "c4136034fc8e84bf01150e48e6004d70d07f3029a798c02b4e88b2634608807c"
                                                    },
                                                    {
                                                        "hash": "337cf6886f0179f3d6a8a6aa550167695a7e45596f2675fd400de3d90a77777a"
                                                    },
                                                    {
                                                        "hash": "9e5e0cedbde8aaca69bd73b305a5157fa8929ee3facf706c86627c7064ec1767"
                                                    },
                                                    {
                                                        "hash": "4472fdbcfbcad5209f7e2a2a8c009e35dac0d03e53d48a484aeaeec3c6b5d993"
                                                    },
                                                    {
                                                        "hash": "cf69c7387abc3e14c39f96c624758a1dd335caca47147ac45457a47283d91ecb"
                                                    },
                                                    {
                                                        "hash": "106a563245495fbaa118cb2ca4274fea45821ec186070c928c9415da1b0621cf"
                                                    },
                                                    {
                                                        "hash": "85a44f2ca3ec5e3dcf59cbe468fae38269c4cb0c68d8aebc72a2b73a7fc4f354"
                                                    },
                                                    {
                                                        "hash": "d3f1f628a34dc36a35ee725601a468bf4d75179e65a36070d8d222e73a96a332"
                                                    },
                                                    {
                                                        "hash": "40bd99969dc9e74245243ce33675fa226fe141530c763f1c0a0c69fe0e340b78"
                                                    },
                                                    {
                                                        "hash": "b2ff0c192d92053f4f102174f192957eb4c6f5bc078e64b0990a53cdba92392a"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "fe24aa1185b59c050c7e1f9c046c69a65bf2b05900ac0145d5eed5cb06fca7a9"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "3ae91a3ef4198046f5aeb4b507e939a5987d234f98706f7e482027bfb1fb68b8"
                                                    },
                                                    {
                                                        "hash": "e1e9f8a0d8ab6cd192e8b175b2ce52064e9ac8061287b76e56cb74083b799cd4"
                                                    },
                                                    {
                                                        "hash": "4722bdb5b15724125e1e916f555cded4977d820abed3775c904d6395e6b9146a"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "0d793f1e1af4ceab4631297653ebecc3222033645404bcc26bf3253329c06377"
                                                    },
                                                    {
                                                        "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                                    },
                                                    {
                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                    },
                                                    {
                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                    },
                                                    {
                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                    },
                                                    {
                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                    },
                                                    {
                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                    },
                                                    {
                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                    },
                                                    {
                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                    }
                                                ]
                                            }
                                        }
                                    ],
                                    "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                }
                            }
                        },
                        "source": "acc://dn.acme",
                        "destination": "acc://dn.acme",
                        "number": 134006
                    }
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 134530,
                "produced": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://06653d8cf2638c082c5ee954d555fc1606df1e97aea1f881191dbb3d110e7720@dn.acme/network"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://f1124fd4906be71f911a4903b7536f22c2889aeee4419d04f30e76161e6d98be@dn.acme"
                        }
                    ],
                    "start": 0,
                    "total": 2
                },
                "cause": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://bvn-BVN3.acme/anchors",
            "name": "main",
            "type": "transaction",
            "index": 134004,
            "entry": "b4bca7ad379a94c1f438b0c1f32a9b82ef7ef25c47539194bd9d8d9b6f11b920",
            "value": {
                "recordType": "message",
                "id": "acc://b4bca7ad379a94c1f438b0c1f32a9b82ef7ef25c47539194bd9d8d9b6f11b920@bvn-BVN3.acme/anchors",
                "message": {
                    "type": "transaction",
                    "transaction": {
                        "header": {
                            "principal": "acc://bvn-BVN3.acme/anchors"
                        },
                        "body": {
                            "type": "directoryAnchor",
                            "source": "acc://dn.acme",
                            "minorBlockIndex": 134526,
                            "rootChainIndex": 1124831,
                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                            "receipts": [
                                {
                                    "anchor": {
                                        "source": "acc://bvn-BVN1.acme",
                                        "minorBlockIndex": 171829,
                                        "rootChainIndex": 1401584,
                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                    },
                                    "rootChainReceipt": {
                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                        "startIndex": 171828,
                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                        "endIndex": 171828,
                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                        "entries": [
                                            {
                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                            },
                                            {
                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                            },
                                            {
                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                            },
                                            {
                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                            },
                                            {
                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                            },
                                            {
                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                            },
                                            {
                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                            },
                                            {
                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                            },
                                            {
                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                            },
                                            {
                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                            },
                                            {
                                                "right": true,
                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                            },
                                            {
                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                            },
                                            {
                                                "right": true,
                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                            },
                                            {
                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                            },
                                            {
                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                            },
                                            {
                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                            },
                                            {
                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                            },
                                            {
                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                            },
                                            {
                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                            },
                                            {
                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                            },
                                            {
                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                            },
                                            {
                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                            }
                                        ]
                                    }
                                },
                                {
                                    "anchor": {
                                        "source": "acc://dn.acme",
                                        "minorBlockIndex": 134524,
                                        "rootChainIndex": 1124817,
                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                    },
                                    "rootChainReceipt": {
                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                        "startIndex": 134001,
                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                        "endIndex": 134001,
                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                        "entries": [
                                            {
                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                            },
                                            {
                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                            },
                                            {
                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                            },
                                            {
                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                            },
                                            {
                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                            },
                                            {
                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                            },
                                            {
                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                            },
                                            {
                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                            },
                                            {
                                                "right": true,
                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                            },
                                            {
                                                "right": true,
                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                            },
                                            {
                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                            },
                                            {
                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                            },
                                            {
                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                            },
                                            {
                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                            },
                                            {
                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                            },
                                            {
                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                            },
                                            {
                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                            },
                                            {
                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                            },
                                            {
                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                            },
                                            {
                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                        }
                    }
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 172231,
                "produced": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "cause": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264@bvn-BVN3.acme"
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "signatures": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "signatureSet",
                            "account": {
                                "type": "anchorLedger",
                                "url": "acc://bvn-BVN3.acme/anchors",
                                "minorBlockSequenceNumber": 127085,
                                "majorBlockTime": "0001-01-01T00:00:00.000Z",
                                "sequence": [
                                    {
                                        "url": "acc://dn.acme",
                                        "received": 134159,
                                        "delivered": 134159
                                    }
                                ]
                            },
                            "signatures": {
                                "recordType": "range",
                                "records": [
                                    {
                                        "recordType": "message",
                                        "id": "acc://edcb3d4c353a9a24681c35651347d44dfa256675306e8b039183fc4a335db85f@dn.acme/network",
                                        "message": {
                                            "type": "blockAnchor",
                                            "signature": {
                                                "type": "ed25519",
                                                "publicKey": "cf5c0b621f887f3fc6f1a63b258d06420d7ca366e19b8b49328373eb1e5506de",
                                                "signature": "fd0455ea595e9cb623833ae23f0d1dd91bac5e614111ea6f1fdea41f27c80b143a14a0ace1b716089ce0ac2ad364a88c857d347f1114cc05b4b3d0c23befc307",
                                                "signer": "acc://dn.acme/network",
                                                "timestamp": 1768731933052,
                                                "transactionHash": "eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264"
                                            },
                                            "anchor": {
                                                "type": "sequenced",
                                                "message": {
                                                    "type": "transaction",
                                                    "transaction": {
                                                        "header": {
                                                            "principal": "acc://bvn-BVN3.acme/anchors"
                                                        },
                                                        "body": {
                                                            "type": "directoryAnchor",
                                                            "source": "acc://dn.acme",
                                                            "minorBlockIndex": 134526,
                                                            "rootChainIndex": 1124831,
                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                            "receipts": [
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://bvn-BVN1.acme",
                                                                        "minorBlockIndex": 171829,
                                                                        "rootChainIndex": 1401584,
                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "startIndex": 171828,
                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "endIndex": 171828,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                            },
                                                                            {
                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                            },
                                                                            {
                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                            },
                                                                            {
                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                            },
                                                                            {
                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                            },
                                                                            {
                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                            },
                                                                            {
                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                            },
                                                                            {
                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                            },
                                                                            {
                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                            },
                                                                            {
                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                            },
                                                                            {
                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                },
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://dn.acme",
                                                                        "minorBlockIndex": 134524,
                                                                        "rootChainIndex": 1124817,
                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "startIndex": 134001,
                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "endIndex": 134001,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                            },
                                                                            {
                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                            },
                                                                            {
                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                            },
                                                                            {
                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                            },
                                                                            {
                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                            },
                                                                            {
                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                            },
                                                                            {
                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                            },
                                                                            {
                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                            },
                                                                            {
                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                }
                                                            ],
                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                        }
                                                    }
                                                },
                                                "source": "acc://dn.acme",
                                                "destination": "acc://bvn-BVN3.acme",
                                                "number": 134004
                                            }
                                        }
                                    },
                                    {
                                        "recordType": "message",
                                        "id": "acc://6903b3d148bc8c66664fcc710a05ec4428fcc4ac909954cfa8cd9c08ee2b5e92@dn.acme/network",
                                        "message": {
                                            "type": "blockAnchor",
                                            "signature": {
                                                "type": "ed25519",
                                                "publicKey": "51fe2dbfe2a3005f2ab03a3177da7286870ea238d3d74f688043e2ea0b470640",
                                                "signature": "949a193eb5c4cd51585ba39ca7be14c5df623da0802731229d4a65399bdb0b9fa2aa1046141a4157df1206cf5af3b8bcb516c40693ce77ecf6bff7e3c587eb06",
                                                "signer": "acc://dn.acme/network",
                                                "timestamp": 1768731933052,
                                                "transactionHash": "eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264"
                                            },
                                            "anchor": {
                                                "type": "sequenced",
                                                "message": {
                                                    "type": "transaction",
                                                    "transaction": {
                                                        "header": {
                                                            "principal": "acc://bvn-BVN3.acme/anchors"
                                                        },
                                                        "body": {
                                                            "type": "directoryAnchor",
                                                            "source": "acc://dn.acme",
                                                            "minorBlockIndex": 134526,
                                                            "rootChainIndex": 1124831,
                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                            "receipts": [
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://bvn-BVN1.acme",
                                                                        "minorBlockIndex": 171829,
                                                                        "rootChainIndex": 1401584,
                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "startIndex": 171828,
                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "endIndex": 171828,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                            },
                                                                            {
                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                            },
                                                                            {
                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                            },
                                                                            {
                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                            },
                                                                            {
                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                            },
                                                                            {
                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                            },
                                                                            {
                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                            },
                                                                            {
                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                            },
                                                                            {
                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                            },
                                                                            {
                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                            },
                                                                            {
                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                },
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://dn.acme",
                                                                        "minorBlockIndex": 134524,
                                                                        "rootChainIndex": 1124817,
                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "startIndex": 134001,
                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "endIndex": 134001,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                            },
                                                                            {
                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                            },
                                                                            {
                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                            },
                                                                            {
                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                            },
                                                                            {
                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                            },
                                                                            {
                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                            },
                                                                            {
                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                            },
                                                                            {
                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                            },
                                                                            {
                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                }
                                                            ],
                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                        }
                                                    }
                                                },
                                                "source": "acc://dn.acme",
                                                "destination": "acc://bvn-BVN3.acme",
                                                "number": 134004
                                            }
                                        }
                                    },
                                    {
                                        "recordType": "message",
                                        "id": "acc://2d26195853117e0bd9ab7a2e4a6238939ba98c3c7af38639535b22cea52dabcc@dn.acme/network",
                                        "message": {
                                            "type": "blockAnchor",
                                            "signature": {
                                                "type": "ed25519",
                                                "publicKey": "ea744577476905ae36184a8023f8c8dcc24cfbd0e5b6d5792949bf8d02cdadaa",
                                                "signature": "41e4c21cb1f6d449f5f56adcb1add10bb78d52fffbc7c07f71e729596b2d1438ed01861a7abe7c605e26da3464d9fbffa24b7693b185346abb365de1910acc02",
                                                "signer": "acc://dn.acme/network",
                                                "timestamp": 1768731933050,
                                                "transactionHash": "eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264"
                                            },
                                            "anchor": {
                                                "type": "sequenced",
                                                "message": {
                                                    "type": "transaction",
                                                    "transaction": {
                                                        "header": {
                                                            "principal": "acc://bvn-BVN3.acme/anchors"
                                                        },
                                                        "body": {
                                                            "type": "directoryAnchor",
                                                            "source": "acc://dn.acme",
                                                            "minorBlockIndex": 134526,
                                                            "rootChainIndex": 1124831,
                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                            "receipts": [
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://bvn-BVN1.acme",
                                                                        "minorBlockIndex": 171829,
                                                                        "rootChainIndex": 1401584,
                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "startIndex": 171828,
                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "endIndex": 171828,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                            },
                                                                            {
                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                            },
                                                                            {
                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                            },
                                                                            {
                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                            },
                                                                            {
                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                            },
                                                                            {
                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                            },
                                                                            {
                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                            },
                                                                            {
                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                            },
                                                                            {
                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                            },
                                                                            {
                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                            },
                                                                            {
                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                },
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://dn.acme",
                                                                        "minorBlockIndex": 134524,
                                                                        "rootChainIndex": 1124817,
                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "startIndex": 134001,
                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "endIndex": 134001,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                            },
                                                                            {
                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                            },
                                                                            {
                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                            },
                                                                            {
                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                            },
                                                                            {
                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                            },
                                                                            {
                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                            },
                                                                            {
                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                            },
                                                                            {
                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                            },
                                                                            {
                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                }
                                                            ],
                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                        }
                                                    }
                                                },
                                                "source": "acc://dn.acme",
                                                "destination": "acc://bvn-BVN3.acme",
                                                "number": 134004
                                            }
                                        }
                                    }
                                ],
                                "start": 0,
                                "total": 3
                            }
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "sequence": {
                    "type": "sequenced",
                    "message": {
                        "type": "transaction",
                        "transaction": {
                            "header": {
                                "principal": "acc://bvn-BVN3.acme/anchors"
                            },
                            "body": {
                                "type": "directoryAnchor",
                                "source": "acc://dn.acme",
                                "minorBlockIndex": 134526,
                                "rootChainIndex": 1124831,
                                "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                "receipts": [
                                    {
                                        "anchor": {
                                            "source": "acc://bvn-BVN1.acme",
                                            "minorBlockIndex": 171829,
                                            "rootChainIndex": 1401584,
                                            "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                            "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                        },
                                        "rootChainReceipt": {
                                            "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                            "startIndex": 171828,
                                            "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                            "endIndex": 171828,
                                            "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                            "entries": [
                                                {
                                                    "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                },
                                                {
                                                    "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                },
                                                {
                                                    "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                },
                                                {
                                                    "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                },
                                                {
                                                    "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                },
                                                {
                                                    "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                },
                                                {
                                                    "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                },
                                                {
                                                    "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                },
                                                {
                                                    "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                },
                                                {
                                                    "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                },
                                                {
                                                    "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                },
                                                {
                                                    "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                },
                                                {
                                                    "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                },
                                                {
                                                    "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                },
                                                {
                                                    "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                },
                                                {
                                                    "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                },
                                                {
                                                    "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                },
                                                {
                                                    "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                },
                                                {
                                                    "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                },
                                                {
                                                    "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                }
                                            ]
                                        }
                                    },
                                    {
                                        "anchor": {
                                            "source": "acc://dn.acme",
                                            "minorBlockIndex": 134524,
                                            "rootChainIndex": 1124817,
                                            "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                            "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                        },
                                        "rootChainReceipt": {
                                            "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                            "startIndex": 134001,
                                            "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                            "endIndex": 134001,
                                            "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                            "entries": [
                                                {
                                                    "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                },
                                                {
                                                    "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                },
                                                {
                                                    "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                },
                                                {
                                                    "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                },
                                                {
                                                    "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                },
                                                {
                                                    "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                },
                                                {
                                                    "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                },
                                                {
                                                    "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                },
                                                {
                                                    "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                },
                                                {
                                                    "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                },
                                                {
                                                    "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                },
                                                {
                                                    "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                },
                                                {
                                                    "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                },
                                                {
                                                    "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                },
                                                {
                                                    "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                },
                                                {
                                                    "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                },
                                                {
                                                    "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                },
                                                {
                                                    "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                }
                                            ]
                                        }
                                    }
                                ],
                                "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                            }
                        }
                    },
                    "source": "acc://dn.acme",
                    "destination": "acc://bvn-BVN3.acme",
                    "number": 134004
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://bvn-BVN3.acme/anchors",
            "name": "signature",
            "type": "transaction",
            "index": 402011,
            "entry": "2d26195853117e0bd9ab7a2e4a6238939ba98c3c7af38639535b22cea52dabcc",
            "value": {
                "recordType": "message",
                "id": "acc://2d26195853117e0bd9ab7a2e4a6238939ba98c3c7af38639535b22cea52dabcc@dn.acme/network",
                "message": {
                    "type": "blockAnchor",
                    "signature": {
                        "type": "ed25519",
                        "publicKey": "ea744577476905ae36184a8023f8c8dcc24cfbd0e5b6d5792949bf8d02cdadaa",
                        "signature": "41e4c21cb1f6d449f5f56adcb1add10bb78d52fffbc7c07f71e729596b2d1438ed01861a7abe7c605e26da3464d9fbffa24b7693b185346abb365de1910acc02",
                        "signer": "acc://dn.acme/network",
                        "timestamp": 1768731933050,
                        "transactionHash": "eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264"
                    },
                    "anchor": {
                        "type": "sequenced",
                        "message": {
                            "type": "transaction",
                            "transaction": {
                                "header": {
                                    "principal": "acc://bvn-BVN3.acme/anchors"
                                },
                                "body": {
                                    "type": "directoryAnchor",
                                    "source": "acc://dn.acme",
                                    "minorBlockIndex": 134526,
                                    "rootChainIndex": 1124831,
                                    "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                    "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                    "receipts": [
                                        {
                                            "anchor": {
                                                "source": "acc://bvn-BVN1.acme",
                                                "minorBlockIndex": 171829,
                                                "rootChainIndex": 1401584,
                                                "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                            },
                                            "rootChainReceipt": {
                                                "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                "startIndex": 171828,
                                                "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                "endIndex": 171828,
                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                "entries": [
                                                    {
                                                        "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                    },
                                                    {
                                                        "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                    },
                                                    {
                                                        "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                    },
                                                    {
                                                        "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                    },
                                                    {
                                                        "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                    },
                                                    {
                                                        "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                    },
                                                    {
                                                        "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                    },
                                                    {
                                                        "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                    },
                                                    {
                                                        "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                    },
                                                    {
                                                        "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                    },
                                                    {
                                                        "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                    },
                                                    {
                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                    },
                                                    {
                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                    },
                                                    {
                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                    },
                                                    {
                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                    },
                                                    {
                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                    },
                                                    {
                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                    },
                                                    {
                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                    },
                                                    {
                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                    },
                                                    {
                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                    }
                                                ]
                                            }
                                        },
                                        {
                                            "anchor": {
                                                "source": "acc://dn.acme",
                                                "minorBlockIndex": 134524,
                                                "rootChainIndex": 1124817,
                                                "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                            },
                                            "rootChainReceipt": {
                                                "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                "startIndex": 134001,
                                                "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                "endIndex": 134001,
                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                "entries": [
                                                    {
                                                        "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                    },
                                                    {
                                                        "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                    },
                                                    {
                                                        "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                    },
                                                    {
                                                        "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                    },
                                                    {
                                                        "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                    },
                                                    {
                                                        "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                    },
                                                    {
                                                        "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                    },
                                                    {
                                                        "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                    },
                                                    {
                                                        "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                    },
                                                    {
                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                    },
                                                    {
                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                    },
                                                    {
                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                    },
                                                    {
                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                    },
                                                    {
                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                    },
                                                    {
                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                    },
                                                    {
                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                    },
                                                    {
                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                    },
                                                    {
                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                    }
                                                ]
                                            }
                                        }
                                    ],
                                    "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                }
                            }
                        },
                        "source": "acc://dn.acme",
                        "destination": "acc://bvn-BVN3.acme",
                        "number": 134004
                    }
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 172231,
                "produced": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://78535fdd99ee5da8ec82fd388718da3ea9660efb50cca0890b7a5fcaf89d5b7e@dn.acme/network"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://eedb4b7594d8fae1e100d00fa3bb47a4b03207377c6afbee1db4b1882e3f6264@bvn-BVN3.acme"
                        }
                    ],
                    "start": 0,
                    "total": 2
                },
                "cause": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://certen-kermit-11.acme/book",
            "name": "signature",
            "type": "transaction",
            "index": 13,
            "entry": "85d1c899b2efcff50b14966e4b0f5d364021f46c7a45e13dd8741a7811a35f09",
            "value": {
                "recordType": "message",
                "id": "acc://85d1c899b2efcff50b14966e4b0f5d364021f46c7a45e13dd8741a7811a35f09@certen-kermit-11.acme/book",
                "message": {
                    "type": "signatureRequest",
                    "authority": "acc://certen-kermit-11.acme/book",
                    "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                    "cause": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 172231,
                "produced": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data"
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "cause": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://certen-kermit-11.acme/book/1",
            "name": "signature",
            "type": "transaction",
            "index": 16,
            "entry": "ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95",
            "value": {
                "recordType": "message",
                "id": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1",
                "message": {
                    "type": "signature",
                    "signature": {
                        "type": "ed25519",
                        "publicKey": "9d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7",
                        "signature": "b2ec40a1915f0092f8c9e0f9097b21f67c397b9b52b95c0268ebfc0716018cfc0588490ea9858a20969157f8b74e17592091c03e73820656b7da07a3c8f8d908",
                        "signer": "acc://certen-kermit-11.acme/book/1",
                        "signerVersion": 2,
                        "timestamp": 1768731929544000,
                        "transactionHash": "835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a"
                    },
                    "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data"
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 172231,
                "produced": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://cace5d35590ba975764bd0062be1ac52386c83b4871c0e3e45c2e9fee569d7d0@certen-kermit-11.acme/data"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://d0508ff9a08e920aff04c9dff1a1faf070828a4b8dd56e3ee35370c8ed5ddf86@certen-kermit-11.acme/data"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://cace5d35590ba975764bd0062be1ac52386c83b4871c0e3e45c2e9fee569d7d0@certen-kermit-11.acme/data"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://d0508ff9a08e920aff04c9dff1a1faf070828a4b8dd56e3ee35370c8ed5ddf86@certen-kermit-11.acme/data"
                        }
                    ],
                    "start": 0,
                    "total": 6
                },
                "cause": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://certen-kermit-11.acme/data",
            "name": "main",
            "type": "transaction",
            "index": 12,
            "entry": "835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a",
            "value": {
                "recordType": "message",
                "id": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                "message": {
                    "type": "transaction",
                    "transaction": {
                        "header": {
                            "principal": "acc://certen-kermit-11.acme/data",
                            "initiator": "bb0502cbecac0db1e91449a3b2aa1018623aed8a2c7456f235eb8ceb7ebff9f1",
                            "memo": "CERTEN_INTENT",
                            "metadata": "01025f00"
                        },
                        "body": {
                            "type": "writeData",
                            "entry": {
                                "type": "doubleHash",
                                "data": [
                                    "7b226b696e64223a2243455254454e5f494e54454e54222c2276657273696f6e223a22312e30222c2270726f6f665f636c617373223a226f6e5f64656d616e64222c22696e74656e745f6964223a2266343663356538372d393966652d343337352d626465622d336639626330643032656663222c22637265617465645f6174223a22323032362d30312d31385431303a32353a32392e3534325a222c22696e74656e7454797065223a2263726f73735f636861696e5f7472616e73666572222c226465736372697074696f6e223a22455448207472616e73666572206f6e205365706f6c6961227d",
                                    "7b2270726f746f636f6c223a2243455254454e222c2276657273696f6e223a22312e30222c226f7065726174696f6e47726f75704964223a2266343663356538372d393966652d343337352d626465622d336639626330643032656663222c226c656773223a5b7b226c65674964223a226c65672d31222c22636861696e223a22657468657265756d222c22636861696e4964223a31313135353131312c2266726f6d223a22307863363833316461363533373431616665626331346134396539633632393133313261306261336464222c22746f223a22307862653030343361626231306536646235366238633663356362336636333962663766653639323531222c22616d6f756e74576569223a2231222c22616e63686f72436f6e7472616374223a7b2261646472657373223a22307845623137654264333531443265303430613063423330323661334430344245633138326438623938222c2266756e6374696f6e53656c6563746f72223a22637265617465416e63686f7228627974657333322c627974657333322c627974657333322c627974657333322c75696e7432353629227d7d5d7d",
                                    "7b226f7267616e697a6174696f6e416469223a226163633a2f2f63657274656e2d6b65726d69742d31312e61636d65222c22617574686f72697a6174696f6e223a7b2272657175697265645f6b65795f626f6f6b223a226163633a2f2f63657274656e2d6b65726d69742d31312e61636d652f626f6f6b222c227369676e61747572655f7468726573686f6c64223a317d7d",
                                    "7b226e6f6e6365223a2263657274656e5f31373638373331393239353432222c22637265617465645f6174223a313736383733313932392c22657870697265735f6174223a313736383733353532397d"
                                ]
                            }
                        }
                    }
                },
                "status": "delivered",
                "result": {
                    "type": "writeData",
                    "entryHash": "9f453a09d6c4eca244e22427499a1a47ce1b207de9a7bb943c6ef9c89fcdd364",
                    "accountUrl": "acc://certen-kermit-11.acme/data",
                    "accountID": "d738a79366a931132e55183efa167128f225cb1a28852edf3cd467c7ea957ba1"
                },
                "received": 172231,
                "produced": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "cause": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://85d1c899b2efcff50b14966e4b0f5d364021f46c7a45e13dd8741a7811a35f09@certen-kermit-11.acme/book"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                        }
                    ],
                    "start": 0,
                    "total": 2
                },
                "signatures": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "signatureSet",
                            "account": {
                                "type": "keyBook",
                                "url": "acc://certen-kermit-11.acme/book",
                                "authorities": [
                                    {
                                        "url": "acc://certen-kermit-11.acme/book"
                                    }
                                ],
                                "pageCount": 1
                            },
                            "signatures": {
                                "recordType": "range",
                                "records": [
                                    {
                                        "recordType": "message",
                                        "id": "acc://85d1c899b2efcff50b14966e4b0f5d364021f46c7a45e13dd8741a7811a35f09@certen-kermit-11.acme/book",
                                        "message": {
                                            "type": "signatureRequest",
                                            "authority": "acc://certen-kermit-11.acme/book",
                                            "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                                            "cause": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data"
                                        },
                                        "historical": true
                                    }
                                ],
                                "start": 0,
                                "total": 1
                            }
                        },
                        {
                            "recordType": "signatureSet",
                            "account": {
                                "type": "keyPage",
                                "url": "acc://certen-kermit-11.acme/book/1",
                                "creditBalance": 996590,
                                "acceptThreshold": 1,
                                "version": 2,
                                "keys": [
                                    {
                                        "publicKeyHash": "4d07443e23bf3d244facb56f7fd4614d29b21f5530361ca1f77c40ac17f16192",
                                        "lastUsedOn": 1768731929544000
                                    }
                                ]
                            },
                            "signatures": {
                                "recordType": "range",
                                "records": [
                                    {
                                        "recordType": "message",
                                        "id": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1",
                                        "message": {
                                            "type": "signature",
                                            "signature": {
                                                "type": "ed25519",
                                                "publicKey": "9d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7",
                                                "signature": "b2ec40a1915f0092f8c9e0f9097b21f67c397b9b52b95c0268ebfc0716018cfc0588490ea9858a20969157f8b74e17592091c03e73820656b7da07a3c8f8d908",
                                                "signer": "acc://certen-kermit-11.acme/book/1",
                                                "signerVersion": 2,
                                                "timestamp": 1768731929544000,
                                                "transactionHash": "835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a"
                                            },
                                            "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data"
                                        },
                                        "historical": true
                                    }
                                ],
                                "start": 0,
                                "total": 1
                            }
                        },
                        {
                            "recordType": "signatureSet",
                            "account": {
                                "type": "dataAccount",
                                "url": "acc://certen-kermit-11.acme/data"
                            },
                            "signatures": {
                                "recordType": "range",
                                "records": [
                                    {
                                        "recordType": "message",
                                        "id": "acc://bba19e2b65e3d633ec635c5556d8b3ff16b37d608e59678a52e9bd5312fea423@certen-kermit-11.acme/data",
                                        "message": {
                                            "type": "signatureRequest",
                                            "authority": "acc://certen-kermit-11.acme/data",
                                            "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                                            "cause": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1"
                                        },
                                        "historical": true
                                    },
                                    {
                                        "recordType": "message",
                                        "id": "acc://d0508ff9a08e920aff04c9dff1a1faf070828a4b8dd56e3ee35370c8ed5ddf86@certen-kermit-11.acme/data",
                                        "message": {
                                            "type": "creditPayment",
                                            "paid": 40,
                                            "payer": "acc://certen-kermit-11.acme/book/1",
                                            "initiator": true,
                                            "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                                            "cause": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1"
                                        },
                                        "historical": true
                                    },
                                    {
                                        "recordType": "message",
                                        "id": "acc://cace5d35590ba975764bd0062be1ac52386c83b4871c0e3e45c2e9fee569d7d0@certen-kermit-11.acme/data",
                                        "message": {
                                            "type": "signature",
                                            "signature": {
                                                "type": "authority",
                                                "origin": "acc://certen-kermit-11.acme/book/1",
                                                "authority": "acc://certen-kermit-11.acme/book",
                                                "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                                                "cause": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1"
                                            },
                                            "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data"
                                        },
                                        "historical": true
                                    }
                                ],
                                "start": 0,
                                "total": 3
                            }
                        }
                    ],
                    "start": 0,
                    "total": 3
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://certen-kermit-11.acme/data",
            "name": "signature",
            "type": "transaction",
            "index": 35,
            "entry": "cace5d35590ba975764bd0062be1ac52386c83b4871c0e3e45c2e9fee569d7d0",
            "value": {
                "recordType": "message",
                "id": "acc://cace5d35590ba975764bd0062be1ac52386c83b4871c0e3e45c2e9fee569d7d0@certen-kermit-11.acme/data",
                "message": {
                    "type": "signature",
                    "signature": {
                        "type": "authority",
                        "origin": "acc://certen-kermit-11.acme/book/1",
                        "authority": "acc://certen-kermit-11.acme/book",
                        "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data",
                        "cause": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1"
                    },
                    "txID": "acc://835fe24bc66f5d3d94d7a78dd4e296086fd6ef1f40728d8dd6ae56b6872ace5a@certen-kermit-11.acme/data"
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 172231,
                "produced": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "cause": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://ebc3a0a9f57211b75433236b5737f427648909b38969a24c1ee32aabd0e60e95@certen-kermit-11.acme/book/1"
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME",
            "name": "main",
            "type": "transaction",
            "index": 1165105,
            "entry": "874ffd3376508f71d020a8c0c260743d037a5f7d35d21bce3bc7d781e571574c",
            "value": {
                "recordType": "message",
                "id": "acc://874ffd3376508f71d020a8c0c260743d037a5f7d35d21bce3bc7d781e571574c@f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME",
                "message": {
                    "type": "transaction",
                    "transaction": {
                        "header": {
                            "principal": "acc://f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME"
                        },
                        "body": {
                            "type": "syntheticDepositTokens",
                            "cause": "acc://963a2a28c5277f74f0ec55fc7cf2cb46abc35d9fe842be6186171d601f8eb640@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                            "source": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                            "initiator": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                            "feeRefund": 100,
                            "index": 18,
                            "token": "acc://ACME",
                            "amount": "1000000000"
                        }
                    }
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 172231,
                "produced": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "cause": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://bc0a7eb63ddd6dcbe3e69a29a31f907e3f59fd0693f19d7a3d62a71c7e99af43@bvn-BVN3.acme"
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced",
                    "message": {
                        "type": "transaction",
                        "transaction": {
                            "header": {
                                "principal": "acc://f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME"
                            },
                            "body": {
                                "type": "syntheticDepositTokens",
                                "cause": "acc://963a2a28c5277f74f0ec55fc7cf2cb46abc35d9fe842be6186171d601f8eb640@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                "source": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                "initiator": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                "feeRefund": 100,
                                "index": 18,
                                "token": "acc://ACME",
                                "amount": "1000000000"
                            }
                        }
                    },
                    "source": "acc://bvn-BVN1.acme",
                    "destination": "acc://bvn-BVN3.acme",
                    "number": 1165113
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://dn.acme/anchors",
            "name": "anchor-sequence",
            "type": "transaction",
            "index": 134004,
            "entry": "ed16ed15e2c17663bf19579ab9b00c3e5fbd2234e10c1b4a58484b77d345747d",
            "value": {
                "recordType": "message",
                "id": "acc://ed16ed15e2c17663bf19579ab9b00c3e5fbd2234e10c1b4a58484b77d345747d@unknown",
                "message": {
                    "type": "transaction",
                    "transaction": {
                        "header": {},
                        "body": {
                            "type": "directoryAnchor",
                            "source": "acc://dn.acme",
                            "minorBlockIndex": 134527,
                            "rootChainIndex": 1124840,
                            "rootChainAnchor": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                            "stateTreeAnchor": "b6097c12c42c4f86dc18da6e3dabf97e62af2589ecdad1c325077b50d7ecd647",
                            "receipts": [
                                {
                                    "anchor": {
                                        "source": "acc://bvn-BVN3.acme",
                                        "minorBlockIndex": 172227,
                                        "rootChainIndex": 795671,
                                        "rootChainAnchor": "864f64bd3abd1a4f1a92315da01aceb6fd33de169d7970cc8401b08c58062398",
                                        "stateTreeAnchor": "b6af44f71b89d9237b864658b61f51375e4c84eb57ba1d4d81b7550c47a483c0"
                                    },
                                    "rootChainReceipt": {
                                        "start": "864f64bd3abd1a4f1a92315da01aceb6fd33de169d7970cc8401b08c58062398",
                                        "startIndex": 126939,
                                        "end": "864f64bd3abd1a4f1a92315da01aceb6fd33de169d7970cc8401b08c58062398",
                                        "endIndex": 126939,
                                        "anchor": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                        "entries": [
                                            {
                                                "hash": "75b81aa5e876e772ece15d29439e3f3da63deaecfdbd13df853e12a0e6597530"
                                            },
                                            {
                                                "hash": "c1aa0288bf49989a2204be18697d3be48ed9e2da198889f5fd1fd9f173e1db91"
                                            },
                                            {
                                                "hash": "c545b652f3c6c46a40eeaefef1c5e7ae410311aa11b63586391faabcf93b4a22"
                                            },
                                            {
                                                "hash": "426a17720ddcbbe98982b03669954b71f4305394e823a06d50185f49b6e87dbe"
                                            },
                                            {
                                                "hash": "c4136034fc8e84bf01150e48e6004d70d07f3029a798c02b4e88b2634608807c"
                                            },
                                            {
                                                "hash": "337cf6886f0179f3d6a8a6aa550167695a7e45596f2675fd400de3d90a77777a"
                                            },
                                            {
                                                "hash": "9e5e0cedbde8aaca69bd73b305a5157fa8929ee3facf706c86627c7064ec1767"
                                            },
                                            {
                                                "hash": "4472fdbcfbcad5209f7e2a2a8c009e35dac0d03e53d48a484aeaeec3c6b5d993"
                                            },
                                            {
                                                "hash": "cf69c7387abc3e14c39f96c624758a1dd335caca47147ac45457a47283d91ecb"
                                            },
                                            {
                                                "hash": "106a563245495fbaa118cb2ca4274fea45821ec186070c928c9415da1b0621cf"
                                            },
                                            {
                                                "hash": "85a44f2ca3ec5e3dcf59cbe468fae38269c4cb0c68d8aebc72a2b73a7fc4f354"
                                            },
                                            {
                                                "hash": "d3f1f628a34dc36a35ee725601a468bf4d75179e65a36070d8d222e73a96a332"
                                            },
                                            {
                                                "hash": "40bd99969dc9e74245243ce33675fa226fe141530c763f1c0a0c69fe0e340b78"
                                            },
                                            {
                                                "hash": "b2ff0c192d92053f4f102174f192957eb4c6f5bc078e64b0990a53cdba92392a"
                                            },
                                            {
                                                "hash": "37c387421f8801616dd33a37ac2a411b740c7867ee1546ea7b2f1992d1e50f94"
                                            },
                                            {
                                                "hash": "26f9b5466f391d2c82481a27cfdb97371683a6b968e693cab0281ecf23bc4bb3"
                                            },
                                            {
                                                "right": true,
                                                "hash": "b1394edafe5dd880fecaf6aad1f1827b4055cb880ba0104d662fd61fbbfe84e3"
                                            },
                                            {
                                                "right": true,
                                                "hash": "6e4f79a1eddfa5a02c4e2655fe543864f7e39654f5f9b2c9ab4f2cb1bd11a345"
                                            },
                                            {
                                                "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                            },
                                            {
                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                            },
                                            {
                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                            },
                                            {
                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                            },
                                            {
                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                            },
                                            {
                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                            },
                                            {
                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                            },
                                            {
                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                            }
                                        ]
                                    }
                                },
                                {
                                    "anchor": {
                                        "source": "acc://bvn-BVN1.acme",
                                        "minorBlockIndex": 171830,
                                        "rootChainIndex": 1401593,
                                        "rootChainAnchor": "8504c0da129c77c66f0e48a373145d00ffd23aafd958b1ef9ccf92a6aefa8145",
                                        "stateTreeAnchor": "67419a538d3dc4c6dc6fd32d3bc1ff31d4fb048bd6c730c09b2de816d8973ed9"
                                    },
                                    "rootChainReceipt": {
                                        "start": "8504c0da129c77c66f0e48a373145d00ffd23aafd958b1ef9ccf92a6aefa8145",
                                        "startIndex": 171829,
                                        "end": "8504c0da129c77c66f0e48a373145d00ffd23aafd958b1ef9ccf92a6aefa8145",
                                        "endIndex": 171829,
                                        "anchor": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                        "entries": [
                                            {
                                                "hash": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4"
                                            },
                                            {
                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                            },
                                            {
                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                            },
                                            {
                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                            },
                                            {
                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                            },
                                            {
                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                            },
                                            {
                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                            },
                                            {
                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                            },
                                            {
                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                            },
                                            {
                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                            },
                                            {
                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                            },
                                            {
                                                "hash": "8b44a45b75459eb95eeda80da8f60510dd91938dcd385576e89fb52aab1a825d"
                                            },
                                            {
                                                "right": true,
                                                "hash": "e01c090a7133fb9f3a567e469953b4e50445c434f73ca13c19c50bb46ff2a7b0"
                                            },
                                            {
                                                "right": true,
                                                "hash": "b1394edafe5dd880fecaf6aad1f1827b4055cb880ba0104d662fd61fbbfe84e3"
                                            },
                                            {
                                                "right": true,
                                                "hash": "6e4f79a1eddfa5a02c4e2655fe543864f7e39654f5f9b2c9ab4f2cb1bd11a345"
                                            },
                                            {
                                                "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                            },
                                            {
                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                            },
                                            {
                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                            },
                                            {
                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                            },
                                            {
                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                            },
                                            {
                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                            },
                                            {
                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                            },
                                            {
                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                            }
                                        ]
                                    }
                                },
                                {
                                    "anchor": {
                                        "source": "acc://dn.acme",
                                        "minorBlockIndex": 134525,
                                        "rootChainIndex": 1124824,
                                        "rootChainAnchor": "e312f39d2913ede4b010f20ac2186c5c7db5b26cacc9c0569e5ca6b8075c35a4",
                                        "stateTreeAnchor": "8b57b8a89db4bbf8842aeffa19eccb00a82bef723ebd773b5e7b38e2009cddca"
                                    },
                                    "rootChainReceipt": {
                                        "start": "e312f39d2913ede4b010f20ac2186c5c7db5b26cacc9c0569e5ca6b8075c35a4",
                                        "startIndex": 134002,
                                        "end": "e312f39d2913ede4b010f20ac2186c5c7db5b26cacc9c0569e5ca6b8075c35a4",
                                        "endIndex": 134002,
                                        "anchor": "dc42685e4f871c0b80342da09c38c0b591e94149af11694f0fe91c5fb39d7cbf",
                                        "entries": [
                                            {
                                                "hash": "f4b9b8af5cc1d0dc05f1edc20680f60684521c2284947208cd59b6cad4e64527"
                                            },
                                            {
                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                            },
                                            {
                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                            },
                                            {
                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                            },
                                            {
                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                            },
                                            {
                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                            },
                                            {
                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                            },
                                            {
                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                            },
                                            {
                                                "hash": "37be1964ce422eed97a6c33730c7d52741a76fe41b6d2649127c7472062dfa53"
                                            },
                                            {
                                                "right": true,
                                                "hash": "0ba6e906ccbd754f0530ef1297987e8761ccdf063832cb1d12ffae9d36d24d7c"
                                            },
                                            {
                                                "hash": "e9f46e0d5b258869709c059afec81dc144106f7535d6f6e6af91996391cb3a90"
                                            },
                                            {
                                                "right": true,
                                                "hash": "6e4f79a1eddfa5a02c4e2655fe543864f7e39654f5f9b2c9ab4f2cb1bd11a345"
                                            },
                                            {
                                                "hash": "9b6e6eb14625a513fd90e95f75492ca0e2b22d64921279e6a6333abba76b934e"
                                            },
                                            {
                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                            },
                                            {
                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                            },
                                            {
                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                            },
                                            {
                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                            },
                                            {
                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                            },
                                            {
                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                            },
                                            {
                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                        }
                    }
                },
                "status": "remote",
                "result": {
                    "type": "unknown"
                },
                "produced": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "cause": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://dn.acme/anchors",
            "name": "main",
            "type": "transaction",
            "index": 432933,
            "entry": "c46a710be867bc4b6e750616e8f71fcd1ee040be9f0e16a88cc09b8cf60d997c",
            "value": {
                "recordType": "message",
                "id": "acc://c46a710be867bc4b6e750616e8f71fcd1ee040be9f0e16a88cc09b8cf60d997c@dn.acme/anchors",
                "message": {
                    "type": "transaction",
                    "transaction": {
                        "header": {
                            "principal": "acc://dn.acme/anchors"
                        },
                        "body": {
                            "type": "blockValidatorAnchor",
                            "source": "acc://bvn-BVN3.acme",
                            "minorBlockIndex": 172229,
                            "rootChainIndex": 795683,
                            "rootChainAnchor": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                            "stateTreeAnchor": "3a7aeed93b2b5c1d04dbe556d112f1272c38f97499f9341e11c590addea40fc1"
                        }
                    }
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 134528,
                "produced": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "cause": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://d8b7cdc21c39a6aca07a001ad5eac865bffb5af0751dfdcdd494cfce6bc831da@dn.acme"
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "signatures": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "signatureSet",
                            "account": {
                                "type": "anchorLedger",
                                "url": "acc://dn.acme/anchors",
                                "minorBlockSequenceNumber": 134161,
                                "majorBlockIndex": 9,
                                "majorBlockTime": "2026-01-18T00:00:01.000Z",
                                "sequence": [
                                    {
                                        "url": "acc://bvn-BVN1.acme",
                                        "received": 172029,
                                        "delivered": 172029
                                    },
                                    {
                                        "url": "acc://bvn-BVN2.acme",
                                        "received": 156,
                                        "delivered": 156
                                    },
                                    {
                                        "url": "acc://bvn-BVN3.acme",
                                        "received": 127082,
                                        "delivered": 127082
                                    },
                                    {
                                        "url": "acc://dn.acme",
                                        "received": 134158,
                                        "delivered": 134158
                                    }
                                ]
                            },
                            "signatures": {
                                "recordType": "range",
                                "records": [
                                    {
                                        "recordType": "message",
                                        "id": "acc://d6b3fdd6cc4c721c498a1a90ec801f885d72ce724996256187efd33d32f84315@dn.acme/network",
                                        "message": {
                                            "type": "blockAnchor",
                                            "signature": {
                                                "type": "ed25519",
                                                "publicKey": "cf5c0b621f887f3fc6f1a63b258d06420d7ca366e19b8b49328373eb1e5506de",
                                                "signature": "f41a00b755ccec0bf21db2a93e9ce602d0b141d8d9b3c8728d13c223ae070ef0e9ee939296bd127fa99388e943c8f8988ee5e56edb7b9f745d7799e1ae4a8207",
                                                "signer": "acc://dn.acme/network",
                                                "timestamp": 1768731933051,
                                                "transactionHash": "d8b7cdc21c39a6aca07a001ad5eac865bffb5af0751dfdcdd494cfce6bc831da"
                                            },
                                            "anchor": {
                                                "type": "sequenced",
                                                "message": {
                                                    "type": "transaction",
                                                    "transaction": {
                                                        "header": {
                                                            "principal": "acc://dn.acme/anchors"
                                                        },
                                                        "body": {
                                                            "type": "blockValidatorAnchor",
                                                            "source": "acc://bvn-BVN3.acme",
                                                            "minorBlockIndex": 172229,
                                                            "rootChainIndex": 795683,
                                                            "rootChainAnchor": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                                            "stateTreeAnchor": "3a7aeed93b2b5c1d04dbe556d112f1272c38f97499f9341e11c590addea40fc1"
                                                        }
                                                    }
                                                },
                                                "source": "acc://bvn-BVN3.acme",
                                                "destination": "acc://dn.acme",
                                                "number": 126942
                                            }
                                        }
                                    }
                                ],
                                "start": 0,
                                "total": 1
                            }
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "sequence": {
                    "type": "sequenced",
                    "message": {
                        "type": "transaction",
                        "transaction": {
                            "header": {
                                "principal": "acc://dn.acme/anchors"
                            },
                            "body": {
                                "type": "blockValidatorAnchor",
                                "source": "acc://bvn-BVN3.acme",
                                "minorBlockIndex": 172229,
                                "rootChainIndex": 795683,
                                "rootChainAnchor": "071a130e9707e2ac0f759e4e50369c47b67da2139427e6243a0d01c7659254d7",
                                "stateTreeAnchor": "3a7aeed93b2b5c1d04dbe556d112f1272c38f97499f9341e11c590addea40fc1"
                            }
                        }
                    },
                    "source": "acc://bvn-BVN3.acme",
                    "destination": "acc://dn.acme",
                    "number": 126942
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://dn.acme/anchors",
            "name": "signature",
            "type": "transaction",
            "index": 700940,
            "entry": "ad0ff61d5fe03cdda0ee7f7dabf7c9f84c6cb058eb6883e89d5bef2632eb61ee",
            "value": {
                "recordType": "message",
                "id": "acc://ad0ff61d5fe03cdda0ee7f7dabf7c9f84c6cb058eb6883e89d5bef2632eb61ee@dn.acme/network",
                "message": {
                    "type": "blockAnchor",
                    "signature": {
                        "type": "ed25519",
                        "publicKey": "cf5c0b621f887f3fc6f1a63b258d06420d7ca366e19b8b49328373eb1e5506de",
                        "signature": "4fd1b55f1ce8d2b4b35c8497e9d974253d7414a3a4de8d59ad4c67e06459d27d3b0f5fba18f6200e95a0dd63a97cbc24f9440871cd4d8b4c84bcd9f099549101",
                        "signer": "acc://dn.acme/network",
                        "timestamp": 1768731933052,
                        "transactionHash": "9aec9740b2e8e3b596a0d1b3a1190e44561996d4e13dcc190f43656e8112131f"
                    },
                    "anchor": {
                        "type": "sequenced",
                        "message": {
                            "type": "transaction",
                            "transaction": {
                                "header": {
                                    "principal": "acc://dn.acme/anchors"
                                },
                                "body": {
                                    "type": "directoryAnchor",
                                    "source": "acc://dn.acme",
                                    "minorBlockIndex": 134526,
                                    "rootChainIndex": 1124831,
                                    "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                    "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                    "receipts": [
                                        {
                                            "anchor": {
                                                "source": "acc://bvn-BVN1.acme",
                                                "minorBlockIndex": 171829,
                                                "rootChainIndex": 1401584,
                                                "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                            },
                                            "rootChainReceipt": {
                                                "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                "startIndex": 171828,
                                                "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                "endIndex": 171828,
                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                "entries": [
                                                    {
                                                        "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                    },
                                                    {
                                                        "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                    },
                                                    {
                                                        "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                    },
                                                    {
                                                        "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                    },
                                                    {
                                                        "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                    },
                                                    {
                                                        "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                    },
                                                    {
                                                        "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                    },
                                                    {
                                                        "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                    },
                                                    {
                                                        "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                    },
                                                    {
                                                        "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                    },
                                                    {
                                                        "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                    },
                                                    {
                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                    },
                                                    {
                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                    },
                                                    {
                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                    },
                                                    {
                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                    },
                                                    {
                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                    },
                                                    {
                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                    },
                                                    {
                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                    },
                                                    {
                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                    },
                                                    {
                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                    }
                                                ]
                                            }
                                        },
                                        {
                                            "anchor": {
                                                "source": "acc://dn.acme",
                                                "minorBlockIndex": 134524,
                                                "rootChainIndex": 1124817,
                                                "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                            },
                                            "rootChainReceipt": {
                                                "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                "startIndex": 134001,
                                                "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                "endIndex": 134001,
                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                "entries": [
                                                    {
                                                        "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                    },
                                                    {
                                                        "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                    },
                                                    {
                                                        "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                    },
                                                    {
                                                        "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                    },
                                                    {
                                                        "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                    },
                                                    {
                                                        "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                    },
                                                    {
                                                        "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                    },
                                                    {
                                                        "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                    },
                                                    {
                                                        "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                    },
                                                    {
                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                    },
                                                    {
                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                    },
                                                    {
                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                    },
                                                    {
                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                    },
                                                    {
                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                    },
                                                    {
                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                    },
                                                    {
                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                    },
                                                    {
                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                    },
                                                    {
                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                    }
                                                ]
                                            }
                                        }
                                    ],
                                    "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                }
                            }
                        },
                        "source": "acc://dn.acme",
                        "destination": "acc://dn.acme",
                        "number": 134004
                    }
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 134528,
                "produced": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://9aec9740b2e8e3b596a0d1b3a1190e44561996d4e13dcc190f43656e8112131f@dn.acme"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://d3f108ce5d3e995e4983dccbd58f70768282bd142f446e007f01a13b7694df90@dn.acme/network"
                        }
                    ],
                    "start": 0,
                    "total": 2
                },
                "cause": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
            "name": "signature",
            "type": "transaction",
            "index": 1165283,
            "entry": "e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9",
            "value": {
                "recordType": "message",
                "id": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                "message": {
                    "type": "signature",
                    "signature": {
                        "type": "ed25519",
                        "publicKey": "a712ffe3deb1f07753329235c74c1404d82827290b7accb579189ecb251db694",
                        "signature": "52c859328b121914e2db63a90246472d3e129aeab96d99c67489af2ba52b231c5ea57a57f9a0d8c56d6710f8634b81b184f127a5737b1cc3d9c9b38ac3e73e0b",
                        "signer": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                        "signerVersion": 1,
                        "timestamp": 1165284,
                        "transactionHash": "d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d"
                    },
                    "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 171834,
                "produced": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://906c6d3230631ed827d4bc82a01828ecdae36ea74681868590e595f5a8ca1a85@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://f30e957d0b794a4c4f0629ba89c06d861452ae5f4d108dadf408790e87ef3702@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://906c6d3230631ed827d4bc82a01828ecdae36ea74681868590e595f5a8ca1a85@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://f30e957d0b794a4c4f0629ba89c06d861452ae5f4d108dadf408790e87ef3702@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                        }
                    ],
                    "start": 0,
                    "total": 4
                },
                "cause": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
            "name": "main",
            "type": "transaction",
            "index": 1165284,
            "entry": "d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d",
            "value": {
                "recordType": "message",
                "id": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                "message": {
                    "type": "transaction",
                    "transaction": {
                        "header": {
                            "principal": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                            "initiator": "4d7d9ee36124310914b6f92ed2650f23880cadc5ba56d18f9d14c8d42dedfdba"
                        },
                        "body": {
                            "type": "sendTokens",
                            "to": [
                                {
                                    "url": "acc://f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME",
                                    "amount": "1000000000"
                                }
                            ]
                        }
                    }
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 171834,
                "produced": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://f000524c952a6cd998daa2433259ecdeaacc2c8ae2ea227d86440232ca177f07@f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://f000524c952a6cd998daa2433259ecdeaacc2c8ae2ea227d86440232ca177f07@f4c37bdb15cda79379f3ebebe3a445c65c4741a6f78ccb5a/ACME"
                        }
                    ],
                    "start": 0,
                    "total": 2
                },
                "cause": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "signatures": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "signatureSet",
                            "account": {
                                "type": "liteIdentity",
                                "url": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                "creditBalance": 18446744073359528000,
                                "lastUsedOn": 1166748
                            },
                            "signatures": {
                                "recordType": "range",
                                "records": [
                                    {
                                        "recordType": "message",
                                        "id": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                        "message": {
                                            "type": "signature",
                                            "signature": {
                                                "type": "ed25519",
                                                "publicKey": "a712ffe3deb1f07753329235c74c1404d82827290b7accb579189ecb251db694",
                                                "signature": "52c859328b121914e2db63a90246472d3e129aeab96d99c67489af2ba52b231c5ea57a57f9a0d8c56d6710f8634b81b184f127a5737b1cc3d9c9b38ac3e73e0b",
                                                "signer": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                                "signerVersion": 1,
                                                "timestamp": 1165284,
                                                "transactionHash": "d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d"
                                            },
                                            "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                                        },
                                        "historical": true
                                    }
                                ],
                                "start": 0,
                                "total": 1
                            }
                        },
                        {
                            "recordType": "signatureSet",
                            "account": {
                                "type": "liteTokenAccount",
                                "url": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                "tokenUrl": "acc://ACME",
                                "balance": "18833252000000000"
                            },
                            "signatures": {
                                "recordType": "range",
                                "records": [
                                    {
                                        "recordType": "message",
                                        "id": "acc://906c6d3230631ed827d4bc82a01828ecdae36ea74681868590e595f5a8ca1a85@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                        "message": {
                                            "type": "creditPayment",
                                            "paid": 300,
                                            "payer": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                            "initiator": true,
                                            "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                            "cause": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5"
                                        },
                                        "historical": true
                                    },
                                    {
                                        "recordType": "message",
                                        "id": "acc://f30e957d0b794a4c4f0629ba89c06d861452ae5f4d108dadf408790e87ef3702@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                        "message": {
                                            "type": "signature",
                                            "signature": {
                                                "type": "authority",
                                                "origin": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                                "authority": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                                                "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                                                "cause": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5"
                                            },
                                            "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                                        },
                                        "historical": true
                                    }
                                ],
                                "start": 0,
                                "total": 2
                            }
                        }
                    ],
                    "start": 0,
                    "total": 2
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
            "name": "signature",
            "type": "transaction",
            "index": 2330567,
            "entry": "f30e957d0b794a4c4f0629ba89c06d861452ae5f4d108dadf408790e87ef3702",
            "value": {
                "recordType": "message",
                "id": "acc://f30e957d0b794a4c4f0629ba89c06d861452ae5f4d108dadf408790e87ef3702@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                "message": {
                    "type": "signature",
                    "signature": {
                        "type": "authority",
                        "origin": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                        "authority": "acc://4134bf4cd64454316da81832e9a3574973bac8779ef961f5",
                        "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME",
                        "cause": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5"
                    },
                    "txID": "acc://d56a178cc1abebbdc75860a059d33a874684515fd82b193df48ad814a57ae41d@4134bf4cd64454316da81832e9a3574973bac8779ef961f5/ACME"
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 171834,
                "produced": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "cause": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://e19f2d13a11350e20f506b161ed559e7b0af68e0f8f52d71e7414df6996a7ca9@4134bf4cd64454316da81832e9a3574973bac8779ef961f5"
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://bvn-BVN1.acme/anchors",
            "name": "anchor-sequence",
            "type": "transaction",
            "index": 171832,
            "entry": "1f202816465b495152f90dfd4be98e5639cf3bfb0a24bd1ac099e8d359b1f978",
            "value": {
                "recordType": "message",
                "id": "acc://1f202816465b495152f90dfd4be98e5639cf3bfb0a24bd1ac099e8d359b1f978@unknown",
                "message": {
                    "type": "transaction",
                    "transaction": {
                        "header": {},
                        "body": {
                            "type": "blockValidatorAnchor",
                            "source": "acc://bvn-BVN1.acme",
                            "minorBlockIndex": 171833,
                            "rootChainIndex": 1401616,
                            "rootChainAnchor": "7317239eb94c084e25e44468ff20beadcb2e0bf0f0fbc29041745c0c12727d9d",
                            "stateTreeAnchor": "7d14b3d55421d39e2ca3ef29376e771dd2c1555ed849d60f0ba8328a2c3c53cf"
                        }
                    }
                },
                "status": "remote",
                "result": {
                    "type": "unknown"
                },
                "produced": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "cause": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://bvn-BVN1.acme/anchors",
            "name": "main",
            "type": "transaction",
            "index": 134004,
            "entry": "2f7c8156456cd8d7188b9372c53bfc3dde55242c6eb048fdb2ea10c25f46a1da",
            "value": {
                "recordType": "message",
                "id": "acc://2f7c8156456cd8d7188b9372c53bfc3dde55242c6eb048fdb2ea10c25f46a1da@bvn-BVN1.acme/anchors",
                "message": {
                    "type": "transaction",
                    "transaction": {
                        "header": {
                            "principal": "acc://bvn-BVN1.acme/anchors"
                        },
                        "body": {
                            "type": "directoryAnchor",
                            "source": "acc://dn.acme",
                            "minorBlockIndex": 134526,
                            "rootChainIndex": 1124831,
                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                            "receipts": [
                                {
                                    "anchor": {
                                        "source": "acc://bvn-BVN1.acme",
                                        "minorBlockIndex": 171829,
                                        "rootChainIndex": 1401584,
                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                    },
                                    "rootChainReceipt": {
                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                        "startIndex": 171828,
                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                        "endIndex": 171828,
                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                        "entries": [
                                            {
                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                            },
                                            {
                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                            },
                                            {
                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                            },
                                            {
                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                            },
                                            {
                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                            },
                                            {
                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                            },
                                            {
                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                            },
                                            {
                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                            },
                                            {
                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                            },
                                            {
                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                            },
                                            {
                                                "right": true,
                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                            },
                                            {
                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                            },
                                            {
                                                "right": true,
                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                            },
                                            {
                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                            },
                                            {
                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                            },
                                            {
                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                            },
                                            {
                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                            },
                                            {
                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                            },
                                            {
                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                            },
                                            {
                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                            },
                                            {
                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                            },
                                            {
                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                            }
                                        ]
                                    }
                                },
                                {
                                    "anchor": {
                                        "source": "acc://dn.acme",
                                        "minorBlockIndex": 134524,
                                        "rootChainIndex": 1124817,
                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                    },
                                    "rootChainReceipt": {
                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                        "startIndex": 134001,
                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                        "endIndex": 134001,
                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                        "entries": [
                                            {
                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                            },
                                            {
                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                            },
                                            {
                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                            },
                                            {
                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                            },
                                            {
                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                            },
                                            {
                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                            },
                                            {
                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                            },
                                            {
                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                            },
                                            {
                                                "right": true,
                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                            },
                                            {
                                                "right": true,
                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                            },
                                            {
                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                            },
                                            {
                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                            },
                                            {
                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                            },
                                            {
                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                            },
                                            {
                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                            },
                                            {
                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                            },
                                            {
                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                            },
                                            {
                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                            },
                                            {
                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                            },
                                            {
                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                        }
                    }
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 171834,
                "produced": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "cause": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab@bvn-BVN1.acme"
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "signatures": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "signatureSet",
                            "account": {
                                "type": "anchorLedger",
                                "url": "acc://bvn-BVN1.acme/anchors",
                                "minorBlockSequenceNumber": 172032,
                                "majorBlockTime": "0001-01-01T00:00:00.000Z",
                                "sequence": [
                                    {
                                        "url": "acc://dn.acme",
                                        "received": 134159,
                                        "delivered": 134159
                                    }
                                ]
                            },
                            "signatures": {
                                "recordType": "range",
                                "records": [
                                    {
                                        "recordType": "message",
                                        "id": "acc://919c708f3e90616502fc4d6783d4f8dc11c45fdd5e34aeb3108d0d748140f0a7@dn.acme/network",
                                        "message": {
                                            "type": "blockAnchor",
                                            "signature": {
                                                "type": "ed25519",
                                                "publicKey": "cf5c0b621f887f3fc6f1a63b258d06420d7ca366e19b8b49328373eb1e5506de",
                                                "signature": "c288ad717dc1a5b8fdff61367dae8c743f4b02129e1e5a22188bea01c3367c27288d0af4d2f7e92832abb5d9975c79c455ef2b9bee2b78c5947f25c1d6c9be09",
                                                "signer": "acc://dn.acme/network",
                                                "timestamp": 1768731933051,
                                                "transactionHash": "341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab"
                                            },
                                            "anchor": {
                                                "type": "sequenced",
                                                "message": {
                                                    "type": "transaction",
                                                    "transaction": {
                                                        "header": {
                                                            "principal": "acc://bvn-BVN1.acme/anchors"
                                                        },
                                                        "body": {
                                                            "type": "directoryAnchor",
                                                            "source": "acc://dn.acme",
                                                            "minorBlockIndex": 134526,
                                                            "rootChainIndex": 1124831,
                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                            "receipts": [
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://bvn-BVN1.acme",
                                                                        "minorBlockIndex": 171829,
                                                                        "rootChainIndex": 1401584,
                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "startIndex": 171828,
                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "endIndex": 171828,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                            },
                                                                            {
                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                            },
                                                                            {
                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                            },
                                                                            {
                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                            },
                                                                            {
                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                            },
                                                                            {
                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                            },
                                                                            {
                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                            },
                                                                            {
                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                            },
                                                                            {
                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                            },
                                                                            {
                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                            },
                                                                            {
                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                },
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://dn.acme",
                                                                        "minorBlockIndex": 134524,
                                                                        "rootChainIndex": 1124817,
                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "startIndex": 134001,
                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "endIndex": 134001,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                            },
                                                                            {
                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                            },
                                                                            {
                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                            },
                                                                            {
                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                            },
                                                                            {
                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                            },
                                                                            {
                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                            },
                                                                            {
                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                            },
                                                                            {
                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                            },
                                                                            {
                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                }
                                                            ],
                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                        }
                                                    }
                                                },
                                                "source": "acc://dn.acme",
                                                "destination": "acc://bvn-BVN1.acme",
                                                "number": 134004
                                            }
                                        }
                                    },
                                    {
                                        "recordType": "message",
                                        "id": "acc://1a70d16fe83810eb7c8802b1e301dfdc497459b160c1d29ec3aa55ae39aa1e03@dn.acme/network",
                                        "message": {
                                            "type": "blockAnchor",
                                            "signature": {
                                                "type": "ed25519",
                                                "publicKey": "51fe2dbfe2a3005f2ab03a3177da7286870ea238d3d74f688043e2ea0b470640",
                                                "signature": "81573a375479341bfa12ce3c7452947849a2a773204a570351cbfd9588ac3be106b4dedacf352d59925e4f0a882c36e01322278709e25eaa6a2654ca4189bb0a",
                                                "signer": "acc://dn.acme/network",
                                                "timestamp": 1768731933051,
                                                "transactionHash": "341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab"
                                            },
                                            "anchor": {
                                                "type": "sequenced",
                                                "message": {
                                                    "type": "transaction",
                                                    "transaction": {
                                                        "header": {
                                                            "principal": "acc://bvn-BVN1.acme/anchors"
                                                        },
                                                        "body": {
                                                            "type": "directoryAnchor",
                                                            "source": "acc://dn.acme",
                                                            "minorBlockIndex": 134526,
                                                            "rootChainIndex": 1124831,
                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                            "receipts": [
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://bvn-BVN1.acme",
                                                                        "minorBlockIndex": 171829,
                                                                        "rootChainIndex": 1401584,
                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "startIndex": 171828,
                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "endIndex": 171828,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                            },
                                                                            {
                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                            },
                                                                            {
                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                            },
                                                                            {
                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                            },
                                                                            {
                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                            },
                                                                            {
                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                            },
                                                                            {
                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                            },
                                                                            {
                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                            },
                                                                            {
                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                            },
                                                                            {
                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                            },
                                                                            {
                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                },
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://dn.acme",
                                                                        "minorBlockIndex": 134524,
                                                                        "rootChainIndex": 1124817,
                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "startIndex": 134001,
                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "endIndex": 134001,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                            },
                                                                            {
                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                            },
                                                                            {
                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                            },
                                                                            {
                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                            },
                                                                            {
                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                            },
                                                                            {
                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                            },
                                                                            {
                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                            },
                                                                            {
                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                            },
                                                                            {
                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                }
                                                            ],
                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                        }
                                                    }
                                                },
                                                "source": "acc://dn.acme",
                                                "destination": "acc://bvn-BVN1.acme",
                                                "number": 134004
                                            }
                                        }
                                    },
                                    {
                                        "recordType": "message",
                                        "id": "acc://f3731abf73ae48823b4f1d5096d43b079f8cd7019ed49c615b36d7323ee4b78b@dn.acme/network",
                                        "message": {
                                            "type": "blockAnchor",
                                            "signature": {
                                                "type": "ed25519",
                                                "publicKey": "ea744577476905ae36184a8023f8c8dcc24cfbd0e5b6d5792949bf8d02cdadaa",
                                                "signature": "3bebdc6c35ab0a5b23e2ea6e28f0a912b734dfb6d40c6c4c761926f82cbcc9f56463cf0bf8dcf3d675ba04cadcf9f5b2e13eab75b2a7e21e44cb0541e6d8dc01",
                                                "signer": "acc://dn.acme/network",
                                                "timestamp": 1768731933050,
                                                "transactionHash": "341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab"
                                            },
                                            "anchor": {
                                                "type": "sequenced",
                                                "message": {
                                                    "type": "transaction",
                                                    "transaction": {
                                                        "header": {
                                                            "principal": "acc://bvn-BVN1.acme/anchors"
                                                        },
                                                        "body": {
                                                            "type": "directoryAnchor",
                                                            "source": "acc://dn.acme",
                                                            "minorBlockIndex": 134526,
                                                            "rootChainIndex": 1124831,
                                                            "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                            "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                                            "receipts": [
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://bvn-BVN1.acme",
                                                                        "minorBlockIndex": 171829,
                                                                        "rootChainIndex": 1401584,
                                                                        "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "startIndex": 171828,
                                                                        "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                                        "endIndex": 171828,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                                            },
                                                                            {
                                                                                "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                                            },
                                                                            {
                                                                                "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                                            },
                                                                            {
                                                                                "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                                            },
                                                                            {
                                                                                "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                                            },
                                                                            {
                                                                                "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                                            },
                                                                            {
                                                                                "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                                            },
                                                                            {
                                                                                "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                                            },
                                                                            {
                                                                                "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                                            },
                                                                            {
                                                                                "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                                            },
                                                                            {
                                                                                "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                },
                                                                {
                                                                    "anchor": {
                                                                        "source": "acc://dn.acme",
                                                                        "minorBlockIndex": 134524,
                                                                        "rootChainIndex": 1124817,
                                                                        "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                                                    },
                                                                    "rootChainReceipt": {
                                                                        "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "startIndex": 134001,
                                                                        "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                                        "endIndex": 134001,
                                                                        "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                                        "entries": [
                                                                            {
                                                                                "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                                            },
                                                                            {
                                                                                "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                                            },
                                                                            {
                                                                                "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                                            },
                                                                            {
                                                                                "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                                            },
                                                                            {
                                                                                "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                                            },
                                                                            {
                                                                                "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                                            },
                                                                            {
                                                                                "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                                            },
                                                                            {
                                                                                "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                                            },
                                                                            {
                                                                                "right": true,
                                                                                "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                                            },
                                                                            {
                                                                                "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                                            },
                                                                            {
                                                                                "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                                            },
                                                                            {
                                                                                "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                                            },
                                                                            {
                                                                                "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                                            },
                                                                            {
                                                                                "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                                            },
                                                                            {
                                                                                "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                                            },
                                                                            {
                                                                                "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                                            },
                                                                            {
                                                                                "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                                            },
                                                                            {
                                                                                "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                                            },
                                                                            {
                                                                                "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                                            }
                                                                        ]
                                                                    }
                                                                }
                                                            ],
                                                            "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                                        }
                                                    }
                                                },
                                                "source": "acc://dn.acme",
                                                "destination": "acc://bvn-BVN1.acme",
                                                "number": 134004
                                            }
                                        }
                                    }
                                ],
                                "start": 0,
                                "total": 3
                            }
                        }
                    ],
                    "start": 0,
                    "total": 1
                },
                "sequence": {
                    "type": "sequenced",
                    "message": {
                        "type": "transaction",
                        "transaction": {
                            "header": {
                                "principal": "acc://bvn-BVN1.acme/anchors"
                            },
                            "body": {
                                "type": "directoryAnchor",
                                "source": "acc://dn.acme",
                                "minorBlockIndex": 134526,
                                "rootChainIndex": 1124831,
                                "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                "receipts": [
                                    {
                                        "anchor": {
                                            "source": "acc://bvn-BVN1.acme",
                                            "minorBlockIndex": 171829,
                                            "rootChainIndex": 1401584,
                                            "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                            "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                        },
                                        "rootChainReceipt": {
                                            "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                            "startIndex": 171828,
                                            "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                            "endIndex": 171828,
                                            "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                            "entries": [
                                                {
                                                    "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                },
                                                {
                                                    "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                },
                                                {
                                                    "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                },
                                                {
                                                    "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                },
                                                {
                                                    "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                },
                                                {
                                                    "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                },
                                                {
                                                    "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                },
                                                {
                                                    "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                },
                                                {
                                                    "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                },
                                                {
                                                    "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                },
                                                {
                                                    "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                },
                                                {
                                                    "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                },
                                                {
                                                    "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                },
                                                {
                                                    "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                },
                                                {
                                                    "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                },
                                                {
                                                    "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                },
                                                {
                                                    "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                },
                                                {
                                                    "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                },
                                                {
                                                    "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                },
                                                {
                                                    "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                }
                                            ]
                                        }
                                    },
                                    {
                                        "anchor": {
                                            "source": "acc://dn.acme",
                                            "minorBlockIndex": 134524,
                                            "rootChainIndex": 1124817,
                                            "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                            "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                        },
                                        "rootChainReceipt": {
                                            "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                            "startIndex": 134001,
                                            "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                            "endIndex": 134001,
                                            "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                            "entries": [
                                                {
                                                    "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                },
                                                {
                                                    "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                },
                                                {
                                                    "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                },
                                                {
                                                    "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                },
                                                {
                                                    "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                },
                                                {
                                                    "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                },
                                                {
                                                    "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                },
                                                {
                                                    "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                },
                                                {
                                                    "right": true,
                                                    "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                },
                                                {
                                                    "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                },
                                                {
                                                    "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                },
                                                {
                                                    "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                },
                                                {
                                                    "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                },
                                                {
                                                    "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                },
                                                {
                                                    "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                },
                                                {
                                                    "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                },
                                                {
                                                    "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                },
                                                {
                                                    "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                },
                                                {
                                                    "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                }
                                            ]
                                        }
                                    }
                                ],
                                "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                            }
                        }
                    },
                    "source": "acc://dn.acme",
                    "destination": "acc://bvn-BVN1.acme",
                    "number": 134004
                }
            }
        },
        {
            "recordType": "chainEntry",
            "account": "acc://bvn-BVN1.acme/anchors",
            "name": "signature",
            "type": "transaction",
            "index": 402011,
            "entry": "f3731abf73ae48823b4f1d5096d43b079f8cd7019ed49c615b36d7323ee4b78b",
            "value": {
                "recordType": "message",
                "id": "acc://f3731abf73ae48823b4f1d5096d43b079f8cd7019ed49c615b36d7323ee4b78b@dn.acme/network",
                "message": {
                    "type": "blockAnchor",
                    "signature": {
                        "type": "ed25519",
                        "publicKey": "ea744577476905ae36184a8023f8c8dcc24cfbd0e5b6d5792949bf8d02cdadaa",
                        "signature": "3bebdc6c35ab0a5b23e2ea6e28f0a912b734dfb6d40c6c4c761926f82cbcc9f56463cf0bf8dcf3d675ba04cadcf9f5b2e13eab75b2a7e21e44cb0541e6d8dc01",
                        "signer": "acc://dn.acme/network",
                        "timestamp": 1768731933050,
                        "transactionHash": "341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab"
                    },
                    "anchor": {
                        "type": "sequenced",
                        "message": {
                            "type": "transaction",
                            "transaction": {
                                "header": {
                                    "principal": "acc://bvn-BVN1.acme/anchors"
                                },
                                "body": {
                                    "type": "directoryAnchor",
                                    "source": "acc://dn.acme",
                                    "minorBlockIndex": 134526,
                                    "rootChainIndex": 1124831,
                                    "rootChainAnchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                    "stateTreeAnchor": "951da796fab80b2abc2f521b2a34760e9bbde24b1e7906c6647e1b13d447f35a",
                                    "receipts": [
                                        {
                                            "anchor": {
                                                "source": "acc://bvn-BVN1.acme",
                                                "minorBlockIndex": 171829,
                                                "rootChainIndex": 1401584,
                                                "rootChainAnchor": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                "stateTreeAnchor": "027e774032e59b0943aa091c084cd7514de1292a7490b20526e83fd917b6cf81"
                                            },
                                            "rootChainReceipt": {
                                                "start": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                "startIndex": 171828,
                                                "end": "f14a8bb42d0e61b296994ba4fde87fc468dc0658d4b36f6d3ae12ef7ff6f3cc4",
                                                "endIndex": 171828,
                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                "entries": [
                                                    {
                                                        "hash": "07bc0d63fc65754cd227943dfa03d61c1129571a88bde46435996f3cec69df8c"
                                                    },
                                                    {
                                                        "hash": "51b3679b45998fb54e7cfeeeaeb687926f0c27ce8df15700f3a0943515bdff1e"
                                                    },
                                                    {
                                                        "hash": "6fa933965f766df04242d24fd03e6f561bb03925773432df0eef3722aaf88a0a"
                                                    },
                                                    {
                                                        "hash": "75f145a2e84ddeb322cdc1f3d85f7918d2eed20132c1cbb83f0c738bffda9e75"
                                                    },
                                                    {
                                                        "hash": "b4925702e934e39e0fafaf50ed273d4d077585a8ead76fd06908c5d0a5c0be67"
                                                    },
                                                    {
                                                        "hash": "4ad14f419a4ffe053a48a097efe1a70c91ff6769e91f0c0bcf015f0579564de8"
                                                    },
                                                    {
                                                        "hash": "7fb19c02f9e98af4295a07ecd074eca6cca72ffc03714126ca66877a440f4fbd"
                                                    },
                                                    {
                                                        "hash": "fc967f69a0a635f1ac41b77cbdb5eaf1efc21513f061b04d2b2c4fa7857fca2a"
                                                    },
                                                    {
                                                        "hash": "1194be274283d7f2bbb0c5f702c292cce59a5409c1a854eb7634e219a5339411"
                                                    },
                                                    {
                                                        "hash": "15a4636c81b3390cc5abb6c2db04e9a563f0ad05c5e6c920cf7df0f8203f808b"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "6c640ec8a70732fb60c03605da8f80b38917a9ae7b80599de1ce9375a6246523"
                                                    },
                                                    {
                                                        "hash": "d54320f3155599afc36a77533b284ef97b623efc2d974c9dbed66f23dc44bcfe"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "472c6ffd150bcb74abea6de178176a96797c6d4bb786b2a2966fe0c68dbf2e07"
                                                    },
                                                    {
                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                    },
                                                    {
                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                    },
                                                    {
                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                    },
                                                    {
                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                    },
                                                    {
                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                    },
                                                    {
                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                    },
                                                    {
                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                    },
                                                    {
                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                    },
                                                    {
                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                    }
                                                ]
                                            }
                                        },
                                        {
                                            "anchor": {
                                                "source": "acc://dn.acme",
                                                "minorBlockIndex": 134524,
                                                "rootChainIndex": 1124817,
                                                "rootChainAnchor": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                "stateTreeAnchor": "bd45e8b4bf122ba5044404b08cffc1649e70c4948813d2788224d6e04a7cf7ff"
                                            },
                                            "rootChainReceipt": {
                                                "start": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                "startIndex": 134001,
                                                "end": "f87e5d0e86eadeafc932c9f4e76a9bc84ce21e221ff386713ca4dbd5dd930c2e",
                                                "endIndex": 134001,
                                                "anchor": "de08b3dbe6d7737e4dda75a9f4b992ae5cf501b3e5ba4c385a969853283459a6",
                                                "entries": [
                                                    {
                                                        "hash": "0a975cdf305a53da8180be27626a966b2c5dc7ad689abdf7b73f65d33e5f0ab3"
                                                    },
                                                    {
                                                        "hash": "3b26a98ffea42ecf629f068f3ebd1954b736d96833a370469c5e185889ccb881"
                                                    },
                                                    {
                                                        "hash": "bcd68be3dc44dd5137635d2853d57f81ca40c48a918330be9235d7b8ba29be88"
                                                    },
                                                    {
                                                        "hash": "33a2ee2cf5fdab58ef487947fb3f05cfab75e6d1b0d3967fc74f8084dcd8a536"
                                                    },
                                                    {
                                                        "hash": "0d8d6ea25f851f52fa125c7a97b108c0c12fd50cc8d5b8476711b047afb845ec"
                                                    },
                                                    {
                                                        "hash": "e1ef3e0c2df5bb00a86fbf644b62918fbfc7d76d7c4a5573deae4cacb70b8d71"
                                                    },
                                                    {
                                                        "hash": "8d1183732e10002e88b958b53d7128365d859f6589d0c42f29b3b407af04205d"
                                                    },
                                                    {
                                                        "hash": "5ed9b4bf360024798cb92d00e74e0dc71a5147adeafb5c8517794d0163810360"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "07a508d82674354a1537b72795cd50b224fcb3457ff68ed7fc4c8289b44b9275"
                                                    },
                                                    {
                                                        "right": true,
                                                        "hash": "4ca1ab23f0d4c31b306fe42c7a7d4854a0144a0e10f25ca2fd9f5627f14ba5be"
                                                    },
                                                    {
                                                        "hash": "c48e0b78ae42b3027161df319706c951528149591ab693c567c015a8f9967a4f"
                                                    },
                                                    {
                                                        "hash": "d91ddecf2f5fd9180a6f39791babd658d797873b61f829926c97750846e1eb08"
                                                    },
                                                    {
                                                        "hash": "4fea627cb3f82028c860b5216744a906dd22986e3efae85647fabc3b789046dd"
                                                    },
                                                    {
                                                        "hash": "9db4e0cf81d5cd51fd4a97c5eac71ef74a39f676eab100dfb32907ffabff1938"
                                                    },
                                                    {
                                                        "hash": "84f85c9dd03312ba12d13578a068076c67521313a86cd0046974821634fd5183"
                                                    },
                                                    {
                                                        "hash": "f5db0ea0c0bc7e50451f73e97e7b70de9db06da7e19fb5c9615d4bb2a78cfbbb"
                                                    },
                                                    {
                                                        "hash": "0fcff7268162857efbbf64f801312377698b71f0ddf6bd7e59e656c68fd637d4"
                                                    },
                                                    {
                                                        "hash": "9c15ae20c812ecce4caaad430b07bb59ba5dff11fd030fff635e9a16777d1f7e"
                                                    },
                                                    {
                                                        "hash": "7f7f42e873ae9ec959cedd44d85d8d4b027af5ce2dc89e18db876e1d138ce343"
                                                    },
                                                    {
                                                        "hash": "babc62500d6a3fec11c1e5b0ff1c27997839475ece55fb31aab2bf3ba8bb2a8d"
                                                    }
                                                ]
                                            }
                                        }
                                    ],
                                    "makeMajorBlockTime": "0001-01-01T00:00:00.000Z"
                                }
                            }
                        },
                        "source": "acc://dn.acme",
                        "destination": "acc://bvn-BVN1.acme",
                        "number": 134004
                    }
                },
                "status": "delivered",
                "result": {
                    "type": "unknown"
                },
                "received": 171834,
                "produced": {
                    "recordType": "range",
                    "records": [
                        {
                            "recordType": "txID",
                            "value": "acc://2b8355e0b72b89a8052f54574d82001b377ec46c47e526c5b84635b1c89dbf26@dn.acme/network"
                        },
                        {
                            "recordType": "txID",
                            "value": "acc://341bd8f4420464caa6f1435e5fad6e6901476bfb61eb825c1e897288df8233ab@bvn-BVN1.acme"
                        }
                    ],
                    "start": 0,
                    "total": 2
                },
                "cause": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "signatures": {
                    "recordType": "range",
                    "start": 0,
                    "total": 0
                },
                "sequence": {
                    "type": "sequenced"
                }
            }
        }
    ]
}