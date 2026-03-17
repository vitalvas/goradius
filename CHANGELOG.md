# Changelog

## [0.1.0](https://github.com/vitalvas/goradius/compare/v0.0.1...v0.1.0) (2026-03-17)


### ⚠ BREAKING CHANGES

* NewServer and NewClient now use functional options instead of config structs.
* All packages from pkg/ are now merged into a single goradius package at the root level. Import paths and type names changed:
* Server no longer has ListenAndServe method. Users must create their own listener and transport:

### Features

* add bech ([1aa1bc4](https://github.com/vitalvas/goradius/commit/1aa1bc4d367dc3e83447b523749bb69cc898649e))
* add bech for packet ([61581f0](https://github.com/vitalvas/goradius/commit/61581f06a35b120a74e085eca92f3c9095447480))
* add chap ([3fceca7](https://github.com/vitalvas/goradius/commit/3fceca773619188c1db1658366897bb15ac21ec0))
* add check dict to uniq ([610c6d9](https://github.com/vitalvas/goradius/commit/610c6d9dcb8a00c33aa6201aa1dd2b5ac4b938ea))
* add crud ([f69a01b](https://github.com/vitalvas/goradius/commit/f69a01b77414c47bf8b5f2d1fb0296e6801d3a0d))
* add dict attr type ([5cf65c4](https://github.com/vitalvas/goradius/commit/5cf65c454c68c3e1fb24035d33a3776d626ac243))
* add juniper multiline support ([9b97497](https://github.com/vitalvas/goradius/commit/9b97497b594eea1745b88f4ff96146c994268609))
* add list attributes ([6091e62](https://github.com/vitalvas/goradius/commit/6091e6266d3d10d5a81aa4dc6b293083d7150f86))
* add Message-Authenticator ([a54033d](https://github.com/vitalvas/goradius/commit/a54033d718417fc8de7d56b213bfba2e3a23f098))
* add middleware ([d64f331](https://github.com/vitalvas/goradius/commit/d64f331ac2a96b8f615403ec15d01f042ade9236))
* add parser ([08ec4f8](https://github.com/vitalvas/goradius/commit/08ec4f8f103bd8e516b55ccb79e2084a8699570e))
* add string call ([6666d52](https://github.com/vitalvas/goradius/commit/6666d524bcba0e0c2f16c47d39966ae4e0ad240b))
* add transport abstraction for UDP/TCP/TLS support ([5c19701](https://github.com/vitalvas/goradius/commit/5c1970157c7195372e3ec47234c5a24dde3536e5))
* add vendors ([f9c860a](https://github.com/vitalvas/goradius/commit/f9c860ab489fbd05f7c7f54fc84c638ad1fa9219))
* **client:** add multi-transport support and proper Close() implementation ([49a5e9c](https://github.com/vitalvas/goradius/commit/49a5e9c1c73ecb3861653984a1a8a79483a1489d))
* create client ([f74a42e](https://github.com/vitalvas/goradius/commit/f74a42ea686b7009ca98a749125be72eee52fe96))
* enforce lowercase attribute names ([4015f69](https://github.com/vitalvas/goradius/commit/4015f69858617249b713b3fdd2186cdaaf00d114))
* enforce lowercase for attribute values, add transport tests, cleanup ([b4c79a4](https://github.com/vitalvas/goradius/commit/b4c79a4743a40043ca4ae73af08e0d0d2c711e0f))
* finish client ([35817ec](https://github.com/vitalvas/goradius/commit/35817ecdde41cfd7eb13e4b94d0412cf27d0609e))
* init ([9d9d92d](https://github.com/vitalvas/goradius/commit/9d9d92d10a57f18eabf8f30fba0880e32eab8557))
* remove Description field, add GetAllAttributes method ([60e3045](https://github.com/vitalvas/goradius/commit/60e30450bcb7997dc86613e54d6e832d8b1dd072))
* rename Metadata to UserData with map[string]string type ([05b39a8](https://github.com/vitalvas/goradius/commit/05b39a879943d8189f0eb6ab0253f33e4c1b57cd))
* **server:** add secret rotation support ([747cfbb](https://github.com/vitalvas/goradius/commit/747cfbb5ab5176455430bcc35972515628a827fc))
* simplify ([679fa33](https://github.com/vitalvas/goradius/commit/679fa335bbb43f68fd8e4a7f5f9c99902a92789a))
* small refactor ([fff142f](https://github.com/vitalvas/goradius/commit/fff142fd586c3cc6ce94c16b5a6aab2ba8013d55))
* small refactor 1 ([263fe4b](https://github.com/vitalvas/goradius/commit/263fe4b956f1afa0aead7b0c7d36ead1b837a839))
* small refactor 2 ([9e5d7a3](https://github.com/vitalvas/goradius/commit/9e5d7a38a76dd18adcbafa411318606099598d92))
* small refactor 3 ([dbcf7dd](https://github.com/vitalvas/goradius/commit/dbcf7dd89f173c64f44f9110f8a1d3e83ef0079e))
* small refactor 4 ([eeb6d59](https://github.com/vitalvas/goradius/commit/eeb6d597586b2eda224a00f4658437edc91f9cfe))
* small refactor 5 ([0ac8542](https://github.com/vitalvas/goradius/commit/0ac854263f791d839fe8c465465b52c398093b36))
* small refactor 6 ([cb8038b](https://github.com/vitalvas/goradius/commit/cb8038b798b4d030e4219cab4234f88d4b250cd9))
* small refactor 7 ([1bb9b3f](https://github.com/vitalvas/goradius/commit/1bb9b3fadb24f72f62b7b685ae16fb9e7549e2a8))
* small refactor add and set attrs ([d36bb8d](https://github.com/vitalvas/goradius/commit/d36bb8db663a91472218a6412e4bab07f05aac43))
* wip ([06ab30c](https://github.com/vitalvas/goradius/commit/06ab30ce8fb4bbe516977b9ea72c3c2605e73b51))


### Bug Fixes

* add tests ([9c48411](https://github.com/vitalvas/goradius/commit/9c48411d52e5326969f9a7c290387d248451bf20))
* address RADIUS protocol security and RFC compliance issues ([a04b18d](https://github.com/vitalvas/goradius/commit/a04b18dd8e6bad68fa7c72afd6811f1997dfa205))
* allocation ([6c9fa43](https://github.com/vitalvas/goradius/commit/6c9fa4395a4c71d9165fe0957752c9c752261bc6))
* allocation ([6af2af1](https://github.com/vitalvas/goradius/commit/6af2af189bf9ce1a397886b2716a83829d867051))
* drop logs ([3063853](https://github.com/vitalvas/goradius/commit/3063853a678c35dca51592ed70c3ffa4ae46b4bd))
* perf tuning ([bd4b027](https://github.com/vitalvas/goradius/commit/bd4b027b1f3327395e957c3e3e230f1f2d4beccf))
* re-create ([bb85cc6](https://github.com/vitalvas/goradius/commit/bb85cc66ee1c3a36773ae581d781779cdf899d90))
* set and add attributes ([95c5e2f](https://github.com/vitalvas/goradius/commit/95c5e2fb9e43ceff2b9a1273ddc5e61726f2ec50))
* set multiple values ([ce151e2](https://github.com/vitalvas/goradius/commit/ce151e2883fdb0a891aa9bafb52b960e81481523))
* simplify ([4f75903](https://github.com/vitalvas/goradius/commit/4f7590316488b9daf5ce9783c2e1a9550992bee7))
* simplify ([5e58052](https://github.com/vitalvas/goradius/commit/5e580522ba8e59834cf75fa2fde461c54b5cfa4d))
* simplify ([4cadb2f](https://github.com/vitalvas/goradius/commit/4cadb2fa33b34c5ceec10601d73702da34290ee1))
* small bugs ([425325d](https://github.com/vitalvas/goradius/commit/425325d53473429bccafa2c4dbaeaf2ba24cca23))
* small rename ([35ae82b](https://github.com/vitalvas/goradius/commit/35ae82b68c7ea40eb6c9f33f4010872821bdcc59))
* tests ([2feb0de](https://github.com/vitalvas/goradius/commit/2feb0de54d1cfe354c3297edc5385407b8a9323b))
* update docs ([694f0f4](https://github.com/vitalvas/goradius/commit/694f0f45c41130048cc49ba0d781e0057496454d))
* update simple-server ([dc555f4](https://github.com/vitalvas/goradius/commit/dc555f4cf7eb8892421c7222187e657d6cd4fbd3))


### Performance Improvements

* reduce memory allocations and fix server resource leaks ([746b676](https://github.com/vitalvas/goradius/commit/746b6766dad3c42a124f277c0aadcdd915e5fefd))


### Miscellaneous Chores

* release 0.1.0 ([59ed5ef](https://github.com/vitalvas/goradius/commit/59ed5efc07bb9cc7936d4feb9a69484a604a807f))


### Code Refactoring

* flatten pkg/ structure into single goradius package ([03979c5](https://github.com/vitalvas/goradius/commit/03979c5ddff5bb821609f24d5adbbcf7e034d1f2))
* remove ListenAndServe in favor of external transport only ([240cb51](https://github.com/vitalvas/goradius/commit/240cb51d8b0039bc5d8f0febf83f8d36b0657b4c))
* replace config structs with functional options pattern ([59844bf](https://github.com/vitalvas/goradius/commit/59844bfefe47d52df4cad271af4721b172abfb2b))
