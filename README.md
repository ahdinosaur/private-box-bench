# private-box-bench

tests for a discussion on Scuttlebutt: `%Tx+4gYbcZuQ57gsrF+ljftYP9OlMgJSHSL0BppKiebk=.sha256`

## results

| max recipients count | recipient count | receiver key index | msg size (bytes) | decryption time (nanoseconds) |
|---|---|---|---|---|
| 8 | 2 | 1 | 16448 | 278435 |
| 8 | 2 | null | 16448 | 236817 |
| 8 | 8 | 7 | 16448 | 237117 |
| 8 | 8 | null | 16448 | 157998 |
| 16 | 2 | 1 | 16448 | 108776 |
| 16 | 2 | null | 16448 | 438207 |
| 16 | 8 | 7 | 16448 | 173598 |
| 16 | 8 | null | 16448 | 251324 |
| 16 | 16 | 15 | 16448 | 269449 |
| 16 | 16 | null | 16448 | 248910 |
| 32 | 2 | 1 | 16448 | 115789 |
| 32 | 2 | null | 16448 | 631191 |
| 32 | 8 | 7 | 16448 | 192663 |
| 32 | 8 | null | 16448 | 744305 |
| 32 | 16 | 15 | 16448 | 281320 |
| 32 | 16 | null | 16448 | 568463 |
| 32 | 32 | 31 | 16448 | 529098 |
| 32 | 32 | null | 16448 | 462373 |
| 64 | 2 | 1 | 16448 | 112052 |
| 64 | 2 | null | 16448 | 850185 |
| 64 | 8 | 7 | 16448 | 176503 |
| 64 | 8 | null | 16448 | 858590 |
| 64 | 16 | 15 | 16448 | 276271 |
| 64 | 16 | null | 16448 | 849733 |
| 64 | 32 | 31 | 16448 | 680434 |
| 64 | 32 | null | 16448 | 846357 |
| 64 | 64 | 63 | 16448 | 951314 |
| 64 | 64 | null | 16448 | 859282 |
| 128 | 2 | 1 | 16448 | 101412 |
| 128 | 2 | null | 16448 | 1809204 |
| 128 | 8 | 7 | 16448 | 200649 |
| 128 | 8 | null | 16448 | 1811308 |
| 128 | 16 | 15 | 16448 | 488652 |
| 128 | 16 | null | 16448 | 1622712 |
| 128 | 32 | 31 | 16448 | 464566 |
| 128 | 32 | null | 16448 | 1603716 |
| 128 | 64 | 63 | 16448 | 864051 |
| 128 | 64 | null | 16448 | 1616510 |
| 128 | 128 | 127 | 16448 | 1693115 |
| 128 | 128 | null | 16448 | 1642600 |
| 255 | 2 | 1 | 16448 | 119926 |
| 255 | 2 | null | 16448 | 3554256 |
| 255 | 8 | 7 | 16448 | 173458 |
| 255 | 8 | null | 16448 | 3147689 |
| 255 | 16 | 15 | 16448 | 273516 |
| 255 | 16 | null | 16448 | 3405105 |
| 255 | 32 | 31 | 16448 | 479545 |
| 255 | 32 | null | 16448 | 3269499 |
| 255 | 64 | 63 | 16448 | 1013212 |
| 255 | 64 | null | 16448 | 3274439 |
| 255 | 128 | 127 | 16448 | 1868316 |
| 255 | 128 | null | 16448 | 3355370 |
| 255 | 255 | 254 | 16448 | 3541803 |
| 255 | 255 | null | 16448 | 3498000 |