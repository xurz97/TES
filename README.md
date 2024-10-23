### Fast implementation of four TES standards
Tweakable enciphering scheme (TES) is a type of encryption scheme that provides strong pseudorandom permutation security on arbitrarily long messages.

four TES standards: XTS, HCTR, XCB, EME2

You can try to compile the code in codespaces or local. Use `draw.py` to draw.

```
// compile XTS mode
gcc aes_xts.c timing_xts.c -march=native -O3 (-DUSE_AESNI_1 / -DUSE_AESNI_2 -DUSE_AESNI_4 -DUSE_AESNI_6 -DUSE_AESNI_8)
// compile EME2 mode
gcc eme2_aes.c timing_eme2.c -march=native -O3 (-DUSE_AESNI_1 / -DUSE_AESNI_2)
// compile HCTR mode
gcc hctr_aes.c timing_hctr.c -march=native -O3 (-DUSE_AESNI_1 / -DUSE_AESNI_2 / -DUSE_AESNI_4 / -DUSE_AESNI_8)
// compile XCB mode
gcc xcb_aes.c timing_xcb.c -march=native -O3 (-DUSE_AESNI_1 / -DUSE_AESNI_2 / -DUSE_AESNI_4 / -DUSE_AESNI_8)
```
