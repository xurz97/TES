// AE template from OCB code https://www.cs.ucdavis.edu/~rogaway/ocb/performance/
#ifndef _AE_H_
#define _AE_H_

typedef struct _ae_ctx ae_ctx;

ae_ctx *ae_allocate(void *misc);
void ae_free(ae_ctx *ctx);

int ae_init(ae_ctx *ctx,
            const void *key,
            int key_len,
            int nonce_len,
            int tag_len);

int ae_encrypt(ae_ctx *ctx,
               const void *nonce,
               const void *pt,
               int pt_len,
               const void *ad,
               int ad_len,
               void *ct,
               void *tag,
               int final);
#endif
