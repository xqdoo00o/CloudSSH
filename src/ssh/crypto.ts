export class SSHAESGCMCipher {
  private key: CryptoKey | null = null;
  private baseIV: Uint8Array;
  private seqNum: number = 0;
  private rawKey: Uint8Array;

  constructor(rawKey: Uint8Array, iv: Uint8Array) {
    this.baseIV = iv;
    this.rawKey = rawKey;
  }

  async init(): Promise<void> {
    this.key = await crypto.subtle.importKey(
      'raw',
      this.rawKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  private buildNonce(seqNum: number): Uint8Array {
    const nonce = new Uint8Array(this.baseIV);
    nonce[8] ^= (seqNum >>> 24) & 0xff;
    nonce[9] ^= (seqNum >>> 16) & 0xff;
    nonce[10] ^= (seqNum >>> 8) & 0xff;
    nonce[11] ^= seqNum & 0xff;
    console.log('[CRYPTO] buildNonce: seqNum=' + seqNum + ', nonce=' + Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join(''));
    return nonce;
  }

  async encrypt(plaintext: Uint8Array, seqNum?: number, aad?: Uint8Array): Promise<Uint8Array> {
    if (!this.key) throw new Error('Cipher not initialized');
    const seq = seqNum ?? this.seqNum++;
    const nonce = this.buildNonce(seq);

    const alg: Record<string, unknown> = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
    if (aad) alg.additionalData = aad;

    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(alg as AesGcmParams, this.key, plaintext)
    );

    return encrypted;
  }

  async decrypt(ciphertext: Uint8Array, seqNum?: number, aad?: Uint8Array): Promise<Uint8Array | null> {
    if (!this.key) throw new Error('Cipher not initialized');
    const seq = seqNum ?? this.seqNum++;
    const nonce = this.buildNonce(seq);

    const alg: Record<string, unknown> = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
    if (aad) alg.additionalData = aad;

    try {
      const decrypted = new Uint8Array(
        await crypto.subtle.decrypt(alg as AesGcmParams, this.key, ciphertext)
      );
      return decrypted;
    } catch (e) {
      console.error('[CRYPTO] Decrypt failed, seqNum:', seq, 'ciphertextLen:', ciphertext.length, 'error:', e instanceof Error ? e.message : String(e));
      return null;
    }
  }
}

export const REKEY_THRESHOLD = 1 << 30;

export function shouldRekey(seqNum: number): boolean {
  return seqNum >= REKEY_THRESHOLD;
}
