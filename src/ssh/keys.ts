import { SessionKeys } from '../types';
import { concat, encodeString } from './utils';

export class KeyDerivation {
  static async deriveKeys(
    sharedSecret: Uint8Array,
    exchangeHash: Uint8Array,
    sessionID: Uint8Array
  ): Promise<SessionKeys> {
    const ivC2S    = await this.expandKey(sharedSecret, exchangeHash, 'A', sessionID, 12);
    const ivS2C    = await this.expandKey(sharedSecret, exchangeHash, 'B', sessionID, 12);
    const keyC2S   = await this.expandKey(sharedSecret, exchangeHash, 'C', sessionID, 32);
    const keyS2C   = await this.expandKey(sharedSecret, exchangeHash, 'D', sessionID, 32);
    const intKeyC2S = await this.expandKey(sharedSecret, exchangeHash, 'E', sessionID, 32);
    const intKeyS2C = await this.expandKey(sharedSecret, exchangeHash, 'F', sessionID, 32);

    return {
      ivClientToServer: ivC2S,
      ivServerToClient: ivS2C,
      encKeyClientToServer: keyC2S,
      encKeyServerToClient: keyS2C,
      integrityKeyC2S: intKeyC2S,
      integrityKeyS2C: intKeyS2C,
      sessionID,
    };
  }

  private static async expandKey(
    K: Uint8Array,
    H: Uint8Array,
    X: string,
    sessionId: Uint8Array,
    needed: number
  ): Promise<Uint8Array> {
    const hashLen = 32;
    const rounds = Math.ceil(needed / hashLen);
    const result = new Uint8Array(needed);
    let offset = 0;

    const HStr = encodeString(H);
    const sessionIdStr = encodeString(sessionId);
    const XBytes = new TextEncoder().encode(X);

    if (X === 'A') {
      console.log('[KDF] Input lengths: K=' + K.length + ' H=' + H.length + ' HStr=' + HStr.length + ' X=' + XBytes.length + ' sessionId=' + sessionId.length + ' sessionIdStr=' + sessionIdStr.length);
    }

    let key = new Uint8Array(
      await crypto.subtle.digest('SHA-256',
        concat(K, HStr, XBytes, sessionIdStr)
      )
    );
    result.set(key.slice(0, Math.min(hashLen, needed)), 0);
    offset += hashLen;

    for (let i = 1; i < rounds; i++) {
      key = new Uint8Array(
        await crypto.subtle.digest('SHA-256',
          concat(K, HStr, key, sessionIdStr)
        )
      );
      const remaining = needed - offset;
      result.set(key.slice(0, Math.min(hashLen, remaining)), offset);
      offset += hashLen;
    }

    return result;
  }
}
