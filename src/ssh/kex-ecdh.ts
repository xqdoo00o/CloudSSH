import { SSH_MSG_KEX_ECDH_INIT } from '../types';
import { concat, readUint32, encodeString, toSSHMPInt } from './utils';

export class ECDHKeyExchange {
  static async generateKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
  }

  static async exportRawPublicKey(keyPair: CryptoKeyPair): Promise<Uint8Array> {
    return new Uint8Array(
      await crypto.subtle.exportKey('raw', keyPair.publicKey)
    );
  }

  static buildInit(clientRawPublicKey: Uint8Array): Uint8Array {
    return concat(
      new Uint8Array([SSH_MSG_KEX_ECDH_INIT]),
      encodeString(clientRawPublicKey)
    );
  }

  static parseReply(data: Uint8Array): {
    hostKey: Uint8Array;
    serverRawPublicKey: Uint8Array;
    signature: Uint8Array;
  } {
    let offset = 1;

    const hostKeyLen = readUint32(data, offset);
    offset += 4;
    const hostKey = data.slice(offset, offset + hostKeyLen);
    offset += hostKeyLen;

    const qSLen = readUint32(data, offset);
    offset += 4;
    const serverRawPublicKey = data.slice(offset, offset + qSLen);
    offset += qSLen;

    const sigLen = readUint32(data, offset);
    offset += 4;
    const signature = data.slice(offset, offset + sigLen);

    return { hostKey, serverRawPublicKey, signature };
  }

  static async computeSharedSecret(
    privateKey: CryptoKey,
    serverRawPublicKey: Uint8Array
  ): Promise<Uint8Array> {
    const serverKey = await crypto.subtle.importKey(
      'raw',
      serverRawPublicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: serverKey },
      privateKey,
      256
    );

    return toSSHMPInt(new Uint8Array(sharedBits));
  }

  static async computeExchangeHash(
    clientVersion: string,
    serverVersion: string,
    clientKEXInit: Uint8Array,
    serverKEXInit: Uint8Array,
    hostKey: Uint8Array,
    clientRawPublicKey: Uint8Array,
    serverRawPublicKey: Uint8Array,
    sharedSecret: Uint8Array
  ): Promise<Uint8Array> {
    const v_c = encodeString(clientVersion);
    const v_s = encodeString(serverVersion);
    const i_c = encodeString(clientKEXInit);
    const i_s = encodeString(serverKEXInit);
    const k_s = encodeString(hostKey);
    const e = encodeString(clientRawPublicKey);
    const f = encodeString(serverRawPublicKey);
    const k = sharedSecret;

    console.log('[KEX] Hash input lengths: V_C=' + v_c.length + ' V_S=' + v_s.length +
      ' I_C=' + i_c.length + ' I_S=' + i_s.length +
      ' K_S=' + k_s.length + ' e=' + e.length + ' f=' + f.length + ' K=' + k.length);
    console.log('[KEX] V_C hex=' + Array.from(v_c).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('[KEX] V_S hex=' + Array.from(v_s).map(b => b.toString(16).padStart(2, '0')).join(''));

    const data = concat(v_c, v_s, i_c, i_s, k_s, e, f, k);
    console.log('[KEX] Hash input total length: ' + data.length);

    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer);
  }
}
