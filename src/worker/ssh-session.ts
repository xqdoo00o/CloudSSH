import { SSHConnectionConfig } from '../types';
import {
  SSH_MSG_KEXINIT,
  SSH_MSG_NEWKEYS,
  SSH_MSG_KEX_ECDH_REPLY,
  SSH_MSG_SERVICE_REQUEST,
  SSH_MSG_SERVICE_ACCEPT,
  SSH_MSG_USERAUTH_SUCCESS,
  SSH_MSG_USERAUTH_FAILURE,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_FAILURE,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_DISCONNECT,
  SSH_MSG_IGNORE,
  SSH_MSG_DEBUG,
  SSH_MSG_UNIMPLEMENTED,
  SSH_MSG_CHANNEL_OPEN_FAILURE,
} from '../types';
import { SSHTransport } from '../ssh/transport';
import { SSHPacketParser, SSHPacketBuilder } from '../ssh/packet';
import { KEXInitBuilder } from '../ssh/kex';
import { ECDHKeyExchange } from '../ssh/kex-ecdh';
import { KeyDerivation } from '../ssh/keys';
import { SSHAESGCMCipher } from '../ssh/crypto';
import { SSHAuth } from '../ssh/auth';
import { SSHChannel } from '../ssh/channel';

function findCRLF(data: Uint8Array): number {
  for (let i = 0; i < data.length - 1; i++) {
    if (data[i] === 0x0d && data[i + 1] === 0x0a) {
      return i;
    }
  }
  return -1;
}

export class SSHSession {
  private ws: WebSocket;
  private socket: any;
  private config: SSHConnectionConfig;

  private transport: SSHTransport;
  private packetParser: SSHPacketParser;
  private channel: SSHChannel;
  private encryptCipher: SSHAESGCMCipher | null = null;
  private decryptCipher: SSHAESGCMCipher | null = null;
  private derivedKeys: any = null;

  private seqNumSend: number = 0;
  private sessionID: Uint8Array | null = null;

  private kexInitLocal: Uint8Array | null = null;
  private kexInitRemote: Uint8Array | null = null;

  private ecdhKeyPair!: CryptoKeyPair;
  private ecdhRawPublicKey!: Uint8Array;

  private state: 'connecting' | 'version' | 'kex' | 'auth' | 'shell' | 'ready'
    = 'connecting';

  constructor(ws: WebSocket, socket: any, config: SSHConnectionConfig) {
    this.ws = ws;
    this.socket = socket;
    this.config = config;
    this.transport = new SSHTransport();
    this.packetParser = new SSHPacketParser();
    this.channel = new SSHChannel();
  }

  async startHandshake(): Promise<void> {
    this.sendStatus('正在交换版本信息...');
    this.state = 'version';

    const writer = this.socket.writable.getWriter();
    await writer.write(new TextEncoder().encode('SSH-2.0-CloudSSH_1.0\r\n'));
    writer.releaseLock();

    this.startReading();
  }

  private async startReading(): Promise<void> {
    const reader = this.socket.readable.getReader();
    const decoder = new TextDecoder();

    let leftover: Uint8Array | null = null;

    try {
      while (true) {
        let value: Uint8Array;
        if (leftover) {
          value = leftover;
          leftover = null;
        } else {
          const result = await reader.read();
          if (result.done) break;
          value = result.value;
        }

        if (this.state === 'version') {
          const crlfIndex = findCRLF(value);
          if (crlfIndex === -1) {
            this.transport.handleVersionExchange(decoder.decode(value));
            continue;
          }

          const versionPart = value.slice(0, crlfIndex + 2);
          const remaining = value.slice(crlfIndex + 2);
          this.transport.handleVersionExchange(decoder.decode(versionPart));
          console.log('[SSH] Version exchange complete, remote=' + this.transport.getRemoteVersion());
          this.sendStatus('版本交换完成，正在密钥协商...');
          this.state = 'kex';
          await this.startKEX();

          if (remaining.length > 0) {
            console.log('[SSH] Remaining data after version: ' + remaining.length + ' bytes');
            this.packetParser.feed(remaining);
            await this.processPackets();
          }
        } else {
          console.log('[SSH] Received ' + value.length + ' bytes, state=' + this.state);
          this.packetParser.feed(value);
          await this.processPackets();
        }
      }
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      console.error('[SSH] Read loop error:', errMsg);
      try {
        this.ws.send(JSON.stringify({ type: 'error', message: 'SSH 连接断开: ' + errMsg }));
      } catch {}
    }
  }

  private async startKEX(): Promise<void> {
    console.log('[KEX] Starting key exchange');
    this.kexInitLocal = KEXInitBuilder.build();

    const packet = await SSHPacketBuilder.build(
      this.kexInitLocal, 8, null, this.seqNumSend++
    );
    await this.writeSocket(packet);
    console.log('[KEX] KEXINIT sent');

    this.ecdhKeyPair = await ECDHKeyExchange.generateKeyPair();
    this.ecdhRawPublicKey = await ECDHKeyExchange.exportRawPublicKey(this.ecdhKeyPair);

    const ecdhInit = ECDHKeyExchange.buildInit(this.ecdhRawPublicKey);
    const ecdhPacket = await SSHPacketBuilder.build(
      ecdhInit, 8, null, this.seqNumSend++
    );
    await this.writeSocket(ecdhPacket);
    console.log('[KEX] ECDH_INIT sent, waiting for server reply');
  }

  private async writeSocket(data: Uint8Array): Promise<void> {
    const writer = this.socket.writable.getWriter();
    await writer.write(data);
    writer.releaseLock();
  }

  private async processPackets(): Promise<void> {
    const blockSize = this.decryptCipher ? 16 : 8;
    console.log('[PKT] processPackets: blockSize=' + blockSize + ', hasDecrypt=' + !!this.decryptCipher + ', bufferLen=' + this.packetParser.getBufferLength());

    while (true) {
      const packet = await this.packetParser.nextPacket(
        blockSize,
        this.decryptCipher
          ? (data, seq, aad) => this.decryptCipher!.decrypt(data, seq, aad)
          : (data) => data,
        !!this.decryptCipher
      );

      if (!packet) {
        console.log('[PKT] No more packets, buffer remaining: ' + this.packetParser.getBufferLength());
        break;
      }

      console.log('[PKT] Received msgType=' + packet.payload[0] + ', state=' + this.state + ', payloadLen=' + packet.payload.length);
      await this.handlePacket(packet);
    }
  }

  private async handlePacket(packet: any): Promise<void> {
    const msgType = packet.payload[0];

    switch (this.state) {
      case 'kex':
        await this.handleKEXPacket(msgType, packet.payload);
        break;

      case 'auth':
        await this.handleAuthPacket(msgType, packet.payload);
        break;

      case 'shell':
      case 'ready':
        await this.handleSessionPacket(msgType, packet.payload);
        break;
    }
  }

  private async handleKEXPacket(msgType: number, payload: Uint8Array): Promise<void> {
    console.log('[KEX] handleKEXPacket: msgType=' + msgType);
    switch (msgType) {
      case SSH_MSG_KEXINIT:
        this.kexInitRemote = payload;
        console.log('[KEX] Received KEXINIT from server');
        break;

      case SSH_MSG_KEX_ECDH_REPLY:
        console.log('[KEX] Received ECDH_REPLY');
        await this.handleECDHReply(payload);
        break;

      case SSH_MSG_NEWKEYS: {
        console.log('[KEX] Received NEWKEYS from server, seqNumSend=' + this.seqNumSend);
        const newKeys = new Uint8Array([SSH_MSG_NEWKEYS]);
        const packet = await SSHPacketBuilder.build(
          newKeys, 8, null, this.seqNumSend++
        );
        await this.writeSocket(packet);
        console.log('[KEX] Client NEWKEYS sent, seqNumSend=' + this.seqNumSend);

        await this.enableEncryption();
        console.log('[KEX] Encryption enabled');
        this.state = 'auth';
        try {
          await this.sendServiceRequest();
          console.log('[AUTH] SERVICE_REQUEST sent');
        } catch (e) {
          const errMsg = e instanceof Error ? e.message : String(e);
          console.error('[AUTH] SERVICE_REQUEST failed:', errMsg);
          this.sendError('密钥协商失败: ' + errMsg);
          this.close();
        }
        break;
      }

      case SSH_MSG_UNIMPLEMENTED:
        console.warn('[KEX] Server sent UNIMPLEMENTED');
        break;

      default:
        console.warn('[KEX] Unexpected msgType=' + msgType + ' in kex state');
        break;
    }
  }

  private async handleECDHReply(payload: Uint8Array): Promise<void> {
    console.log('[KEX] Parsing ECDH_REPLY...');
    const { hostKey, serverRawPublicKey, signature } =
      ECDHKeyExchange.parseReply(payload);
    console.log('[KEX] ECDH_REPLY parsed: hostKey=' + hostKey.length + ', serverPubKey=' + serverRawPublicKey.length + ', sig=' + signature.length);

    console.log('[KEX] Computing shared secret...');
    const sharedSecret = await ECDHKeyExchange.computeSharedSecret(
      this.ecdhKeyPair.privateKey,
      serverRawPublicKey
    );
    console.log('[KEX] Shared secret computed: ' + sharedSecret.length + ' bytes');

    console.log('[KEX] Computing exchange hash...');
    const localVer = this.transport.getLocalVersion();
    const remoteVer = this.transport.getRemoteVersion();
    console.log('[KEX] localVer="' + localVer + '" len=' + localVer.length);
    console.log('[KEX] remoteVer="' + remoteVer + '" len=' + remoteVer.length);
    console.log('[KEX] kexInitLocal len=' + this.kexInitLocal!.length + ' kexInitRemote len=' + this.kexInitRemote!.length);
    console.log('[KEX] hostKey len=' + hostKey.length + ' clientPubKey len=' + this.ecdhRawPublicKey.length + ' serverPubKey len=' + serverRawPublicKey.length);
    console.log('[KEX] sharedSecret len=' + sharedSecret.length);
    const H = await ECDHKeyExchange.computeExchangeHash(
      this.transport.getLocalVersion(),
      this.transport.getRemoteVersion(),
      this.kexInitLocal!,
      this.kexInitRemote!,
      hostKey,
      this.ecdhRawPublicKey,
      serverRawPublicKey,
      sharedSecret
    );
    console.log('[KEX] Exchange hash hex=' + Array.from(H).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('[KEX] sharedSecret hex=' + Array.from(sharedSecret).map(b => b.toString(16).padStart(2, '0')).join(''));

    if (!this.sessionID) {
      this.sessionID = H;
      console.log('[KEX] Session ID set');
    }

    console.log('[KEX] Deriving keys...');
    this.derivedKeys = await KeyDerivation.deriveKeys(sharedSecret, H, this.sessionID!);
    console.log('[KEX] Keys derived, waiting for NEWKEYS');
  }

  private async enableEncryption(): Promise<void> {
    const keys = this.derivedKeys;
    console.log('[KEX] encKeyC2S len=' + keys.encKeyClientToServer.length + ', ivC2S len=' + keys.ivClientToServer.length);
    console.log('[KEX] ivC2S hex=' + Array.from(keys.ivClientToServer).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('[KEX] encKeyC2S hex=' + Array.from(keys.encKeyClientToServer).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('[KEX] ivS2C hex=' + Array.from(keys.ivServerToClient).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('[KEX] encKeyS2C hex=' + Array.from(keys.encKeyServerToClient).map(b => b.toString(16).padStart(2, '0')).join(''));

    this.encryptCipher = new SSHAESGCMCipher(
      keys.encKeyClientToServer,
      keys.ivClientToServer
    );
    await this.encryptCipher.init();

    this.decryptCipher = new SSHAESGCMCipher(
      keys.encKeyServerToClient,
      keys.ivServerToClient
    );
    await this.decryptCipher.init();

    try {
      const testPlain = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
      const testAad = new Uint8Array([0, 0, 0, 5]);
      const testEnc = await this.encryptCipher.encrypt(testPlain, 0, testAad);
      console.log('[KEX] Round-trip test: encrypted ' + testPlain.length + ' -> ' + testEnc.length + ' bytes');
      const testDec = await this.encryptCipher.decrypt(testEnc, 0, testAad);
      const match = testDec && testDec.length === testPlain.length && testDec.every((b, i) => b === testPlain[i]);
      console.log('[KEX] Round-trip test: ' + (match ? 'PASS' : 'FAIL'));
    } catch (e) {
      console.error('[KEX] Round-trip test ERROR:', e instanceof Error ? e.message : String(e));
    }
  }

  private async sendServiceRequest(): Promise<void> {
    const serviceName = 'ssh-userauth';
    const nameBytes = new TextEncoder().encode(serviceName);
    const serviceRequest = new Uint8Array(1 + 4 + nameBytes.length);
    serviceRequest[0] = SSH_MSG_SERVICE_REQUEST;
    new DataView(serviceRequest.buffer).setUint32(1, nameBytes.length, false);
    serviceRequest.set(nameBytes, 5);

    console.log('[AUTH] SERVICE_REQUEST payload len=' + serviceRequest.length + ', seqNum=' + this.seqNumSend);
    console.log('[AUTH] encryptCipher exists=' + !!this.encryptCipher);

    const packet = await SSHPacketBuilder.build(
      serviceRequest, 16,
      (data, seq, aad) => {
        console.log('[AUTH] Encrypting: dataLen=' + data.length + ', seq=' + seq + ', aadLen=' + aad?.length);
        return this.encryptCipher!.encrypt(data, seq, aad);
      },
      this.seqNumSend++,
      true
    );
    console.log('[AUTH] Encrypted packet len=' + packet.length + ', first16=' + Array.from(packet.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(''));
    await this.writeSocket(packet);
    console.log('[AUTH] SERVICE_REQUEST sent to socket');
  }

  private async authenticate(): Promise<void> {
    const authRequest = SSHAuth.buildPasswordAuthRequest(
      this.config.username,
      this.config.password
    );

    const packet = await SSHPacketBuilder.build(
      authRequest, 16,
      (data, seq, aad) => this.encryptCipher!.encrypt(data, seq, aad),
      this.seqNumSend++,
      true
    );
    await this.writeSocket(packet);
  }

  private async handleAuthPacket(msgType: number, payload: Uint8Array): Promise<void> {
    switch (msgType) {
      case SSH_MSG_SERVICE_ACCEPT:
        this.sendStatus('认证服务已接受，正在认证...');
        await this.authenticate();
        break;

      case SSH_MSG_USERAUTH_SUCCESS:
        this.sendStatus('认证成功');
        this.state = 'shell';
        await this.openShell();
        break;

      case SSH_MSG_USERAUTH_FAILURE:
        this.sendError('认证失败：用户名或密码错误');
        this.close();
        break;

      case SSH_MSG_UNIMPLEMENTED:
        console.warn('[AUTH] Server sent UNIMPLEMENTED');
        break;
    }
  }

  private async openShell(): Promise<void> {
    const openMsg = this.channel.buildOpenSession();
    await this.sendEncrypted(openMsg);
  }

  private async handleSessionPacket(msgType: number, payload: Uint8Array): Promise<void> {
    switch (msgType) {
      case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        this.channel.handleOpenConfirmation(payload);
        const ptyReq = this.channel.buildPTYRequest(120, 40);
        await this.sendEncrypted(ptyReq);
        break;

      case SSH_MSG_CHANNEL_OPEN_FAILURE:
        this.sendError('通道打开被拒绝');
        this.close();
        break;

      case SSH_MSG_CHANNEL_SUCCESS:
        if (this.state === 'shell') {
          const shellReq = this.channel.buildShellRequest();
          await this.sendEncrypted(shellReq);
          this.state = 'ready';
          this.sendStatus('Shell 已就绪');
        }
        break;

      case SSH_MSG_CHANNEL_FAILURE:
        if (this.state === 'shell') {
          this.sendError('PTY 或 Shell 请求被拒绝');
          this.close();
        }
        break;

      case SSH_MSG_CHANNEL_DATA: {
        const outputData = this.channel.handleChannelData(payload);
        this.ws.send(outputData.slice().buffer as ArrayBuffer);
        break;
      }

      case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        break;

      case SSH_MSG_CHANNEL_EOF:
      case SSH_MSG_CHANNEL_CLOSE:
        this.sendStatus('会话已结束');
        this.close();
        break;

      case SSH_MSG_DISCONNECT:
        this.sendStatus('服务器断开连接');
        this.close();
        break;

      case SSH_MSG_IGNORE:
      case SSH_MSG_DEBUG:
      case SSH_MSG_UNIMPLEMENTED:
        break;
    }
  }

  async handleWebSocketMessage(data: string | ArrayBuffer): Promise<void> {
    if (this.state !== 'ready') return;

    if (typeof data === 'string') {
      try {
        const msg = JSON.parse(data);
        if (msg.type === 'resize') {
          await this.handleResize(msg.cols, msg.rows);
          return;
        }
      } catch {
        const encoded = new TextEncoder().encode(data);
        const channelData = this.channel.buildChannelData(encoded);
        await this.sendEncrypted(channelData);
      }
    } else {
      const channelData = this.channel.buildChannelData(new Uint8Array(data));
      await this.sendEncrypted(channelData);
    }
  }

  private async handleResize(cols: number, rows: number): Promise<void> {
    const resizeMsg = this.channel.buildWindowChange(cols, rows);
    await this.sendEncrypted(resizeMsg);
  }

  private async sendEncrypted(payload: Uint8Array): Promise<void> {
    if (!this.encryptCipher) {
      throw new Error('Encryption not initialized');
    }

    const encrypted = await SSHPacketBuilder.build(
      payload, 16,
      (data, seq, aad) => this.encryptCipher!.encrypt(data, seq, aad),
      this.seqNumSend++,
      true
    );
    await this.writeSocket(encrypted);
  }

  private sendStatus(message: string): void {
    try {
      this.ws.send(JSON.stringify({ type: 'status', message }));
    } catch {}
  }

  private sendError(message: string): void {
    try {
      this.ws.send(JSON.stringify({ type: 'error', message }));
    } catch {}
  }

  close(): void {
    try { this.socket.close(); } catch {}
    try { this.ws.close(); } catch {}
  }
}
