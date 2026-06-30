import { readUint32, writeUint32, encodeString, concat } from './utils';
import {
  SSH_FXP_INIT,
  SSH_FXP_VERSION,
  SSH_FXP_OPEN,
  SSH_FXP_CLOSE,
  SSH_FXP_READ,
  SSH_FXP_WRITE,
  SSH_FXP_OPENDIR,
  SSH_FXP_READDIR,
  SSH_FXP_REMOVE,
  SSH_FXP_MKDIR,
  SSH_FXP_RMDIR,
  SSH_FXP_REALPATH,
  SSH_FXP_STAT,
  SSH_FXP_RENAME,
  SSH_FXP_STATUS,
  SSH_FXP_HANDLE,
  SSH_FXP_DATA,
  SSH_FXP_NAME,
  SSH_FXP_ATTRS,
  SSH_FX_OK,
  SSH_FX_EOF,
  SSH_FXF_READ,
  SSH_FXF_WRITE,
  SSH_FXF_CREAT,
  SSH_FXF_TRUNC,
  SSH_FILEXFER_ATTR_SIZE,
  SSH_FILEXFER_ATTR_UIDGID,
  SSH_FILEXFER_ATTR_PERMISSIONS,
  SSH_FILEXFER_ATTR_ACMODTIME,
  SSH_S_IFDIR,
  type SFTPFileAttributes,
  type SFTPFileEntry,
  type SFTPPendingRequest,
  getStatusMessage,
  getFileTypeFromPermissions,
  formatPermissions,
  formatTimestamp,
} from './sftp-types';

const SFTP_VERSION = 3;
const DEFAULT_READ_SIZE = 32768;
const REQUEST_TIMEOUT_MS = 30000;

export class SFTPClient {
  private requestId: number = 0;
  private pendingRequests: Map<number, SFTPPendingRequest> = new Map();
  private recvBuffer: Uint8Array = new Uint8Array(0);
  private version: number = 0;
  private sendData: ((data: Uint8Array) => void) | null = null;

  setSendCallback(fn: (data: Uint8Array) => void): void {
    this.sendData = fn;
  }

  dispose(): void {
    for (const [, req] of this.pendingRequests) {
      if (req.timeout) clearTimeout(req.timeout);
      req.reject(new Error('SFTP session closed'));
    }
    this.pendingRequests.clear();
    this.recvBuffer = new Uint8Array(0);
  }

  // Build SFTP init packet
  buildInit(): Uint8Array {
    const packet = new Uint8Array(5);
    writeUint32(packet, 0, 1 + 4); // length = type(1) + version(4)
    packet[4] = SSH_FXP_INIT;
    writeUint32(packet, 5, SFTP_VERSION);
    return packet;
  }

  // Feed incoming channel data into the SFTP receive buffer
  feed(data: Uint8Array): void {
    const merged = new Uint8Array(this.recvBuffer.length + data.length);
    merged.set(this.recvBuffer);
    merged.set(data, this.recvBuffer.length);
    this.recvBuffer = merged;
  }

  // Try to extract and dispatch complete SFTP packets from the buffer
  processReceivedPackets(): void {
    while (this.recvBuffer.length >= 4) {
      const packetLen = readUint32(this.recvBuffer, 0);
      const totalLen = 4 + packetLen;

      if (this.recvBuffer.length < totalLen) {
        break; // incomplete packet
      }

      const packetData = this.recvBuffer.subarray(4, totalLen);
      this.recvBuffer = this.recvBuffer.slice(totalLen);

      this.handleSFTPPacket(packetData);
    }
  }

  private handleSFTPPacket(data: Uint8Array): void {
    const type = data[0];

    if (type === SSH_FXP_VERSION) {
      this.version = readUint32(data, 1);
      // Resolve the init request
      const req = this.pendingRequests.get(0);
      if (req) {
        if (req.timeout) clearTimeout(req.timeout);
        this.pendingRequests.delete(0);
        req.resolve(data);
      }
      return;
    }

    // For all other response types, read the request ID at offset 1
    const reqId = readUint32(data, 1);
    const req = this.pendingRequests.get(reqId);
    if (!req) {
      return; // stale or unsolicited
    }

    if (req.timeout) clearTimeout(req.timeout);
    this.pendingRequests.delete(reqId);

    req.resolve(data);
  }

  private nextRequestId(): number {
    return ++this.requestId;
  }

  private sendRequest(requestId: number, type: number, payload: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const packetLen = 1 + 4 + payload.length; // type + requestId + payload
      const packet = new Uint8Array(4 + packetLen);
      writeUint32(packet, 0, packetLen);
      packet[4] = type;
      writeUint32(packet, 5, requestId);
      packet.set(payload, 9);

      const timeout = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        reject(new Error('SFTP request timeout'));
      }, REQUEST_TIMEOUT_MS);

      this.pendingRequests.set(requestId, { requestId, type, resolve, reject, timeout });

      if (this.sendData) {
        this.sendData(packet);
      } else {
        reject(new Error('SFTP send callback not set'));
      }
    });
  }

  // Wait for init/version exchange
  async waitForVersion(): Promise<number> {
    const data = await new Promise<Uint8Array>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(0);
        reject(new Error('SFTP version timeout'));
      }, REQUEST_TIMEOUT_MS);
      this.pendingRequests.set(0, { requestId: 0, type: SSH_FXP_INIT, resolve, reject, timeout });
    });

    this.version = readUint32(data, 1);
    return this.version;
  }

  // Parse SFTP_ATTRS from buffer
  parseAttributes(data: Uint8Array, offset: number): { attrs: SFTPFileAttributes; consumed: number } {
    const attrs: SFTPFileAttributes = {};
    let pos = offset;

    const flags = readUint32(data, pos);
    pos += 4;

    if (flags & SSH_FILEXFER_ATTR_SIZE) {
      attrs.size = readUint32(data, pos); // Note: SFTP v3 uses uint64, but we read uint32 for simplicity
      pos += 4;
      pos += 4; // skip high 32 bits
    }

    if (flags & SSH_FILEXFER_ATTR_UIDGID) {
      attrs.uid = readUint32(data, pos);
      pos += 4;
      attrs.gid = readUint32(data, pos);
      pos += 4;
    }

    if (flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
      attrs.permissions = readUint32(data, pos);
      pos += 4;
    }

    if (flags & SSH_FILEXFER_ATTR_ACMODTIME) {
      attrs.atime = readUint32(data, pos);
      pos += 4;
      attrs.mtime = readUint32(data, pos);
      pos += 4;
    }

    return { attrs, consumed: pos - offset };
  }

  // SSH_FXP_OPENDIR
  async openDir(path: string): Promise<Uint8Array> {
    const reqId = this.nextRequestId();
    const pathBytes = encodeString(path);
    const payload = new Uint8Array(pathBytes.length);
    payload.set(pathBytes);
    return this.sendRequest(reqId, SSH_FXP_OPENDIR, payload);
  }

  // SSH_FXP_READDIR
  async readDir(handle: Uint8Array): Promise<Uint8Array> {
    const reqId = this.nextRequestId();
    const payload = new Uint8Array(4 + handle.length);
    writeUint32(payload, 0, handle.length);
    payload.set(handle, 4);
    return this.sendRequest(reqId, SSH_FXP_READDIR, payload);
  }

  // SSH_FXP_CLOSE
  async closeHandle(handle: Uint8Array): Promise<void> {
    const reqId = this.nextRequestId();
    const payload = new Uint8Array(4 + handle.length);
    writeUint32(payload, 0, handle.length);
    payload.set(handle, 4);
    await this.sendRequest(reqId, SSH_FXP_CLOSE, payload);
  }

  // SSH_FXP_STAT
  async stat(path: string): Promise<Uint8Array> {
    const reqId = this.nextRequestId();
    const pathBytes = encodeString(path);
    const payload = new Uint8Array(pathBytes.length);
    payload.set(pathBytes);
    return this.sendRequest(reqId, SSH_FXP_STAT, payload);
  }

  // SSH_FXP_OPEN
  async openFile(path: string, flags: number): Promise<Uint8Array> {
    const reqId = this.nextRequestId();
    const pathBytes = encodeString(path);
    // pflags(4) + attrs(4 for flags=0)
    const payload = new Uint8Array(pathBytes.length + 4 + 4);
    let offset = 0;
    payload.set(pathBytes, offset);
    offset += pathBytes.length;
    writeUint32(payload, offset, flags);
    offset += 4;
    writeUint32(payload, offset, 0); // no attributes
    return this.sendRequest(reqId, SSH_FXP_OPEN, payload);
  }

  // SSH_FXP_READ
  async readFile(handle: Uint8Array, offset: number, length: number): Promise<Uint8Array> {
    const reqId = this.nextRequestId();
    const payload = new Uint8Array(4 + handle.length + 8 + 4);
    let pos = 0;
    writeUint32(payload, pos, handle.length);
    pos += 4;
    payload.set(handle, pos);
    pos += handle.length;
    // offset as uint64 (high=0, low=offset)
    writeUint32(payload, pos, 0);
    pos += 4;
    writeUint32(payload, pos, offset);
    pos += 4;
    writeUint32(payload, pos, length);
    return this.sendRequest(reqId, SSH_FXP_READ, payload);
  }

  // SSH_FXP_WRITE
  async writeFile(handle: Uint8Array, offset: number, data: Uint8Array): Promise<Uint8Array> {
    const reqId = this.nextRequestId();
    const payload = new Uint8Array(4 + handle.length + 8 + 4 + data.length);
    let pos = 0;
    writeUint32(payload, pos, handle.length);
    pos += 4;
    payload.set(handle, pos);
    pos += handle.length;
    writeUint32(payload, pos, 0);
    pos += 4;
    writeUint32(payload, pos, offset);
    pos += 4;
    writeUint32(payload, pos, data.length);
    pos += 4;
    payload.set(data, pos);
    return this.sendRequest(reqId, SSH_FXP_WRITE, payload);
  }

  // SSH_FXP_REMOVE
  async removeFile(path: string): Promise<Uint8Array> {
    const reqId = this.nextRequestId();
    const pathBytes = encodeString(path);
    const payload = new Uint8Array(pathBytes.length);
    payload.set(pathBytes);
    return this.sendRequest(reqId, SSH_FXP_REMOVE, payload);
  }

  // SSH_FXP_MKDIR
  async mkdir(path: string, permissions: number = 0o755): Promise<Uint8Array> {
    const reqId = this.nextRequestId();
    const pathBytes = encodeString(path);
    const payload = new Uint8Array(pathBytes.length + 4 + 4);
    let offset = 0;
    payload.set(pathBytes, offset);
    offset += pathBytes.length;
    writeUint32(payload, offset, SSH_FILEXFER_ATTR_PERMISSIONS);
    offset += 4;
    writeUint32(payload, offset, permissions);
    return this.sendRequest(reqId, SSH_FXP_MKDIR, payload);
  }

  // SSH_FXP_RMDIR
  async rmdir(path: string): Promise<Uint8Array> {
    const reqId = this.nextRequestId();
    const pathBytes = encodeString(path);
    const payload = new Uint8Array(pathBytes.length);
    payload.set(pathBytes);
    return this.sendRequest(reqId, SSH_FXP_RMDIR, payload);
  }

  // SSH_FXP_RENAME
  async rename(oldPath: string, newPath: string): Promise<Uint8Array> {
    const reqId = this.nextRequestId();
    const oldBytes = encodeString(oldPath);
    const newBytes = encodeString(newPath);
    const payload = new Uint8Array(oldBytes.length + newBytes.length);
    payload.set(oldBytes);
    payload.set(newBytes, oldBytes.length);
    return this.sendRequest(reqId, SSH_FXP_RENAME, payload);
  }

  // SSH_FXP_REALPATH
  async realpath(path: string): Promise<Uint8Array> {
    const reqId = this.nextRequestId();
    const pathBytes = encodeString(path);
    const payload = new Uint8Array(pathBytes.length);
    payload.set(pathBytes);
    return this.sendRequest(reqId, SSH_FXP_REALPATH, payload);
  }

  // Parse SSH_FXP_STATUS response
  parseStatusResponse(data: Uint8Array): { code: number; message: string } {
    const code = readUint32(data, 5); // skip type(1) + requestId(4)
    let offset = 9;
    const msgLen = readUint32(data, offset);
    offset += 4;
    const message = new TextDecoder().decode(data.slice(offset, offset + msgLen));
    return { code, message: message || getStatusMessage(code) };
  }

  // Parse SSH_FXP_HANDLE response
  parseHandleResponse(data: Uint8Array): Uint8Array {
    let offset = 5; // skip type(1) + requestId(4)
    const handleLen = readUint32(data, offset);
    offset += 4;
    return data.slice(offset, offset + handleLen);
  }

  // Parse SSH_FXP_DATA response
  parseDataResponse(data: Uint8Array): Uint8Array {
    let offset = 5; // skip type(1) + requestId(4)
    const dataLen = readUint32(data, offset);
    offset += 4;
    return data.slice(offset, offset + dataLen);
  }

  // Parse SSH_FXP_NAME response for directory listing
  parseNameResponse(data: Uint8Array): SFTPFileEntry[] {
    let offset = 5; // skip type(1) + requestId(4)
    const count = readUint32(data, offset);
    offset += 4;

    const entries: SFTPFileEntry[] = [];
    for (let i = 0; i < count; i++) {
      const filenameLen = readUint32(data, offset);
      offset += 4;
      const filename = new TextDecoder().decode(data.slice(offset, offset + filenameLen));
      offset += filenameLen;

      const longnameLen = readUint32(data, offset);
      offset += 4;
      const longname = new TextDecoder().decode(data.slice(offset, offset + longnameLen));
      offset += longnameLen;

      const { attrs, consumed } = this.parseAttributes(data, offset);
      offset += consumed;

      entries.push({ filename, longname, attrs });
    }

    return entries;
  }

  // Parse SSH_FXP_ATTRS response
  parseAttrsResponse(data: Uint8Array): SFTPFileAttributes {
    const { attrs } = this.parseAttributes(data, 5); // skip type(1) + requestId(4)
    return attrs;
  }

  // Parse all entries from a full directory listing (may need multiple READDIR calls)
  async listAllEntries(handle: Uint8Array): Promise<SFTPFileEntry[]> {
    const allEntries: SFTPFileEntry[] = [];

    while (true) {
      try {
        const response = await this.readDir(handle);
        const type = response[0];

        if (type === SSH_FXP_STATUS) {
          const status = this.parseStatusResponse(response);
          if (status.code === SSH_FX_EOF) break;
          throw new Error(status.message);
        }

        if (type === SSH_FXP_NAME) {
          const entries = this.parseNameResponse(response);
          allEntries.push(...entries);
        }
      } catch (e) {
        if (e instanceof Error && e.message.includes('EOF')) break;
        throw e;
      }
    }

    return allEntries;
  }
}
