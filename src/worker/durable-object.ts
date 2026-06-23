import { Env, SSHConnectionConfig } from '../types';
import { SSHSession } from './ssh-session';

/**
 * SSRF 防护：检测目标主机是否为内网、保留或特殊地址。
 * 覆盖 IPv4 私有段、IPv6 回环/链路本地/私有段、IPv4-mapped IPv6 等。
 */
function isBlockedHost(host: string): boolean {
  const h = host.toLowerCase().trim();

  // 特殊主机名
  if (h === 'localhost' || h === 'ip6-localhost' || h === 'ip6-loopback') return true;

  // IPv4 私有 / 保留地址
  if (/^(127\.|10\.|0\.|192\.168\.|169\.254\.)/.test(h)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(h)) return true;

  // 移除 IPv6 方括号 (e.g. [::1])
  const v6 = h.replace(/^\[|\]$/g, '');

  // IPv6 回环
  if (v6 === '::1' || v6 === '0:0:0:0:0:0:0:1') return true;
  // IPv6 未指定地址
  if (v6 === '::' || v6 === '0:0:0:0:0:0:0:0') return true;
  // IPv6 链路本地 (fe80::/10)
  if (/^fe[89ab]/i.test(v6)) return true;
  // IPv6 唯一本地 (fc00::/7)
  if (/^f[cd]/i.test(v6)) return true;
  // IPv4-mapped IPv6 (::ffff:127.0.0.1 等)
  const v4mapped = v6.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4mapped) return isBlockedHost(v4mapped[1]);

  return false;
}

export class SSHSessionDO {
  private state: DurableObjectState;
  private env: Env;
  private sessions: Map<WebSocket, SSHSession> = new Map();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket', { status: 400 });
    }

    // 检查是否有预填充配置（来自 one-time-token 连接）
    const url = new URL(request.url);
    const configParam = url.searchParams.get('config');
    let prefilledConfig: SSHConnectionConfig | null = null;

    if (configParam) {
      try {
        prefilledConfig = JSON.parse(atob(configParam)) as SSHConnectionConfig;
      } catch {
        return new Response('Invalid config parameter', { status: 400 });
      }
    }

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];

    // 不使用 Hibernation API (acceptWebSocket)，因为 SSH 会话需要保持持久的
    // TCP 连接。Hibernation API 会在 handler 返回后休眠 DO，导致 TCP socket
    // 被销毁（Stream was cancelled），SSH 连接断开。
    server.accept();

    // 公共：连接关闭 / 错误处理
    const handleClose = () => {
      const session = this.sessions.get(server);
      if (session) {
        session.close();
        this.sessions.delete(server);
      }
    };
    server.addEventListener('close', handleClose);
    server.addEventListener('error', handleClose);

    if (prefilledConfig) {
      // 预填充模式：直接发起 SSH 连接，不等待前端凭据
      server.addEventListener('message', async (event) => {
        const session = this.sessions.get(server);
        if (session) {
          await session.handleWebSocketMessage(event.data as string | ArrayBuffer);
        }
      });

      // 使用 setTimeout 确保 WebSocket 就绪后再连接
      setTimeout(async () => {
        try {
          await this.initSSHSession(server, prefilledConfig!);
        } catch (e) {
          const errMsg = e instanceof Error ? e.message : String(e);
          try {
            server.send(JSON.stringify({ type: 'error', message: `连接失败: ${errMsg}` }));
            server.close(1011, 'SSH connection failed');
          } catch {}
        }
      }, 0);
    } else {
      // 匿名模式：等待前端发送凭据
      const credentialTimeout = setTimeout(() => {
        try {
          server.send(JSON.stringify({ type: 'error', message: 'Connection timeout' }));
          server.close(1011, 'Timeout');
        } catch {}
      }, 10000);

      server.addEventListener('message', async (event) => {
        const session = this.sessions.get(server);
        if (session) {
          await session.handleWebSocketMessage(event.data as string | ArrayBuffer);
          return;
        }

        // 第一条消息：凭据
        clearTimeout(credentialTimeout);

        try {
          const config = JSON.parse(event.data as string) as SSHConnectionConfig;

          if (!config.host || !config.username || (!config.password && !config.privateKey)) {
            server.send(JSON.stringify({ type: 'error', message: 'Missing credentials' }));
            server.close(1011, 'Invalid credentials');
            return;
          }

          await this.initSSHSession(server, config);
        } catch (e) {
          server.send(JSON.stringify({ type: 'error', message: 'Invalid credentials format' }));
          server.close(1011, 'Invalid format');
        }
      });
    }

    return new Response(null, {
      status: 101,
      webSocket: client,
    } as any);
  }

  private async initSSHSession(
    ws: WebSocket,
    config: SSHConnectionConfig
  ): Promise<void> {
    try {
      // --- SSRF Protection ---
      if (isBlockedHost(config.host)) {
        throw new Error('禁止连接内网或保留地址 (SSRF 防护)');
      }
      const BLOCKED_PORTS = [80, 443, 25, 465, 587, 3306, 6379, 27017, 11211];
      if (BLOCKED_PORTS.includes(config.port)) {
        throw new Error(`端口 ${config.port} 存在安全风险，已被禁止连接`);
      }

      const { connect } = await import('cloudflare:sockets');
      const hostname = config.host.includes(':') ? `[${config.host}]` : config.host;
      const socket = connect({ hostname, port: config.port });

      await socket.opened;

      const strictVerify = this.env.STRICT_HOST_KEY_VERIFY !== 'false';
      const session = new SSHSession(ws, socket, config, strictVerify);
      this.sessions.set(ws, session);

      await session.startHandshake();

    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      console.error('[SSH] Session error:', errMsg);
      try {
        ws.send(JSON.stringify({ type: 'error', message: `连接失败: ${errMsg}` }));
        ws.close(1011, 'SSH connection failed');
      } catch {}
    }
  }
}
