import { Env, SSHConnectionConfig } from '../types';
import { SSHSession } from './ssh-session';

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

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];

    (server as any).accept();

    this.waitForCredentials(server);

    return new Response(null, {
      status: 101,
      webSocket: client,
    } as any);
  }

  private waitForCredentials(ws: WebSocket): void {
    const timeout = setTimeout(() => {
      ws.send(JSON.stringify({ type: 'error', message: 'Connection timeout' }));
      ws.close(1011, 'Timeout');
    }, 10000);

    const handler = (event: MessageEvent) => {
      clearTimeout(timeout);
      ws.removeEventListener('message', handler);

      try {
        const config = JSON.parse(event.data as string) as SSHConnectionConfig;

        if (!config.host || !config.username || !config.password) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing credentials' }));
          ws.close(1011, 'Invalid credentials');
          return;
        }

        this.initSSHSession(ws, config);
      } catch (e) {
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid credentials format' }));
        ws.close(1011, 'Invalid format');
      }
    };

    ws.addEventListener('message', handler);
    ws.addEventListener('close', () => clearTimeout(timeout));
  }

  private async initSSHSession(
    ws: WebSocket,
    config: SSHConnectionConfig
  ): Promise<void> {
    try {
      const { connect } = await import('cloudflare:sockets');
      const socket = connect({ hostname: config.host, port: config.port });

      await socket.opened;

      const session = new SSHSession(ws, socket, config);
      this.sessions.set(ws, session);

      ws.addEventListener('message', (event) => {
        session.handleWebSocketMessage(event.data).catch((e) => {
          console.error('[WS] Input error:', e instanceof Error ? e.message : String(e));
        });
      });

      ws.addEventListener('close', () => {
        session.close();
        this.sessions.delete(ws);
      });

      ws.addEventListener('error', () => {
        session.close();
        this.sessions.delete(ws);
      });

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
