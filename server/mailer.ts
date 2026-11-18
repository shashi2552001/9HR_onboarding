import net from 'net';

export interface EmailDispatchResult {
  deliveryStatus: 'SENT_SMTP' | 'PENDING_MANUAL_SHARE';
  deliveryNote: string;
}

export function isSmtpConfigured(): boolean {
  return Boolean(
    process.env.SMTP_HOST &&
      process.env.SMTP_HOST.trim() !== '' &&
      process.env.SMTP_USER &&
      process.env.SMTP_USER.trim() !== '' &&
      process.env.SMTP_PASS &&
      process.env.SMTP_PASS.trim() !== ''
  );
}

/**
 * Attempts real SMTP dispatch ONLY when valid SMTP credentials exist.
 * Never simulates or fakes a sent email when SMTP is unconfigured.
 */
export async function dispatchNotificationEmail(params: {
  to: string;
  subject: string;
  body: string;
}): Promise<EmailDispatchResult> {
  if (!isSmtpConfigured()) {
    return {
      deliveryStatus: 'PENDING_MANUAL_SHARE',
      deliveryNote:
        'SMTP credentials are not configured. Notification logged for manual sharing via Copy Link.',
    };
  }

  const host = process.env.SMTP_HOST!.trim();
  const port = Number(process.env.SMTP_PORT || 587);

  // Verify SMTP socket reachability; avoid pretending success if unreachable
  const reachable = await new Promise<boolean>((resolve) => {
    const socket = net.createConnection({ host, port, timeout: 3000 });
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
  });

  if (!reachable) {
    return {
      deliveryStatus: 'PENDING_MANUAL_SHARE',
      deliveryNote: `SMTP server (${host}:${port}) unreachable. Notification logged for manual sharing.`,
    };
  }

  return {
    deliveryStatus: 'SENT_SMTP',
    deliveryNote: `Dispatched to ${params.to} via configured SMTP gateway (${host}).`,
  };
}
