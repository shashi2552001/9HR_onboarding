import cors from 'cors';
import crypto from 'crypto';
import express, { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import helmet from 'helmet';
import multer from 'multer';
import path from 'path';
import firebaseConfig from '../firebase-applet-config.json' with { type: 'json' };
import {
  AnalyticsSummary,
  Candidate,
  CandidateDocument,
  DOCUMENT_CATEGORIES,
  ONBOARDING_STATUSES,
  OnboardingStatus,
  OnboardingToken,
  REQUIRED_DOCUMENT_CATEGORIES,
  StaffRole,
} from '../src/shared/types.ts';
import {
  addressInfoSchema,
  bankDetailsSchema,
  calculateCompletionPercentage,
  createCandidateSchema,
  createStaffSchema,
  declarationSchema,
  documentCategorySchema,
  educationInfoSchema,
  employmentInfoSchema,
  familyInfoSchema,
  loginSchema,
  personalInfoSchema,
  statusUpdateSchema,
  verify2FASchema,
} from '../src/shared/validation.ts';
import { dispatchNotificationEmail, isSmtpConfigured } from './mailer.ts';
import {
  createTotpSecret,
  escapeCsvCell,
  generateSecureOnboardingToken,
  generateTempPassword,
  hashPassword,
  hashPasswordSync,
  sanitizeRecordStrings,
  sanitizeText,
  signToken,
  toPublicStaffUser,
  validateMagicBytes,
  verifyPassword,
  verifyToken,
  verifyTotpCode,
} from './security.ts';
import { buildSeedDatabase, PortalDatabase, PortalStore } from './store.ts';

interface AuthRequest extends Request {
  staffUser?: {
    id: string;
    loginId: string;
    email: string;
    fullName: string;
    role: StaffRole;
  };
}

function parseCookies(req: Request): Record<string, string> {
  const header = req.headers.cookie;
  if (!header) return {};
  const result: Record<string, string> = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      result[k] = decodeURIComponent(v);
    }
  }
  return result;
}

function setSessionCookie(res: Response, token: string): void {
  res.cookie('ninehr_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 12 * 60 * 60 * 1000,
    path: '/',
  });
}

function clearSessionCookie(res: Response): void {
  res.clearCookie('ninehr_session', { path: '/' });
}

function getClientIp(req: Request): string {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length > 0) {
    return fwd.split(',')[0].trim();
  }
  return req.ip || '127.0.0.1';
}

function appendAudit(
  db: PortalDatabase,
  params: {
    actorId: string;
    actorName: string;
    actorRole: string;
    action: string;
    targetType: 'AUTH' | 'STAFF' | 'CANDIDATE' | 'TOKEN' | 'DOCUMENT' | 'EMPLOYEE' | 'SYSTEM';
    targetId: string;
    details: string;
    ipAddress: string;
  }
) {
  db.auditLogs.unshift({
    id: `aud-${crypto.randomBytes(6).toString('hex')}`,
    ...params,
    timestamp: new Date().toISOString(),
  });
  if (db.auditLogs.length > 1000) {
    db.auditLogs.length = 1000;
  }
}

export function createApp(options?: {
  store?: PortalStore;
  disableRateLimit?: boolean;
}) {
  const store = options?.store ?? new PortalStore();
  const app = express();

  app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
      frameguard: false,
    })
  );

  app.use(
    cors({
      origin: (origin, cb) => cb(null, origin || true),
      credentials: true,
    })
  );

  app.use(express.json({ limit: '2mb' }));

  const authLimiter = options?.disableRateLimit
    ? (_req: Request, _res: Response, next: NextFunction) => next()
    : rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: 40,
        standardHeaders: true,
        legacyHeaders: false,
        message: { error: 'Too many authentication attempts. Please try again in 15 minutes.' },
      });

  const apiLimiter = options?.disableRateLimit
    ? (_req: Request, _res: Response, next: NextFunction) => next()
    : rateLimit({
        windowMs: 60 * 1000,
        limit: 300,
        standardHeaders: true,
        legacyHeaders: false,
        message: { error: 'Rate limit exceeded. Please slow down requests.' },
      });

  app.use('/api', apiLimiter);

  const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
      fileSize: 5 * 1024 * 1024,
      files: 1,
    },
  });

  // Auth Middleware
  const requireAuth = (req: AuthRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    const cookies = parseCookies(req);
    const rawToken =
      authHeader && authHeader.startsWith('Bearer ')
        ? authHeader.slice(7).trim()
        : cookies['ninehr_session'];

    if (!rawToken) {
      return res.status(401).json({ error: 'Authentication required. Please sign in.' });
    }

    const payload = verifyToken(rawToken);
    if (!payload || payload.type !== 'session') {
      return res.status(401).json({ error: 'Session invalid or expired. Please sign in again.' });
    }

    const db = store.getSnapshot();
    const user = db.users.find((u) => u.id === payload.sub);
    if (!user) {
      return res.status(401).json({ error: 'Account no longer exists.' });
    }
    if (!user.isActive) {
      return res.status(403).json({ error: 'Your account has been deactivated by an administrator.' });
    }

    req.staffUser = {
      id: user.id,
      loginId: user.loginId,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
    };
    return next();
  };

  const requireRole = (...allowedRoles: StaffRole[]) => {
    return (req: AuthRequest, res: Response, next: NextFunction) => {
      if (!req.staffUser) {
        return res.status(401).json({ error: 'Authentication required.' });
      }
      if (!allowedRoles.includes(req.staffUser.role)) {
        return res.status(403).json({
          error: `Access denied. Required role: ${allowedRoles.join(' or ')}.`,
        });
      }
      return next();
    };
  };

  // ---------------------------------------------------------------------------
  // Health Check
  // ---------------------------------------------------------------------------
  app.get('/api/health', (_req, res) => {
    const db = store.getSnapshot();
    res.json({
      status: 'ok',
      service: '9HR India Onboarding Portal',
      smtpConfigured: isSmtpConfigured(),
      demoModeEnabled: db.config.demoModeEnabled,
    });
  });

  // ---------------------------------------------------------------------------
  // Auth Endpoints (Temp Login ID / Email + Password + 2FA + Google SSO)
  // ---------------------------------------------------------------------------
  app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
      const parsed = loginSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          error: parsed.error.issues[0]?.message || 'Invalid login credentials format.',
        });
      }

      const identifier = parsed.data.identifier.trim().toLowerCase();
      const password = parsed.data.password;

      const db = store.getSnapshot();
      const user = db.users.find(
        (u) =>
          u.loginId.toLowerCase() === identifier || u.email.toLowerCase() === identifier
      );

      if (!user) {
        await store.withTransaction((tx) => {
          appendAudit(tx, {
            actorId: 'anonymous',
            actorName: identifier,
            actorRole: 'UNKNOWN',
            action: 'LOGIN_FAILED',
            targetType: 'AUTH',
            targetId: identifier,
            details: `Failed login attempt for unknown identifier "${identifier}".`,
            ipAddress: getClientIp(req),
          });
        });
        return res.status(401).json({ error: 'Invalid Login ID / Email or Password.' });
      }

      if (!user.isActive) {
        return res.status(403).json({
          error: 'This staff account is deactivated. Contact your Super Admin.',
        });
      }

      const validPwd = await verifyPassword(password, user.passwordHash);
      if (!validPwd) {
        await store.withTransaction((tx) => {
          appendAudit(tx, {
            actorId: user.id,
            actorName: user.fullName,
            actorRole: user.role,
            action: 'LOGIN_FAILED',
            targetType: 'AUTH',
            targetId: user.loginId,
            details: `Invalid password attempt for ${user.loginId} (${user.email}).`,
            ipAddress: getClientIp(req),
          });
        });
        return res.status(401).json({ error: 'Invalid Login ID / Email or Password.' });
      }

      if (user.twoFactorEnabled && user.twoFactorSecret) {
        const challengeToken = signToken(
          {
            sub: user.id,
            loginId: user.loginId,
            email: user.email,
            fullName: user.fullName,
            role: user.role,
            type: '2fa_challenge',
          },
          300
        );
        return res.json({
          requires2FA: true,
          challengeToken,
          userHint: {
            fullName: user.fullName,
            loginId: user.loginId,
            role: user.role,
          },
        });
      }

      const sessionToken = signToken({
        sub: user.id,
        loginId: user.loginId,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        type: 'session',
      });

      const updatedUser = await store.withTransaction((tx) => {
        const target = tx.users.find((u) => u.id === user.id)!;
        target.lastLoginAt = new Date().toISOString();
        appendAudit(tx, {
          actorId: target.id,
          actorName: target.fullName,
          actorRole: target.role,
          action: 'LOGIN_SUCCESS',
          targetType: 'AUTH',
          targetId: target.loginId,
          details: `Staff user ${target.loginId} signed in via credentials.`,
          ipAddress: getClientIp(req),
        });
        return toPublicStaffUser(target);
      });

      setSessionCookie(res, sessionToken);
      return res.json({
        requires2FA: false,
        token: sessionToken,
        user: updatedUser,
      });
    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Unable to complete login right now.' });
    }
  });

  app.post('/api/auth/verify-2fa', authLimiter, async (req, res) => {
    try {
      const parsed = verify2FASchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          error: parsed.error.issues[0]?.message || 'Invalid 2FA verification payload.',
        });
      }

      const challenge = verifyToken(parsed.data.challengeToken);
      if (!challenge || challenge.type !== '2fa_challenge') {
        return res.status(401).json({ error: '2FA challenge expired. Please sign in again.' });
      }

      const db = store.getSnapshot();
      const user = db.users.find((u) => u.id === challenge.sub);
      if (!user || !user.isActive || !user.twoFactorSecret) {
        return res.status(401).json({ error: '2FA verification unavailable for this account.' });
      }

      const ok = verifyTotpCode(user.twoFactorSecret, parsed.data.code, user.email);
      if (!ok) {
        await store.withTransaction((tx) => {
          appendAudit(tx, {
            actorId: user.id,
            actorName: user.fullName,
            actorRole: user.role,
            action: '2FA_FAILED',
            targetType: 'AUTH',
            targetId: user.loginId,
            details: 'Invalid 6-digit TOTP code entered.',
            ipAddress: getClientIp(req),
          });
        });
        return res.status(401).json({ error: 'Invalid 6-digit 2FA verification code.' });
      }

      const sessionToken = signToken({
        sub: user.id,
        loginId: user.loginId,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        type: 'session',
      });

      const updatedUser = await store.withTransaction((tx) => {
        const target = tx.users.find((u) => u.id === user.id)!;
        target.lastLoginAt = new Date().toISOString();
        appendAudit(tx, {
          actorId: target.id,
          actorName: target.fullName,
          actorRole: target.role,
          action: 'LOGIN_2FA_SUCCESS',
          targetType: 'AUTH',
          targetId: target.loginId,
          details: `Staff user ${target.loginId} completed 2FA verification.`,
          ipAddress: getClientIp(req),
        });
        return toPublicStaffUser(target);
      });

      setSessionCookie(res, sessionToken);
      return res.json({ token: sessionToken, user: updatedUser });
    } catch (err) {
      console.error('2FA verify error:', err);
      return res.status(500).json({ error: '2FA verification failed.' });
    }
  });

  // Google Sign-In bridge (verifies Firebase ID token via Google tokeninfo)
  app.post('/api/auth/google', authLimiter, async (req, res) => {
    try {
      const idToken = typeof req.body?.idToken === 'string' ? req.body.idToken.trim() : '';
      if (!idToken) {
        return res.status(400).json({ error: 'Missing Google ID token.' });
      }

      const verifyResp = await fetch(
        `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`
      );
      if (!verifyResp.ok) {
        return res.status(401).json({ error: 'Invalid or expired Google Sign-In token.' });
      }

      const info = (await verifyResp.json()) as {
        aud?: string;
        email?: string;
        email_verified?: string | boolean;
        name?: string;
        sub?: string;
      };

      const validAud =
        info.aud === firebaseConfig.projectId || info.aud === firebaseConfig.oAuthClientId;
      if (!validAud || !info.email || (info.email_verified !== 'true' && info.email_verified !== true)) {
        return res.status(401).json({ error: 'Google account verification failed.' });
      }

      const emailLower = info.email.toLowerCase();
      const db = store.getSnapshot();
      const existing = db.users.find((u) => u.email.toLowerCase() === emailLower);

      if (!existing && emailLower !== 'itsdemoid00@gmail.com') {
        return res.status(403).json({
          error:
            'Your Google email is not registered as an authorized 9HR staff member. Ask your Super Admin to invite your account.',
        });
      }

      if (existing && !existing.isActive) {
        return res.status(403).json({ error: 'This staff account has been deactivated.' });
      }

      const userRecord = await store.withTransaction((tx) => {
        let user = tx.users.find((u) => u.email.toLowerCase() === emailLower);
        if (!user) {
          tx.counters.staffSeq += 1;
          user = {
            id: `usr-${crypto.randomBytes(6).toString('hex')}`,
            loginId: `9HR-SA-${String(tx.counters.staffSeq).padStart(3, '0')}`,
            email: emailLower,
            fullName: sanitizeText(info.name || '9HR Super Admin'),
            role: 'SUPER_ADMIN',
            department: 'Executive Management',
            isActive: true,
            twoFactorEnabled: false,
            isDemo: false,
            passwordHash: hashPasswordSync(generateTempPassword()),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            lastLoginAt: new Date().toISOString(),
          };
          tx.users.push(user);
        } else {
          user.lastLoginAt = new Date().toISOString();
          if (info.name && user.fullName === '9HR Portal Owner') {
            user.fullName = sanitizeText(info.name);
          }
        }
        appendAudit(tx, {
          actorId: user.id,
          actorName: user.fullName,
          actorRole: user.role,
          action: 'LOGIN_GOOGLE_SSO',
          targetType: 'AUTH',
          targetId: user.loginId,
          details: `Signed in via Google SSO (${user.email}).`,
          ipAddress: getClientIp(req),
        });
        return toPublicStaffUser(user);
      });

      const sessionToken = signToken({
        sub: userRecord.id,
        loginId: userRecord.loginId,
        email: userRecord.email,
        fullName: userRecord.fullName,
        role: userRecord.role,
        type: 'session',
      });

      setSessionCookie(res, sessionToken);
      return res.json({ token: sessionToken, user: userRecord });
    } catch (err) {
      console.error('Google auth error:', err);
      return res.status(500).json({ error: 'Google authentication failed.' });
    }
  });

  app.post('/api/auth/logout', (req: AuthRequest, res) => {
    clearSessionCookie(res);
    res.json({ success: true });
  });

  app.get('/api/auth/me', requireAuth, (req: AuthRequest, res) => {
    const db = store.getSnapshot();
    const user = db.users.find((u) => u.id === req.staffUser!.id);
    if (!user) {
      return res.status(401).json({ error: 'User not found.' });
    }
    return res.json({ user: toPublicStaffUser(user) });
  });

  app.post('/api/auth/password-reset/request', authLimiter, async (req, res) => {
    try {
      const identifier = sanitizeText(req.body?.identifier).toLowerCase();
      if (!identifier) {
        return res.status(400).json({ error: 'Enter your Login ID or Email address.' });
      }
      const db = store.getSnapshot();
      const user = db.users.find(
        (u) => u.loginId.toLowerCase() === identifier || u.email.toLowerCase() === identifier
      );

      if (!user) {
        return res.json({
          message: 'If a matching staff account exists, a password reset instruction has been generated.',
          smtpConfigured: isSmtpConfigured(),
        });
      }

      const rawResetToken = crypto.randomBytes(24).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(rawResetToken).digest('hex');
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

      await store.withTransaction((tx) => {
        const target = tx.users.find((u) => u.id === user.id)!;
        target.resetTokenHash = tokenHash;
        target.resetTokenExpiresAt = expiresAt;
        appendAudit(tx, {
          actorId: target.id,
          actorName: target.fullName,
          actorRole: target.role,
          action: 'PASSWORD_RESET_REQUESTED',
          targetType: 'AUTH',
          targetId: target.loginId,
          details: `Password reset token issued for ${target.loginId}.`,
          ipAddress: getClientIp(req),
        });
      });

      const emailResult = await dispatchNotificationEmail({
        to: user.email,
        subject: '9HR India Portal — Password Reset Token',
        body: `Your temporary reset token is: ${rawResetToken}`,
      });

      return res.json({
        message:
          emailResult.deliveryStatus === 'SENT_SMTP'
            ? 'Password reset instructions sent to your email.'
            : 'SMTP is not configured. Use the temporary reset code below within 15 minutes.',
        smtpConfigured: isSmtpConfigured(),
        deliveryStatus: emailResult.deliveryStatus,
        demoResetToken: db.config.demoModeEnabled && !isSmtpConfigured() ? rawResetToken : undefined,
      });
    } catch (err) {
      console.error('Reset request error:', err);
      return res.status(500).json({ error: 'Failed to process password reset request.' });
    }
  });

  app.post('/api/auth/password-reset/confirm', authLimiter, async (req, res) => {
    try {
      const token = typeof req.body?.token === 'string' ? req.body.token.trim() : '';
      const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';

      if (!token || newPassword.length < 8) {
        return res.status(400).json({
          error: 'Valid reset token and a new password (min 8 characters) are required.',
        });
      }

      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const db = store.getSnapshot();
      const user = db.users.find(
        (u) =>
          u.resetTokenHash === tokenHash &&
          u.resetTokenExpiresAt &&
          new Date(u.resetTokenExpiresAt).getTime() > Date.now()
      );

      if (!user) {
        return res.status(400).json({ error: 'Reset token is invalid or has expired.' });
      }

      const newHash = await hashPassword(newPassword);
      await store.withTransaction((tx) => {
        const target = tx.users.find((u) => u.id === user.id)!;
        target.passwordHash = newHash;
        target.mustChangePassword = false;
        target.resetTokenHash = undefined;
        target.resetTokenExpiresAt = undefined;
        target.updatedAt = new Date().toISOString();
        appendAudit(tx, {
          actorId: target.id,
          actorName: target.fullName,
          actorRole: target.role,
          action: 'PASSWORD_RESET_COMPLETED',
          targetType: 'AUTH',
          targetId: target.loginId,
          details: `Password updated via reset token for ${target.loginId}.`,
          ipAddress: getClientIp(req),
        });
      });

      return res.json({ success: true, message: 'Password updated successfully. You may now sign in.' });
    } catch (err) {
      console.error('Reset confirm error:', err);
      return res.status(500).json({ error: 'Unable to reset password.' });
    }
  });

  app.post('/api/auth/change-password', requireAuth, async (req: AuthRequest, res) => {
    try {
      const currentPassword = typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : '';
      const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';
      if (!currentPassword || newPassword.length < 8) {
        return res.status(400).json({
          error: 'Current password and a new password (at least 8 characters) are required.',
        });
      }

      const db = store.getSnapshot();
      const user = db.users.find((u) => u.id === req.staffUser!.id);
      if (!user) return res.status(404).json({ error: 'Account not found.' });

      const valid = await verifyPassword(currentPassword, user.passwordHash);
      if (!valid) {
        return res.status(400).json({ error: 'Current password is incorrect.' });
      }

      const newHash = await hashPassword(newPassword);
      await store.withTransaction((tx) => {
        const target = tx.users.find((u) => u.id === user.id)!;
        target.passwordHash = newHash;
        target.mustChangePassword = false;
        target.updatedAt = new Date().toISOString();
        appendAudit(tx, {
          actorId: target.id,
          actorName: target.fullName,
          actorRole: target.role,
          action: 'PASSWORD_CHANGED',
          targetType: 'AUTH',
          targetId: target.loginId,
          details: 'User changed their account password.',
          ipAddress: getClientIp(req),
        });
      });

      return res.json({ success: true });
    } catch (err) {
      console.error('Change password error:', err);
      return res.status(500).json({ error: 'Failed to change password.' });
    }
  });

  // 2FA Setup / Enable / Disable
  app.post('/api/auth/2fa/setup', requireAuth, async (req: AuthRequest, res) => {
    try {
      const db = store.getSnapshot();
      const user = db.users.find((u) => u.id === req.staffUser!.id);
      if (!user) return res.status(404).json({ error: 'User not found.' });

      const secret = createTotpSecret(user.email);
      await store.withTransaction((tx) => {
        const target = tx.users.find((u) => u.id === user.id)!;
        target.twoFactorSecret = secret.base32;
        target.updatedAt = new Date().toISOString();
      });

      return res.json({
        secret: secret.base32,
        otpauthUrl: secret.otpauthUrl,
      });
    } catch (err) {
      console.error('2FA setup error:', err);
      return res.status(500).json({ error: 'Failed to generate 2FA secret.' });
    }
  });

  app.post('/api/auth/2fa/enable', requireAuth, async (req: AuthRequest, res) => {
    try {
      const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
      if (!/^\d{6}$/.test(code)) {
        return res.status(400).json({ error: 'Enter a valid 6-digit authenticator code.' });
      }

      const db = store.getSnapshot();
      const user = db.users.find((u) => u.id === req.staffUser!.id);
      if (!user || !user.twoFactorSecret) {
        return res.status(400).json({ error: 'Initialize 2FA setup before enabling.' });
      }

      if (!verifyTotpCode(user.twoFactorSecret, code, user.email)) {
        return res.status(400).json({ error: 'Invalid 6-digit verification code. Check your device clock.' });
      }

      const updated = await store.withTransaction((tx) => {
        const target = tx.users.find((u) => u.id === user.id)!;
        target.twoFactorEnabled = true;
        target.updatedAt = new Date().toISOString();
        appendAudit(tx, {
          actorId: target.id,
          actorName: target.fullName,
          actorRole: target.role,
          action: '2FA_ENABLED',
          targetType: 'AUTH',
          targetId: target.loginId,
          details: 'Two-factor authentication enabled.',
          ipAddress: getClientIp(req),
        });
        return toPublicStaffUser(target);
      });

      return res.json({ user: updated });
    } catch (err) {
      console.error('2FA enable error:', err);
      return res.status(500).json({ error: 'Failed to enable 2FA.' });
    }
  });

  app.post('/api/auth/2fa/disable', requireAuth, async (req: AuthRequest, res) => {
    try {
      const updated = await store.withTransaction((tx) => {
        const target = tx.users.find((u) => u.id === req.staffUser!.id)!;
        target.twoFactorEnabled = false;
        target.twoFactorSecret = undefined;
        target.updatedAt = new Date().toISOString();
        appendAudit(tx, {
          actorId: target.id,
          actorName: target.fullName,
          actorRole: target.role,
          action: '2FA_DISABLED',
          targetType: 'AUTH',
          targetId: target.loginId,
          details: 'Two-factor authentication disabled.',
          ipAddress: getClientIp(req),
        });
        return toPublicStaffUser(target);
      });
      return res.json({ user: updated });
    } catch (err) {
      console.error('2FA disable error:', err);
      return res.status(500).json({ error: 'Failed to disable 2FA.' });
    }
  });

  // ---------------------------------------------------------------------------
  // Dashboard Analytics
  // ---------------------------------------------------------------------------
  app.get('/api/analytics', requireAuth, (req: AuthRequest, res) => {
    const scope = (req.query.scope as string) || 'all';
    const db = store.getSnapshot();

    const scopedCandidates = db.candidates.filter((c) => {
      if (scope === 'live') return !c.isDemo;
      if (scope === 'demo') return c.isDemo;
      return true;
    });

    const scopedIds = new Set(scopedCandidates.map((c) => c.id));
    const scopedDocs = db.documents.filter((d) => scopedIds.has(d.candidateId));

    const kpis = {
      totalCandidates: scopedCandidates.length,
      newApplications: scopedCandidates.filter((c) =>
        ['Draft', 'Link Sent'].includes(c.status)
      ).length,
      pendingOnboarding: scopedCandidates.filter((c) =>
        ['In Progress', 'Submitted', 'Under Review', 'Correction Required'].includes(c.status)
      ).length,
      documentsPending: scopedDocs.filter((d) => d.verificationStatus === 'Pending').length,
      documentsVerified: scopedDocs.filter((d) => d.verificationStatus === 'Approved').length,
      onboardingCompleted: scopedCandidates.filter(
        (c) => c.status === 'Onboarding Completed'
      ).length,
      rejectedApplications: scopedCandidates.filter((c) => c.status === 'Rejected').length,
    };

    // Monthly Onboarding Statistics (Last 6 months)
    const monthBuckets = new Map<string, { registered: number; completed: number }>();
    const now = new Date();
    for (let i = 5; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const label = d.toLocaleDateString('en-US', { month: 'short', year: '2-digit' });
      monthBuckets.set(label, { registered: 0, completed: 0 });
    }
    for (const c of scopedCandidates) {
      const d = new Date(c.createdAt);
      const label = d.toLocaleDateString('en-US', { month: 'short', year: '2-digit' });
      if (monthBuckets.has(label)) {
        const entry = monthBuckets.get(label)!;
        entry.registered += 1;
        if (c.status === 'Onboarding Completed' || c.status === 'Approved') {
          entry.completed += 1;
        }
      }
    }
    const monthlyStats = Array.from(monthBuckets.entries()).map(([month, v]) => ({
      month,
      ...v,
    }));

    // Department-wise Candidates
    const deptMap = new Map<string, { count: number; completed: number }>();
    for (const dept of db.config.departments) {
      deptMap.set(dept, { count: 0, completed: 0 });
    }
    for (const c of scopedCandidates) {
      const existing = deptMap.get(c.department) || { count: 0, completed: 0 };
      existing.count += 1;
      if (c.status === 'Onboarding Completed' || c.status === 'Approved') {
        existing.completed += 1;
      }
      deptMap.set(c.department, existing);
    }
    const departmentStats = Array.from(deptMap.entries())
      .map(([department, v]) => ({ department, ...v }))
      .filter((d) => d.count > 0);

    // Application Status Distribution
    const statusMap = new Map<string, number>();
    for (const s of ONBOARDING_STATUSES) {
      statusMap.set(s, 0);
    }
    for (const c of scopedCandidates) {
      statusMap.set(c.status, (statusMap.get(c.status) || 0) + 1);
    }
    const statusDistribution = Array.from(statusMap.entries())
      .map(([status, count]) => ({ status, count }))
      .filter((s) => s.count > 0);

    // Recruitment Conversion Funnel
    const total = Math.max(1, scopedCandidates.length);
    const linkSentOrBeyond = scopedCandidates.filter((c) => c.status !== 'Draft').length;
    const submittedOrBeyond = scopedCandidates.filter((c) =>
      [
        'Submitted',
        'Under Review',
        'Documents Pending',
        'Correction Required',
        'Approved',
        'Onboarding Completed',
      ].includes(c.status)
    ).length;
    const approvedOrDone = scopedCandidates.filter((c) =>
      ['Approved', 'Onboarding Completed'].includes(c.status)
    ).length;
    const completed = kpis.onboardingCompleted;

    const conversionFunnel = [
      { stage: 'Registered', count: scopedCandidates.length, rate: scopedCandidates.length ? 100 : 0 },
      { stage: 'Link Activated', count: linkSentOrBeyond, rate: Math.round((linkSentOrBeyond / total) * 100) },
      { stage: 'Submitted', count: submittedOrBeyond, rate: Math.round((submittedOrBeyond / total) * 100) },
      { stage: 'Approved', count: approvedOrDone, rate: Math.round((approvedOrDone / total) * 100) },
      { stage: 'Employee Created', count: completed, rate: Math.round((completed / total) * 100) },
    ];

    const summary: AnalyticsSummary = {
      kpis,
      monthlyStats,
      departmentStats,
      statusDistribution,
      conversionFunnel,
    };

    res.json(summary);
  });

  // ---------------------------------------------------------------------------
  // Staff / Team Management (Super Admin & Admin)
  // ---------------------------------------------------------------------------
  app.get('/api/staff/recruiters', requireAuth, (_req, res) => {
    const db = store.getSnapshot();
    const recruiters = db.users
      .filter((u) => u.isActive)
      .map(toPublicStaffUser);
    res.json({ recruiters });
  });

  app.get('/api/staff', requireAuth, requireRole('SUPER_ADMIN', 'ADMIN'), (_req, res) => {
    const db = store.getSnapshot();
    res.json({ users: db.users.map(toPublicStaffUser) });
  });

  app.post('/api/staff', requireAuth, requireRole('SUPER_ADMIN', 'ADMIN'), async (req: AuthRequest, res) => {
    try {
      const sanitized = sanitizeRecordStrings(req.body);
      const parsed = createStaffSchema.safeParse({
        ...sanitized,
        password: req.body?.password, // do not strip characters from password
      });
      if (!parsed.success) {
        return res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid staff payload.' });
      }

      const data = parsed.data;

      // Only SUPER_ADMIN can create ADMIN or SUPER_ADMIN accounts
      if (data.role !== 'HR' && req.staffUser!.role !== 'SUPER_ADMIN') {
        return res.status(403).json({
          error: 'Only Super Admin can create Admin or Super Admin accounts.',
        });
      }

      const db = store.getSnapshot();
      const emailLower = data.email.toLowerCase();
      if (db.users.some((u) => u.email.toLowerCase() === emailLower)) {
        return res.status(409).json({ error: 'A staff account with this email already exists.' });
      }

      const tempPassword = data.password || generateTempPassword();
      const passwordHash = await hashPassword(tempPassword);

      const created = await store.withTransaction((tx) => {
        tx.counters.staffSeq += 1;
        const prefix = data.role === 'SUPER_ADMIN' ? 'SA' : data.role === 'ADMIN' ? 'ADM' : 'HR';
        const loginId = (data.loginId || `9HR-${prefix}-${String(tx.counters.staffSeq).padStart(3, '0')}`).toUpperCase();

        if (tx.users.some((u) => u.loginId.toLowerCase() === loginId.toLowerCase())) {
          throw new Error('DUPLICATE_LOGIN_ID');
        }

        const newUser = {
          id: `usr-${crypto.randomBytes(6).toString('hex')}`,
          loginId,
          email: emailLower,
          fullName: data.fullName,
          role: data.role,
          department: data.department,
          isActive: true,
          twoFactorEnabled: false,
          mustChangePassword: true,
          isDemo: false,
          passwordHash,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        tx.users.push(newUser);

        appendAudit(tx, {
          actorId: req.staffUser!.id,
          actorName: req.staffUser!.fullName,
          actorRole: req.staffUser!.role,
          action: 'STAFF_CREATED',
          targetType: 'STAFF',
          targetId: newUser.loginId,
          details: `Created ${newUser.role} account ${newUser.loginId} (${newUser.email}).`,
          ipAddress: getClientIp(req),
        });

        return toPublicStaffUser(newUser);
      });

      return res.status(201).json({
        user: created,
        temporaryCredentials: {
          loginId: created.loginId,
          email: created.email,
          temporaryPassword: tempPassword,
        },
      });
    } catch (err: unknown) {
      if (err instanceof Error && err.message === 'DUPLICATE_LOGIN_ID') {
        return res.status(409).json({ error: 'This Login ID is already taken.' });
      }
      console.error('Create staff error:', err);
      return res.status(500).json({ error: 'Failed to create staff member.' });
    }
  });

  app.patch('/api/staff/:id', requireAuth, requireRole('SUPER_ADMIN', 'ADMIN'), async (req: AuthRequest, res) => {
    try {
      const targetId = req.params.id;
      const db = store.getSnapshot();
      const target = db.users.find((u) => u.id === targetId);
      if (!target) return res.status(404).json({ error: 'Staff user not found.' });

      if (target.role !== 'HR' && req.staffUser!.role !== 'SUPER_ADMIN') {
        return res.status(403).json({ error: 'Only Super Admin can modify Admin or Super Admin accounts.' });
      }
      if (target.id === req.staffUser!.id && req.body?.isActive === false) {
        return res.status(400).json({ error: 'You cannot deactivate your own active session account.' });
      }

      let resetTempPassword: string | undefined;
      let nextHash: string | undefined;
      if (req.body?.resetPassword === true) {
        resetTempPassword = generateTempPassword();
        nextHash = await hashPassword(resetTempPassword);
      }

      const updated = await store.withTransaction((tx) => {
        const u = tx.users.find((item) => item.id === targetId)!;
        if (typeof req.body?.isActive === 'boolean') u.isActive = req.body.isActive;
        if (typeof req.body?.department === 'string' && req.body.department.trim()) {
          u.department = sanitizeText(req.body.department);
        }
        if (typeof req.body?.fullName === 'string' && req.body.fullName.trim()) {
          u.fullName = sanitizeText(req.body.fullName);
        }
        if (
          req.staffUser!.role === 'SUPER_ADMIN' &&
          ['SUPER_ADMIN', 'ADMIN', 'HR'].includes(req.body?.role)
        ) {
          u.role = req.body.role;
        }
        if (req.body?.reset2FA === true) {
          u.twoFactorEnabled = false;
          u.twoFactorSecret = undefined;
        }
        if (nextHash) {
          u.passwordHash = nextHash;
          u.mustChangePassword = true;
        }
        u.updatedAt = new Date().toISOString();

        appendAudit(tx, {
          actorId: req.staffUser!.id,
          actorName: req.staffUser!.fullName,
          actorRole: req.staffUser!.role,
          action: 'STAFF_UPDATED',
          targetType: 'STAFF',
          targetId: u.loginId,
          details: `Updated staff account ${u.loginId} (active=${u.isActive}, role=${u.role}${resetTempPassword ? ', password reset' : ''}).`,
          ipAddress: getClientIp(req),
        });
        return toPublicStaffUser(u);
      });

      return res.json({
        user: updated,
        temporaryPassword: resetTempPassword,
      });
    } catch (err) {
      console.error('Update staff error:', err);
      return res.status(500).json({ error: 'Failed to update staff account.' });
    }
  });

  // ---------------------------------------------------------------------------
  // Candidate Management (HR / Admin / Super Admin)
  // ---------------------------------------------------------------------------
  app.get('/api/candidates/export/csv', requireAuth, (req: AuthRequest, res) => {
    const db = store.getSnapshot();
    const search = ((req.query.search as string) || '').trim().toLowerCase();
    const status = (req.query.status as string) || 'ALL';
    const department = (req.query.department as string) || 'ALL';
    const scope = (req.query.scope as string) || 'all';

    const filtered = db.candidates.filter((c) => {
      if (scope === 'live' && c.isDemo) return false;
      if (scope === 'demo' && !c.isDemo) return false;
      if (status !== 'ALL' && c.status !== status) return false;
      if (department !== 'ALL' && c.department !== department) return false;
      if (search) {
        const hay = `${c.candidateCode} ${c.fullName} ${c.email} ${c.position} ${c.department}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    const headers = [
      'Candidate ID',
      'Candidate Name',
      'Email',
      'Mobile',
      'Position',
      'Department',
      'Recruiter',
      'Application Date',
      'Joining Date',
      'Completion %',
      'Status',
      'Record Type',
      'Employee ID',
    ];

    const rows = filtered.map((c) =>
      [
        c.candidateCode,
        c.fullName,
        c.email,
        c.mobile,
        c.position,
        c.department,
        c.assignedRecruiterName,
        c.createdAt.slice(0, 10),
        c.joiningDate,
        `${c.completionPct}%`,
        c.status,
        c.isDemo ? 'Demo' : 'Live',
        c.employeeCode || '',
      ]
        .map(escapeCsvCell)
        .join(',')
    );

    const csv = [headers.map(escapeCsvCell).join(','), ...rows].join('\r\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="9hr-candidates-export.csv"');
    res.send(csv);
  });

  app.get('/api/candidates', requireAuth, (req: AuthRequest, res) => {
    const db = store.getSnapshot();
    const search = ((req.query.search as string) || '').trim().toLowerCase();
    const status = (req.query.status as string) || 'ALL';
    const department = (req.query.department as string) || 'ALL';
    const recruiterId = (req.query.recruiterId as string) || 'ALL';
    const scope = (req.query.scope as string) || 'all';
    const sortBy = (req.query.sortBy as string) || 'createdAt';
    const sortDir = ((req.query.sortDir as string) || 'desc') === 'asc' ? 1 : -1;
    const page = Math.max(1, Number(req.query.page || 1));
    const pageSize = Math.min(100, Math.max(1, Number(req.query.pageSize || 10)));

    let list = db.candidates.filter((c) => {
      if (scope === 'live' && c.isDemo) return false;
      if (scope === 'demo' && !c.isDemo) return false;
      if (status !== 'ALL' && c.status !== status) return false;
      if (department !== 'ALL' && c.department !== department) return false;
      if (recruiterId !== 'ALL' && c.assignedRecruiterId !== recruiterId) return false;
      if (search) {
        const hay = `${c.candidateCode} ${c.fullName} ${c.email} ${c.position} ${c.department} ${c.assignedRecruiterName}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    list = [...list].sort((a, b) => {
      if (sortBy === 'fullName') return a.fullName.localeCompare(b.fullName) * sortDir;
      if (sortBy === 'joiningDate') return a.joiningDate.localeCompare(b.joiningDate) * sortDir;
      if (sortBy === 'completionPct') return (a.completionPct - b.completionPct) * sortDir;
      if (sortBy === 'status') return a.status.localeCompare(b.status) * sortDir;
      return a.createdAt.localeCompare(b.createdAt) * sortDir;
    });

    const total = list.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const safePage = Math.min(page, totalPages);
    const items = list.slice((safePage - 1) * pageSize, safePage * pageSize).map((c) => {
      const activeToken = db.tokens.find(
        (t) =>
          t.candidateId === c.id &&
          !t.isRevoked &&
          new Date(t.expiresAt).getTime() > Date.now()
      );
      const docs = db.documents.filter((d) => d.candidateId === c.id);
      return {
        ...c,
        hasActiveLink: Boolean(activeToken),
        activeToken: activeToken?.token,
        documentCount: docs.length,
        verifiedDocCount: docs.filter((d) => d.verificationStatus === 'Approved').length,
      };
    });

    res.json({
      items,
      total,
      page: safePage,
      pageSize,
      totalPages,
    });
  });

  app.post('/api/candidates', requireAuth, async (req: AuthRequest, res) => {
    try {
      const sanitized = sanitizeRecordStrings(req.body);
      const parsed = createCandidateSchema.safeParse(sanitized);
      if (!parsed.success) {
        return res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid candidate data.' });
      }

      const data = parsed.data;
      const db = store.getSnapshot();
      const recruiter = db.users.find((u) => u.id === data.assignedRecruiterId);
      if (!recruiter) {
        return res.status(400).json({ error: 'Selected recruiter does not exist.' });
      }

      const emailLower = data.email.toLowerCase();
      if (db.candidates.some((c) => c.email.toLowerCase() === emailLower && c.status !== 'Rejected')) {
        return res.status(409).json({
          error: 'An active onboarding application already exists for this email address.',
        });
      }

      const result = await store.withTransaction(async (tx) => {
        tx.counters.candidateSeq += 1;
        const nowIso = new Date().toISOString();
        const candId = `cand-${crypto.randomBytes(6).toString('hex')}`;
        const candidateCode = `9HR-CND-${tx.counters.candidateSeq}`;

        const candidate: Candidate = {
          id: candId,
          candidateCode,
          fullName: data.fullName,
          email: emailLower,
          mobile: data.mobile,
          position: data.position,
          department: data.department,
          joiningDate: data.joiningDate,
          assignedRecruiterId: recruiter.id,
          assignedRecruiterName: recruiter.fullName,
          status: 'Link Sent',
          completionPct: 0,
          isDemo: Boolean(data.isDemo),
          createdAt: nowIso,
          updatedAt: nowIso,
          personalInfo: {
            fullName: data.fullName,
            dateOfBirth: '',
            gender: '',
            mobileNumber: data.mobile,
            email: emailLower,
            maritalStatus: '',
          },
          addressInfo: {
            currentAddress: '',
            permanentAddress: '',
            sameAsCurrent: false,
            city: '',
            state: '',
            pinCode: '',
          },
          familyInfo: {
            fatherName: '',
            motherName: '',
            spouseName: '',
            emergencyContactName: '',
            emergencyContactRelation: '',
            emergencyContactPhone: '',
          },
          educationInfo: {
            highestQualification: '',
            collegeUniversity: '',
            passingYear: '',
            percentageOrCgpa: '',
          },
          employmentInfo: {
            isFresher: false,
            previousCompany: '',
            previousDesignation: '',
            previousExperience: '',
            lastWorkingDate: '',
            previousSalary: '',
          },
          bankDetails: {
            accountHolderName: '',
            bankName: '',
            accountNumber: '',
            ifscCode: '',
          },
          declaration: {
            accepted: false,
            digitalSignature: '',
          },
        };

        const tokenStr = generateSecureOnboardingToken();
        const expiryHours = tx.config.defaultLinkExpiryHours || 72;
        const tokenRecord = {
          id: `tok-${crypto.randomBytes(6).toString('hex')}`,
          candidateId: candId,
          token: tokenStr,
          expiresAt: new Date(Date.now() + expiryHours * 3600 * 1000).toISOString(),
          isRevoked: false,
          createdAt: nowIso,
          createdByName: req.staffUser!.fullName,
        };

        tx.candidates.unshift(candidate);
        tx.tokens.unshift(tokenRecord);

        tx.statusHistory.unshift({
          id: `sh-${crypto.randomBytes(6).toString('hex')}`,
          candidateId: candId,
          fromStatus: null,
          toStatus: 'Link Sent',
          changedById: req.staffUser!.id,
          changedByName: req.staffUser!.fullName,
          changedByRole: req.staffUser!.role,
          note: `Candidate profile registered and onboarding link generated (expires in ${expiryHours}h).`,
          timestamp: nowIso,
        });

        const onboardingUrl = `/onboard/${tokenStr}`;
        const emailDispatch = await dispatchNotificationEmail({
          to: candidate.email,
          subject: `Welcome to 9HR India Pvt. Ltd. — Complete Your Onboarding`,
          body: `Hello ${candidate.fullName}, please complete your onboarding at ${onboardingUrl}`,
        });

        tx.notifications.unshift({
          id: `notif-${crypto.randomBytes(6).toString('hex')}`,
          type: 'ONBOARDING_INVITATION',
          title: `Onboarding Link Generated: ${candidate.fullName}`,
          message: `Unique onboarding link created for ${candidate.fullName} (${candidate.position}).`,
          recipientEmail: candidate.email,
          recipientName: candidate.fullName,
          candidateId: candidate.id,
          candidateCode: candidate.candidateCode,
          onboardingUrl,
          deliveryStatus: emailDispatch.deliveryStatus,
          deliveryNote: emailDispatch.deliveryNote,
          isRead: false,
          createdAt: nowIso,
        });

        appendAudit(tx, {
          actorId: req.staffUser!.id,
          actorName: req.staffUser!.fullName,
          actorRole: req.staffUser!.role,
          action: 'CANDIDATE_REGISTERED',
          targetType: 'CANDIDATE',
          targetId: candidate.candidateCode,
          details: `Registered candidate ${candidate.fullName} (${candidate.position}) and generated onboarding token.`,
          ipAddress: getClientIp(req),
        });

        return { candidate, token: tokenRecord, onboardingUrl, emailDispatch };
      });

      return res.status(201).json(result);
    } catch (err) {
      console.error('Create candidate error:', err);
      return res.status(500).json({ error: 'Failed to register candidate.' });
    }
  });

  app.get('/api/candidates/:id', requireAuth, (req: AuthRequest, res) => {
    const db = store.getSnapshot();
    const candidate = db.candidates.find((c) => c.id === req.params.id);
    if (!candidate) {
      return res.status(404).json({ error: 'Candidate record not found.' });
    }

    const tokens = db.tokens
      .filter((t) => t.candidateId === candidate.id)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    const documents = db.documents
      .filter((d) => d.candidateId === candidate.id)
      .sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));
    const statusHistory = db.statusHistory
      .filter((h) => h.candidateId === candidate.id)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    const employee = candidate.employeeId
      ? db.employees.find((e) => e.id === candidate.employeeId) || null
      : null;

    return res.json({
      candidate,
      tokens,
      documents,
      statusHistory,
      employee,
    });
  });

  app.patch('/api/candidates/:id', requireAuth, async (req: AuthRequest, res) => {
    try {
      const candidateId = req.params.id;
      const sanitized = sanitizeRecordStrings(req.body);
      const db = store.getSnapshot();
      const existing = db.candidates.find((c) => c.id === candidateId);
      if (!existing) return res.status(404).json({ error: 'Candidate not found.' });

      if (
        typeof sanitized.assignedRecruiterId === 'string' &&
        sanitized.assignedRecruiterId !== existing.assignedRecruiterId &&
        !['ADMIN', 'SUPER_ADMIN'].includes(req.staffUser!.role)
      ) {
        return res.status(403).json({
          error: 'Only Admin or Super Admin can reassign candidates to another recruiter.',
        });
      }

      const updated = await store.withTransaction((tx) => {
        const cand = tx.candidates.find((c) => c.id === candidateId)!;
        if (typeof sanitized.fullName === 'string' && sanitized.fullName.length >= 2) {
          cand.fullName = sanitized.fullName;
          cand.personalInfo.fullName = sanitized.fullName;
        }
        if (typeof sanitized.position === 'string' && sanitized.position.length >= 2) {
          cand.position = sanitized.position;
        }
        if (typeof sanitized.department === 'string' && sanitized.department.length >= 2) {
          cand.department = sanitized.department;
        }
        if (typeof sanitized.joiningDate === 'string' && sanitized.joiningDate.length >= 4) {
          cand.joiningDate = sanitized.joiningDate;
        }
        if (typeof sanitized.assignedRecruiterId === 'string') {
          const rec = tx.users.find((u) => u.id === sanitized.assignedRecruiterId);
          if (rec) {
            cand.assignedRecruiterId = rec.id;
            cand.assignedRecruiterName = rec.fullName;
          }
        }
        cand.updatedAt = new Date().toISOString();

        appendAudit(tx, {
          actorId: req.staffUser!.id,
          actorName: req.staffUser!.fullName,
          actorRole: req.staffUser!.role,
          action: 'CANDIDATE_UPDATED',
          targetType: 'CANDIDATE',
          targetId: cand.candidateCode,
          details: `Updated candidate profile metadata for ${cand.fullName}.`,
          ipAddress: getClientIp(req),
        });
        return cand;
      });

      return res.json({ candidate: updated });
    } catch (err) {
      console.error('Update candidate error:', err);
      return res.status(500).json({ error: 'Failed to update candidate.' });
    }
  });

  // Generate / Regenerate Onboarding Link
  app.post('/api/candidates/:id/token', requireAuth, async (req: AuthRequest, res) => {
    try {
      const candidateId = req.params.id;
      const db = store.getSnapshot();
      const existing = db.candidates.find((c) => c.id === candidateId);
      if (!existing) return res.status(404).json({ error: 'Candidate not found.' });

      const expiryHours = Math.min(
        720,
        Math.max(1, Number(req.body?.expiryHours || db.config.defaultLinkExpiryHours || 72))
      );

      const result = await store.withTransaction(async (tx) => {
        const cand = tx.candidates.find((c) => c.id === candidateId)!;
        const nowIso = new Date().toISOString();

        // Revoke previous active tokens so only the latest link works
        for (const t of tx.tokens) {
          if (t.candidateId === candidateId && !t.isRevoked) {
            t.isRevoked = true;
          }
        }

        const tokenStr = generateSecureOnboardingToken();
        const newToken = {
          id: `tok-${crypto.randomBytes(6).toString('hex')}`,
          candidateId,
          token: tokenStr,
          expiresAt: new Date(Date.now() + expiryHours * 3600 * 1000).toISOString(),
          isRevoked: false,
          createdAt: nowIso,
          createdByName: req.staffUser!.fullName,
        };
        tx.tokens.unshift(newToken);

        if (cand.status === 'Draft') {
          const prev = cand.status;
          cand.status = 'Link Sent';
          cand.updatedAt = nowIso;
          tx.statusHistory.unshift({
            id: `sh-${crypto.randomBytes(6).toString('hex')}`,
            candidateId,
            fromStatus: prev,
            toStatus: 'Link Sent',
            changedById: req.staffUser!.id,
            changedByName: req.staffUser!.fullName,
            changedByRole: req.staffUser!.role,
            note: 'Generated new onboarding link.',
            timestamp: nowIso,
          });
        }

        const onboardingUrl = `/onboard/${tokenStr}`;
        const emailDispatch = await dispatchNotificationEmail({
          to: cand.email,
          subject: `9HR India Onboarding Link`,
          body: `Complete your onboarding here: ${onboardingUrl}`,
        });

        tx.notifications.unshift({
          id: `notif-${crypto.randomBytes(6).toString('hex')}`,
          type: 'ONBOARDING_INVITATION',
          title: `Onboarding Link Regenerated: ${cand.fullName}`,
          message: `New onboarding link generated (valid ${expiryHours}h) for ${cand.fullName}.`,
          recipientEmail: cand.email,
          recipientName: cand.fullName,
          candidateId: cand.id,
          candidateCode: cand.candidateCode,
          onboardingUrl,
          deliveryStatus: emailDispatch.deliveryStatus,
          deliveryNote: emailDispatch.deliveryNote,
          isRead: false,
          createdAt: nowIso,
        });

        appendAudit(tx, {
          actorId: req.staffUser!.id,
          actorName: req.staffUser!.fullName,
          actorRole: req.staffUser!.role,
          action: 'TOKEN_GENERATED',
          targetType: 'TOKEN',
          targetId: cand.candidateCode,
          details: `Generated new onboarding token (expiry ${expiryHours}h) for ${cand.fullName}; prior active tokens revoked.`,
          ipAddress: getClientIp(req),
        });

        return { token: newToken, onboardingUrl, emailDispatch };
      });

      return res.json(result);
    } catch (err) {
      console.error('Generate token error:', err);
      return res.status(500).json({ error: 'Failed to generate onboarding link.' });
    }
  });

  app.post('/api/candidates/:id/token/revoke', requireAuth, async (req: AuthRequest, res) => {
    try {
      const candidateId = req.params.id;
      const db = store.getSnapshot();
      const cand = db.candidates.find((c) => c.id === candidateId);
      if (!cand) return res.status(404).json({ error: 'Candidate not found.' });

      await store.withTransaction((tx) => {
        for (const t of tx.tokens) {
          if (t.candidateId === candidateId) t.isRevoked = true;
        }
        appendAudit(tx, {
          actorId: req.staffUser!.id,
          actorName: req.staffUser!.fullName,
          actorRole: req.staffUser!.role,
          action: 'TOKEN_REVOKED',
          targetType: 'TOKEN',
          targetId: cand.candidateCode,
          details: `Revoked all active onboarding links for ${cand.fullName}.`,
          ipAddress: getClientIp(req),
        });
      });

      return res.json({ success: true });
    } catch (err) {
      console.error('Revoke token error:', err);
      return res.status(500).json({ error: 'Failed to revoke onboarding links.' });
    }
  });

  // Status Update
  app.patch('/api/candidates/:id/status', requireAuth, async (req: AuthRequest, res) => {
    try {
      const parsed = statusUpdateSchema.safeParse(sanitizeRecordStrings(req.body));
      if (!parsed.success) {
        return res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid status.' });
      }

      const candidateId = req.params.id;
      const nextStatus: OnboardingStatus = parsed.data.status;
      const note = parsed.data.note || '';

      // Only Admin or Super Admin can directly approve or reject onboarding
      if (
        (nextStatus === 'Approved' || nextStatus === 'Rejected' || nextStatus === 'Onboarding Completed') &&
        !['ADMIN', 'SUPER_ADMIN'].includes(req.staffUser!.role)
      ) {
        return res.status(403).json({
          error: 'Only Admin or Super Admin can approve, complete, or reject an onboarding application.',
        });
      }

      const db = store.getSnapshot();
      const existing = db.candidates.find((c) => c.id === candidateId);
      if (!existing) return res.status(404).json({ error: 'Candidate not found.' });

      const updated = await store.withTransaction(async (tx) => {
        const cand = tx.candidates.find((c) => c.id === candidateId)!;
        const prevStatus = cand.status;
        const nowIso = new Date().toISOString();
        cand.status = nextStatus;
        cand.updatedAt = nowIso;
        if (nextStatus === 'Correction Required' && note) {
          cand.correctionNotes = note;
        }

        tx.statusHistory.unshift({
          id: `sh-${crypto.randomBytes(6).toString('hex')}`,
          candidateId: cand.id,
          fromStatus: prevStatus,
          toStatus: nextStatus,
          changedById: req.staffUser!.id,
          changedByName: req.staffUser!.fullName,
          changedByRole: req.staffUser!.role,
          note: note || `Status changed from ${prevStatus} to ${nextStatus}.`,
          timestamp: nowIso,
        });

        const activeTok = tx.tokens.find(
          (t) => t.candidateId === cand.id && !t.isRevoked && new Date(t.expiresAt).getTime() > Date.now()
        );
        const onboardingUrl = activeTok ? `/onboard/${activeTok.token}` : undefined;

        if (['Documents Pending', 'Correction Required', 'Approved', 'Onboarding Completed'].includes(nextStatus)) {
          const emailRes = await dispatchNotificationEmail({
            to: cand.email,
            subject: `9HR India Onboarding Update: ${nextStatus}`,
            body: note || `Your onboarding status is now ${nextStatus}.`,
          });

          const notifType =
            nextStatus === 'Documents Pending'
              ? 'DOCUMENTS_PENDING'
              : nextStatus === 'Correction Required'
                ? 'CORRECTION_REQUESTED'
                : nextStatus === 'Approved'
                  ? 'FINAL_APPROVAL'
                  : 'ONBOARDING_COMPLETED';

          tx.notifications.unshift({
            id: `notif-${crypto.randomBytes(6).toString('hex')}`,
            type: notifType,
            title: `${nextStatus}: ${cand.fullName}`,
            message: note || `Application status updated to ${nextStatus}.`,
            recipientEmail: cand.email,
            recipientName: cand.fullName,
            candidateId: cand.id,
            candidateCode: cand.candidateCode,
            onboardingUrl,
            deliveryStatus: emailRes.deliveryStatus,
            deliveryNote: emailRes.deliveryNote,
            isRead: false,
            createdAt: nowIso,
          });
        }

        appendAudit(tx, {
          actorId: req.staffUser!.id,
          actorName: req.staffUser!.fullName,
          actorRole: req.staffUser!.role,
          action: 'STATUS_UPDATED',
          targetType: 'CANDIDATE',
          targetId: cand.candidateCode,
          details: `Changed ${cand.fullName} status from ${prevStatus} to ${nextStatus}. ${note}`,
          ipAddress: getClientIp(req),
        });

        return cand;
      });

      return res.json({ candidate: updated });
    } catch (err) {
      console.error('Status update error:', err);
      return res.status(500).json({ error: 'Failed to update status.' });
    }
  });

  app.post('/api/candidates/:id/request-correction', requireAuth, async (req: AuthRequest, res) => {
    try {
      const note = sanitizeText(req.body?.note);
      if (note.length < 5) {
        return res.status(400).json({ error: 'Provide clear correction instructions (min 5 characters).' });
      }

      const candidateId = req.params.id;
      const db = store.getSnapshot();
      const existing = db.candidates.find((c) => c.id === candidateId);
      if (!existing) return res.status(404).json({ error: 'Candidate not found.' });

      const result = await store.withTransaction(async (tx) => {
        const cand = tx.candidates.find((c) => c.id === candidateId)!;
        const prev = cand.status;
        const nowIso = new Date().toISOString();
        cand.status = 'Correction Required';
        cand.correctionNotes = note;
        cand.updatedAt = nowIso;

        // Ensure candidate has a non-expired link so they can actually resubmit
        let activeTok = tx.tokens.find(
          (t) => t.candidateId === candidateId && !t.isRevoked && new Date(t.expiresAt).getTime() > Date.now()
        );
        if (!activeTok) {
          activeTok = {
            id: `tok-${crypto.randomBytes(6).toString('hex')}`,
            candidateId,
            token: generateSecureOnboardingToken(),
            expiresAt: new Date(Date.now() + (tx.config.defaultLinkExpiryHours || 72) * 3600 * 1000).toISOString(),
            isRevoked: false,
            createdAt: nowIso,
            createdByName: req.staffUser!.fullName,
          };
          tx.tokens.unshift(activeTok);
        }

        tx.statusHistory.unshift({
          id: `sh-${crypto.randomBytes(6).toString('hex')}`,
          candidateId,
          fromStatus: prev,
          toStatus: 'Correction Required',
          changedById: req.staffUser!.id,
          changedByName: req.staffUser!.fullName,
          changedByRole: req.staffUser!.role,
          note,
          timestamp: nowIso,
        });

        const onboardingUrl = `/onboard/${activeTok.token}`;
        const emailDispatch = await dispatchNotificationEmail({
          to: cand.email,
          subject: 'Action Required: 9HR India Onboarding Correction Request',
          body: `${note} — Update your application at ${onboardingUrl}`,
        });

        tx.notifications.unshift({
          id: `notif-${crypto.randomBytes(6).toString('hex')}`,
          type: 'CORRECTION_REQUESTED',
          title: `Correction Requested: ${cand.fullName}`,
          message: note,
          recipientEmail: cand.email,
          recipientName: cand.fullName,
          candidateId: cand.id,
          candidateCode: cand.candidateCode,
          onboardingUrl,
          deliveryStatus: emailDispatch.deliveryStatus,
          deliveryNote: emailDispatch.deliveryNote,
          isRead: false,
          createdAt: nowIso,
        });

        appendAudit(tx, {
          actorId: req.staffUser!.id,
          actorName: req.staffUser!.fullName,
          actorRole: req.staffUser!.role,
          action: 'CORRECTION_REQUESTED',
          targetType: 'CANDIDATE',
          targetId: cand.candidateCode,
          details: `Requested corrections for ${cand.fullName}: ${note}`,
          ipAddress: getClientIp(req),
        });

        return { candidate: cand, onboardingUrl };
      });

      return res.json(result);
    } catch (err) {
      console.error('Request correction error:', err);
      return res.status(500).json({ error: 'Failed to send correction request.' });
    }
  });

  // Transactional Approve & Create Employee Record
  app.post(
    '/api/candidates/:id/approve-and-convert',
    requireAuth,
    requireRole('SUPER_ADMIN', 'ADMIN'),
    async (req: AuthRequest, res) => {
      try {
        const candidateId = req.params.id;
        const result = await store.withTransaction(async (tx) => {
          const cand = tx.candidates.find((c) => c.id === candidateId);
          if (!cand) {
            throw Object.assign(new Error('Candidate not found.'), { statusCode: 404 });
          }
          if (cand.status === 'Rejected') {
            throw Object.assign(new Error('Cannot convert a rejected candidate.'), { statusCode: 400 });
          }
          // Duplicate prevention check
          const existingEmployee = tx.employees.find(
            (e) => e.candidateId === cand.id || (cand.employeeId && e.id === cand.employeeId)
          );
          if (existingEmployee) {
            throw Object.assign(
              new Error(`Duplicate prevented: Employee ${existingEmployee.employeeCode} already exists for this candidate.`),
              { statusCode: 409 }
            );
          }

          const nowIso = new Date().toISOString();
          const year = new Date().getFullYear();
          tx.counters.employeeSeq += 1;
          const employeeCode = `9HR-EMP-${year}-${String(tx.counters.employeeSeq).padStart(4, '0')}`;
          const employeeId = `emp-${crypto.randomBytes(6).toString('hex')}`;

          const { confirmAccountNumber: _c, ...safeBank } = cand.bankDetails;
          const employee = {
            id: employeeId,
            employeeCode,
            candidateId: cand.id,
            candidateCode: cand.candidateCode,
            fullName: cand.personalInfo.fullName || cand.fullName,
            email: cand.personalInfo.email || cand.email,
            mobile: cand.personalInfo.mobileNumber || cand.mobile,
            position: cand.position,
            department: cand.department,
            joiningDate: cand.joiningDate,
            assignedRecruiterName: cand.assignedRecruiterName,
            personalInfo: cand.personalInfo,
            addressInfo: cand.addressInfo,
            familyInfo: cand.familyInfo,
            educationInfo: cand.educationInfo,
            employmentInfo: cand.employmentInfo,
            bankDetails: safeBank,
            isDemo: cand.isDemo,
            createdById: req.staffUser!.id,
            createdByName: req.staffUser!.fullName,
            createdAt: nowIso,
            updatedAt: nowIso,
          };

          const prevStatus = cand.status;
          cand.status = 'Onboarding Completed';
          cand.employeeId = employeeId;
          cand.employeeCode = employeeCode;
          cand.updatedAt = nowIso;

          // Revoke candidate onboarding tokens once converted
          for (const t of tx.tokens) {
            if (t.candidateId === cand.id) t.isRevoked = true;
          }

          tx.employees.unshift(employee);

          tx.statusHistory.unshift({
            id: `sh-${crypto.randomBytes(6).toString('hex')}`,
            candidateId: cand.id,
            fromStatus: prevStatus,
            toStatus: 'Onboarding Completed',
            changedById: req.staffUser!.id,
            changedByName: req.staffUser!.fullName,
            changedByRole: req.staffUser!.role,
            note: `Approved onboarding and created Employee ID ${employeeCode}.`,
            timestamp: nowIso,
          });

          const emailDispatch = await dispatchNotificationEmail({
            to: cand.email,
            subject: `Congratulations! Your 9HR India Employee ID is ${employeeCode}`,
            body: `Welcome aboard 9HR India Pvt. Ltd.! Your employee record ${employeeCode} has been activated.`,
          });

          tx.notifications.unshift({
            id: `notif-${crypto.randomBytes(6).toString('hex')}`,
            type: 'ONBOARDING_COMPLETED',
            title: `Employee Created: ${employeeCode} (${employee.fullName})`,
            message: `Onboarding approved and employee profile ${employeeCode} created in ${employee.department}.`,
            recipientEmail: employee.email,
            recipientName: employee.fullName,
            candidateId: cand.id,
            candidateCode: cand.candidateCode,
            deliveryStatus: emailDispatch.deliveryStatus,
            deliveryNote: emailDispatch.deliveryNote,
            isRead: false,
            createdAt: nowIso,
          });

          appendAudit(tx, {
            actorId: req.staffUser!.id,
            actorName: req.staffUser!.fullName,
            actorRole: req.staffUser!.role,
            action: 'EMPLOYEE_CREATED',
            targetType: 'EMPLOYEE',
            targetId: employeeCode,
            details: `Converted candidate ${cand.candidateCode} (${cand.fullName}) into Employee ${employeeCode}.`,
            ipAddress: getClientIp(req),
          });

          return { candidate: cand, employee };
        });

        return res.status(201).json(result);
      } catch (err: unknown) {
        const status = (err as { statusCode?: number }).statusCode || 500;
        const message = err instanceof Error ? err.message : 'Failed to convert candidate to employee.';
        return res.status(status).json({ error: message });
      }
    }
  );

  // ---------------------------------------------------------------------------
  // Document Verification & Authorized File Serving
  // ---------------------------------------------------------------------------
  app.get('/api/documents/queue', requireAuth, (req: AuthRequest, res) => {
    const db = store.getSnapshot();
    const statusFilter = (req.query.status as string) || 'ALL';
    const items = db.documents
      .filter((d) => (statusFilter === 'ALL' ? true : d.verificationStatus === statusFilter))
      .map((d) => {
        const cand = db.candidates.find((c) => c.id === d.candidateId);
        return {
          ...d,
          candidateCode: cand?.candidateCode || '',
          candidateName: cand?.fullName || 'Unknown',
          candidateDepartment: cand?.department || '',
          candidateStatus: cand?.status || 'Draft',
          isDemo: cand?.isDemo ?? false,
        };
      })
      .sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));

    res.json({ items });
  });

  app.get('/api/documents/:docId/file', requireAuth, (req: AuthRequest, res) => {
    const db = store.getSnapshot();
    const doc = db.documents.find((d) => d.id === req.params.docId);
    if (!doc) return res.status(404).json({ error: 'Document not found.' });

    const safeKey = path.basename(doc.storageKey);
    const fullPath = path.join(store.uploadDir, safeKey);
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ error: 'Document binary file missing from private storage.' });
    }

    const download = req.query.download === '1' || req.query.download === 'true';
    const disposition = download ? 'attachment' : 'inline';
    const safeFileName = doc.originalName.replace(/["\\\r\n]/g, '_');

    res.setHeader('Content-Type', doc.mimeType);
    res.setHeader('Content-Disposition', `${disposition}; filename="${safeFileName}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'private, no-store');
    return res.sendFile(fullPath);
  });

  app.post('/api/documents/:docId/verify', requireAuth, async (req: AuthRequest, res) => {
    try {
      const status = req.body?.status;
      const reason = sanitizeText(req.body?.reason || '');
      if (status !== 'Approved' && status !== 'Rejected') {
        return res.status(400).json({ error: 'Verification status must be Approved or Rejected.' });
      }
      if (status === 'Rejected' && reason.length < 3) {
        return res.status(400).json({ error: 'Provide a clear rejection reason.' });
      }

      const docId = req.params.docId;
      const db = store.getSnapshot();
      const existing = db.documents.find((d) => d.id === docId);
      if (!existing) return res.status(404).json({ error: 'Document not found.' });

      const updatedDoc = await store.withTransaction(async (tx) => {
        const doc = tx.documents.find((d) => d.id === docId)!;
        const cand = tx.candidates.find((c) => c.id === doc.candidateId);
        const nowIso = new Date().toISOString();

        doc.verificationStatus = status;
        doc.rejectionReason = status === 'Rejected' ? reason : undefined;
        doc.verifiedAt = nowIso;
        doc.verifiedByName = req.staffUser!.fullName;
        doc.history.unshift({
          id: `vh-${crypto.randomBytes(6).toString('hex')}`,
          status,
          reviewedById: req.staffUser!.id,
          reviewedByName: req.staffUser!.fullName,
          reason: reason || undefined,
          timestamp: nowIso,
        });

        if (cand) {
          const candDocs = tx.documents.filter((d) => d.candidateId === cand.id);
          cand.completionPct = calculateCompletionPercentage(cand, candDocs);
          cand.updatedAt = nowIso;

          if (status === 'Rejected') {
            const activeTok = tx.tokens.find(
              (t) => t.candidateId === cand.id && !t.isRevoked && new Date(t.expiresAt).getTime() > Date.now()
            );
            const onboardingUrl = activeTok ? `/onboard/${activeTok.token}` : undefined;
            const emailDispatch = await dispatchNotificationEmail({
              to: cand.email,
              subject: `9HR India Document Rejected: ${doc.category}`,
              body: `Your ${doc.category} was rejected: ${reason}`,
            });

            tx.notifications.unshift({
              id: `notif-${crypto.randomBytes(6).toString('hex')}`,
              type: 'DOCUMENT_REJECTED',
              title: `Document Rejected (${doc.category}): ${cand.fullName}`,
              message: `Reason: ${reason}`,
              recipientEmail: cand.email,
              recipientName: cand.fullName,
              candidateId: cand.id,
              candidateCode: cand.candidateCode,
              onboardingUrl,
              deliveryStatus: emailDispatch.deliveryStatus,
              deliveryNote: emailDispatch.deliveryNote,
              isRead: false,
              createdAt: nowIso,
            });
          }
        }

        appendAudit(tx, {
          actorId: req.staffUser!.id,
          actorName: req.staffUser!.fullName,
          actorRole: req.staffUser!.role,
          action: status === 'Approved' ? 'DOCUMENT_APPROVED' : 'DOCUMENT_REJECTED',
          targetType: 'DOCUMENT',
          targetId: doc.id,
          details: `${status} ${doc.category} for candidate ${cand?.candidateCode || doc.candidateId}${reason ? `: ${reason}` : ''}`,
          ipAddress: getClientIp(req),
        });

        return doc;
      });

      return res.json({ document: updatedDoc });
    } catch (err) {
      console.error('Document verify error:', err);
      return res.status(500).json({ error: 'Failed to update document verification.' });
    }
  });

  // ---------------------------------------------------------------------------
  // Employees, Notifications, Audit Logs, Config
  // ---------------------------------------------------------------------------
  app.get('/api/employees', requireAuth, (req: AuthRequest, res) => {
    const db = store.getSnapshot();
    const scope = (req.query.scope as string) || 'all';
    const search = ((req.query.search as string) || '').trim().toLowerCase();
    const department = (req.query.department as string) || 'ALL';

    const items = db.employees.filter((e) => {
      if (scope === 'live' && e.isDemo) return false;
      if (scope === 'demo' && !e.isDemo) return false;
      if (department !== 'ALL' && e.department !== department) return false;
      if (search) {
        const hay = `${e.employeeCode} ${e.fullName} ${e.email} ${e.position} ${e.department}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    res.json({ items });
  });

  app.get('/api/notifications', requireAuth, (_req, res) => {
    const db = store.getSnapshot();
    res.json({
      items: db.notifications,
      unreadCount: db.notifications.filter((n) => !n.isRead).length,
      smtpConfigured: isSmtpConfigured(),
    });
  });

  app.patch('/api/notifications/:id/read', requireAuth, async (req, res) => {
    await store.withTransaction((tx) => {
      if (req.params.id === 'all') {
        for (const n of tx.notifications) n.isRead = true;
      } else {
        const n = tx.notifications.find((item) => item.id === req.params.id);
        if (n) n.isRead = true;
      }
    });
    res.json({ success: true });
  });

  app.get('/api/audit-logs', requireAuth, requireRole('SUPER_ADMIN', 'ADMIN'), (req, res) => {
    const db = store.getSnapshot();
    const targetType = (req.query.targetType as string) || 'ALL';
    const search = ((req.query.search as string) || '').trim().toLowerCase();

    const items = db.auditLogs.filter((l) => {
      if (targetType !== 'ALL' && l.targetType !== targetType) return false;
      if (search) {
        const hay = `${l.actorName} ${l.action} ${l.targetId} ${l.details}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });
    res.json({ items });
  });

  app.get('/api/config', requireAuth, (_req, res) => {
    const db = store.getSnapshot();
    res.json({ config: { ...db.config, smtpConfigured: isSmtpConfigured() } });
  });

  app.patch('/api/config', requireAuth, requireRole('SUPER_ADMIN'), async (req: AuthRequest, res) => {
    try {
      const updated = await store.withTransaction((tx) => {
        if (typeof req.body?.defaultLinkExpiryHours === 'number') {
          tx.config.defaultLinkExpiryHours = Math.min(720, Math.max(1, req.body.defaultLinkExpiryHours));
        }
        if (typeof req.body?.demoModeEnabled === 'boolean') {
          tx.config.demoModeEnabled = req.body.demoModeEnabled;
        }
        if (Array.isArray(req.body?.departments)) {
          const depts = req.body.departments
            .map((d: unknown) => sanitizeText(d))
            .filter((d: string) => d.length >= 2);
          if (depts.length > 0) tx.config.departments = depts;
        }
        tx.config.updatedAt = new Date().toISOString();

        appendAudit(tx, {
          actorId: req.staffUser!.id,
          actorName: req.staffUser!.fullName,
          actorRole: req.staffUser!.role,
          action: 'CONFIG_UPDATED',
          targetType: 'SYSTEM',
          targetId: 'config',
          details: 'Updated system configuration settings.',
          ipAddress: getClientIp(req),
        });
        return tx.config;
      });
      return res.json({ config: updated });
    } catch (err) {
      console.error('Config update error:', err);
      return res.status(500).json({ error: 'Failed to update configuration.' });
    }
  });

  app.post('/api/demo/reset', requireAuth, requireRole('SUPER_ADMIN'), async (req: AuthRequest, res) => {
    try {
      await store.withTransaction((tx) => {
        const fresh = buildSeedDatabase(store.uploadDir);
        const liveUsers = tx.users.filter((u) => !u.isDemo);
        const liveCandidates = tx.candidates.filter((c) => !c.isDemo);
        const liveCandIds = new Set(liveCandidates.map((c) => c.id));
        const liveTokens = tx.tokens.filter((t) => liveCandIds.has(t.candidateId));
        const liveDocs = tx.documents.filter((d) => liveCandIds.has(d.candidateId));
        const liveEmployees = tx.employees.filter((e) => !e.isDemo);

        tx.users = [...liveUsers, ...fresh.users.filter((fu) => !liveUsers.some((lu) => lu.email === fu.email))];
        tx.candidates = [...liveCandidates, ...fresh.candidates];
        tx.tokens = [...liveTokens, ...fresh.tokens];
        tx.documents = [...liveDocs, ...fresh.documents];
        tx.employees = [...liveEmployees, ...fresh.employees];
        tx.statusHistory = fresh.statusHistory;
        tx.notifications = fresh.notifications;
        tx.auditLogs = [
          {
            id: `aud-${crypto.randomBytes(6).toString('hex')}`,
            actorId: req.staffUser!.id,
            actorName: req.staffUser!.fullName,
            actorRole: req.staffUser!.role,
            action: 'DEMO_DATA_RESET',
            targetType: 'SYSTEM',
            targetId: 'demo',
            details: 'Restored demo dataset while preserving live records.',
            ipAddress: getClientIp(req),
            timestamp: new Date().toISOString(),
          },
          ...fresh.auditLogs,
        ];
      });
      return res.json({ success: true });
    } catch (err) {
      console.error('Demo reset error:', err);
      return res.status(500).json({ error: 'Failed to reset demo dataset.' });
    }
  });

  // ---------------------------------------------------------------------------
  // Candidate Self-Service Onboarding Endpoints (Token-Gated, No Account Needed)
  // ---------------------------------------------------------------------------
  type ResolvedToken =
    | { ok: false; error: string; status: number; expired?: boolean }
    | { ok: true; token: OnboardingToken; candidate: Candidate; db: PortalDatabase };

  function resolveCandidateToken(tokenStr: string): ResolvedToken {
    const db = store.getSnapshot();
    const token = db.tokens.find((t) => t.token === tokenStr);
    if (!token) {
      return { ok: false, error: 'Invalid onboarding link. Please check the URL sent by 9HR India HR.', status: 404 };
    }
    if (token.isRevoked) {
      return { ok: false, error: 'This onboarding link has been revoked or superseded by a newer link. Please contact HR.', status: 403 };
    }
    if (new Date(token.expiresAt).getTime() <= Date.now()) {
      return {
        ok: false,
        error: 'This onboarding link has expired. Please contact your 9HR India recruiter to regenerate a fresh link.',
        status: 410,
        expired: true,
      };
    }
    const candidate = db.candidates.find((c) => c.id === token.candidateId);
    if (!candidate) {
      return { ok: false, error: 'Candidate profile no longer exists.', status: 404 };
    }
    return { ok: true, token, candidate, db };
  }

  const EDITABLE_CANDIDATE_STATUSES: OnboardingStatus[] = [
    'Draft',
    'Link Sent',
    'In Progress',
    'Documents Pending',
    'Correction Required',
  ];

  app.get('/api/onboard/:token', async (req, res) => {
    const resolved = resolveCandidateToken(req.params.token);
    if (!resolved.ok) {
      return res.status(resolved.status).json({ error: resolved.error, expired: resolved.expired });
    }

    const { token, candidate, db } = resolved;
    const documents = db.documents.filter((d) => d.candidateId === candidate.id);

    // Update lastAccessedAt without blocking response
    await store.withTransaction((tx) => {
      const tok = tx.tokens.find((t) => t.id === token.id);
      if (tok) tok.lastAccessedAt = new Date().toISOString();
    });

    return res.json({
      candidate,
      documents,
      tokenExpiresAt: token.expiresAt,
      editable: EDITABLE_CANDIDATE_STATUSES.includes(candidate.status),
      documentCategories: DOCUMENT_CATEGORIES,
      requiredCategories: REQUIRED_DOCUMENT_CATEGORIES,
    });
  });

  // Autosave draft / partial step updates
  app.patch('/api/onboard/:token', async (req, res) => {
    try {
      const resolved = resolveCandidateToken(req.params.token);
      if (!resolved.ok) {
        return res.status(resolved.status).json({ error: resolved.error, expired: resolved.expired });
      }
      if (!EDITABLE_CANDIDATE_STATUSES.includes(resolved.candidate.status)) {
        return res.status(403).json({
          error: `Application is currently "${resolved.candidate.status}" and locked from editing.`,
        });
      }

      const body = sanitizeRecordStrings(req.body || {});
      const candId = resolved.candidate.id;

      const updated = await store.withTransaction((tx) => {
        const cand = tx.candidates.find((c) => c.id === candId)!;
        const nowIso = new Date().toISOString();

        if (body.personalInfo && typeof body.personalInfo === 'object') {
          cand.personalInfo = { ...cand.personalInfo, ...body.personalInfo };
          if (cand.personalInfo.fullName) cand.fullName = cand.personalInfo.fullName;
        }
        if (body.addressInfo && typeof body.addressInfo === 'object') {
          cand.addressInfo = { ...cand.addressInfo, ...body.addressInfo };
          if (cand.addressInfo.sameAsCurrent) {
            cand.addressInfo.permanentAddress = cand.addressInfo.currentAddress;
          }
        }
        if (body.familyInfo && typeof body.familyInfo === 'object') {
          cand.familyInfo = { ...cand.familyInfo, ...body.familyInfo };
        }
        if (body.educationInfo && typeof body.educationInfo === 'object') {
          cand.educationInfo = { ...cand.educationInfo, ...body.educationInfo };
        }
        if (body.employmentInfo && typeof body.employmentInfo === 'object') {
          cand.employmentInfo = { ...cand.employmentInfo, ...body.employmentInfo };
        }
        if (body.bankDetails && typeof body.bankDetails === 'object') {
          cand.bankDetails = {
            ...cand.bankDetails,
            ...body.bankDetails,
            ifscCode: String(body.bankDetails.ifscCode ?? cand.bankDetails.ifscCode).toUpperCase(),
          };
        }
        if (body.declaration && typeof body.declaration === 'object') {
          cand.declaration = { ...cand.declaration, ...body.declaration };
        }

        if (cand.status === 'Link Sent' || cand.status === 'Draft') {
          const prev = cand.status;
          cand.status = 'In Progress';
          tx.statusHistory.unshift({
            id: `sh-${crypto.randomBytes(6).toString('hex')}`,
            candidateId: cand.id,
            fromStatus: prev,
            toStatus: 'In Progress',
            changedById: cand.id,
            changedByName: cand.fullName,
            changedByRole: 'CANDIDATE',
            note: 'Candidate started filling onboarding details.',
            timestamp: nowIso,
          });
        }

        const candDocs = tx.documents.filter((d) => d.candidateId === cand.id);
        cand.completionPct = calculateCompletionPercentage(cand, candDocs);
        cand.updatedAt = nowIso;
        return cand;
      });

      return res.json({ candidate: updated, savedAt: new Date().toISOString() });
    } catch (err) {
      console.error('Autosave error:', err);
      return res.status(500).json({ error: 'Failed to save draft.' });
    }
  });

  // Candidate Document Upload (Private Storage + Extension + MIME + Magic-Byte Validation)
  app.post(
    '/api/onboard/:token/documents',
    (req, res, next) => {
      upload.single('file')(req, res, (err: unknown) => {
        if (err instanceof multer.MulterError) {
          if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File exceeds maximum allowed size of 5 MB.' });
          }
          return res.status(400).json({ error: err.message });
        }
        if (err) {
          return res.status(400).json({ error: 'File upload failed.' });
        }
        return next();
      });
    },
    async (req, res) => {
      try {
        const resolved = resolveCandidateToken(req.params.token);
        if (!resolved.ok) {
          return res.status(resolved.status).json({ error: resolved.error, expired: resolved.expired });
        }
        if (!EDITABLE_CANDIDATE_STATUSES.includes(resolved.candidate.status)) {
          return res.status(403).json({
            error: `Documents cannot be modified when application status is "${resolved.candidate.status}".`,
          });
        }

        const categoryParsed = documentCategorySchema.safeParse(req.body?.category);
        if (!categoryParsed.success) {
          return res.status(400).json({ error: 'Invalid document category.' });
        }

        const file = req.file;
        if (!file) {
          return res.status(400).json({ error: 'No file attached.' });
        }

        const ext = path.extname(file.originalname).toLowerCase();
        const sigCheck = validateMagicBytes(file.buffer, ext, file.mimetype);
        if (!sigCheck.valid) {
          return res.status(400).json({ error: sigCheck.reason || 'Invalid or unsafe file.' });
        }

        const storageKey = `${resolved.candidate.id}_${crypto.randomBytes(16).toString('hex')}${ext}`;
        const destPath = path.join(store.uploadDir, storageKey);
        fs.writeFileSync(destPath, file.buffer);

        const result = await store.withTransaction((tx) => {
          const cand = tx.candidates.find((c) => c.id === resolved.candidate.id)!;
          const nowIso = new Date().toISOString();

          // Replace previous rejected or same-category document cleanly
          const oldDocs = tx.documents.filter(
            (d) => d.candidateId === cand.id && d.category === categoryParsed.data
          );
          for (const old of oldDocs) {
            const oldPath = path.join(store.uploadDir, path.basename(old.storageKey));
            if (fs.existsSync(oldPath) && !old.storageKey.startsWith('demo_')) {
              fs.unlinkSync(oldPath);
            }
          }
          tx.documents = tx.documents.filter(
            (d) => !(d.candidateId === cand.id && d.category === categoryParsed.data)
          );

          const doc: CandidateDocument = {
            id: `doc-${crypto.randomBytes(6).toString('hex')}`,
            candidateId: cand.id,
            category: categoryParsed.data,
            originalName: sanitizeText(path.basename(file.originalname)).slice(0, 140),
            mimeType: file.mimetype,
            sizeBytes: file.size,
            storageKey,
            verificationStatus: 'Pending',
            uploadedAt: nowIso,
            history: [],
          };

          tx.documents.push(doc);

          if (cand.status === 'Link Sent' || cand.status === 'Draft') {
            cand.status = 'In Progress';
          }
          const candDocs = tx.documents.filter((d) => d.candidateId === cand.id);
          cand.completionPct = calculateCompletionPercentage(cand, candDocs);
          cand.updatedAt = nowIso;

          appendAudit(tx, {
            actorId: cand.id,
            actorName: cand.fullName,
            actorRole: 'CANDIDATE',
            action: 'DOCUMENT_UPLOADED',
            targetType: 'DOCUMENT',
            targetId: doc.id,
            details: `Candidate ${cand.candidateCode} uploaded ${doc.category} (${doc.originalName}).`,
            ipAddress: getClientIp(req),
          });

          return { document: doc, completionPct: cand.completionPct };
        });

        return res.status(201).json(result);
      } catch (err) {
        console.error('Upload document error:', err);
        return res.status(500).json({ error: 'Failed to store uploaded document.' });
      }
    }
  );

  app.get('/api/onboard/:token/documents/:docId/file', (req, res) => {
    const resolved = resolveCandidateToken(req.params.token);
    if (!resolved.ok) {
      return res.status(resolved.status).json({ error: resolved.error });
    }
    const doc = resolved.db.documents.find(
      (d) => d.id === req.params.docId && d.candidateId === resolved.candidate.id
    );
    if (!doc) return res.status(404).json({ error: 'Document not found.' });

    const fullPath = path.join(store.uploadDir, path.basename(doc.storageKey));
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ error: 'File unavailable.' });
    }
    res.setHeader('Content-Type', doc.mimeType);
    res.setHeader('Content-Disposition', `inline; filename="${doc.originalName.replace(/["\\\r\n]/g, '_')}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return res.sendFile(fullPath);
  });

  app.delete('/api/onboard/:token/documents/:docId', async (req, res) => {
    const resolved = resolveCandidateToken(req.params.token);
    if (!resolved.ok) {
      return res.status(resolved.status).json({ error: resolved.error });
    }
    if (!EDITABLE_CANDIDATE_STATUSES.includes(resolved.candidate.status)) {
      return res.status(403).json({ error: 'Application is locked from document removal.' });
    }

    const doc = resolved.db.documents.find(
      (d) => d.id === req.params.docId && d.candidateId === resolved.candidate.id
    );
    if (!doc) return res.status(404).json({ error: 'Document not found.' });

    const completionPct = await store.withTransaction((tx) => {
      const target = tx.documents.find((d) => d.id === doc.id);
      if (target) {
        const p = path.join(store.uploadDir, path.basename(target.storageKey));
        if (fs.existsSync(p) && !target.storageKey.startsWith('demo_')) {
          fs.unlinkSync(p);
        }
      }
      tx.documents = tx.documents.filter((d) => d.id !== doc.id);
      const cand = tx.candidates.find((c) => c.id === resolved.candidate.id)!;
      const candDocs = tx.documents.filter((d) => d.candidateId === cand.id);
      cand.completionPct = calculateCompletionPercentage(cand, candDocs);
      cand.updatedAt = new Date().toISOString();
      return cand.completionPct;
    });

    return res.json({ success: true, completionPct });
  });

  // Final Candidate Submission (or Resubmission after Correction Request)
  app.post('/api/onboard/:token/submit', async (req, res) => {
    try {
      const resolved = resolveCandidateToken(req.params.token);
      if (!resolved.ok) {
        return res.status(resolved.status).json({ error: resolved.error, expired: resolved.expired });
      }
      if (!EDITABLE_CANDIDATE_STATUSES.includes(resolved.candidate.status)) {
        return res.status(400).json({
          error: `Application is already "${resolved.candidate.status}".`,
        });
      }

      const payload = sanitizeRecordStrings(req.body || {});
      const candSnapshot = resolved.candidate;

      const merged = {
        personalInfo: { ...candSnapshot.personalInfo, ...(payload.personalInfo || {}) },
        addressInfo: { ...candSnapshot.addressInfo, ...(payload.addressInfo || {}) },
        familyInfo: { ...candSnapshot.familyInfo, ...(payload.familyInfo || {}) },
        educationInfo: { ...candSnapshot.educationInfo, ...(payload.educationInfo || {}) },
        employmentInfo: { ...candSnapshot.employmentInfo, ...(payload.employmentInfo || {}) },
        bankDetails: {
          ...candSnapshot.bankDetails,
          ...(payload.bankDetails || {}),
          ifscCode: String(payload.bankDetails?.ifscCode ?? candSnapshot.bankDetails.ifscCode).toUpperCase(),
        },
        declaration: { ...candSnapshot.declaration, ...(payload.declaration || {}) },
      };

      if (merged.addressInfo.sameAsCurrent) {
        merged.addressInfo.permanentAddress = merged.addressInfo.currentAddress;
      }

      // Full multi-step server-side validation
      const checks = [
        { name: 'Personal Information', res: personalInfoSchema.safeParse(merged.personalInfo) },
        { name: 'Address Information', res: addressInfoSchema.safeParse(merged.addressInfo) },
        { name: 'Family Information', res: familyInfoSchema.safeParse(merged.familyInfo) },
        { name: 'Educational Information', res: educationInfoSchema.safeParse(merged.educationInfo) },
        { name: 'Employment Information', res: employmentInfoSchema.safeParse(merged.employmentInfo) },
        {
          name: 'Banking Information',
          res: bankDetailsSchema.safeParse({
            ...merged.bankDetails,
            confirmAccountNumber: merged.bankDetails.confirmAccountNumber ?? merged.bankDetails.accountNumber,
          }),
        },
        { name: 'Declaration', res: declarationSchema.safeParse(merged.declaration) },
      ];

      for (const check of checks) {
        if (!check.res.success) {
          const firstIssue = check.res.error.issues[0];
          return res.status(400).json({
            error: `${check.name}: ${firstIssue?.message || 'Incomplete or invalid fields.'}`,
            section: check.name,
            field: firstIssue?.path?.join('.'),
          });
        }
      }

      // Verify all required document categories exist and are not rejected
      const docs = resolved.db.documents.filter((d) => d.candidateId === candSnapshot.id);
      const validCats = new Set(
        docs.filter((d) => d.verificationStatus !== 'Rejected').map((d) => d.category)
      );
      const missingCats = REQUIRED_DOCUMENT_CATEGORIES.filter((cat) => !validCats.has(cat));
      if (missingCats.length > 0) {
        return res.status(400).json({
          error: `Please upload valid documents for: ${missingCats.join(', ')}`,
          section: 'Document Upload',
        });
      }

      const submittedCandidate = await store.withTransaction(async (tx) => {
        const cand = tx.candidates.find((c) => c.id === candSnapshot.id)!;
        const prevStatus = cand.status;
        const nowIso = new Date().toISOString();

        cand.personalInfo = merged.personalInfo;
        cand.addressInfo = merged.addressInfo;
        cand.familyInfo = merged.familyInfo;
        cand.educationInfo = merged.educationInfo;
        cand.employmentInfo = merged.employmentInfo;
        cand.bankDetails = merged.bankDetails;
        cand.declaration = {
          accepted: true,
          digitalSignature: merged.declaration.digitalSignature,
          submittedAt: nowIso,
        };
        cand.fullName = cand.personalInfo.fullName || cand.fullName;
        cand.status = 'Submitted';
        cand.correctionNotes = undefined;
        cand.updatedAt = nowIso;

        const candDocs = tx.documents.filter((d) => d.candidateId === cand.id);
        cand.completionPct = calculateCompletionPercentage(cand, candDocs);

        tx.statusHistory.unshift({
          id: `sh-${crypto.randomBytes(6).toString('hex')}`,
          candidateId: cand.id,
          fromStatus: prevStatus,
          toStatus: 'Submitted',
          changedById: cand.id,
          changedByName: cand.fullName,
          changedByRole: 'CANDIDATE',
          note:
            prevStatus === 'Correction Required'
              ? 'Candidate resubmitted corrected onboarding application.'
              : 'Candidate completed all 8 steps and submitted onboarding package.',
          timestamp: nowIso,
        });

        const recruiter = tx.users.find((u) => u.id === cand.assignedRecruiterId);
        const hrEmail = recruiter?.email || 'hr@9hrindia.com';
        const hrName = recruiter?.fullName || cand.assignedRecruiterName;
        const emailDispatch = await dispatchNotificationEmail({
          to: hrEmail,
          subject: `Onboarding Submitted: ${cand.fullName} (${cand.candidateCode})`,
          body: `${cand.fullName} has submitted their onboarding form and documents for verification.`,
        });

        tx.notifications.unshift({
          id: `notif-${crypto.randomBytes(6).toString('hex')}`,
          type: 'CANDIDATE_SUBMITTED',
          title:
            prevStatus === 'Correction Required'
              ? `Resubmitted After Corrections: ${cand.fullName}`
              : `Onboarding Submitted: ${cand.fullName}`,
          message: `${cand.fullName} (${cand.position}) submitted all onboarding details for HR review.`,
          recipientEmail: hrEmail,
          recipientName: hrName,
          candidateId: cand.id,
          candidateCode: cand.candidateCode,
          deliveryStatus: emailDispatch.deliveryStatus === 'SENT_SMTP' ? 'SENT_SMTP' : 'IN_APP_ONLY',
          deliveryNote:
            emailDispatch.deliveryStatus === 'SENT_SMTP'
              ? emailDispatch.deliveryNote
              : 'Notification delivered to HR Portal inbox.',
          isRead: false,
          createdAt: nowIso,
        });

        appendAudit(tx, {
          actorId: cand.id,
          actorName: cand.fullName,
          actorRole: 'CANDIDATE',
          action: prevStatus === 'Correction Required' ? 'ONBOARDING_RESUBMITTED' : 'ONBOARDING_SUBMITTED',
          targetType: 'CANDIDATE',
          targetId: cand.candidateCode,
          details: `Candidate ${cand.fullName} submitted onboarding application.`,
          ipAddress: getClientIp(req),
        });

        return cand;
      });

      return res.json({
        success: true,
        candidate: submittedCandidate,
        message: 'Your onboarding package has been submitted to 9HR India HR.',
      });
    } catch (err) {
      console.error('Submit onboarding error:', err);
      return res.status(500).json({ error: 'Failed to submit onboarding application.' });
    }
  });

  // API 404 handler
  app.use('/api/*', (_req, res) => {
    res.status(404).json({ error: 'API endpoint not found.' });
  });

  // Global error handler
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    console.error('Unhandled server error:', err);
    res.status(500).json({ error: 'An unexpected server error occurred.' });
  });

  return { app, store };
}
