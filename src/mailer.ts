import nodemailer from 'nodemailer'

import { baselineConfig } from './baseline.js'
import { getAllConfig, type ConfigValue } from './store.js'

export type SmtpSettings = {
  host: string
  port: number
  user: string
  pass: string
  adminEmail: string
  senderName: string
}

function asString(value: ConfigValue | undefined): string {
  return typeof value === 'string' ? value : ''
}

/** Effective SMTP settings: runtime overrides on top of the stack's env
 * baseline - the same values GoTrue uses for auth emails. */
export async function getSmtpSettings(): Promise<SmtpSettings | null> {
  // Dashboard emails (team invitations) always go through the main stack's
  // SMTP configuration, which lives under the default project.
  const config = { ...baselineConfig(), ...(await getAllConfig('default')) }
  const host = asString(config.SMTP_HOST)
  const adminEmail = asString(config.SMTP_ADMIN_EMAIL)
  if (!host || !adminEmail) return null
  const port = Number(asString(config.SMTP_PORT) || '587')
  return {
    host,
    port: Number.isInteger(port) && port > 0 ? port : 587,
    user: asString(config.SMTP_USER),
    pass: asString(config.SMTP_PASS),
    adminEmail,
    senderName: asString(config.SMTP_SENDER_NAME),
  }
}

export async function isSmtpConfigured(): Promise<boolean> {
  return (await getSmtpSettings()) !== null
}

/** Sends a dashboard invitation email. Returns false when SMTP is not
 * configured; throws when SMTP is configured but delivery fails. */
export async function sendInvitationEmail(input: {
  to: string
  joinUrl: string
  invitedBy: string
  role: string
}): Promise<boolean> {
  const smtp = await getSmtpSettings()
  if (!smtp) return false

  const transport = nodemailer.createTransport({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.port === 465,
    auth: smtp.user ? { user: smtp.user, pass: smtp.pass } : undefined,
  })

  const from = smtp.senderName ? `"${smtp.senderName}" <${smtp.adminEmail}>` : smtp.adminEmail
  await transport.sendMail({
    from,
    to: input.to,
    subject: 'You have been invited to a Supabase dashboard',
    text: [
      `${input.invitedBy} invited you to join the Supabase dashboard as ${input.role}.`,
      '',
      `Accept the invitation (one-time link):`,
      input.joinUrl,
      '',
      'If you were not expecting this invitation, you can ignore this email.',
    ].join('\n'),
  })
  return true
}
