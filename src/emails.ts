import { createRequire } from 'node:module'
import vm from 'node:vm'

import { render } from '@react-email/render'
import { transform } from 'esbuild'
import { createElement, type ComponentType } from 'react'

const require = createRequire(import.meta.url)

/**
 * Props passed to react-email templates. Values are GoTrue Go-template
 * tokens: they survive rendering as literal strings and GoTrue substitutes
 * them when the email is sent.
 */
export const GOTRUE_TEMPLATE_PROPS = {
  confirmationURL: '{{ .ConfirmationURL }}',
  token: '{{ .Token }}',
  tokenHash: '{{ .TokenHash }}',
  siteURL: '{{ .SiteURL }}',
  email: '{{ .Email }}',
  newEmail: '{{ .NewEmail }}',
  redirectTo: '{{ .RedirectTo }}',
  data: '{{ .Data }}',
} as const

export type GoTrueTemplateProps = Record<keyof typeof GOTRUE_TEMPLATE_PROPS, string>

/**
 * Compiles a react-email TSX/JSX module source and renders its default
 * export to HTML. The module may import react and @react-email/components.
 */
export async function renderReactEmail(source: string): Promise<string> {
  const { code } = await transform(source, {
    loader: 'tsx',
    format: 'cjs',
    jsx: 'automatic',
    target: 'node20',
  })

  const module = { exports: {} as { default?: ComponentType<GoTrueTemplateProps> } }
  const context = vm.createContext({
    module,
    exports: module.exports,
    require,
    process: { env: {} },
    console,
  })
  new vm.Script(code, { filename: 'email-template.tsx' }).runInContext(context, {
    timeout: 5_000,
  })

  const Component = module.exports.default
  if (typeof Component !== 'function') {
    throw new Error('react email template must have a React component as its default export')
  }

  return render(createElement(Component, { ...GOTRUE_TEMPLATE_PROPS }))
}
