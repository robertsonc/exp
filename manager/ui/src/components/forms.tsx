import type { ComponentChildren, JSX } from 'preact';
import { useId } from 'preact/hooks';
import type { SecretState } from '../api/types';
import { formatAbsolute } from '../lib/format';
import { ApiFailure } from '../data/store';

type InputEl = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
const val = (e: Event): string => (e.currentTarget as InputEl).value;

interface BaseProps { label: string; hint?: ComponentChildren; error?: string | null; wide?: boolean }

function FieldShell({ label, hint, error, id, wide, children }: BaseProps & { id: string; children: ComponentChildren }): JSX.Element {
  return (
    <div class={`field${wide ? ' field-wide' : ''}`}>
      <label for={id}>{label}</label>
      {children}
      {hint ? <span class="hint" id={`${id}-hint`}>{hint}</span> : null}
      {error ? <span class="field-error" id={`${id}-err`} role="alert">{error}</span> : null}
    </div>
  );
}

const describe = (id: string, hint: unknown, error: unknown): string | undefined => [hint ? `${id}-hint` : '', error ? `${id}-err` : ''].filter(Boolean).join(' ') || undefined;

export function TextField({ label, value, onInput, error, hint, type = 'text', placeholder, disabled, wide, autoComplete = 'off', inputMode, maxLength, name }: BaseProps & {
  value: string; onInput: (v: string) => void; type?: 'text' | 'number' | 'password' | 'email' | 'url' | 'datetime-local'; placeholder?: string; disabled?: boolean;
  autoComplete?: string; inputMode?: 'numeric' | 'decimal' | 'text'; maxLength?: number; name?: string;
}): JSX.Element {
  const id = useId();
  return (
    <FieldShell label={label} hint={hint} error={error} id={id} wide={wide}>
      <input id={id} name={name} type={type} value={value} placeholder={placeholder} disabled={disabled} autocomplete={autoComplete} spellcheck={false}
        inputMode={inputMode} maxLength={maxLength} aria-invalid={error ? 'true' : undefined} aria-describedby={describe(id, hint, error)} onInput={(e) => onInput(val(e))} />
    </FieldShell>
  );
}

export function TextArea({ label, value, onInput, error, hint, rows = 3, disabled, wide }: BaseProps & { value: string; onInput: (v: string) => void; rows?: number; disabled?: boolean }): JSX.Element {
  const id = useId();
  return (
    <FieldShell label={label} hint={hint} error={error} id={id} wide={wide}>
      <textarea id={id} rows={rows} value={value} disabled={disabled} spellcheck={false} aria-invalid={error ? 'true' : undefined} aria-describedby={describe(id, hint, error)} onInput={(e) => onInput(val(e))} />
    </FieldShell>
  );
}

export function SelectField({ label, value, onChange, options, error, hint, disabled, wide }: BaseProps & {
  value: string; onChange: (v: string) => void; options: { value: string; label: string; disabled?: boolean }[]; disabled?: boolean;
}): JSX.Element {
  const id = useId();
  return (
    <FieldShell label={label} hint={hint} error={error} id={id} wide={wide}>
      <select id={id} value={value} disabled={disabled} aria-invalid={error ? 'true' : undefined} aria-describedby={describe(id, hint, error)} onChange={(e) => onChange(val(e))}>
        {options.map((o) => <option key={o.value} value={o.value} disabled={o.disabled}>{o.label}</option>)}
      </select>
    </FieldShell>
  );
}

export function CheckField({ label, checked, onChange, disabled, hint }: { label: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; hint?: string }): JSX.Element {
  const id = useId();
  return (
    <div class="check-field">
      <label class="check" for={id}>
        <input id={id} type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange((e.currentTarget as HTMLInputElement).checked)} />
        <span>{label}</span>
      </label>
      {hint ? <span class="hint">{hint}</span> : null}
    </div>
  );
}

/** "set · updated 2 Nov 2026, 09:14 UTC" or "not set": the only thing ever shown of a write-only secret. */
export function secretSummary(s: SecretState | null | undefined): string {
  if (!s || !s.set) return 'not set';
  return s.updated_at ? `set · updated ${formatAbsolute(s.updated_at)}` : 'set';
}

/** Write-only field: never prefilled, shows only whether a value is stored; typing replaces it, empty keeps it. */
export function SecretField({ label, state, value, onInput, error, hint, placeholder = 'Enter a new value to replace it', disabled }: BaseProps & {
  state: SecretState | null | undefined; value: string; onInput: (v: string) => void; placeholder?: string; disabled?: boolean;
}): JSX.Element {
  const id = useId();
  const summary = secretSummary(state);
  return (
    <FieldShell label={label} hint={hint} error={error} id={id}>
      <div class="secret-row">
        <span class={`secret-state${state?.set ? ' secret-set' : ''}`} data-testid="secret-state">{summary}</span>
        <input id={id} type="text" value={value} disabled={disabled} placeholder={state?.set ? placeholder : 'https://…'} autocomplete="off" spellcheck={false}
          aria-invalid={error ? 'true' : undefined} aria-describedby={describe(id, hint, error)} onInput={(e) => onInput(val(e))} />
      </div>
    </FieldShell>
  );
}

export function FormError({ error }: { error: string | null }): JSX.Element | null {
  return error ? <p class="form-error" role="alert">{error}</p> : null;
}

/** One line for an API failure: the message plus its code, so the admin can quote it. */
export function failText(e: unknown): string {
  if (e instanceof ApiFailure) return e.code && e.code !== 'unknown' ? `${e.message} (${e.code})` : e.message;
  return e instanceof Error ? e.message : 'Request failed';
}

export function Fieldset({ legend, children, hint }: { legend: string; children: ComponentChildren; hint?: ComponentChildren }): JSX.Element {
  return (
    <fieldset class="fieldset">
      <legend>{legend}</legend>
      {hint ? <p class="hint">{hint}</p> : null}
      {children}
    </fieldset>
  );
}

export function Row({ children }: { children: ComponentChildren }): JSX.Element {
  return <div class="form-row">{children}</div>;
}
