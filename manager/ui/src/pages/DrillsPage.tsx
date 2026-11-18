import type { JSX } from 'preact';
import { EmptyState } from '../components/atoms';
import { Link } from '../components/viz';
import { PageHeader } from './common';

/** Honest placeholder: drills are specified in 10-drills-integrations.md and arrive in milestone M5. Nothing here acts. */
export function DrillsPage(): JSX.Element {
  return (
    <>
      <PageHeader title="Drills" />
      <EmptyState title="Drills arrive in M5" action={<Link to="/settings" class="btn">Open settings</Link>}>
        Failure drills (scheduled, approved and aborted from this page) are not part of this release, so there is nothing to create, approve or start yet. The drill switches in Settings are stored but have no effect until then.
      </EmptyState>
    </>
  );
}
